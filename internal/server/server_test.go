// Caminho: internal/server/server_test.go
//
// Testes de INTEGRAÇÃO: o gateway completo (todos os middlewares e rotas), com
// Redis em memória (miniredis) e serviços internos falsos (httptest.Server).
// Cada teste exercita uma defesa do OWASP API Security Top 10 de ponta a ponta.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"gateway-seguranca/internal/auth"
	"gateway-seguranca/internal/clientip"
	"gateway-seguranca/internal/config"
	"gateway-seguranca/internal/ipblock"
	"gateway-seguranca/internal/ratelimit"
	"gateway-seguranca/internal/seclog"
)

// Segredos SINTÉTICOS usados só nos testes.
const (
	ledgerSecret  = "segredo-ledger-de-teste-com-32-caracteres!"
	leituraSecret = "segredo-leitura-de-teste-com-32-caracteres"
)

// memSink guarda os eventos de segurança (protegido por mutex, pois o
// servidor de teste atende em outra goroutine).
type memSink struct {
	mu     sync.Mutex
	events []seclog.Event
}

func (m *memSink) Write(e seclog.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
}

func (m *memSink) count(t seclog.EventType) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.events {
		if e.Type == t {
			n++
		}
	}
	return n
}

// env é o "ambiente de teste" montado por newEnv.
type env struct {
	gw    *httptest.Server
	mr    *miniredis.Miniredis
	sink  *memSink
	cfg   *config.Config
	block *ipblock.Blocker
}

type options struct {
	clientCapacity int64
	maxBody        int64
	trusted        string
}

func newEnv(t *testing.T, opt options) *env {
	t.Helper()
	if opt.clientCapacity == 0 {
		opt.clientCapacity = 100
	}
	if opt.maxBody == 0 {
		opt.maxBody = 1 << 20
	}

	// Serviços internos falsos: devolvem o path e a identidade recebida.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"path":          r.URL.Path,
			"client_id":     r.Header.Get("X-Gateway-Client-ID"),
			"authorization": r.Header.Get("Authorization"),
		})
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)

	cfg := &config.Config{
		MaxBodyBytes:    opt.maxBody,
		UpstreamTimeout: 2 * time.Second,
		Upstreams: []config.Upstream{
			{Name: "ledger", URL: u}, {Name: "pix", URL: u}, {Name: "antifraude", URL: u},
		},
		RateIP:     config.RateLimit{Capacity: 1000, Refill: 1000},
		RateOAuth:  config.RateLimit{Capacity: 1000, Refill: 1000},
		RateClient: config.RateLimit{Capacity: opt.clientCapacity, Refill: 0.001},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	tokens, err := auth.NewTokenService([]byte(strings.Repeat("s", 32)), "gw", "svc", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clients, err := auth.ParseClients(fmt.Sprintf(`[
		{"client_id":"app-ledger","secret_sha256":"%s","scopes":["ledger:read","ledger:write"]},
		{"client_id":"app-leitura","secret_sha256":"%s","scopes":["ledger:read"]}
	]`, auth.HashSecret(ledgerSecret), auth.HashSecret(leituraSecret)))
	if err != nil {
		t.Fatal(err)
	}

	blocker, _ := ipblock.New(rdb, 3, time.Minute, 10*time.Minute)
	resolver, err := clientip.New(opt.trusted)
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSink{}
	monitor := seclog.NewMonitor(logger, blocker, sink)

	mk := func(prefix string, rl config.RateLimit) ratelimit.Limiter {
		l, err := ratelimit.NewRedisLimiter(rdb, prefix, rl.Capacity, rl.Refill)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}

	h := NewRouter(Deps{
		Config: cfg, Logger: logger, Tokens: tokens, Clients: clients, Reporter: monitor,
		IPLimiter: mk("rl:ip", cfg.RateIP), OAuthLimiter: mk("rl:oauth", cfg.RateOAuth),
		ClientLimiter: mk("rl:svc", cfg.RateClient),
		Blocker:       blocker, ClientIP: resolver.ClientIP,
		ReadyChecks: map[string]func(ctx context.Context) error{"redis": func(ctx context.Context) error { return rdb.Ping(ctx).Err() }},
	})
	gw := httptest.NewServer(h)
	t.Cleanup(gw.Close)
	return &env{gw: gw, mr: mr, sink: sink, cfg: cfg, block: blocker}
}

// do envia uma requisição ao gateway de teste.
func (e *env) do(t *testing.T, method, path, token string, body io.Reader, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, e.gw.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.gw.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// token obtém um access token pelo endpoint real.
func (e *env) token(t *testing.T, id, secret string) string {
	t.Helper()
	req, _ := http.NewRequest("POST", e.gw.URL+"/oauth/token", strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(id, secret)
	resp, err := e.gw.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("emissão de token falhou: %d", resp.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return body.AccessToken
}

func readJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("resposta não é JSON: %v", err)
	}
	return m
}

func TestHealthAndReady(t *testing.T) {
	e := newEnv(t, options{})
	if r := e.do(t, "GET", "/healthz", "", nil, nil); r.StatusCode != 200 {
		t.Errorf("/healthz = %d", r.StatusCode)
	}
	if r := e.do(t, "GET", "/readyz", "", nil, nil); r.StatusCode != 200 {
		t.Errorf("/readyz = %d", r.StatusCode)
	}
	e.mr.Close()
	r := e.do(t, "GET", "/readyz", "", nil, nil)
	if r.StatusCode != 503 || readJSON(t, r)["redis"] != "down" {
		t.Errorf("/readyz com Redis fora deveria ser 503")
	}
}

func TestFullFlowAndIdentityForwarding(t *testing.T) {
	e := newEnv(t, options{})
	tok := e.token(t, "app-ledger", ledgerSecret)
	resp := e.do(t, "GET", "/ledger/contas/123", tok, nil, map[string]string{"X-Gateway-Client-ID": "admin"})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body := readJSON(t, resp)
	if body["path"] != "/contas/123" || body["client_id"] != "app-ledger" || body["authorization"] != "" {
		t.Errorf("encaminhamento incorreto: %v", body)
	}
	// Cabeçalhos de segurança (API8).
	for k, v := range map[string]string{"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"} {
		if resp.Header.Get(k) != v {
			t.Errorf("%s = %q", k, resp.Header.Get(k))
		}
	}
	if len(resp.Header.Get("X-Request-ID")) != 32 {
		t.Error("X-Request-ID ausente")
	}
}

func TestAuthenticationAndAuthorization(t *testing.T) {
	e := newEnv(t, options{})
	leitura := e.token(t, "app-leitura", leituraSecret)
	cases := []struct {
		name, method, path, token string
		want                      int
	}{
		{"sem token (API2)", "GET", "/ledger/contas", "", 401},
		{"leitura permitida", "GET", "/ledger/contas", leitura, 200},
		{"escrita negada (API5)", "POST", "/ledger/lancamentos", leitura, 403},
		{"outro serviço negado", "GET", "/pix/chaves", leitura, 403},
		{"método proibido", "TRACE", "/ledger/contas", leitura, 405},
		{"rota inexistente", "GET", "/admin", leitura, 404},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if r := e.do(t, tc.method, tc.path, tc.token, nil, nil); r.StatusCode != tc.want {
				t.Errorf("status = %d, esperado %d", r.StatusCode, tc.want)
			}
		})
	}
	if e.sink.count(seclog.EventScopeDenied) != 2 {
		t.Errorf("scope_denied = %d, esperado 2", e.sink.count(seclog.EventScopeDenied))
	}
}

func TestIPBlockAfterFailures(t *testing.T) {
	e := newEnv(t, options{})
	for i := 0; i < 3; i++ {
		// X-Forwarded-For forjado não ajuda: sem proxy confiável, ele é ignorado.
		e.do(t, "GET", "/ledger/contas", "token-falso", nil, map[string]string{"X-Forwarded-For": fmt.Sprintf("10.9.9.%d", i)})
	}
	if e.sink.count(seclog.EventIPBlockTriggered) != 1 {
		t.Fatalf("IP deveria ter sido bloqueado; eventos: %+v", e.sink.events)
	}
	// Até um cliente com credenciais corretas é barrado vindo desse IP.
	req, _ := http.NewRequest("POST", e.gw.URL+"/oauth/token", strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("app-ledger", ledgerSecret)
	resp, err := e.gw.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || readJSON(t, resp)["error"] != "ip_blocked" {
		t.Errorf("IP bloqueado deveria receber 403 ip_blocked, recebeu %d", resp.StatusCode)
	}
	// Health check continua respondendo (probes não são bloqueadas).
	if r := e.do(t, "GET", "/healthz", "", nil, nil); r.StatusCode != 200 {
		t.Error("/healthz não deve ser afetado pelo bloqueio")
	}
}

func TestTrustedProxyResolvesRealIP(t *testing.T) {
	e := newEnv(t, options{trusted: "127.0.0.0/8"}) // o "load balancer" é o localhost
	for i := 0; i < 3; i++ {
		e.do(t, "GET", "/ledger/contas", "token-falso", nil, map[string]string{"X-Forwarded-For": "198.51.100.20"})
	}
	ctx := t.Context()
	if blocked, _, _ := e.block.IsBlocked(ctx, "198.51.100.20"); !blocked {
		t.Error("o IP real (vindo do proxy confiável) deveria estar bloqueado")
	}
	if blocked, _, _ := e.block.IsBlocked(ctx, "127.0.0.1"); blocked {
		t.Error("o IP do proxy não pode ser bloqueado no lugar do cliente")
	}
}

func TestRateLimitPerClient(t *testing.T) {
	e := newEnv(t, options{clientCapacity: 3})
	tok := e.token(t, "app-ledger", ledgerSecret)
	codes := []int{}
	for i := 0; i < 4; i++ {
		codes = append(codes, e.do(t, "GET", "/ledger/contas", tok, nil, nil).StatusCode)
	}
	if fmt.Sprint(codes) != "[200 200 200 429]" {
		t.Errorf("sequência = %v, esperado [200 200 200 429]", codes)
	}
	r := e.do(t, "GET", "/ledger/contas", tok, nil, nil)
	if r.Header.Get("Retry-After") == "" || r.Header.Get("RateLimit-Remaining") != "0" {
		t.Error("cabeçalhos de rate limit ausentes")
	}
	// Outro cliente não é afetado (baldes separados por client_id).
	other := e.token(t, "app-leitura", leituraSecret)
	if r := e.do(t, "GET", "/ledger/contas", other, nil, nil); r.StatusCode != 200 {
		t.Errorf("outro cliente recebeu %d", r.StatusCode)
	}
}

func TestPathTraversalAndBodyLimit(t *testing.T) {
	e := newEnv(t, options{maxBody: 64})
	tok := e.token(t, "app-ledger", ledgerSecret)
	// Path traversal: o cliente HTTP do Go normalizaria "..", então usamos Opaque.
	req, _ := http.NewRequest("GET", e.gw.URL, nil)
	req.URL.Opaque = "/ledger/../pix/chaves"
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := e.gw.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 || e.sink.count(seclog.EventPathRejected) != 1 {
		t.Errorf("path traversal: status = %d", resp.StatusCode)
	}

	big := strings.NewReader(strings.Repeat("x", 1000))
	if r := e.do(t, "POST", "/ledger/lancamentos", tok, big, nil); r.StatusCode != 413 {
		t.Errorf("corpo grande: status = %d, esperado 413", r.StatusCode)
	}
}

func TestIsSuspiciousPath(t *testing.T) {
	cases := map[string]bool{
		"/ledger/contas":       false,
		"/ledger/../admin":     true,
		"/ledger/./x":          true,
		"/ledger//x":           true,
		"/ledger/a%2Fb":        true,
		"/ledger/a%5cb":        true,
		"/ledger/a\\b":         true,
		"/ledger/contas/12-ab": false,
	}
	for p, want := range cases {
		u, _ := url.Parse("http://x" + p)
		if got := isSuspiciousPath(u.Path, u.EscapedPath()); got != want {
			t.Errorf("isSuspiciousPath(%q) = %v, esperado %v", p, got, want)
		}
	}
}

func TestRequestIDIgnoresClientValue(t *testing.T) {
	e := newEnv(t, options{})
	r := e.do(t, "GET", "/healthz", "", nil, map[string]string{"X-Request-ID": "forjado"})
	if r.Header.Get("X-Request-ID") == "forjado" {
		t.Error("o gateway não pode aceitar o X-Request-ID do cliente")
	}
}

func TestRemoteIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.4:5555"
	if RemoteIP(r) != "203.0.113.4" {
		t.Errorf("RemoteIP = %q", RemoteIP(r))
	}
	r.RemoteAddr = "sem-porta"
	if RemoteIP(r) != "sem-porta" {
		t.Errorf("RemoteIP sem porta = %q", RemoteIP(r))
	}
}
