// Caminho: internal/proxy/proxy_test.go
package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gateway-seguranca/internal/auth"
	"gateway-seguranca/internal/config"
	"gateway-seguranca/internal/httpx"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// echoUpstream devolve, em JSON, os cabeçalhos que recebeu.
func echoUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.0")
		w.Header().Set("X-Powered-By", "PHP/5")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_ = json.NewEncoder(w).Encode(map[string]any{"path": r.URL.Path, "headers": r.Header})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func mustURL(t *testing.T, raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestProxyStripsAndForwardsHeaders(t *testing.T) {
	up := echoUpstream(t)
	h := New("pix", mustURL(t, up.URL), nil, 5*time.Second, discard())

	r := httptest.NewRequest("GET", "/chaves", nil)
	r.Header.Set("Authorization", "Bearer segredo")
	r.Header.Set("X-Gateway-Client-ID", "admin") // tentativa de forjar identidade
	r.Header.Set("X-Internal-Bypass", "1")       // cabeçalho interno forjado
	r.Header.Set("X-Forwarded-For", "6.6.6.6")   // IP forjado
	ctx := httpx.WithRequestID(r.Context(), "req-42")
	ctx = httpx.WithClientIP(ctx, "203.0.113.10")
	ctx = auth.WithClaims(ctx, &auth.Claims{ClientID: "app-pix", Scope: "pix:read"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r.WithContext(ctx))

	var got struct {
		Path    string
		Headers http.Header
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	hd := got.Headers
	checks := map[string]string{
		"Authorization":       "",
		"X-Internal-Bypass":   "",
		"X-Gateway-Client-Id": "app-pix",
		"X-Gateway-Scopes":    "pix:read",
		"X-Gateway-Service":   "pix",
		"X-Request-Id":        "req-42",
		"X-Forwarded-For":     "203.0.113.10",
	}
	for k, want := range checks {
		if v := hd.Get(k); v != want {
			t.Errorf("upstream recebeu %s=%q, esperado %q", k, v, want)
		}
	}
	if got.Path != "/chaves" {
		t.Errorf("path = %q", got.Path)
	}
	for _, k := range []string{"Server", "X-Powered-By", "Cache-Control"} {
		if rec.Header().Get(k) != "" {
			t.Errorf("cabeçalho %s do upstream deveria ser removido", k)
		}
	}
}

func TestProxyErrors(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer slow.Close()
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // ninguém escuta mais nesse endereço

	cases := []struct {
		name       string
		target     string
		timeout    time.Duration
		body       io.Reader
		limit      int64
		wantStatus int
		wantCode   string
	}{
		{"serviço fora do ar", deadURL, time.Second, nil, 0, 502, "upstream_unavailable"},
		{"serviço lento", slow.URL, 50 * time.Millisecond, nil, 0, 504, "upstream_timeout"},
		{"corpo grande demais", slow.URL, time.Second, strings.NewReader(strings.Repeat("x", 100)), 10, 413, "payload_too_large"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := New("ledger", mustURL(t, tc.target), nil, tc.timeout, discard())
			r := httptest.NewRequest("POST", "/", tc.body)
			rec := httptest.NewRecorder()
			if tc.limit > 0 {
				r.ContentLength = -1 // simula corpo "chunked", sem tamanho declarado
				r.Body = http.MaxBytesReader(rec, r.Body, tc.limit)
			}
			h.ServeHTTP(rec, r)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, esperado %d (%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantCode) {
				t.Errorf("corpo = %s", rec.Body.String())
			}
			// A resposta de erro não pode revelar o endereço interno.
			if strings.Contains(rec.Body.String(), "127.0.0.1") {
				t.Error("erro vazou o endereço do serviço interno")
			}
		})
	}
}

func TestHasAnyPrefix(t *testing.T) {
	if !hasAnyPrefix("x-gateway-scopes", internalHeaderPrefixes) || hasAnyPrefix("X-Request-Id", internalHeaderPrefixes) {
		t.Error("hasAnyPrefix incorreto")
	}
}

// O upstream simulado faz o papel da Ledger: exige HTTP Basic e guarda o que recebeu.
func basicUpstream(t *testing.T, user, pass string, got *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = r.Header.Get("Authorization")
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="ledger"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestProxyInjectsServiceCredential(t *testing.T) {
	var got string
	up := basicUpstream(t, "svc-gateway", "senha-servico", &got)
	creds := &config.BasicAuth{Username: "svc-gateway", Password: "senha-servico"}
	h := New("ledger", mustURL(t, up.URL), creds, 5*time.Second, discard())

	// O cliente tenta se passar pelo gateway com um Basic próprio e um Bearer.
	for _, clientAuth := range []string{"Bearer token-do-cliente", "Basic YWRtaW46YWRtaW4="} {
		r := httptest.NewRequest("GET", "/api/v1/contas/1", nil)
		r.Header.Set("Authorization", clientAuth)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, esperado 200", rec.Code)
		}
		req := &http.Request{Header: http.Header{"Authorization": {got}}}
		if u, p, ok := req.BasicAuth(); !ok || u != "svc-gateway" || p != "senha-servico" {
			t.Errorf("upstream recebeu %q; esperado só o Basic de serviço", got)
		}
	}
}

func TestProxyWithoutCredentialSendsNoAuthorization(t *testing.T) {
	var got string
	up := basicUpstream(t, "x", "y", &got)
	h := New("pix", mustURL(t, up.URL), nil, 5*time.Second, discard())
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer token-do-cliente")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if got != "" {
		t.Errorf("sem credencial configurada, nada deve seguir no Authorization; veio %q", got)
	}
	// Sem credencial de serviço, um 401 do upstream é legítimo e passa adiante.
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, esperado 401 repassado", rec.Code)
	}
}

func TestProxyRejectedServiceCredentialBecomes502(t *testing.T) {
	var got string
	up := basicUpstream(t, "svc-gateway", "senha-certa", &got)
	creds := &config.BasicAuth{Username: "svc-gateway", Password: "senha-errada"}
	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	h := New("ledger", mustURL(t, up.URL), creds, 5*time.Second, logger)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/contas/1", nil))
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "upstream_unavailable") {
		t.Fatalf("status = %d corpo = %s; esperado 502 genérico", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("WWW-Authenticate") != "" {
		t.Error("o desafio Basic da Ledger não pode chegar ao cliente")
	}
	if !strings.Contains(logs.String(), "credencial de serviço recusada") || !strings.Contains(logs.String(), "svc-gateway") {
		t.Errorf("o operador deveria ver o motivo no log: %s", logs.String())
	}
	if strings.Contains(logs.String(), "senha-errada") {
		t.Error("a senha de serviço vazou no log")
	}
}
