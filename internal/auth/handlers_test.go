// Caminho: internal/auth/handlers_test.go
//
// Testes dos endpoints /oauth/token e /oauth/introspect e do middleware Bearer.
// O pacote httptest da biblioteca padrão cria requisições e "gravadores" de
// resposta em memória, sem abrir porta de rede (como o TestClient do FastAPI).
package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"gateway-seguranca/internal/httpx"
	"gateway-seguranca/internal/seclog"
)

// fakeReporter guarda os eventos relatados para o teste conferir.
type fakeReporter struct {
	mu     sync.Mutex // protege a lista contra acesso simultâneo (como threading.Lock)
	events []seclog.EventType
}

func (f *fakeReporter) Report(_ *http.Request, t seclog.EventType, _ int, _ string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, t)
}

func (f *fakeReporter) has(t seclog.EventType) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.events {
		if e == t {
			return true
		}
	}
	return false
}

func newRequestWithHeader(k, v string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if v != "" {
		r.Header.Set(k, v)
	}
	return r
}

// Segredos de teste: "password" (app-pix) e "validador" (validador).
func newHandlers(t *testing.T) (*Handlers, *TokenService, *fakeReporter) {
	t.Helper()
	store, err := ParseClients(`[
		{"client_id":"app-pix","secret_sha256":"` + validHash + `","scopes":["pix:read","pix:write"]},
		{"client_id":"validador","secret_sha256":"` + HashSecret("validador") + `","scopes":["token:introspect"]}
	]`)
	if err != nil {
		t.Fatal(err)
	}
	ts := newTestService(t)
	rep := &fakeReporter{}
	return NewHandlers(ts, store, rep), ts, rep
}

func postForm(target string, form url.Values, user, pass string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		r.SetBasicAuth(user, pass)
	}
	return r
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("resposta não é JSON: %q", rec.Body.String())
	}
	return m
}

func TestTokenEndpointSuccess(t *testing.T) {
	h, ts, rep := newHandlers(t)
	rec := httptest.NewRecorder()
	h.Token(rec, postForm("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "scope": {"pix:read pix:read"}}, "app-pix", "password"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, corpo = %s", rec.Code, rec.Body.String())
	}
	body := decode(t, rec)
	if body["token_type"] != "Bearer" || body["scope"] != "pix:read" { // escopo repetido é deduplicado
		t.Errorf("resposta inesperada: %v", body)
	}
	if rec.Header().Get("Pragma") != "no-cache" {
		t.Error("faltou Pragma: no-cache (RFC 6749)")
	}
	claims, err := ts.Validate(body["access_token"].(string))
	if err != nil || claims.HasScope("pix:write") {
		t.Errorf("token emitido inválido ou com escopo a mais: %v", err)
	}
	if !rep.has(seclog.EventTokenIssued) {
		t.Error("emissão não foi registrada no log de segurança")
	}
}

func TestTokenEndpointFormCredentials(t *testing.T) {
	h, _, _ := newHandlers(t)
	rec := httptest.NewRecorder()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"app-pix"}, "client_secret": {"password"}}
	h.Token(rec, postForm("/oauth/token", form, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if decode(t, rec)["scope"] != "pix:read pix:write" {
		t.Error("sem scope pedido, todos os escopos do cliente deveriam ser concedidos")
	}
}

func TestTokenEndpointErrors(t *testing.T) {
	cases := []struct {
		name       string
		req        func() *http.Request
		wantStatus int
		wantError  string
		wantEvent  seclog.EventType
	}{
		{"segredo errado", func() *http.Request {
			return postForm("/oauth/token", url.Values{"grant_type": {"client_credentials"}}, "app-pix", "errado")
		}, 401, "invalid_client", seclog.EventAuthFailure},
		{"cliente inexistente", func() *http.Request {
			return postForm("/oauth/token", url.Values{"grant_type": {"client_credentials"}}, "fantasma", "password")
		}, 401, "invalid_client", seclog.EventAuthFailure},
		{"grant não suportado", func() *http.Request {
			return postForm("/oauth/token", url.Values{"grant_type": {"password"}}, "app-pix", "password")
		}, 400, "unsupported_grant_type", ""},
		{"escopo não permitido", func() *http.Request {
			return postForm("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "scope": {"ledger:write"}}, "app-pix", "password")
		}, 400, "invalid_scope", seclog.EventScopeDenied},
		{"dois métodos de autenticação", func() *http.Request {
			return postForm("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {"app-pix"}}, "app-pix", "password")
		}, 400, "invalid_request", ""},
		{"credenciais na query string", func() *http.Request {
			return postForm("/oauth/token?client_secret=password", url.Values{"grant_type": {"client_credentials"}}, "app-pix", "password")
		}, 400, "invalid_request", ""},
		{"content-type json", func() *http.Request {
			r := postForm("/oauth/token", url.Values{"grant_type": {"client_credentials"}}, "app-pix", "password")
			r.Header.Set("Content-Type", "application/json")
			return r
		}, 415, "invalid_request", ""},
		{"corpo grande demais", func() *http.Request {
			r := postForm("/oauth/token", url.Values{"grant_type": {strings.Repeat("a", 100)}}, "app-pix", "password")
			r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, 10)
			return r
		}, 413, "invalid_request", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _, rep := newHandlers(t)
			rec := httptest.NewRecorder()
			h.Token(rec, tc.req())
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, esperado %d (%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if got := decode(t, rec)["error"]; got != tc.wantError {
				t.Errorf("error = %v, esperado %s", got, tc.wantError)
			}
			if tc.wantEvent != "" && !rep.has(tc.wantEvent) {
				t.Errorf("evento %s não registrado", tc.wantEvent)
			}
		})
	}
}

func TestIntrospect(t *testing.T) {
	h, ts, _ := newHandlers(t)
	tok, _, _ := ts.Issue("app-pix", []string{"pix:read"})

	// Válido: active=true com os dados do token.
	rec := httptest.NewRecorder()
	h.Introspect(rec, postForm("/oauth/introspect", url.Values{"token": {tok}}, "validador", "validador"))
	body := decode(t, rec)
	if rec.Code != 200 || body["active"] != true || body["client_id"] != "app-pix" {
		t.Fatalf("introspecção de token válido falhou: %d %v", rec.Code, body)
	}

	// Inválido: active=false e NENHUM outro campo (não vaza o motivo).
	rec = httptest.NewRecorder()
	h.Introspect(rec, postForm("/oauth/introspect", url.Values{"token": {tok + "x"}}, "validador", "validador"))
	body = decode(t, rec)
	if body["active"] != false || len(body) != 1 {
		t.Errorf("token inválido deveria devolver só {active:false}: %v", body)
	}

	// Sem o parâmetro token.
	rec = httptest.NewRecorder()
	h.Introspect(rec, postForm("/oauth/introspect", url.Values{}, "validador", "validador"))
	if rec.Code != 400 {
		t.Errorf("sem token: status = %d", rec.Code)
	}

	// Cliente sem o escopo token:introspect.
	rec = httptest.NewRecorder()
	h.Introspect(rec, postForm("/oauth/introspect", url.Values{"token": {tok}}, "app-pix", "password"))
	if rec.Code != 403 {
		t.Errorf("cliente sem escopo: status = %d", rec.Code)
	}

	// Cliente não autenticado.
	rec = httptest.NewRecorder()
	h.Introspect(rec, postForm("/oauth/introspect", url.Values{"token": {tok}}, "", ""))
	if rec.Code != 401 {
		t.Errorf("sem autenticação: status = %d", rec.Code)
	}
}

func TestRequireBearer(t *testing.T) {
	_, ts, _ := newHandlers(t)
	tok, _, _ := ts.Issue("app-pix", []string{"pix:read"})

	// Handler final que confirma que as claims chegaram no contexto.
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := ClaimsFrom(r.Context())
		if c == nil || c.ClientID != "app-pix" || httpx.ClientIDFrom(r.Context()) != "app-pix" {
			t.Error("claims ausentes no contexto")
		}
		w.WriteHeader(http.StatusTeapot)
	})

	cases := []struct {
		name       string
		header     string
		wantStatus int
		wantEvent  seclog.EventType
		wantWWW    string
	}{
		{"válido", "Bearer " + tok, http.StatusTeapot, "", ""},
		{"ausente", "", 401, seclog.EventAuthMissing, `Bearer realm="gateway-seguranca"`},
		{"inválido", "Bearer abc.def.ghi", 401, seclog.EventTokenInvalid, `error="invalid_token"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := &fakeReporter{}
			rec := httptest.NewRecorder()
			RequireBearer(ts, rep)(final).ServeHTTP(rec, newRequestWithHeader("Authorization", tc.header))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, esperado %d", rec.Code, tc.wantStatus)
			}
			if tc.wantEvent != "" && !rep.has(tc.wantEvent) {
				t.Errorf("evento %s não registrado", tc.wantEvent)
			}
			if !strings.Contains(rec.Header().Get("WWW-Authenticate"), tc.wantWWW) {
				t.Errorf("WWW-Authenticate = %q", rec.Header().Get("WWW-Authenticate"))
			}
		})
	}
}
