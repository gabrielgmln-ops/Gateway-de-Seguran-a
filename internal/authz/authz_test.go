// Caminho: internal/authz/authz_test.go
package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gateway-seguranca/internal/auth"
	"gateway-seguranca/internal/seclog"
)

type countingReporter struct{ denied int }

func (c *countingReporter) Report(_ *http.Request, t seclog.EventType, _ int, _ string) {
	if t == seclog.EventScopeDenied {
		c.denied++
	}
}

func TestMatchPath(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/api/v1/contas/*", "/api/v1/contas/42", true},
		{"/api/v1/contas/*", "/api/v1/contas/", false},           // "*" exige um valor
		{"/api/v1/contas/*", "/api/v1/contas", false},            // falta o segmento
		{"/api/v1/contas/*", "/api/v1/contas/42/extrato", false}, // "*" é um segmento só
		{"/api/v1/contas/*/extrato", "/api/v1/contas/42/extrato", true},
		{"/api/v1/auditoria", "/api/v1/auditoria/", false}, // barra no fim não casa
		{"/api/v1/auditoria", "/API/V1/AUDITORIA", false},  // caminho diferencia maiúsculas
		{"/decisoes", "", false},
	}
	for _, tc := range cases {
		if got := matchPath(tc.pattern, tc.path); got != tc.want {
			t.Errorf("matchPath(%q, %q) = %v, esperado %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestFind(t *testing.T) {
	rules := []Rule{
		{"GET", "/x/*", "s:read"},
		{"DELETE", "/x/*", "s:write"},
	}
	if r, _ := Find(rules, "GET", "/x/1"); r == nil || r.Scope != "s:read" {
		t.Errorf("GET deveria casar com s:read: %+v", r)
	}
	if r, _ := Find(rules, "HEAD", "/x/1"); r == nil || r.Scope != "s:read" {
		t.Errorf("HEAD deveria ser tratado como GET: %+v", r)
	}
	if r, _ := Find(rules, "DELETE", "/x/1"); r == nil || r.Scope != "s:write" {
		t.Errorf("DELETE deveria casar com s:write: %+v", r)
	}
	if r, known := Find(rules, "POST", "/x/1"); r != nil || !known {
		t.Errorf("POST: caminho conhecido, método não (405); veio (%v, %v)", r, known)
	}
	if r, known := Find(rules, "GET", "/y"); r != nil || known {
		t.Errorf("caminho desconhecido deveria dar (nil, false); veio (%v, %v)", r, known)
	}
}

func TestRequireRoute(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	rules := []Rule{
		{"GET", "/api/v1/chaves/*", "pix:read"},
		{"POST", "/api/v1/chaves", "pix:write"},
	}

	cases := []struct {
		name       string
		method     string
		path       string
		scopes     string
		noClaims   bool
		wantStatus int
		wantDenied int
	}{
		{"leitura com pix:read", "GET", "/api/v1/chaves/abc", "pix:read", false, 204, 0},
		{"escrita só com pix:read (BFLA)", "POST", "/api/v1/chaves", "pix:read", false, 403, 1},
		{"escrita com pix:write", "POST", "/api/v1/chaves", "pix:write", false, 204, 0},
		{"escopo de outro serviço", "GET", "/api/v1/chaves/abc", "ledger:read", false, 403, 1},
		{"método fora da lista", "TRACE", "/api/v1/chaves/abc", "pix:read pix:write", false, 405, 0},
		{"rota interna não exposta", "GET", "/actuator/env", "pix:read pix:write", false, 404, 0},
		{"sem claims (falha fechada)", "GET", "/api/v1/chaves/abc", "", true, 401, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := &countingReporter{}
			r := httptest.NewRequest(tc.method, tc.path, nil)
			if !tc.noClaims {
				r = r.WithContext(auth.WithClaims(r.Context(), &auth.Claims{ClientID: "app", Scope: tc.scopes}))
			}
			rec := httptest.NewRecorder()
			RequireRoute(rules, rep)(ok).ServeHTTP(rec, r)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, esperado %d", rec.Code, tc.wantStatus)
			}
			if rep.denied != tc.wantDenied {
				t.Errorf("eventos scope_denied = %d, esperado %d", rep.denied, tc.wantDenied)
			}
			if tc.wantStatus == 403 && rec.Header().Get("WWW-Authenticate") == "" {
				t.Error("403 sem WWW-Authenticate insufficient_scope")
			}
		})
	}
}
