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

func TestRequiredScope(t *testing.T) {
	cases := []struct {
		method, want string
		ok           bool
	}{
		{http.MethodGet, "pix:read", true},
		{http.MethodHead, "pix:read", true},
		{http.MethodPost, "pix:write", true},
		{http.MethodPut, "pix:write", true},
		{http.MethodPatch, "pix:write", true},
		{http.MethodDelete, "pix:write", true},
		{http.MethodOptions, "", false},
		{http.MethodTrace, "", false},
		{"INVENTADO", "", false},
	}
	for _, tc := range cases {
		got, ok := RequiredScope("pix", tc.method)
		if got != tc.want || ok != tc.ok {
			t.Errorf("RequiredScope(pix, %s) = (%q, %v), esperado (%q, %v)", tc.method, got, ok, tc.want, tc.ok)
		}
	}
}

func TestRequireServiceScope(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	cases := []struct {
		name       string
		method     string
		scopes     string // "" + noClaims = sem autenticação
		noClaims   bool
		wantStatus int
		wantDenied int
	}{
		{"leitura com pix:read", http.MethodGet, "pix:read", false, 204, 0},
		{"escrita só com pix:read (BFLA)", http.MethodPost, "pix:read", false, 403, 1},
		{"escrita com pix:write", http.MethodPost, "pix:write", false, 204, 0},
		{"escopo de outro serviço", http.MethodGet, "ledger:read", false, 403, 1},
		{"método proibido", http.MethodTrace, "pix:read pix:write", false, 405, 0},
		{"sem claims (falha fechada)", http.MethodGet, "", true, 401, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := &countingReporter{}
			r := httptest.NewRequest(tc.method, "/pix/x", nil)
			if !tc.noClaims {
				r = r.WithContext(auth.WithClaims(r.Context(), &auth.Claims{ClientID: "app", Scope: tc.scopes}))
			}
			rec := httptest.NewRecorder()
			RequireServiceScope("pix", rep)(ok).ServeHTTP(rec, r)
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
