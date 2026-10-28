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
	h := New("pix", mustURL(t, up.URL), 5*time.Second, discard())

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
			h := New("ledger", mustURL(t, tc.target), tc.timeout, discard())
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
