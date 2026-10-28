// Caminho: internal/ipblock/ipblock_test.go
package ipblock

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"gateway-seguranca/internal/httpx"
	"gateway-seguranca/internal/seclog"
)

func setup(t *testing.T) (*miniredis.Miniredis, *Blocker) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	b, err := New(rdb, 3, time.Minute, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return mr, b
}

func TestBlockAfterMaxFailures(t *testing.T) {
	mr, b := setup(t)
	ctx := context.Background()
	ip := "203.0.113.5"

	for i := 1; i <= 2; i++ {
		blocked, err := b.RecordFailure(ctx, ip)
		if err != nil || blocked {
			t.Fatalf("falha %d não deveria bloquear: %v", i, err)
		}
	}
	if blocked, _, _ := b.IsBlocked(ctx, ip); blocked {
		t.Fatal("IP bloqueado antes do limite")
	}
	blocked, err := b.RecordFailure(ctx, ip)
	if err != nil || !blocked {
		t.Fatal("a 3ª falha deveria bloquear o IP")
	}
	isBlocked, ttl, _ := b.IsBlocked(ctx, ip)
	if !isBlocked || ttl <= 0 || ttl > 10*time.Minute {
		t.Fatalf("bloqueio inválido: %v %v", isBlocked, ttl)
	}
	if blocked, _, _ := b.IsBlocked(ctx, "198.51.100.1"); blocked {
		t.Error("outro IP não pode ser afetado")
	}

	// O bloqueio expira sozinho.
	mr.FastForward(11 * time.Minute)
	if blocked, _, _ := b.IsBlocked(ctx, ip); blocked {
		t.Error("o bloqueio deveria ter expirado")
	}
}

func TestFailureWindowExpires(t *testing.T) {
	mr, b := setup(t)
	ctx := context.Background()
	_, _ = b.RecordFailure(ctx, "1.2.3.4")
	_, _ = b.RecordFailure(ctx, "1.2.3.4")
	mr.FastForward(2 * time.Minute) // janela de 1 minuto passou: contador zera
	if blocked, _ := b.RecordFailure(ctx, "1.2.3.4"); blocked {
		t.Error("falhas fora da janela não deveriam somar")
	}
}

func TestUnblock(t *testing.T) {
	_, b := setup(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, _ = b.RecordFailure(ctx, "1.2.3.4")
	}
	if err := b.Unblock(ctx, "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if blocked, _, _ := b.IsBlocked(ctx, "1.2.3.4"); blocked {
		t.Error("Unblock não removeu o bloqueio")
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(nil, 0, time.Minute, time.Minute); err == nil {
		t.Error("maxFailures 0 aceito")
	}
}

type lastEvent struct{ t seclog.EventType }

func (l *lastEvent) Report(_ *http.Request, t seclog.EventType, _ int, _ string) { l.t = t }

func TestMiddleware(t *testing.T) {
	mr, b := setup(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	req := func(ip string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		return r.WithContext(httpx.WithClientIP(r.Context(), ip))
	}

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, _ = b.RecordFailure(ctx, "9.9.9.9")
	}

	rep := &lastEvent{}
	rec := httptest.NewRecorder()
	Middleware(b, false, rep, logger)(next).ServeHTTP(rec, req("9.9.9.9"))
	if rec.Code != http.StatusForbidden || rep.t != seclog.EventIPBlocked || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("IP bloqueado deveria receber 403 com Retry-After: %d %q", rec.Code, rep.t)
	}

	rec = httptest.NewRecorder()
	Middleware(b, false, rep, logger)(next).ServeHTTP(rec, req("8.8.8.8"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("IP livre deveria passar: %d", rec.Code)
	}

	// Redis fora do ar: fail closed (503) ou fail open (passa).
	mr.Close()
	rec = httptest.NewRecorder()
	Middleware(b, false, rep, logger)(next).ServeHTTP(rec, req("8.8.8.8"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("fail closed: status = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	Middleware(b, true, rep, logger)(next).ServeHTTP(rec, req("8.8.8.8"))
	if rec.Code != http.StatusNoContent {
		t.Errorf("fail open: status = %d", rec.Code)
	}
	if _, err := b.RecordFailure(ctx, "1.1.1.1"); err == nil {
		t.Error("RecordFailure deveria devolver erro com o Redis fora")
	}
}
