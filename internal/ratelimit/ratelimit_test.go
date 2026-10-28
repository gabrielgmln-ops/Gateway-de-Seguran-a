// Caminho: internal/ratelimit/ratelimit_test.go
//
// O miniredis é um servidor Redis em memória, feito para testes: roda os
// scripts Lua de verdade sem precisar de um Redis instalado (lembra o fakeredis do Python).
package ratelimit

import (
	"context"
	"errors"
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

func newRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t) // encerrado automaticamente no fim do teste
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() }) // t.Cleanup é como um fixture com yield no pytest
	return mr, rdb
}

func TestTokenBucketBurstAndRefill(t *testing.T) {
	mr, rdb := newRedis(t)
	l, err := NewRedisLimiter(rdb, "rl:test", 3, 1) // rajada de 3, repõe 1 ficha/s
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now()
	mr.SetTime(now) // controla o relógio usado pelo comando TIME dentro do Lua

	for i := 1; i <= 3; i++ {
		res, err := l.Allow(ctx, "cliente")
		if err != nil || !res.Allowed {
			t.Fatalf("requisição %d da rajada deveria passar: %v %+v", i, err, res)
		}
		if res.Remaining != int64(3-i) {
			t.Errorf("Remaining = %d, esperado %d", res.Remaining, 3-i)
		}
	}
	res, _ := l.Allow(ctx, "cliente")
	if res.Allowed {
		t.Fatal("a 4ª requisição deveria ser bloqueada")
	}
	if res.RetryAfter <= 0 || res.RetryAfter > time.Second {
		t.Errorf("RetryAfter = %v, esperado entre 0 e 1s", res.RetryAfter)
	}

	// Outro cliente tem o próprio balde.
	if res, _ := l.Allow(ctx, "outro"); !res.Allowed {
		t.Error("baldes de clientes diferentes não podem ser compartilhados")
	}

	// Passado 1,1s, uma ficha foi reposta.
	mr.SetTime(now.Add(1100 * time.Millisecond))
	if res, _ := l.Allow(ctx, "cliente"); !res.Allowed {
		t.Error("após a reposição, a requisição deveria passar")
	}
	if ttl := mr.TTL("rl:test:cliente"); ttl <= 0 {
		t.Error("a chave do balde deveria ter expiração (sem lixo no Redis)")
	}
}

func TestNewRedisLimiterValidation(t *testing.T) {
	_, rdb := newRedis(t)
	if _, err := NewRedisLimiter(rdb, "x", 0, 1); err == nil {
		t.Error("capacidade 0 aceita")
	}
	if _, err := NewRedisLimiter(rdb, "x", 1, 0); err == nil {
		t.Error("reposição 0 aceita")
	}
}

// stubLimiter permite simular respostas e falhas.
type stubLimiter struct {
	res Result
	err error
}

func (s stubLimiter) Allow(context.Context, string) (Result, error) { return s.res, s.err }

type eventRecorder struct{ last seclog.EventType }

func (e *eventRecorder) Report(_ *http.Request, t seclog.EventType, _ int, _ string) { e.last = t }

func TestMiddleware(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil)) // descarta os logs
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	cases := []struct {
		name       string
		lim        Limiter
		failOpen   bool
		wantStatus int
		wantEvent  seclog.EventType
	}{
		{"permitido", stubLimiter{res: Result{Allowed: true, Limit: 5, Remaining: 4}}, false, 204, ""},
		{"excedido", stubLimiter{res: Result{Allowed: false, Limit: 5, RetryAfter: 1500 * time.Millisecond}}, false, 429, seclog.EventRateLimited},
		{"redis fora, fail closed", stubLimiter{err: errors.New("conexão recusada")}, false, 503, seclog.EventInfraError},
		{"redis fora, fail open", stubLimiter{err: errors.New("conexão recusada")}, true, 204, seclog.EventInfraError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := &eventRecorder{}
			rec := httptest.NewRecorder()
			Middleware(tc.lim, ByClientIP, tc.failOpen, rep, logger)(next).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, esperado %d", rec.Code, tc.wantStatus)
			}
			if rep.last != tc.wantEvent {
				t.Errorf("evento = %q, esperado %q", rep.last, tc.wantEvent)
			}
			if tc.wantStatus == 429 && rec.Header().Get("Retry-After") != "2" {
				t.Errorf("Retry-After = %q, esperado 2 (arredondado para cima)", rec.Header().Get("Retry-After"))
			}
		})
	}
}

func TestMiddlewareEmptyKeySkips(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	deny := stubLimiter{res: Result{Allowed: false}}
	rec := httptest.NewRecorder()
	Middleware(deny, func(*http.Request) string { return "" }, false, &eventRecorder{}, logger)(next).
		ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 204 {
		t.Errorf("chave vazia deveria pular o limite, status = %d", rec.Code)
	}
}

func TestKeyFuncs(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(httpx.WithClientIP(r.Context(), "203.0.113.1"))
	if got := ByClientID(r); got != "ip:203.0.113.1" {
		t.Errorf("sem client_id deveria cair para o IP, obteve %q", got)
	}
	r = r.WithContext(httpx.WithClientID(r.Context(), "app-pix"))
	if got := ByClientID(r); got != "client:app-pix" {
		t.Errorf("ByClientID = %q", got)
	}
}
