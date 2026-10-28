// Caminho: internal/ratelimit/ratelimit.go
//
// Pacote ratelimit: limita requisições com o algoritmo TOKEN BUCKET ("balde de
// fichas"), com o estado guardado no Redis (OWASP API4: Unrestricted Resource
// Consumption).
//
// Como funciona: cada cliente tem um balde com até "capacity" fichas. Cada
// requisição gasta 1 ficha, e o balde é reabastecido continuamente à taxa de
// "refill" fichas por segundo. Isso permite rajadas curtas (até capacity) sem
// deixar passar uma média acima de refill/s.
//
// Por que o Redis? Com várias réplicas do gateway, o limite precisa ser
// compartilhado. Se cada réplica contasse sozinha, 3 réplicas = 3x o limite.
package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"gateway-seguranca/internal/httpx"
	"gateway-seguranca/internal/seclog"
)

// tokenBucketScript roda ATOMICAMENTE dentro do Redis. Ler o saldo, calcular
// e gravar em comandos separados criaria uma condição de corrida: duas
// requisições simultâneas leriam o mesmo saldo e ambas passariam.
//
// O relógio usado é o do Redis (TIME), e não o do gateway, para que réplicas com
// relógios ligeiramente diferentes não corrompam o cálculo.
//
// KEYS[1] = chave do balde; ARGV[1] = capacidade; ARGV[2] = fichas por segundo.
// Retorno: {permitido (0/1), fichas restantes, milissegundos até a próxima ficha}.
const tokenBucketScript = `
local key      = KEYS[1]
local capacity = tonumber(ARGV[1])
local rate     = tonumber(ARGV[2])

local t   = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)

local state  = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts     = tonumber(state[2])
if tokens == nil or ts == nil then
  tokens = capacity
  ts = now
end

local elapsed = math.max(0, now - ts) / 1000.0
tokens = math.min(capacity, tokens + elapsed * rate)

local allowed = 0
local retry_ms = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  retry_ms = math.ceil((1 - tokens) / rate * 1000)
end

redis.call('HSET', key, 'tokens', tostring(tokens), 'ts', tostring(now))
-- A chave expira quando o balde estaria cheio de novo: o Redis não acumula lixo.
redis.call('PEXPIRE', key, math.ceil(capacity / rate * 1000) + 1000)

return {allowed, math.floor(tokens), retry_ms}
`

// Result é o resultado de uma verificação.
type Result struct {
	Allowed    bool
	Limit      int64
	Remaining  int64
	RetryAfter time.Duration
}

// Limiter é a interface usada pelo middleware (permite trocar a implementação nos testes).
type Limiter interface {
	Allow(ctx context.Context, key string) (Result, error)
}

// RedisLimiter implementa Limiter usando o script Lua acima.
type RedisLimiter struct {
	rdb      redis.Scripter // interface do go-redis: qualquer cliente capaz de rodar scripts
	script   *redis.Script
	prefix   string
	capacity int64
	refill   float64
}

// NewRedisLimiter cria um limitador. "prefix" separa os baldes de cada
// política no Redis (ex.: "rl:ip", "rl:client").
func NewRedisLimiter(rdb redis.Scripter, prefix string, capacity int64, refillPerSec float64) (*RedisLimiter, error) {
	if capacity < 1 || refillPerSec <= 0 {
		return nil, fmt.Errorf("rate limit inválido: capacidade=%d, reposição=%v", capacity, refillPerSec)
	}
	return &RedisLimiter{
		rdb: rdb,
		// redis.NewScript usa EVALSHA (envia só o hash do script) e reenvia o
		// código completo só se o Redis ainda não o conhecer.
		script:   redis.NewScript(tokenBucketScript),
		prefix:   prefix,
		capacity: capacity,
		refill:   refillPerSec,
	}, nil
}

// Allow consome uma ficha do balde "key".
func (l *RedisLimiter) Allow(ctx context.Context, key string) (Result, error) {
	// "...any" aceita argumentos de qualquer tipo, como *args no Python.
	vals, err := l.script.Run(ctx, l.rdb, []string{l.prefix + ":" + key},
		l.capacity, strconv.FormatFloat(l.refill, 'f', -1, 64)).Int64Slice()
	if err != nil {
		return Result{}, fmt.Errorf("rate limit no redis: %w", err)
	}
	if len(vals) != 3 {
		return Result{}, fmt.Errorf("resposta inesperada do script de rate limit: %v", vals)
	}
	return Result{
		Allowed:    vals[0] == 1,
		Limit:      l.capacity,
		Remaining:  vals[1],
		RetryAfter: time.Duration(vals[2]) * time.Millisecond,
	}, nil
}

// KeyFunc extrai a identidade usada como chave do balde. Devolve "" para não limitar.
type KeyFunc func(r *http.Request) string

// ByClientIP usa o IP do cliente como chave (para rotas sem autenticação).
func ByClientIP(r *http.Request) string { return "ip:" + httpx.ClientIPFrom(r.Context()) }

// ByClientID usa o client_id autenticado. Deve ficar DEPOIS da autenticação.
// Se não houver client_id, cai para o IP: nunca fica sem limite.
func ByClientID(r *http.Request) string {
	if id := httpx.ClientIDFrom(r.Context()); id != "" {
		return "client:" + id
	}
	return ByClientIP(r)
}

// Middleware aplica o limitador.
//
// failOpen decide o que fazer se o Redis cair:
//   - false (padrão, "fail closed"): responde 503. Nenhum abuso passa, mas a API para.
//   - true ("fail open"): deixa passar. A API continua no ar, porém sem limite.
//
// Para um gateway financeiro, o padrão seguro é falhar FECHADO.
func Middleware(l Limiter, keyFn KeyFunc, failOpen bool, reporter seclog.Reporter, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Timeout curto: um Redis lento não pode travar o gateway inteiro.
			ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
			res, err := l.Allow(ctx, key)
			cancel()

			if err != nil {
				logger.Error("rate limiter indisponível", "error", err.Error(), "fail_open", failOpen)
				reporter.Report(r, seclog.EventInfraError, http.StatusServiceUnavailable, "rate limiter indisponível")
				if failOpen {
					next.ServeHTTP(w, r)
					return
				}
				httpx.WriteError(w, r, http.StatusServiceUnavailable, "service_unavailable", "serviço temporariamente indisponível")
				return
			}

			// Cabeçalhos informativos (padrão do draft IETF "RateLimit header fields").
			w.Header().Set("RateLimit-Limit", strconv.FormatInt(res.Limit, 10))
			w.Header().Set("RateLimit-Remaining", strconv.FormatInt(res.Remaining, 10))

			if !res.Allowed {
				// Retry-After em segundos inteiros, arredondado para cima (mínimo 1).
				secs := int64(math.Max(1, math.Ceil(res.RetryAfter.Seconds())))
				w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
				reporter.Report(r, seclog.EventRateLimited, http.StatusTooManyRequests, "limite excedido para "+key)
				httpx.WriteError(w, r, http.StatusTooManyRequests, "rate_limited", "muitas requisições; tente novamente mais tarde")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
