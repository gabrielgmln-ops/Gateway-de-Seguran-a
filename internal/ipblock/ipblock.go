// Caminho: internal/ipblock/ipblock.go
//
// Pacote ipblock: bloqueia temporariamente um IP após N falhas de segurança
// numa janela de tempo (ex.: 5 falhas em 10 minutos -> bloqueio por 15 minutos).
// É a defesa contra força bruta de credenciais, credential stuffing e varredura
// de tokens (OWASP API2), compartilhada entre réplicas via Redis.
package ipblock

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"gateway-seguranca/internal/httpx"
	"gateway-seguranca/internal/seclog"
)

// recordFailureScript conta a falha e, ao atingir o limite, cria a chave de
// bloqueio, tudo de forma atômica.
//
// KEYS[1] = contador de falhas; KEYS[2] = chave de bloqueio.
// ARGV[1] = janela (ms); ARGV[2] = máximo de falhas; ARGV[3] = duração do bloqueio (ms).
const recordFailureScript = `
local n = redis.call('INCR', KEYS[1])
if n == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
if n >= tonumber(ARGV[2]) then
  redis.call('SET', KEYS[2], '1', 'PX', ARGV[3])
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
`

// Blocker implementa seclog.FailureRecorder e a checagem de bloqueio.
type Blocker struct {
	rdb         redis.Cmdable // interface com todos os comandos do Redis
	script      *redis.Script
	maxFailures int
	window      time.Duration
	blockFor    time.Duration
}

// New cria o bloqueador.
func New(rdb redis.Cmdable, maxFailures int, window, blockFor time.Duration) (*Blocker, error) {
	if maxFailures < 1 || window <= 0 || blockFor <= 0 {
		return nil, fmt.Errorf("configuração de bloqueio de IP inválida")
	}
	return &Blocker{
		rdb:         rdb,
		script:      redis.NewScript(recordFailureScript),
		maxFailures: maxFailures,
		window:      window,
		blockFor:    blockFor,
	}, nil
}

func failKey(ip string) string  { return "ipblock:fail:" + ip }
func blockKey(ip string) string { return "ipblock:block:" + ip }

// RecordFailure registra uma falha. Devolve true se o IP acabou de ser bloqueado.
func (b *Blocker) RecordFailure(ctx context.Context, ip string) (bool, error) {
	n, err := b.script.Run(ctx, b.rdb, []string{failKey(ip), blockKey(ip)},
		b.window.Milliseconds(), b.maxFailures, b.blockFor.Milliseconds()).Int()
	if err != nil {
		return false, fmt.Errorf("registrar falha no redis: %w", err)
	}
	return n == 1, nil
}

// IsBlocked informa se o IP está bloqueado e por quanto tempo ainda.
func (b *Blocker) IsBlocked(ctx context.Context, ip string) (bool, time.Duration, error) {
	ttl, err := b.rdb.PTTL(ctx, blockKey(ip)).Result()
	if err != nil {
		return false, 0, fmt.Errorf("consultar bloqueio no redis: %w", err)
	}
	// PTTL devolve um valor negativo quando a chave não existe: IP livre.
	if ttl <= 0 {
		return false, 0, nil
	}
	return true, ttl, nil
}

// Unblock remove o bloqueio e o contador de um IP (uso administrativo e testes).
func (b *Blocker) Unblock(ctx context.Context, ip string) error {
	return b.rdb.Del(ctx, failKey(ip), blockKey(ip)).Err()
}

// Middleware rejeita requisições de IPs bloqueados ANTES de qualquer outro
// processamento: um atacante bloqueado não consome Redis de rate limit, CPU de
// validação de JWT nem os serviços internos.
func Middleware(b *Blocker, failOpen bool, reporter seclog.Reporter, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := httpx.ClientIPFrom(r.Context())
			ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
			blocked, ttl, err := b.IsBlocked(ctx, ip)
			cancel()

			if err != nil {
				logger.Error("verificação de bloqueio de IP indisponível", "error", err.Error(), "fail_open", failOpen)
				if !failOpen {
					httpx.WriteError(w, r, http.StatusServiceUnavailable, "service_unavailable", "serviço temporariamente indisponível")
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			if blocked {
				reporter.Report(r, seclog.EventIPBlocked, http.StatusForbidden, "requisição de IP bloqueado")
				w.Header().Set("Retry-After", strconv.FormatInt(int64(ttl.Seconds())+1, 10))
				httpx.WriteError(w, r, http.StatusForbidden, "ip_blocked", "acesso temporariamente bloqueado")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
