// Caminho: internal/server/router.go
//
// Monta o roteador chi com os middlewares e as rotas de proxy.
//
// Comparação com Python: o chi é parecido com o roteamento do Flask/FastAPI,
// mas é minimalista e 100% compatível com a biblioteca padrão net/http.
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"gateway-seguranca/internal/auth"
	"gateway-seguranca/internal/authz"
	"gateway-seguranca/internal/config"
	"gateway-seguranca/internal/httpx"
	"gateway-seguranca/internal/proxy"
	"gateway-seguranca/internal/ratelimit"
	"gateway-seguranca/internal/seclog"
)

// Deps reúne tudo de que o roteador precisa. Receber as dependências prontas
// ("injeção de dependências") permite montar o roteador nos testes com
// versões falsas ou em memória.
type Deps struct {
	Config   *config.Config
	Logger   *slog.Logger
	Tokens   *auth.TokenService
	Clients  *auth.ClientStore
	Reporter seclog.Reporter

	// Limitadores (Etapa 3). São interfaces: nos testes, podem ser trocados.
	IPLimiter     ratelimit.Limiter
	OAuthLimiter  ratelimit.Limiter
	ClientLimiter ratelimit.Limiter

	// ReadyChecks: verificações de prontidão (ex.: "redis" -> ping). Usadas no /readyz.
	ReadyChecks map[string]func(context.Context) error
}

// probePaths não passam por rate limit: o orquestrador (Docker/Kubernetes)
// consulta essas rotas o tempo todo.
var probePaths = map[string]bool{"/healthz": true, "/readyz": true}

// NewRouter cria o http.Handler principal do gateway.
func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()

	// A ORDEM importa, como decorators empilhados: o primeiro Use é a camada mais externa.
	r.Use(RequestID)                                                              // 1. todo log e todo erro passam a ter um ID
	r.Use(ClientIP(RemoteIP))                                                     // 2. IP real do cliente no contexto
	r.Use(AccessLog(d.Logger))                                                    // 3. registra tudo, inclusive requisições rejeitadas abaixo
	r.Use(middleware.Recoverer)                                                   // 4. um panic vira 500 em vez de derrubar o processo
	r.Use(SecurityHeaders)                                                        // 5. cabeçalhos de segurança em todas as respostas
	r.Use(SkipPaths(probePaths, rateLimit(d, d.IPLimiter, ratelimit.ByClientIP))) // 6. limite global por IP
	r.Use(RejectSuspiciousPath(d.Reporter))                                       // 7. bloqueia "..", "//" e barras codificadas
	r.Use(LimitBody(d.Config.MaxBodyBytes))                                       // 8. limita o tamanho do corpo

	// Respostas 404/405 em JSON, sem revelar quais rotas existem (OWASP API8/API9).
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, http.StatusNotFound, "not_found", "recurso não encontrado")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "método não permitido")
	})

	// Health check do próprio gateway (não consulta os serviços internos).
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Prontidão: o gateway só está "pronto" se as dependências (Redis...) respondem.
	// A resposta não traz a mensagem de erro, apenas o nome da dependência que falhou.
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		status, code := map[string]string{}, http.StatusOK
		for name, check := range d.ReadyChecks {
			if err := check(ctx); err != nil {
				d.Logger.Error("dependência indisponível", "dependency", name, "error", err.Error())
				status[name], code = "down", http.StatusServiceUnavailable
				continue
			}
			status[name] = "up"
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(status)
	})

	// Endpoints OAuth2 públicos (não exigem Bearer; o cliente se autentica com id e segredo).
	oauth := auth.NewHandlers(d.Tokens, d.Clients, d.Reporter)
	// r.Route cria um sub-roteador com prefixo, parecido com um Blueprint do Flask.
	r.Route("/oauth", func(or chi.Router) {
		// Limite mais rígido por IP: dificulta força bruta de client_secret (OWASP API2/API4).
		or.Use(rateLimit(d, d.OAuthLimiter, ratelimit.ByClientIP))
		or.Post("/token", oauth.Token)
		or.Post("/introspect", oauth.Introspect)
	})

	// Uma rota de proxy por serviço: /ledger/*, /pix/*, /antifraude/*.
	// O inventário de rotas expostas fica explícito e centralizado aqui (OWASP API9).
	for _, up := range d.Config.Upstreams {
		prefix := "/" + up.Name
		handler := proxy.New(up.Name, up.URL, d.Config.UpstreamTimeout, d.Logger)

		// r.Group cria um grupo de rotas que compartilha middlewares, sem mudar o prefixo.
		r.Group(func(g chi.Router) {
			g.Use(auth.RequireBearer(d.Tokens, d.Reporter))            // 1º autenticação: quem é você?
			g.Use(rateLimit(d, d.ClientLimiter, ratelimit.ByClientID)) // 2º limite por cliente
			g.Use(authz.RequireServiceScope(up.Name, d.Reporter))      // 3º autorização: pode fazer isto?
			// Mount atende "/ledger" e "/ledger/*". StripPrefix remove "/ledger" antes de
			// encaminhar, então GET /ledger/contas chega ao Ledger como GET /contas.
			g.Mount(prefix, http.StripPrefix(prefix, handler))
		})
		d.Logger.Info("rota de proxy registrada", "prefix", prefix, "upstream", up.URL.String())
	}

	return r
}

// rateLimit é um atalho para montar o middleware com as dependências comuns.
func rateLimit(d Deps, l ratelimit.Limiter, key ratelimit.KeyFunc) func(http.Handler) http.Handler {
	return ratelimit.Middleware(l, key, d.Config.RedisFailOpen, d.Reporter, d.Logger)
}
