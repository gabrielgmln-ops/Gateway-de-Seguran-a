// Caminho: internal/server/router.go
//
// Monta o roteador chi com os middlewares e as rotas de proxy.
//
// Comparação com Python: o chi é parecido com o roteamento do Flask/FastAPI,
// mas é minimalista e 100% compatível com a biblioteca padrão net/http.
package server

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"gateway-seguranca/internal/auth"
	"gateway-seguranca/internal/authz"
	"gateway-seguranca/internal/config"
	"gateway-seguranca/internal/httpx"
	"gateway-seguranca/internal/proxy"
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
}

// NewRouter cria o http.Handler principal do gateway.
func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()

	// A ORDEM importa, como decorators empilhados: o primeiro Use é a camada mais externa.
	r.Use(RequestID)                        // 1. todo log e todo erro passam a ter um ID
	r.Use(ClientIP(RemoteIP))               // 2. IP real do cliente no contexto
	r.Use(AccessLog(d.Logger))              // 3. registra tudo, inclusive requisições rejeitadas abaixo
	r.Use(middleware.Recoverer)             // 4. um panic vira 500 em vez de derrubar o processo
	r.Use(SecurityHeaders)                  // 5. cabeçalhos de segurança em todas as respostas
	r.Use(RejectSuspiciousPath(d.Reporter)) // 6. bloqueia "..", "//" e barras codificadas
	r.Use(LimitBody(d.Config.MaxBodyBytes)) // 7. limita o tamanho do corpo

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

	// Endpoints OAuth2 públicos (não exigem Bearer; o cliente se autentica com id e segredo).
	oauth := auth.NewHandlers(d.Tokens, d.Clients, d.Reporter)
	// r.Route cria um sub-roteador com prefixo, parecido com um Blueprint do Flask.
	r.Route("/oauth", func(or chi.Router) {
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
			g.Use(auth.RequireBearer(d.Tokens, d.Reporter))       // 1º autenticação: quem é você?
			g.Use(authz.RequireServiceScope(up.Name, d.Reporter)) // 2º autorização: pode fazer isto?
			// Mount atende "/ledger" e "/ledger/*". StripPrefix remove "/ledger" antes de
			// encaminhar, então GET /ledger/contas chega ao Ledger como GET /contas.
			g.Mount(prefix, http.StripPrefix(prefix, handler))
		})
		d.Logger.Info("rota de proxy registrada", "prefix", prefix, "upstream", up.URL.String())
	}

	return r
}
