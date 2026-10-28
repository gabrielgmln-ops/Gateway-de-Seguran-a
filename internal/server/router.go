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

	"gateway-seguranca/internal/config"
	"gateway-seguranca/internal/httpx"
	"gateway-seguranca/internal/proxy"
)

// NewRouter cria o http.Handler principal do gateway.
func NewRouter(cfg *config.Config, logger *slog.Logger) http.Handler {
	r := chi.NewRouter()

	// A ORDEM importa, como decorators empilhados: o primeiro Use é a camada mais externa.
	r.Use(RequestID)                   // 1. todo log e todo erro passam a ter um ID
	r.Use(AccessLog(logger))           // 2. registra tudo, inclusive requisições rejeitadas abaixo
	r.Use(middleware.Recoverer)        // 3. um panic vira 500 em vez de derrubar o processo
	r.Use(SecurityHeaders)             // 4. cabeçalhos de segurança em todas as respostas
	r.Use(RejectSuspiciousPath)        // 5. bloqueia "..", "//" e barras codificadas
	r.Use(LimitBody(cfg.MaxBodyBytes)) // 6. limita o tamanho do corpo

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

	// Uma rota de proxy por serviço: /ledger/*, /pix/*, /antifraude/*.
	// O inventário de rotas expostas fica explícito e centralizado aqui (OWASP API9).
	for _, up := range cfg.Upstreams {
		prefix := "/" + up.Name
		handler := proxy.New(up.Name, up.URL, cfg.UpstreamTimeout, logger)
		// Mount atende "/ledger" e "/ledger/*". StripPrefix remove "/ledger" antes de
		// encaminhar, então GET /ledger/contas chega ao Ledger como GET /contas.
		r.Mount(prefix, http.StripPrefix(prefix, handler))
		logger.Info("rota de proxy registrada", "prefix", prefix, "upstream", up.URL.String())
	}

	return r
}
