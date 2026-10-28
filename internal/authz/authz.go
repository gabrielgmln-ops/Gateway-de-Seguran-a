// Caminho: internal/authz/authz.go
//
// Pacote authz: AUTORIZAÇÃO por escopo. A autenticação responde "quem é você?";
// a autorização responde "você pode fazer ISTO?".
//
// Regra: o escopo exigido é "<serviço>:<ação>", e a ação depende do método HTTP:
//
//	GET, HEAD               -> <serviço>:read   (ex.: ledger:read)
//	POST, PUT, PATCH, DELETE -> <serviço>:write  (ex.: pix:write)
//	qualquer outro método   -> negado (405)
//
// A política é "negar por padrão" (deny by default): um método desconhecido
// nunca passa por engano. Ela é a defesa contra OWASP API5 (Broken Function
// Level Authorization): um cliente só de leitura não consegue disparar um Pix.
package authz

import (
	"fmt"
	"net/http"

	"gateway-seguranca/internal/auth"
	"gateway-seguranca/internal/httpx"
	"gateway-seguranca/internal/seclog"
)

// methodActions associa cada método HTTP permitido à sua ação.
// O que não está neste map é proibido (TRACE, CONNECT, OPTIONS...).
var methodActions = map[string]string{
	http.MethodGet:    "read",
	http.MethodHead:   "read",
	http.MethodPost:   "write",
	http.MethodPut:    "write",
	http.MethodPatch:  "write",
	http.MethodDelete: "write",
}

// RequiredScope devolve o escopo exigido para o serviço e o método.
// ok=false quando o método não é permitido.
func RequiredScope(service, method string) (scope string, ok bool) {
	action, ok := methodActions[method] // leitura de map com "ok", como "if key in d" no Python
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%s:%s", service, action), true
}

// RequireServiceScope exige que o token tenha o escopo do serviço.
// Deve vir DEPOIS do auth.RequireBearer, que coloca as claims no contexto.
func RequireServiceScope(service string, reporter seclog.Reporter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scope, ok := RequiredScope(service, r.Method)
			if !ok {
				httpx.WriteError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "método não permitido")
				return
			}

			claims := auth.ClaimsFrom(r.Context())
			if claims == nil {
				// Erro de montagem das rotas (faltou o RequireBearer): falha FECHADA.
				httpx.WriteError(w, r, http.StatusUnauthorized, "unauthorized", "autenticação obrigatória")
				return
			}

			if !claims.HasScope(scope) {
				reporter.Report(r, seclog.EventScopeDenied, http.StatusForbidden, "escopo exigido: "+scope)
				// RFC 6750 §3.1: informa o escopo necessário. Isso não vaza nada sensível,
				// pois a regra de escopos é pública para os clientes da API.
				w.Header().Set("WWW-Authenticate",
					fmt.Sprintf(`Bearer realm="gateway-seguranca", error="insufficient_scope", scope=%q`, scope))
				httpx.WriteError(w, r, http.StatusForbidden, "insufficient_scope", "token sem permissão para esta operação")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
