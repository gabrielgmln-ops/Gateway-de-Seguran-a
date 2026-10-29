// Caminho: internal/authz/authz.go
//
// Pacote authz: AUTORIZAÇÃO por rota e escopo. A autenticação responde
// "quem é você?"; a autorização responde "você pode fazer ISTO?".
//
// Cada serviço tem uma lista FECHADA de rotas (policies.go). Cada rota diz o
// método, o caminho e o escopo exigido, por exemplo:
//
//	GET  /api/v1/contas/*  -> ledger:read
//	POST /api/v1/depositos -> ledger:write
//
// A política é "negar por padrão" (deny by default):
//
//	caminho fora da lista            -> 404 (não revela o que existe atrás do gateway)
//	caminho na lista, método errado  -> 405
//	rota certa, escopo ausente       -> 403 insufficient_scope
//
// Isso defende contra OWASP API5 (Broken Function Level Authorization) e API9
// (Improper Inventory Management): rotas internas como /actuator, /swagger-ui
// ou o /painel do Antifraude simplesmente não existem do lado de fora.
package authz

import (
	"fmt"
	"net/http"
	"strings"

	"gateway-seguranca/internal/auth"
	"gateway-seguranca/internal/httpx"
	"gateway-seguranca/internal/seclog"
)

// Rule é uma rota permitida de um serviço.
//
// Path usa segmentos separados por "/"; um segmento "*" casa com exatamente
// UM segmento qualquer (um id, uma chave Pix...), nunca com vários.
// Comparação com Python: é como um fnmatch restrito, sem o "**" recursivo.
type Rule struct {
	Method string // GET, POST, DELETE... (uma regra GET também atende HEAD)
	Path   string // caminho no serviço, já sem o prefixo /ledger, /pix...
	Scope  string // escopo exigido, ex.: "ledger:read"
}

// matchPath compara o caminho da requisição com o padrão, segmento a segmento.
// Caminhos com barra no fim ou segmentos vazios não casam (falha fechada).
func matchPath(pattern, path string) bool {
	// strings.Split é o str.split do Python: "/a/b" -> ["", "a", "b"].
	ps, xs := strings.Split(pattern, "/"), strings.Split(path, "/")
	if len(ps) != len(xs) {
		return false
	}
	for i := range ps {
		if ps[i] == "*" {
			if xs[i] == "" { // "*" exige um valor de verdade, não um segmento vazio
				return false
			}
			continue
		}
		if ps[i] != xs[i] {
			return false
		}
	}
	return true
}

// methodMatches trata HEAD como GET, que é o que a RFC 9110 §9.3.2 define.
func methodMatches(ruleMethod, reqMethod string) bool {
	return ruleMethod == reqMethod || (ruleMethod == http.MethodGet && reqMethod == http.MethodHead)
}

// Find procura a regra para o método e o caminho.
// Devolve (regra, true) se achou; (nil, true) se o caminho existe, mas com outro
// método (vira 405); (nil, false) se o caminho não existe (vira 404).
func Find(rules []Rule, method, path string) (rule *Rule, pathKnown bool) {
	// "for i := range rules" + &rules[i] devolve um ponteiro para o item do slice,
	// sem copiá-lo (no Python, tudo já é referência, então não há essa distinção).
	for i := range rules {
		if !matchPath(rules[i].Path, path) {
			continue
		}
		pathKnown = true
		if methodMatches(rules[i].Method, method) {
			return &rules[i], true
		}
	}
	return nil, pathKnown
}

// RequireRoute aplica a lista de rotas do serviço e o escopo de cada uma.
// Deve vir DEPOIS do auth.RequireBearer, que coloca as claims no contexto, e
// recebe o caminho já sem o prefixo do serviço (usado após o http.StripPrefix).
func RequireRoute(rules []Rule, reporter seclog.Reporter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.ClaimsFrom(r.Context())
			if claims == nil {
				// Erro de montagem das rotas (faltou o RequireBearer): falha FECHADA.
				httpx.WriteError(w, r, http.StatusUnauthorized, "unauthorized", "autenticação obrigatória")
				return
			}

			rule, pathKnown := Find(rules, r.Method, r.URL.Path)
			switch {
			case rule == nil && !pathKnown:
				// Mesma resposta do 404 global: o cliente não distingue "não existe"
				// de "existe, mas não está exposto" (OWASP API9).
				httpx.WriteError(w, r, http.StatusNotFound, "not_found", "recurso não encontrado")
				return
			case rule == nil:
				httpx.WriteError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "método não permitido")
				return
			}

			if !claims.HasScope(rule.Scope) {
				reporter.Report(r, seclog.EventScopeDenied, http.StatusForbidden, "escopo exigido: "+rule.Scope)
				// RFC 6750 §3.1: informa o escopo necessário. Isso não vaza nada sensível,
				// pois a regra de escopos é pública para os clientes da API.
				w.Header().Set("WWW-Authenticate",
					fmt.Sprintf(`Bearer realm="gateway-seguranca", error="insufficient_scope", scope=%q`, rule.Scope))
				httpx.WriteError(w, r, http.StatusForbidden, "insufficient_scope", "token sem permissão para esta operação")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
