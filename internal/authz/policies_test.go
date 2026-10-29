// Caminho: internal/authz/policies_test.go
//
// Trava o inventário de rotas: se alguém mudar um escopo ou expor uma rota
// interna por engano, este teste quebra no CI.
package authz

import (
	"strings"
	"testing"
)

func TestPoliciesRealRoutes(t *testing.T) {
	cases := []struct {
		service, method, path string
		wantScope             string // "" = a rota NÃO pode estar exposta
	}{
		// Ledger
		{"ledger", "GET", "/api/v1/contas/1", "ledger:read"},
		{"ledger", "GET", "/api/v1/contas/1/extrato", "ledger:read"},
		{"ledger", "GET", "/api/v1/transferencias/9", "ledger:read"},
		{"ledger", "GET", "/api/v1/auditoria", "ledger:read"},
		{"ledger", "POST", "/api/v1/contas", "ledger:write"},
		{"ledger", "POST", "/api/v1/depositos", "ledger:write"},
		{"ledger", "POST", "/api/v1/transferencias", "ledger:write"},
		{"ledger", "GET", "/api/v1/saude", ""},
		{"ledger", "GET", "/actuator/health", ""},
		{"ledger", "GET", "/swagger-ui/index.html", ""},
		{"ledger", "GET", "/v3/api-docs", ""},
		{"ledger", "DELETE", "/api/v1/contas/1", ""},
		// Pix
		{"pix", "GET", "/api/v1/chaves", "pix:read"},
		{"pix", "GET", "/api/v1/chaves/abc", "pix:read"},
		{"pix", "GET", "/api/v1/qrcodes/imagem", "pix:read"},
		{"pix", "GET", "/api/v1/pagamentos/E123", "pix:read"},
		{"pix", "GET", "/api/v1/pagamentos/E123/devolucoes", "pix:read"},
		{"pix", "POST", "/api/v1/qrcodes/leitura", "pix:read"}, // exceção aprovada
		{"pix", "POST", "/api/v1/qrcodes/leitura/imagem", "pix:read"},
		{"pix", "POST", "/api/v1/chaves", "pix:write"},
		{"pix", "DELETE", "/api/v1/chaves/abc", "pix:write"},
		{"pix", "POST", "/api/v1/qrcodes", "pix:write"},
		{"pix", "POST", "/api/v1/pagamentos", "pix:write"},
		{"pix", "POST", "/api/v1/pagamentos/end-to-end-id", "pix:write"},
		{"pix", "POST", "/api/v1/pagamentos/E123/devolucoes", "pix:write"},
		{"pix", "POST", "/api/v1/pagamentos/E123/devolucoes/id", "pix:write"},
		{"pix", "GET", "/actuator/env", ""},
		// Antifraude
		{"antifraude", "GET", "/decisoes", "antifraude:read"},
		{"antifraude", "GET", "/metricas", "antifraude:read"},
		{"antifraude", "GET", "/painel", ""},
		{"antifraude", "GET", "/saude", ""},
		{"antifraude", "GET", "/docs", ""},
		{"antifraude", "POST", "/decisoes", ""},
	}
	for _, tc := range cases {
		rule, _ := Find(Policies[tc.service], tc.method, tc.path)
		got := ""
		if rule != nil {
			got = rule.Scope
		}
		if got != tc.wantScope {
			t.Errorf("%s %s %s: escopo %q, esperado %q", tc.service, tc.method, tc.path, got, tc.wantScope)
		}
	}
}

// Toda regra precisa usar o escopo do PRÓPRIO serviço e um método conhecido;
// um "ledger:read" dentro da lista do Pix seria um erro de digitação perigoso.
func TestPoliciesAreConsistent(t *testing.T) {
	methods := map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}
	for service, rules := range Policies {
		for _, r := range rules {
			if r.Scope != service+":read" && r.Scope != service+":write" {
				t.Errorf("%s: escopo %q fora do padrão <serviço>:read|write", service, r.Scope)
			}
			if !methods[r.Method] {
				t.Errorf("%s: método %q não permitido em regra", service, r.Method)
			}
			if !strings.HasPrefix(r.Path, "/") || strings.HasSuffix(r.Path, "/") || strings.Contains(r.Path, "**") {
				t.Errorf("%s: caminho %q inválido", service, r.Path)
			}
		}
	}
}
