// Caminho: internal/authz/policies.go
//
// Inventário ÚNICO das rotas que o gateway expõe (OWASP API9). Tudo o que não
// está aqui responde 404, inclusive /actuator, /swagger-ui, /v3/api-docs, as
// rotas /saude dos serviços e o /painel HTML do Antifraude.
//
// Os caminhos são os dos serviços reais, já sem o prefixo do gateway:
// GET /ledger/api/v1/contas/42 chega à Ledger como GET /api/v1/contas/42.
//
// Para expor uma rota nova, acrescente uma linha aqui e um caso de teste em
// policies_test.go. Nunca use um curinga para "liberar tudo" de um serviço.
package authz

// Policies associa o nome de cada serviço (config.Upstream.Name) às suas rotas.
//
// Comparação com Python: é um dict[str, list[Rule]] declarado como literal.
// Em Go, dentro do literal, o tipo de cada item ({...}) pode ser omitido.
var Policies = map[string][]Rule{
	// Ledger API (Java/Spring), protegida por HTTP Basic: o gateway injeta a
	// credencial de serviço LEDGER_USUARIO/LEDGER_SENHA (ver internal/proxy).
	"ledger": {
		{"GET", "/api/v1/contas/*", "ledger:read"},
		{"GET", "/api/v1/contas/*/extrato", "ledger:read"},
		{"GET", "/api/v1/transferencias/*", "ledger:read"},
		{"GET", "/api/v1/auditoria", "ledger:read"},
		{"POST", "/api/v1/contas", "ledger:write"},
		{"POST", "/api/v1/depositos", "ledger:write"},
		{"POST", "/api/v1/transferencias", "ledger:write"},
	},

	// Pix Simulado (Kotlin/Spring), sem autenticação própria.
	"pix": {
		{"GET", "/api/v1/chaves", "pix:read"},
		{"GET", "/api/v1/chaves/*", "pix:read"},
		{"GET", "/api/v1/qrcodes/imagem", "pix:read"},
		{"GET", "/api/v1/pagamentos/*", "pix:read"},
		{"GET", "/api/v1/pagamentos/*/devolucoes", "pix:read"},
		// Exceções aprovadas: são POST, mas só DECODIFICAM um QR Code enviado no
		// corpo, sem gravar nada. Exigir pix:write aqui obrigaria a dar poder de
		// escrita a quem só precisa ler um QR Code (privilégio mínimo).
		{"POST", "/api/v1/qrcodes/leitura", "pix:read"},
		{"POST", "/api/v1/qrcodes/leitura/imagem", "pix:read"},
		{"POST", "/api/v1/chaves", "pix:write"},
		{"DELETE", "/api/v1/chaves/*", "pix:write"},
		{"POST", "/api/v1/qrcodes", "pix:write"},
		{"POST", "/api/v1/pagamentos", "pix:write"},
		{"POST", "/api/v1/pagamentos/end-to-end-id", "pix:write"},
		{"POST", "/api/v1/pagamentos/*/devolucoes", "pix:write"},
		{"POST", "/api/v1/pagamentos/*/devolucoes/id", "pix:write"},
	},

	// Motor Antifraude (Python/FastAPI): só consultas.
	"antifraude": {
		{"GET", "/decisoes", "antifraude:read"},
		{"GET", "/metricas", "antifraude:read"},
	},
}
