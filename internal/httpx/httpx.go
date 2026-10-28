// Caminho: internal/httpx/httpx.go
//
// Pacote httpx: utilitários HTTP compartilhados pelo servidor e pelo proxy
// (respostas de erro padronizadas, ID de requisição e cabeçalhos de segurança).
package httpx

import (
	"context"
	"encoding/json"
	"net/http"
)

// contextKey é um tipo próprio para chaves de contexto. Usar um tipo privado
// evita colisão com chaves de outros pacotes.
//
// Comparação com Python: o "context.Context" do Go é parecido com o
// contextvars do Python. Ele carrega valores (como o ID da requisição) e
// sinais de cancelamento ao longo de toda a cadeia de chamadas.
type contextKey string

const requestIDKey contextKey = "request_id"

// SecurityHeaders são os cabeçalhos de segurança aplicados a TODAS as respostas
// (OWASP API8: Security Misconfiguration).
//
// Comparação com Python: map[string]string é um dict[str, str].
var SecurityHeaders = map[string]string{
	"X-Content-Type-Options":  "nosniff",                                    // impede o navegador de "adivinhar" o tipo
	"X-Frame-Options":         "DENY",                                       // impede embutir em iframe
	"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'", // API não serve HTML
	"Referrer-Policy":         "no-referrer",
	"Cache-Control":           "no-store", // dados financeiros não devem ficar em cache
}

// ErrorBody é o formato JSON único de erro do gateway.
// As "tags" `json:"..."` dizem o nome do campo no JSON, como o alias do Pydantic.
type ErrorBody struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"` // omitempty: omite o campo se estiver vazio
}

// WriteError escreve um erro JSON genérico. Nunca inclui detalhes internos
// (stack trace, endereço do serviço etc.), para não vazar informação (API8).
func WriteError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	// json.NewEncoder(w).Encode(...) é parecido com json.dump(obj, arquivo) no Python.
	// O erro é ignorado de propósito com "_": se o cliente já desconectou, não há o que fazer.
	_ = json.NewEncoder(w).Encode(ErrorBody{
		Error:     code,
		Message:   message,
		RequestID: RequestIDFrom(r.Context()),
	})
}

// WithRequestID devolve um novo contexto contendo o ID da requisição.
// Contextos em Go são imutáveis: cada valor novo gera um contexto "filho".
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDFrom lê o ID da requisição do contexto ("" se não existir).
func RequestIDFrom(ctx context.Context) string {
	// ".(string)" é uma "type assertion": verifica se o valor é mesmo uma string.
	// Parecido com "isinstance(v, str)", só que já convertendo o valor.
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}
