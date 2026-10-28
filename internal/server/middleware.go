// Caminho: internal/server/middleware.go
//
// Middlewares do gateway. Um middleware "embrulha" um handler para executar
// algo antes ou depois dele.
//
// Comparação com Python: é exatamente a ideia de um decorator. A assinatura
// func(next http.Handler) http.Handler equivale a um decorator que recebe a
// view e devolve outra view, como os middlewares do Django e do FastAPI.
package server

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"gateway-seguranca/internal/httpx"
	"gateway-seguranca/internal/seclog"
)

// RequestID gera um ID aleatório para CADA requisição.
// O valor enviado pelo cliente em X-Request-ID é ignorado de propósito: um
// valor controlado pelo atacante poderia poluir ou forjar logs de auditoria.
func RequestID(next http.Handler) http.Handler {
	// http.HandlerFunc converte uma função comum em http.Handler.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		w.Header().Set("X-Request-ID", id)
		// r.WithContext cria uma CÓPIA da requisição com o novo contexto.
		next.ServeHTTP(w, r.WithContext(httpx.WithRequestID(r.Context(), id)))
	})
}

// newRequestID gera 16 bytes aleatórios criptograficamente seguros em hexadecimal.
// Equivalente em Python: secrets.token_hex(16).
func newRequestID() string {
	b := make([]byte, 16) // make() cria um slice com 16 posições zeradas, como bytearray(16)
	if _, err := rand.Read(b); err != nil {
		return "sem-id"
	}
	return hex.EncodeToString(b)
}

// ClientIP descobre o IP real do cliente uma única vez e o guarda no contexto.
// "resolve" é uma função recebida como parâmetro (funções são valores em Go,
// como no Python), o que permite trocar a estratégia sem mudar o middleware.
func ClientIP(resolve func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(httpx.WithClientIP(r.Context(), resolve(r))))
		})
	}
}

// RemoteIP usa só o endereço da conexão TCP, que não pode ser falsificado
// pelo cliente (ao contrário de cabeçalhos como X-Forwarded-For).
func RemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// AccessLog registra cada requisição em JSON estruturado (base para os logs
// de segurança da Etapa 4, OWASP API10).
// Esta função RECEBE o logger e DEVOLVE o middleware: é um "decorator com
// parâmetros", como @decorator(logger) no Python.
func AccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			// WrapResponseWriter "espiona" a resposta para descobrir o status e os bytes enviados.
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(ww, r)

			status := ww.Status()
			if status == 0 { // o handler não chamou WriteHeader explicitamente
				status = http.StatusOK
			}
			logger.Info("http_request",
				"request_id", httpx.RequestIDFrom(r.Context()),
				"method", r.Method,
				"path", r.URL.Path, // só o caminho: a query string pode conter dados sensíveis
				"status", status,
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
				"client_ip", httpx.ClientIPFrom(r.Context()),
				"user_agent", r.UserAgent(),
			)
		})
	}
}

// SecurityHeaders aplica os cabeçalhos de segurança a todas as respostas (OWASP API8).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range httpx.SecurityHeaders { // iterar um map é como dict.items()
			w.Header().Set(k, v)
		}
		next.ServeHTTP(w, r)
	})
}

// RejectSuspiciousPath bloqueia caminhos com travessia de diretório ("..") ou
// barras codificadas. Sem isso, "/ledger/../admin" poderia burlar as regras
// de autorização por rota das próximas etapas (OWASP API5).
func RejectSuspiciousPath(reporter seclog.Reporter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSuspiciousPath(r.URL.Path, r.URL.EscapedPath()) {
				reporter.Report(r, seclog.EventPathRejected, http.StatusBadRequest, "caminho suspeito")
				httpx.WriteError(w, r, http.StatusBadRequest, "invalid_path", "caminho da requisição inválido")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isSuspiciousPath(decoded, escaped string) bool {
	// strings.ContainsAny verifica se algum desses caracteres aparece: "\\" é a barra invertida,
	// "\x00" é o byte nulo.
	if strings.ContainsAny(decoded, "\\\x00") || strings.Contains(decoded, "//") {
		return true
	}
	// strings.Split é o equivalente a str.split("/").
	for _, segment := range strings.Split(decoded, "/") {
		if segment == ".." || segment == "." {
			return true
		}
	}
	// %2F (barra) e %5C (barra invertida) codificados escondem separadores de caminho.
	lowerEscaped := strings.ToLower(escaped)
	return strings.Contains(lowerEscaped, "%2f") || strings.Contains(lowerEscaped, "%5c")
}

// LimitBody limita o tamanho do corpo das requisições (OWASP API4:
// Unrestricted Resource Consumption). Evita que um cliente envie gigabytes
// e esgote a memória do gateway ou do serviço interno.
func LimitBody(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Rejeição imediata quando o cliente já declara um tamanho grande demais.
			if r.ContentLength > maxBytes {
				httpx.WriteError(w, r, http.StatusRequestEntityTooLarge,
					"payload_too_large", "corpo da requisição excede o limite permitido")
				return
			}
			// Proteção também para corpos sem Content-Length (chunked):
			// a leitura falha ao ultrapassar o limite.
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// SkipPaths aplica o middleware "mw" a todas as rotas, EXCETO às listadas.
func SkipPaths(paths map[string]bool, mw func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		wrapped := mw(next) // monta a versão "com middleware" uma única vez
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if paths[r.URL.Path] { // ler chave ausente de um map devolve o valor zero (false)
				next.ServeHTTP(w, r)
				return
			}
			wrapped.ServeHTTP(w, r)
		})
	}
}
