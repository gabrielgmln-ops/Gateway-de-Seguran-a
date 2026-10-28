// Caminho: cmd/mockservice/main.go
//
// Serviço interno FALSO (mock) para testes locais. O mesmo binário faz o papel
// de Ledger, Pix ou Antifraude, conforme a variável SERVICE_NAME. Devolve um eco
// da requisição recebida e dados 100% SINTÉTICOS, para conferirmos o que o
// gateway realmente encaminha.
package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	name := os.Getenv("SERVICE_NAME")
	if name == "" {
		name = "mock"
	}
	addr := os.Getenv("MOCK_ADDR")
	if addr == "" {
		addr = ":9000"
	}

	mux := http.NewServeMux() // roteador da biblioteca padrão; aqui não precisamos do chi
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Cabeçalhos que "vazam" tecnologia, de propósito: o gateway deve removê-los.
		w.Header().Set("Server", "mock-"+name+"/1.0")
		w.Header().Set("X-Powered-By", "MockFramework 0.1")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		// map[string]any equivale a um dict[str, Any] do Python.
		resp := map[string]any{
			"service":         name,
			"method":          r.Method,
			"path":            r.URL.Path,
			"query":           r.URL.RawQuery,
			"host":            r.Host,
			"request_id":      r.Header.Get("X-Request-ID"),
			"x_forwarded_for": r.Header.Get("X-Forwarded-For"),
			"gateway_service": r.Header.Get("X-Gateway-Service"),
			// Identidade repassada pelo gateway. Se o cliente tentar forjar estes
			// cabeçalhos, o gateway os apaga antes de definir os valores verdadeiros.
			"gateway_client_id": r.Header.Get("X-Gateway-Client-ID"),
			"gateway_scopes":    r.Header.Get("X-Gateway-Scopes"),
			// Prova de que o token NÃO chega aos serviços internos (deve vir vazio):
			"authorization_recebido": r.Header.Get("Authorization"),
			"dados_sinteticos":       syntheticData(name),
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	logger.Info("mock iniciado", "service", name, "addr", addr)
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("falha no mock", "error", err.Error())
		os.Exit(1)
	}
}

// syntheticData devolve dados fictícios por tipo de serviço.
// "switch" em Go é como o "match" do Python 3.10; não precisa de "break".
func syntheticData(service string) map[string]any {
	switch service {
	case "ledger":
		return map[string]any{"conta": "0001-SINT", "saldo_centavos": 150000, "moeda": "BRL"}
	case "pix":
		return map[string]any{"chave": "sintetico@exemplo.com", "tipo": "email", "status": "ativa"}
	case "antifraude":
		return map[string]any{"score": 0.12, "decisao": "aprovar", "modelo": "regras-v0"}
	default:
		return map[string]any{"info": "mock genérico"}
	}
}
