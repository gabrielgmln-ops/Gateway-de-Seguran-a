// Caminho: internal/proxy/proxy.go
//
// Pacote proxy: cria um reverse proxy seguro para cada serviço interno.
// O gateway recebe a requisição do cliente, limpa os cabeçalhos perigosos e a
// encaminha ao serviço interno (Ledger, Pix ou Antifraude).
package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"gateway-seguranca/internal/auth"
	"gateway-seguranca/internal/config"
	"gateway-seguranca/internal/httpx"
)

// internalHeaderPrefixes são prefixos de cabeçalhos que SÓ o gateway pode definir.
// Se o cliente enviar, por exemplo, "X-Gateway-Scopes: admin", o cabeçalho é
// apagado antes de chegar ao serviço interno. Nas próximas etapas, o gateway
// usará esses cabeçalhos para repassar a identidade já validada (OWASP API1/API5).
var internalHeaderPrefixes = []string{"X-Gateway-", "X-Internal-"}

// errUpstreamAuth sinaliza que o serviço RECUSOU a credencial de serviço do gateway.
// Comparação com Python: errors.New cria um valor de erro fixo, como uma
// instância de exceção reaproveitável; o ErrorHandler o reconhece com errors.Is.
var errUpstreamAuth = errors.New("serviço interno recusou a credencial do gateway")

// leakyResponseHeaders revelam tecnologia/versão do serviço interno (OWASP API8).
var leakyResponseHeaders = []string{"Server", "X-Powered-By", "X-Aspnet-Version"}

// New cria o handler de proxy para um serviço.
//
// creds é a credencial de serviço (nil = o upstream não exige login). Com ela,
// o gateway apaga o Authorization do cliente e coloca o PRÓPRIO, em HTTP Basic.
//
// Comparação com Python: http.Handler é uma "interface", um contrato com um
// único método, ServeHTTP(w, r). É parecido com um Protocol do typing: qualquer
// tipo que tenha esse método serve, sem precisar herdar de nada.
func New(name string, target *url.URL, creds *config.BasicAuth, timeout time.Duration, logger *slog.Logger) http.Handler {
	// Transport próprio com timeouts. O padrão do Go não tem timeout de resposta,
	// então um serviço lento prenderia conexões do gateway para sempre (OWASP API4).
	transport := &http.Transport{
		// Proxy: nil faz o tráfego interno NUNCA passar por HTTP_PROXY/HTTPS_PROXY
		// do ambiente, o que vazaria dados financeiros para fora da rede interna.
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &httputil.ReverseProxy{
		Transport: transport,

		// Rewrite monta a requisição de saída (pr.Out) a partir da de entrada (pr.In).
		// Comparação com Python: "func(pr ...) { ... }" é uma função anônima,
		// como um lambda, só que pode ter várias linhas.
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Aponta para o serviço interno e ajusta o cabeçalho Host.
			pr.SetURL(target)

			// Ao usar Rewrite, o Go APAGA os X-Forwarded-* que vieram do cliente.
			// SetXForwarded recria esses cabeçalhos usando o IP REAL da conexão.
			// Isso impede que o cliente falsifique o próprio IP (será essencial
			// na Etapa 4, quando bloquearemos IPs).
			pr.SetXForwarded()

			// Remove cabeçalhos internos enviados pelo cliente (anti-spoofing).
			// Em Go é seguro apagar chaves de um map enquanto se itera sobre ele
			// (no Python isso daria RuntimeError).
			for key := range pr.Out.Header {
				if hasAnyPrefix(key, internalHeaderPrefixes) {
					pr.Out.Header.Del(key)
				}
			}

			// O X-Forwarded-For passa a conter o IP real já resolvido pelo gateway
			// (considerando os proxies confiáveis), e não o do último salto.
			if ip := httpx.ClientIPFrom(pr.In.Context()); ip != "" {
				pr.Out.Header.Set("X-Forwarded-For", ip)
			}

			// O token JWT NÃO segue para os serviços internos: o gateway já o validou.
			// Se um serviço interno for comprometido, ele não terá tokens para reutilizar.
			pr.Out.Header.Del("Authorization")

			// A ORDEM importa: só DEPOIS de apagar o do cliente é que entra a
			// credencial de serviço. Assim, nada que o cliente envie chega ao
			// upstream como se fosse o gateway. SetBasicAuth monta
			// "Basic base64(usuario:senha)", como requests.auth.HTTPBasicAuth.
			if creds != nil {
				pr.Out.SetBasicAuth(creds.Username, creds.Password)
			}

			// Repassa a identidade validada em cabeçalhos que só o gateway pode definir.
			// Os serviços usam X-Gateway-Client-ID para checar a posse do objeto
			// (ex.: a conta pertence a este cliente?), a defesa contra BOLA (OWASP API1).
			if claims := auth.ClaimsFrom(pr.In.Context()); claims != nil {
				pr.Out.Header.Set("X-Gateway-Client-ID", claims.ClientID)
				pr.Out.Header.Set("X-Gateway-Scopes", claims.Scope)
				pr.Out.Header.Set("X-Gateway-Token-ID", claims.ID)
			}

			// Propaga o ID da requisição para correlacionar logs entre os serviços.
			pr.Out.Header.Set("X-Request-ID", httpx.RequestIDFrom(pr.In.Context()))
			pr.Out.Header.Set("X-Gateway-Service", name)
		},

		// ModifyResponse permite ajustar a resposta do serviço antes de devolvê-la ao cliente.
		ModifyResponse: func(resp *http.Response) error {
			// 401 com credencial configurada = a conta de serviço está errada,
			// expirada ou bloqueada (a Ledger bloqueia após falhas seguidas).
			// O cliente não tem culpa nem como resolver: devolver o 401 só o
			// confundiria e revelaria que há login atrás do gateway. Vira 502 e o
			// operador vê o motivo no log.
			if creds != nil && resp.StatusCode == http.StatusUnauthorized {
				_ = resp.Body.Close()
				return errUpstreamAuth
			}
			for _, h := range leakyResponseHeaders {
				resp.Header.Del(h)
			}
			// O gateway define os próprios cabeçalhos de segurança no middleware.
			// Remover os do serviço evita valores duplicados ou conflitantes.
			for h := range httpx.SecurityHeaders {
				resp.Header.Del(h)
			}
			return nil
		},

		// ErrorHandler é chamado quando o serviço está fora do ar, demora demais etc.
		// Responde ao cliente com um erro genérico e registra o detalhe só no log.
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			reqID := httpx.RequestIDFrom(r.Context())

			// errors.As é parecido com "except MaxBytesError as e:" no Python:
			// verifica se o erro (ou algum erro embrulhado nele) é desse tipo.
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				httpx.WriteError(w, r, http.StatusRequestEntityTooLarge,
					"payload_too_large", "corpo da requisição excede o limite permitido")
				return
			}

			// O cliente desistiu (fechou a conexão): não há a quem responder.
			if errors.Is(err, context.Canceled) {
				logger.Info("cliente cancelou a requisição", "service", name, "request_id", reqID)
				return
			}

			if errors.Is(err, errUpstreamAuth) {
				// Só o usuário vai para o log; a senha, nunca.
				logger.Error("credencial de serviço recusada pelo upstream; confira o .env",
					"service", name, "request_id", reqID, "service_user", creds.Username)
				httpx.WriteError(w, r, http.StatusBadGateway,
					"upstream_unavailable", "serviço temporariamente indisponível")
				return
			}

			var netErr net.Error
			if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
				logger.Warn("timeout no serviço interno", "service", name, "request_id", reqID, "error", err.Error())
				httpx.WriteError(w, r, http.StatusGatewayTimeout,
					"upstream_timeout", "o serviço não respondeu a tempo")
				return
			}

			logger.Error("falha ao contatar serviço interno", "service", name, "request_id", reqID, "error", err.Error())
			httpx.WriteError(w, r, http.StatusBadGateway,
				"upstream_unavailable", "serviço temporariamente indisponível")
		},
	}
}

// hasAnyPrefix diz se s começa com algum dos prefixos (comparação sem
// diferenciar maiúsculas de minúsculas, pois cabeçalhos HTTP são case-insensitive).
func hasAnyPrefix(s string, prefixes []string) bool {
	lower := strings.ToLower(s)
	for _, p := range prefixes {
		if strings.HasPrefix(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}
