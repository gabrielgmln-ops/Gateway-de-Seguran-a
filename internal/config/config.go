// Caminho: internal/config/config.go
//
// Pacote config: lê TODA a configuração do gateway a partir de variáveis de
// ambiente (nenhum segredo ou endereço fica fixo no código).
//
// Comparação com Python: em Go, cada pasta é um "package" (parecido com um
// módulo .py). Diferente do Python, não existe __init__.py: todos os arquivos
// .go da mesma pasta compartilham o mesmo "package <nome>".
package config

// "import" funciona como no Python, mas com aspas e agrupado entre parênteses.
// Imports não usados são ERRO de compilação em Go (no Python seriam só um aviso do linter).
import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"
)

// Upstream representa um serviço interno (Ledger, Pix, Antifraude).
//
// Comparação com Python: "struct" é parecido com um @dataclass. Campos que
// começam com letra MAIÚSCULA são públicos (exportados para outros pacotes);
// com letra minúscula são privados ao pacote. Go não tem "self._privado":
// a visibilidade depende só da primeira letra.
type Upstream struct {
	Name string   // prefixo da rota, ex.: "ledger" -> /ledger/*
	URL  *url.URL // endereço interno do serviço; "*" indica um ponteiro (referência)
}

// Config agrupa todas as configurações do gateway.
type Config struct {
	Addr            string        // endereço em que o gateway escuta, ex.: ":8080"
	MaxBodyBytes    int64         // tamanho máximo do corpo da requisição (OWASP API4)
	UpstreamTimeout time.Duration // tempo máximo esperando o serviço interno responder
	Upstreams       []Upstream    // "[]Upstream" é um slice: parecido com list[Upstream]
}

// Load lê as variáveis de ambiente e valida tudo logo na inicialização
// ("fail fast"): melhor o gateway não subir do que subir mal configurado (OWASP API8).
//
// Comparação com Python: Go não tem exceções. Funções que podem falhar
// retornam DOIS valores: o resultado e um "error". Quem chama verifica
// "if err != nil", que é o equivalente ao "except" do Python.
func Load() (*Config, error) {
	// ":=" declara e atribui ao mesmo tempo, com o tipo inferido (como "x = ..." no Python).
	cfg := &Config{
		Addr: getEnv("GATEWAY_ADDR", ":8080"),
	}

	maxBodyRaw := getEnv("MAX_BODY_BYTES", "1048576") // 1 MiB por padrão
	maxBody, err := strconv.ParseInt(maxBodyRaw, 10, 64)
	if err != nil || maxBody <= 0 {
		return nil, fmt.Errorf("MAX_BODY_BYTES inválido: %q", maxBodyRaw)
	}
	cfg.MaxBodyBytes = maxBody

	timeoutRaw := getEnv("UPSTREAM_TIMEOUT", "10s")
	timeout, err := time.ParseDuration(timeoutRaw) // aceita "500ms", "10s", "1m"...
	if err != nil || timeout <= 0 {
		return nil, fmt.Errorf("UPSTREAM_TIMEOUT inválido: %q", timeoutRaw)
	}
	cfg.UpstreamTimeout = timeout

	// Slice de structs anônimas: parecido com uma lista de tuplas no Python.
	// Uso uma lista (e não um map/dict) para que a ordem seja sempre a mesma.
	services := []struct {
		name   string
		envVar string
	}{
		{"ledger", "LEDGER_URL"},
		{"pix", "PIX_URL"},
		{"antifraude", "ANTIFRAUDE_URL"},
	}

	// "for _, s := range services" == "for s in services:" no Python.
	// O "_" descarta o índice, que o range também devolve (como enumerate()).
	for _, s := range services {
		raw := os.Getenv(s.envVar)
		if raw == "" {
			return nil, fmt.Errorf("variável de ambiente %s é obrigatória", s.envVar)
		}
		u, err := parseUpstreamURL(raw)
		if err != nil {
			// "%w" embrulha o erro original, como "raise NovoErro() from err" no Python.
			return nil, fmt.Errorf("%s inválida: %w", s.envVar, err)
		}
		// append() é o equivalente a lista.append(x), mas devolve o slice novo.
		cfg.Upstreams = append(cfg.Upstreams, Upstream{Name: s.name, URL: u})
	}

	return cfg, nil // "nil" é o equivalente ao None do Python
}

// parseUpstreamURL valida o endereço de um serviço interno.
// Começa com letra minúscula, então é privada a este pacote.
func parseUpstreamURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("esquema deve ser http ou https, recebido %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("host ausente")
	}
	// Credenciais na URL (http://user:senha@host) acabariam vazando em logs.
	if u.User != nil {
		return nil, fmt.Errorf("não coloque credenciais na URL do serviço")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("a URL do serviço não deve ter query string nem fragmento")
	}
	return u, nil
}

// getEnv devolve a variável de ambiente ou um valor padrão.
// É o equivalente ao os.getenv("NOME", "padrao") do Python.
func getEnv(key, fallback string) string {
	// os.LookupEnv devolve (valor, existe). Esse padrão "valor, ok" é muito comum em Go.
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
