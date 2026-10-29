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
	"strings"
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

	// Auth é a credencial de SERVIÇO que o gateway apresenta ao upstream.
	// nil = o serviço não exige autenticação (ex.: Pix Simulado, mocks).
	// O Authorization do cliente nunca segue adiante; quando o serviço exige
	// login (a Ledger usa HTTP Basic), quem se autentica é o próprio gateway.
	Auth *BasicAuth
}

// BasicAuth guarda usuário e senha de uma conta de serviço.
//
// Comparação com Python: o método String() abaixo é como o __repr__. Qualquer
// fmt.Print/%v/%+v e o slog usam ele, então a senha nunca aparece num log,
// mesmo que alguém imprima a struct Upstream inteira por descuido.
type BasicAuth struct {
	Username string
	Password string
}

// String esconde a senha (OWASP API8: segredo fora de logs).
func (b BasicAuth) String() string {
	return fmt.Sprintf("BasicAuth{Username: %q, Password: \"***\"}", b.Username)
}

// Config agrupa todas as configurações do gateway.
type Config struct {
	Addr            string        // endereço em que o gateway escuta, ex.: ":8080"
	MaxBodyBytes    int64         // tamanho máximo do corpo da requisição (OWASP API4)
	UpstreamTimeout time.Duration // tempo máximo esperando o serviço interno responder
	Upstreams       []Upstream    // "[]Upstream" é um slice: parecido com list[Upstream]

	// --- Autenticação (Etapa 1) ---
	JWTSecret        []byte        // chave HMAC do JWT; []byte é como o tipo bytes do Python
	JWTIssuer        string        // claim "iss"
	JWTAudience      string        // claim "aud"
	JWTTTL           time.Duration // validade do access token
	OAuthClientsJSON string        // cadastro de clientes OAuth2 (JSON), lido de variável de ambiente

	// --- Redis e rate limiting (Etapa 3) ---
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	RedisFailOpen bool      // false = se o Redis cair, o gateway recusa as requisições (mais seguro)
	RateIP        RateLimit // limite global por IP, aplicado antes de qualquer coisa
	RateOAuth     RateLimit // limite por IP no /oauth/* (anti força bruta de credenciais)
	RateClient    RateLimit // limite por client_id autenticado nas rotas de serviço

	// --- Bloqueio de IP e logs de segurança (Etapa 4) ---
	IPBlockMaxFailures int           // falhas na janela até bloquear
	IPBlockWindow      time.Duration // janela de contagem das falhas
	IPBlockDuration    time.Duration // por quanto tempo o IP fica bloqueado
	TrustedProxies     string        // CIDRs dos proxies confiáveis, ex.: "10.0.0.0/8,172.16.0.0/12"
	DatabaseURL        string        // PostgreSQL; vazio = eventos só no stdout
	SecLogBuffer       int           // tamanho da fila de eventos para o PostgreSQL
}

// RateLimit descreve um token bucket: Capacity = rajada máxima; Refill = fichas por segundo.
type RateLimit struct {
	Capacity int64
	Refill   float64
}

// minJWTSecretBytes: 32 bytes (256 bits) é o mínimo recomendado para HS256.
// Segredos curtos podem ser quebrados por força bruta offline (OWASP API2).
const minJWTSecretBytes = 32

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
		creds, err := loadServiceAuth(s.name)
		if err != nil {
			return nil, err
		}
		// append() é o equivalente a lista.append(x), mas devolve o slice novo.
		cfg.Upstreams = append(cfg.Upstreams, Upstream{Name: s.name, URL: u, Auth: creds})
	}

	// --- Autenticação ---
	secret := os.Getenv("JWT_SECRET")
	if len(secret) < minJWTSecretBytes {
		// Nunca imprima o segredo na mensagem de erro, só o problema.
		return nil, fmt.Errorf("JWT_SECRET é obrigatório e precisa ter pelo menos %d bytes", minJWTSecretBytes)
	}
	cfg.JWTSecret = []byte(secret) // conversão de string para bytes, como secret.encode()
	cfg.JWTIssuer = getEnv("JWT_ISSUER", "gateway-seguranca")
	cfg.JWTAudience = getEnv("JWT_AUDIENCE", "servicos-internos")

	ttlRaw := getEnv("JWT_TTL", "15m")
	ttl, err := time.ParseDuration(ttlRaw)
	// Tokens de vida curta reduzem o estrago caso um token vaze.
	if err != nil || ttl <= 0 || ttl > time.Hour {
		return nil, fmt.Errorf("JWT_TTL inválido (use entre 1s e 1h): %q", ttlRaw)
	}
	cfg.JWTTTL = ttl

	cfg.OAuthClientsJSON = os.Getenv("OAUTH_CLIENTS")
	if cfg.OAuthClientsJSON == "" {
		return nil, fmt.Errorf("variável de ambiente OAUTH_CLIENTS é obrigatória")
	}

	// --- Redis ---
	cfg.RedisAddr = os.Getenv("REDIS_ADDR")
	if cfg.RedisAddr == "" {
		return nil, fmt.Errorf("variável de ambiente REDIS_ADDR é obrigatória (ex.: localhost:6379)")
	}
	cfg.RedisPassword = os.Getenv("REDIS_PASSWORD")
	if cfg.RedisDB, err = strconv.Atoi(getEnv("REDIS_DB", "0")); err != nil || cfg.RedisDB < 0 {
		return nil, fmt.Errorf("REDIS_DB inválido")
	}
	if cfg.RedisFailOpen, err = strconv.ParseBool(getEnv("REDIS_FAIL_OPEN", "false")); err != nil {
		return nil, fmt.Errorf("REDIS_FAIL_OPEN deve ser true ou false")
	}

	// Os limites padrão são exemplos razoáveis; ajuste conforme a carga real.
	if cfg.RateIP, err = loadRate("RATE_LIMIT_IP", 100, 50); err != nil {
		return nil, err
	}
	if cfg.RateOAuth, err = loadRate("RATE_LIMIT_OAUTH", 10, 0.5); err != nil {
		return nil, err
	}
	if cfg.RateClient, err = loadRate("RATE_LIMIT_CLIENT", 20, 10); err != nil {
		return nil, err
	}

	// --- Bloqueio de IP ---
	if cfg.IPBlockMaxFailures, err = strconv.Atoi(getEnv("IPBLOCK_MAX_FAILURES", "5")); err != nil || cfg.IPBlockMaxFailures < 1 {
		return nil, fmt.Errorf("IPBLOCK_MAX_FAILURES inválido")
	}
	if cfg.IPBlockWindow, err = time.ParseDuration(getEnv("IPBLOCK_WINDOW", "10m")); err != nil || cfg.IPBlockWindow <= 0 {
		return nil, fmt.Errorf("IPBLOCK_WINDOW inválido")
	}
	if cfg.IPBlockDuration, err = time.ParseDuration(getEnv("IPBLOCK_DURATION", "15m")); err != nil || cfg.IPBlockDuration <= 0 {
		return nil, fmt.Errorf("IPBLOCK_DURATION inválido")
	}
	cfg.TrustedProxies = os.Getenv("TRUSTED_PROXIES")

	// --- Logs de segurança ---
	cfg.DatabaseURL = os.Getenv("DATABASE_URL")
	if cfg.SecLogBuffer, err = strconv.Atoi(getEnv("SECLOG_BUFFER", "1000")); err != nil || cfg.SecLogBuffer < 1 {
		return nil, fmt.Errorf("SECLOG_BUFFER inválido")
	}

	return cfg, nil // "nil" é o equivalente ao None do Python
}

// loadServiceAuth lê <SERVIÇO>_USUARIO e <SERVIÇO>_SENHA (ex.: LEDGER_USUARIO).
// As duas vazias: o serviço não usa autenticação. Só uma preenchida: erro, porque
// é quase certo um .env incompleto, e subir assim geraria 401 em toda chamada.
func loadServiceAuth(service string) (*BasicAuth, error) {
	prefix := strings.ToUpper(service) // "ledger" -> "LEDGER", como str.upper()
	user := os.Getenv(prefix + "_USUARIO")
	pass := os.Getenv(prefix + "_SENHA")
	switch {
	case user == "" && pass == "":
		return nil, nil
	case user == "" || pass == "":
		return nil, fmt.Errorf("defina %s_USUARIO e %s_SENHA juntos (ou nenhum dos dois)", prefix, prefix)
	case strings.Contains(user, ":"):
		// No HTTP Basic, o ":" separa usuário de senha (RFC 7617 §2).
		return nil, fmt.Errorf("%s_USUARIO não pode conter \":\"", prefix)
	}
	return &BasicAuth{Username: user, Password: pass}, nil
}

// loadRate lê <prefixo>_CAPACITY e <prefixo>_REFILL_PER_SEC.
func loadRate(prefix string, defCapacity int64, defRefill float64) (RateLimit, error) {
	capRaw := getEnv(prefix+"_CAPACITY", strconv.FormatInt(defCapacity, 10))
	capacity, err := strconv.ParseInt(capRaw, 10, 64)
	if err != nil || capacity < 1 {
		return RateLimit{}, fmt.Errorf("%s_CAPACITY inválido: %q", prefix, capRaw)
	}
	refillRaw := getEnv(prefix+"_REFILL_PER_SEC", strconv.FormatFloat(defRefill, 'f', -1, 64))
	refill, err := strconv.ParseFloat(refillRaw, 64)
	if err != nil || refill <= 0 {
		return RateLimit{}, fmt.Errorf("%s_REFILL_PER_SEC inválido: %q", prefix, refillRaw)
	}
	return RateLimit{Capacity: capacity, Refill: refill}, nil
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
