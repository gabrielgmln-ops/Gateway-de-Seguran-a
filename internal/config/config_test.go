// Caminho: internal/config/config_test.go
//
// Testes do pacote config.
//
// Comparação com Python: arquivos terminados em _test.go são como test_*.py do
// pytest. Cada função TestXxx(t *testing.T) é um teste; t.Errorf/t.Fatalf fazem o
// papel do assert. Rode com: go test ./...
package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// setValidEnv define o mínimo de variáveis para Load() funcionar.
// t.Setenv restaura o valor original ao fim do teste (como monkeypatch.setenv do pytest).
func setValidEnv(t *testing.T) {
	t.Helper() // em caso de falha, o erro aponta a linha de quem chamou
	t.Setenv("LEDGER_URL", "http://ledger:9000")
	t.Setenv("PIX_URL", "http://pix:9000")
	t.Setenv("ANTIFRAUDE_URL", "https://antifraude:9443")
	t.Setenv("JWT_SECRET", strings.Repeat("a", 32))
	t.Setenv("OAUTH_CLIENTS", `[{"client_id":"x"}]`)
	t.Setenv("REDIS_ADDR", "localhost:6379")
	// Zera as credenciais de serviço, para o teste não depender do ambiente da máquina.
	for _, svc := range []string{"LEDGER", "PIX", "ANTIFRAUDE"} {
		t.Setenv(svc+"_USUARIO", "")
		t.Setenv(svc+"_SENHA", "")
	}
}

func TestLoadDefaults(t *testing.T) {
	setValidEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() falhou: %v", err)
	}
	if cfg.Addr != ":8080" {
		t.Errorf("Addr = %q, esperado :8080", cfg.Addr)
	}
	if cfg.JWTTTL != 15*time.Minute {
		t.Errorf("JWTTTL = %v, esperado 15m", cfg.JWTTTL)
	}
	if len(cfg.Upstreams) != 3 || cfg.Upstreams[0].Name != "ledger" {
		t.Errorf("Upstreams inesperados: %+v", cfg.Upstreams)
	}
	if cfg.RedisFailOpen {
		t.Error("REDIS_FAIL_OPEN deve ser false por padrão (fail closed)")
	}
	if cfg.IPBlockMaxFailures != 5 || cfg.RateOAuth.Capacity != 10 {
		t.Errorf("padrões de segurança inesperados: %+v", cfg)
	}
}

// Teste "table-driven": a forma idiomática em Go de testar vários casos,
// equivalente ao @pytest.mark.parametrize.
func TestLoadRejectsInvalidConfig(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		value   string
		wantErr string
	}{
		{"segredo curto", "JWT_SECRET", "curto", "JWT_SECRET"},
		{"url sem esquema http", "LEDGER_URL", "ftp://ledger", "LEDGER_URL"},
		{"url com credenciais", "PIX_URL", "http://user:senha@pix:9000", "credenciais"},
		{"url com query", "PIX_URL", "http://pix:9000/?debug=1", "query"},
		{"url ausente", "ANTIFRAUDE_URL", "", "ANTIFRAUDE_URL"},
		{"ttl longo demais", "JWT_TTL", "24h", "JWT_TTL"},
		{"corpo negativo", "MAX_BODY_BYTES", "-1", "MAX_BODY_BYTES"},
		{"timeout inválido", "UPSTREAM_TIMEOUT", "abc", "UPSTREAM_TIMEOUT"},
		{"clientes ausentes", "OAUTH_CLIENTS", "", "OAUTH_CLIENTS"},
		{"redis ausente", "REDIS_ADDR", "", "REDIS_ADDR"},
		{"fail open inválido", "REDIS_FAIL_OPEN", "talvez", "REDIS_FAIL_OPEN"},
		{"rate inválido", "RATE_LIMIT_CLIENT_CAPACITY", "0", "RATE_LIMIT_CLIENT"},
		{"refill inválido", "RATE_LIMIT_IP_REFILL_PER_SEC", "-2", "RATE_LIMIT_IP"},
		{"bloqueio inválido", "IPBLOCK_MAX_FAILURES", "0", "IPBLOCK_MAX_FAILURES"},
		{"janela inválida", "IPBLOCK_WINDOW", "x", "IPBLOCK_WINDOW"},
		{"duração inválida", "IPBLOCK_DURATION", "-1m", "IPBLOCK_DURATION"},
		{"buffer inválido", "SECLOG_BUFFER", "0", "SECLOG_BUFFER"},
		{"redis db inválido", "REDIS_DB", "-1", "REDIS_DB"},
	}
	for _, tc := range cases {
		// t.Run cria um subteste com nome próprio (aparece em go test -v).
		t.Run(tc.name, func(t *testing.T) {
			setValidEnv(t)
			t.Setenv(tc.key, tc.value)
			_, err := Load()
			if err == nil {
				t.Fatalf("esperava erro para %s=%q", tc.key, tc.value)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("erro %q não menciona %q", err, tc.wantErr)
			}
		})
	}
}

func TestErrorDoesNotLeakSecret(t *testing.T) {
	setValidEnv(t)
	t.Setenv("JWT_SECRET", "segredo-curto-123")
	_, err := Load()
	if err == nil || strings.Contains(err.Error(), "segredo-curto-123") {
		t.Fatalf("a mensagem de erro não pode conter o segredo: %v", err)
	}
}

func TestLoadServiceAuth(t *testing.T) {
	setValidEnv(t)
	t.Setenv("LEDGER_USUARIO", "svc-gateway")
	t.Setenv("LEDGER_SENHA", "s3nha")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if a := cfg.Upstreams[0].Auth; a == nil || a.Username != "svc-gateway" || a.Password != "s3nha" {
		t.Errorf("credencial da Ledger não carregada: %v", a)
	}
	if cfg.Upstreams[1].Auth != nil || cfg.Upstreams[2].Auth != nil {
		t.Error("Pix e Antifraude não deveriam ter credencial")
	}
	// A senha não pode aparecer quando a struct é impressa (logs, %v, %+v).
	if s := fmt.Sprintf("%v %+v", *cfg.Upstreams[0].Auth, cfg.Upstreams[0].Auth); strings.Contains(s, "s3nha") {
		t.Errorf("senha vazou na formatação: %s", s)
	}
}

func TestLoadServiceAuthInvalid(t *testing.T) {
	cases := []struct{ user, pass string }{
		{"svc-gateway", ""},
		{"", "s3nha"},
		{"svc:gateway", "s3nha"},
	}
	for _, tc := range cases {
		setValidEnv(t)
		t.Setenv("LEDGER_USUARIO", tc.user)
		t.Setenv("LEDGER_SENHA", tc.pass)
		_, err := Load()
		if err == nil {
			t.Errorf("usuario=%q senha vazia=%v deveria falhar", tc.user, tc.pass == "")
			continue
		}
		if tc.pass != "" && strings.Contains(err.Error(), tc.pass) {
			t.Error("a mensagem de erro não pode conter a senha")
		}
	}
}
