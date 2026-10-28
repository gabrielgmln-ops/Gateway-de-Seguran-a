// Caminho: internal/auth/auth_test.go
//
// Testes de clientes e tokens, incluindo os ATAQUES clássicos contra JWT.
package auth

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var testSecret = []byte(strings.Repeat("k", 32))

func newTestService(t *testing.T) *TokenService {
	t.Helper()
	ts, err := NewTokenService(testSecret, "gateway-teste", "servicos", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestIssueAndValidate(t *testing.T) {
	ts := newTestService(t)
	raw, issued, err := ts.Issue("app-pix", []string{"pix:read", "pix:write"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ts.Validate(raw)
	if err != nil {
		t.Fatalf("token recém-emitido deveria ser válido: %v", err)
	}
	if claims.ClientID != "app-pix" || claims.Subject != "app-pix" {
		t.Errorf("identidade errada: %+v", claims)
	}
	if !claims.HasScope("pix:write") || claims.HasScope("ledger:read") {
		t.Errorf("escopos errados: %q", claims.Scope)
	}
	if claims.ID == "" || claims.ID != issued.ID {
		t.Error("jti ausente ou divergente")
	}
}

func TestNewTokenServiceRejectsShortSecret(t *testing.T) {
	if _, err := NewTokenService([]byte("curto"), "i", "a", time.Minute); err == nil {
		t.Fatal("segredo curto deveria ser recusado")
	}
}

func TestValidateRejectsExpired(t *testing.T) {
	ts := newTestService(t)
	past := time.Now().Add(-time.Hour)
	ts.now = func() time.Time { return past } // emite "no passado"
	raw, _, _ := ts.Issue("app", []string{"pix:read"})
	ts.now = time.Now
	if _, err := ts.Validate(raw); err == nil {
		t.Fatal("token expirado foi aceito")
	}
}

func TestValidateRejectsFutureIssuedAt(t *testing.T) {
	ts := newTestService(t)
	future := time.Now().Add(time.Hour)
	ts.now = func() time.Time { return future }
	raw, _, _ := ts.Issue("app", []string{"pix:read"})
	ts.now = time.Now
	if _, err := ts.Validate(raw); err == nil {
		t.Fatal("token emitido no futuro foi aceito")
	}
}

// signWith monta um token arbitrário para simular um atacante.
func signWith(t *testing.T, method jwt.SigningMethod, key any, typ string, claims jwt.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	if typ != "" {
		tok.Header["typ"] = typ
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validClaims() *Claims {
	now := time.Now()
	return &Claims{
		ClientID: "app",
		Scope:    "pix:write",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "gateway-teste",
			Subject:   "app",
			Audience:  jwt.ClaimStrings{"servicos"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
	}
}

func TestValidateRejectsAttacks(t *testing.T) {
	ts := newTestService(t)

	wrongIss := validClaims()
	wrongIss.Issuer = "outro-emissor"
	wrongAud := validClaims()
	wrongAud.Audience = jwt.ClaimStrings{"outro-publico"}
	noExp := validClaims()
	noExp.ExpiresAt = nil
	subMismatch := validClaims()
	subMismatch.Subject = "admin"

	// Token "alg: none": cabeçalho e payload válidos, assinatura vazia.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt"}`))
	good := signWith(t, jwt.SigningMethodHS256, testSecret, tokenType, validClaims())
	payload := strings.Split(good, ".")[1]
	algNone := header + "." + payload + "."

	// Payload adulterado: o atacante troca o escopo por "admin:all" e mantém a
	// assinatura original. A assinatura deixa de bater com o conteúdo.
	parts := strings.Split(good, ".")
	evil := base64.RawURLEncoding.EncodeToString([]byte(
		`{"client_id":"app","scope":"admin:all","iss":"gateway-teste","sub":"app","aud":["servicos"],"exp":9999999999,"iat":1}`))
	tampered := parts[0] + "." + evil + "." + parts[2]

	cases := map[string]string{
		"alg none":            algNone,
		"payload adulterado":  tampered,
		"segredo errado":      signWith(t, jwt.SigningMethodHS256, []byte(strings.Repeat("x", 32)), tokenType, validClaims()),
		"HS512 não permitido": signWith(t, jwt.SigningMethodHS512, testSecret, tokenType, validClaims()),
		"typ ausente":         signWith(t, jwt.SigningMethodHS256, testSecret, "", validClaims()),
		"typ JWT (id token)":  signWith(t, jwt.SigningMethodHS256, testSecret, "JWT", validClaims()),
		"emissor errado":      signWith(t, jwt.SigningMethodHS256, testSecret, tokenType, wrongIss),
		"público errado":      signWith(t, jwt.SigningMethodHS256, testSecret, tokenType, wrongAud),
		"sem exp":             signWith(t, jwt.SigningMethodHS256, testSecret, tokenType, noExp),
		"sub diferente":       signWith(t, jwt.SigningMethodHS256, testSecret, tokenType, subMismatch),
		"vazio":               "",
		"gigante":             strings.Repeat("a", maxTokenLength+1),
		"lixo":                "nao.e.jwt",
	}
	// Iterar um map: a ordem é aleatória em Go (de propósito), diferente do dict do Python.
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ts.Validate(raw); err == nil {
				t.Fatalf("ataque %q foi aceito", name)
			}
		})
	}
}

const validHash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" // sha256("password")

func TestParseClientsAndAuthenticate(t *testing.T) {
	store, err := ParseClients(`[{"client_id":"app-pix","secret_sha256":"` + validHash + `","scopes":["pix:read"]}]`)
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := store.Authenticate("app-pix", "password"); !ok || c.ID != "app-pix" {
		t.Error("credenciais corretas foram recusadas")
	}
	if _, ok := store.Authenticate("app-pix", "errada"); ok {
		t.Error("segredo errado foi aceito")
	}
	if _, ok := store.Authenticate("nao-existe", "password"); ok {
		t.Error("cliente inexistente foi aceito")
	}
	if _, ok := store.Authenticate("app-pix", ""); ok {
		t.Error("segredo vazio foi aceito")
	}
}

func TestParseClientsRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"json inválido":     `{`,
		"lista vazia":       `[]`,
		"id inválido":       `[{"client_id":"a b","secret_sha256":"` + validHash + `","scopes":["pix:read"]}]`,
		"hash curto":        `[{"client_id":"app","secret_sha256":"abc","scopes":["pix:read"]}]`,
		"sem escopos":       `[{"client_id":"app","secret_sha256":"` + validHash + `","scopes":[]}]`,
		"escopo malformado": `[{"client_id":"app","secret_sha256":"` + validHash + `","scopes":["admin"]}]`,
		"duplicado": `[{"client_id":"app","secret_sha256":"` + validHash + `","scopes":["pix:read"]},` +
			`{"client_id":"app","secret_sha256":"` + validHash + `","scopes":["pix:read"]}]`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseClients(raw); err == nil {
				t.Fatalf("configuração inválida aceita: %s", name)
			}
		})
	}
}

func TestHashSecret(t *testing.T) {
	if HashSecret("password") != validHash {
		t.Fatal("hash SHA-256 incorreto")
	}
}

func TestBearerTokenParsing(t *testing.T) {
	cases := []struct {
		header  string
		token   string
		present bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true}, // o esquema não diferencia maiúsculas (RFC 7235)
		{"Basic abc", "", false},
		{"Bearer", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		r := newRequestWithHeader("Authorization", tc.header)
		tok, ok := bearerToken(r)
		if tok != tc.token || ok != tc.present {
			t.Errorf("bearerToken(%q) = (%q, %v), esperado (%q, %v)", tc.header, tok, ok, tc.token, tc.present)
		}
	}
}
