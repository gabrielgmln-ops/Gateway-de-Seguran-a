// Caminho: internal/auth/token.go
//
// Emissão e validação de access tokens JWT (HS256), com as defesas contra os
// ataques clássicos a JWT (OWASP API2: Broken Authentication):
//   - "alg: none" e confusão de algoritmo: só HS256 é aceito;
//   - token sem expiração: "exp" é obrigatório;
//   - token de outro emissor ou público: "iss" e "aud" são conferidos;
//   - confusão de tipo de token: o cabeçalho "typ" deve ser "at+jwt" (RFC 9068).
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	tokenType      = "at+jwt" // tipo de access token definido pela RFC 9068
	maxTokenLength = 4096     // tokens maiores que isso são rejeitados antes do parse
	clockLeeway    = 30 * time.Second
)

// ErrInvalidToken é o erro único devolvido para QUALQUER falha de validação.
// O motivo real (expirado, assinatura errada...) vai só para o log interno:
// dizer ao atacante qual verificação falhou o ajudaria a montar o ataque.
//
// Comparação com Python: errors.New cria um "erro sentinela", parecido com
// definir "class InvalidToken(Exception): pass" e comparar com errors.Is.
var ErrInvalidToken = errors.New("token inválido")

// Claims são os dados carregados dentro do JWT.
// jwt.RegisteredClaims é "embutido" (embedding): seus campos (Issuer, Subject,
// ExpiresAt...) passam a fazer parte de Claims. Lembra herança no Python, mas
// em Go é composição: Claims "tem" um RegisteredClaims.
type Claims struct {
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"` // escopos separados por espaço, como no OAuth2 (RFC 6749)
	jwt.RegisteredClaims
}

// Scopes devolve os escopos como lista. strings.Fields é o str.split() sem argumentos.
func (c *Claims) Scopes() []string {
	return strings.Fields(c.Scope)
}

// HasScope informa se o token contém o escopo exigido.
func (c *Claims) HasScope(scope string) bool {
	for _, s := range c.Scopes() {
		if s == scope {
			return true
		}
	}
	return false
}

// TokenService emite e valida tokens.
type TokenService struct {
	secret   []byte
	issuer   string
	audience string
	ttl      time.Duration
	now      func() time.Time // relógio injetável para os testes
	parser   *jwt.Parser
}

// NewTokenService cria o serviço de tokens.
func NewTokenService(secret []byte, issuer, audience string, ttl time.Duration) (*TokenService, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("segredo JWT precisa ter pelo menos 32 bytes")
	}
	ts := &TokenService{
		secret:   secret,
		issuer:   issuer,
		audience: audience,
		ttl:      ttl,
		now:      time.Now,
	}
	ts.parser = ts.newParser()
	return ts, nil
}

// newParser monta o parser com todas as verificações obrigatórias.
func (t *TokenService) newParser() *jwt.Parser {
	return jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), // bloqueia "none", RS256 etc.
		jwt.WithIssuer(t.issuer),
		jwt.WithAudience(t.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(), // rejeita tokens "emitidos no futuro"
		jwt.WithLeeway(clockLeeway),
		// A função anônima abaixo é uma "closure": ela enxerga a variável t do
		// escopo externo, como uma função aninhada no Python.
		jwt.WithTimeFunc(func() time.Time { return t.now() }),
	)
}

// Issue emite um token para o cliente com os escopos concedidos.
func (t *TokenService) Issue(clientID string, scopes []string) (string, *Claims, error) {
	now := t.now()
	jti, err := randomID()
	if err != nil {
		return "", nil, err
	}
	claims := &Claims{
		ClientID: clientID,
		Scope:    strings.Join(scopes, " "), // " ".join(scopes) no Python
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.issuer,
			Subject:   clientID,
			Audience:  jwt.ClaimStrings{t.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(t.ttl)),
			ID:        jti, // "jti": identificador único, útil para auditoria e revogação futura
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["typ"] = tokenType
	signed, err := token.SignedString(t.secret)
	if err != nil {
		return "", nil, fmt.Errorf("falha ao assinar token: %w", err)
	}
	return signed, claims, nil
}

// Validate confere assinatura, algoritmo, tipo, emissor, público e validade.
// Em caso de falha, devolve ErrInvalidToken embrulhando o motivo real.
func (t *TokenService) Validate(raw string) (*Claims, error) {
	if raw == "" || len(raw) > maxTokenLength {
		return nil, fmt.Errorf("%w: tamanho inválido", ErrInvalidToken)
	}
	claims := &Claims{}
	_, err := t.parser.ParseWithClaims(raw, claims, func(tok *jwt.Token) (any, error) {
		// Esta "keyfunc" devolve a chave de verificação. Conferimos o typ aqui,
		// antes da verificação da assinatura.
		if typ, _ := tok.Header["typ"].(string); !strings.EqualFold(typ, tokenType) {
			return nil, fmt.Errorf("typ inesperado: %q", typ)
		}
		return t.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	// Defesa extra: o sujeito deve existir e ser o próprio cliente.
	if claims.Subject == "" || claims.Subject != claims.ClientID {
		return nil, fmt.Errorf("%w: subject inconsistente", ErrInvalidToken)
	}
	return claims, nil
}

// TTL expõe a validade configurada (usada no campo expires_in da resposta).
func (t *TokenService) TTL() time.Duration { return t.ttl }

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("falha ao gerar jti: %w", err)
	}
	return hex.EncodeToString(b), nil
}
