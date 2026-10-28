// Caminho: internal/auth/clients.go
//
// Cadastro de clientes OAuth2 (fluxo client_credentials, de máquina para máquina).
// O cadastro vem da variável de ambiente OAUTH_CLIENTS, em JSON, e guarda só o
// HASH SHA-256 do segredo, nunca o segredo em si.
//
// Por que SHA-256 e não bcrypt? Os client_secrets são aleatórios e longos
// (32 bytes gerados por máquina), então força bruta no hash é inviável. Um hash
// lento como o bcrypt só se justifica para senhas escolhidas por humanos, e
// ainda abriria um vetor de DoS por CPU no endpoint de token.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
)

// scopePattern: escopos no formato "recurso:acao", ex.: "pix:write".
// regexp.MustCompile é como re.compile() do Python; "Must" = causa panic se a regex for inválida.
var scopePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$`)

// clientIDPattern limita os caracteres do client_id (ele aparece em logs e chaves do Redis).
var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)

// Client é um cliente cadastrado.
type Client struct {
	ID         string
	SecretHash [32]byte // "[32]byte" é um ARRAY de tamanho fixo (diferente do slice []byte)
	Scopes     []string
}

// HasScope informa se o cliente pode receber o escopo pedido.
func (c Client) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// clientJSON é o formato de entrada de cada cliente em OAUTH_CLIENTS.
type clientJSON struct {
	ClientID     string   `json:"client_id"`
	SecretSHA256 string   `json:"secret_sha256"`
	Scopes       []string `json:"scopes"`
}

// ClientStore guarda os clientes indexados por ID.
type ClientStore struct {
	clients map[string]Client
}

// dummyHash é usado quando o client_id não existe, para que a resposta leve o
// mesmo tempo nos dois casos. Sem isso, medir o tempo de resposta revelaria
// quais client_ids existem (enumeração de usuários, OWASP API2).
var dummyHash = sha256.Sum256([]byte("cliente-inexistente"))

// ParseClients lê e valida o JSON de clientes.
//
// Exemplo de OAUTH_CLIENTS:
//
//	[{"client_id":"app-pix","secret_sha256":"<64 hex>","scopes":["pix:read","pix:write"]}]
func ParseClients(raw string) (*ClientStore, error) {
	var items []clientJSON
	// json.Unmarshal é o json.loads() do Go. O "&items" passa o endereço da
	// variável para a função preenchê-la.
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return nil, fmt.Errorf("OAUTH_CLIENTS não é um JSON válido: %w", err)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("OAUTH_CLIENTS não contém nenhum cliente")
	}

	store := &ClientStore{clients: make(map[string]Client, len(items))}
	for _, it := range items {
		if !clientIDPattern.MatchString(it.ClientID) {
			return nil, fmt.Errorf("client_id inválido: %q", it.ClientID)
		}
		if _, exists := store.clients[it.ClientID]; exists {
			return nil, fmt.Errorf("client_id duplicado: %q", it.ClientID)
		}
		hashBytes, err := hex.DecodeString(it.SecretSHA256)
		if err != nil || len(hashBytes) != sha256.Size {
			return nil, fmt.Errorf("secret_sha256 do cliente %q deve ter 64 caracteres hexadecimais", it.ClientID)
		}
		if len(it.Scopes) == 0 {
			return nil, fmt.Errorf("cliente %q sem escopos", it.ClientID)
		}
		for _, s := range it.Scopes {
			if !scopePattern.MatchString(s) {
				return nil, fmt.Errorf("escopo inválido %q no cliente %q", s, it.ClientID)
			}
		}
		c := Client{ID: it.ClientID, Scopes: it.Scopes}
		copy(c.SecretHash[:], hashBytes) // "[:]" converte o array em slice para o copy()
		store.clients[c.ID] = c
	}
	return store, nil
}

// Authenticate confere client_id e client_secret em tempo constante.
// Devolve o cliente e true apenas se ambos estiverem corretos.
func (s *ClientStore) Authenticate(clientID, secret string) (Client, bool) {
	sum := sha256.Sum256([]byte(secret))

	c, found := s.clients[clientID]
	expected := dummyHash
	if found {
		expected = c.SecretHash
	}
	// subtle.ConstantTimeCompare é o equivalente ao hmac.compare_digest do Python.
	// Uma comparação comum (==) para no primeiro byte diferente, o que permite
	// descobrir o hash byte a byte medindo o tempo de resposta.
	match := subtle.ConstantTimeCompare(sum[:], expected[:]) == 1
	if !found || !match {
		return Client{}, false
	}
	return c, true
}

// HashSecret calcula o hash hexadecimal de um segredo (usado pelo cmd/hashsecret).
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
