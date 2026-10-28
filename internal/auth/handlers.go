// Caminho: internal/auth/handlers.go
//
// Endpoints OAuth2:
//
//	POST /oauth/token       emite o token (grant client_credentials, RFC 6749 §4.4)
//	POST /oauth/introspect  valida o token (Token Introspection, RFC 7662)
package auth

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"gateway-seguranca/internal/httpx"
	"gateway-seguranca/internal/seclog"
)

// ScopeIntrospect é o escopo exigido para usar o endpoint de introspecção.
// Sem essa exigência, qualquer um poderia usar o endpoint como "oráculo"
// para testar tokens roubados (princípio do menor privilégio).
const ScopeIntrospect = "token:introspect"

// tokenResponse é o corpo de sucesso definido pela RFC 6749 §5.1.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

// introspectResponse segue a RFC 7662 §2.2. Os ponteiros (*int64) permitem
// omitir o campo: com omitempty, um ponteiro nil some do JSON.
type introspectResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Exp       *int64 `json:"exp,omitempty"`
	Iat       *int64 `json:"iat,omitempty"`
	Jti       string `json:"jti,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

// Handlers agrupa as dependências dos endpoints OAuth2.
type Handlers struct {
	tokens   *TokenService
	clients  *ClientStore
	reporter seclog.Reporter
}

// NewHandlers cria os handlers OAuth2.
func NewHandlers(tokens *TokenService, clients *ClientStore, reporter seclog.Reporter) *Handlers {
	return &Handlers{tokens: tokens, clients: clients, reporter: reporter}
}

// Token implementa POST /oauth/token.
func (h *Handlers) Token(w http.ResponseWriter, r *http.Request) {
	if !h.parseForm(w, r) {
		return
	}

	if grant := r.PostForm.Get("grant_type"); grant != "client_credentials" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "apenas client_credentials é suportado")
		return
	}

	// O handler recebe de volta uma requisição nova, cujo contexto já tem o client_id.
	client, r, ok := h.authenticateClient(w, r)
	if !ok {
		return
	}

	// Escopos: se o cliente pedir, só concedemos o subconjunto permitido a ele.
	// Se não pedir, concedemos todos os escopos cadastrados.
	granted := client.Scopes
	if requested := strings.Fields(r.PostForm.Get("scope")); len(requested) > 0 {
		for _, s := range requested {
			if !client.HasScope(s) {
				h.reporter.Report(r, seclog.EventScopeDenied, http.StatusBadRequest, "escopo solicitado não permitido: "+s)
				writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "escopo solicitado não é permitido para este cliente")
				return
			}
		}
		granted = dedupe(requested)
	}

	token, _, err := h.tokens.Issue(client.ID, granted)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "não foi possível emitir o token")
		return
	}

	// Registra a emissão (sem o token: tokens e segredos NUNCA vão para log).
	h.reporter.Report(r, seclog.EventTokenIssued, http.StatusOK, "escopos: "+strings.Join(granted, " "))
	w.Header().Set("Pragma", "no-cache") // exigido pela RFC 6749 §5.1, junto com Cache-Control: no-store
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int64(h.tokens.TTL().Seconds()),
		Scope:       strings.Join(granted, " "),
	})
}

// Introspect implementa POST /oauth/introspect.
func (h *Handlers) Introspect(w http.ResponseWriter, r *http.Request) {
	if !h.parseForm(w, r) {
		return
	}
	// O handler recebe de volta uma requisição nova, cujo contexto já tem o client_id.
	client, r, ok := h.authenticateClient(w, r)
	if !ok {
		return
	}
	if !client.HasScope(ScopeIntrospect) {
		h.reporter.Report(r, seclog.EventScopeDenied, http.StatusForbidden, "cliente sem escopo "+ScopeIntrospect)
		writeOAuthError(w, http.StatusForbidden, "insufficient_scope", "cliente não autorizado a validar tokens")
		return
	}

	raw := r.PostForm.Get("token")
	if raw == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "parâmetro token é obrigatório")
		return
	}

	claims, err := h.tokens.Validate(raw)
	if err != nil {
		// RFC 7662: token inválido responde 200 com {"active": false}, sem dizer o motivo.
		writeJSON(w, http.StatusOK, introspectResponse{Active: false})
		return
	}
	exp := claims.ExpiresAt.Unix()
	iat := claims.IssuedAt.Unix()
	writeJSON(w, http.StatusOK, introspectResponse{
		Active:    true,
		Scope:     claims.Scope,
		ClientID:  claims.ClientID,
		Sub:       claims.Subject,
		Iss:       claims.Issuer,
		Exp:       &exp, // "&" pega o endereço da variável (cria o ponteiro)
		Iat:       &iat,
		Jti:       claims.ID,
		TokenType: "Bearer",
	})
}

// parseForm valida o Content-Type e lê o corpo do formulário. Devolve false se
// já respondeu com erro. Credenciais na query string são recusadas porque URLs
// acabam em logs de proxies e no histórico.
func (h *Handlers) parseForm(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.RawQuery != "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "parâmetros devem ir no corpo, não na URL")
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		writeOAuthError(w, http.StatusUnsupportedMediaType, "invalid_request",
			"Content-Type deve ser application/x-www-form-urlencoded")
		return false
	}
	if err := r.ParseForm(); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeOAuthError(w, http.StatusRequestEntityTooLarge, "invalid_request", "corpo da requisição muito grande")
			return false
		}
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "formulário inválido")
		return false
	}
	return true
}

// authenticateClient autentica o cliente via HTTP Basic (preferido) ou via
// campos do formulário. Usar os dois ao mesmo tempo é proibido (RFC 6749 §2.3).
func (h *Handlers) authenticateClient(w http.ResponseWriter, r *http.Request) (Client, *http.Request, bool) {
	id, secret, hasBasic := r.BasicAuth()
	formID, formSecret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")

	switch {
	case hasBasic && (formID != "" || formSecret != ""):
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "use apenas um método de autenticação do cliente")
		return Client{}, r, false
	case hasBasic:
		// Na RFC 6749 §2.3.1, id e segredo no Basic vêm codificados como em formulários.
		if v, err := url.QueryUnescape(id); err == nil {
			id = v
		}
		if v, err := url.QueryUnescape(secret); err == nil {
			secret = v
		}
	default:
		id, secret = formID, formSecret
	}

	client, ok := h.clients.Authenticate(id, secret)
	if !ok {
		// Mesma mensagem para "cliente não existe" e "segredo errado" (anti-enumeração).
		// O client_id tentado não é registrado em log: poderia ser um segredo digitado no campo errado.
		h.reporter.Report(r, seclog.EventAuthFailure, http.StatusUnauthorized, "credenciais de cliente inválidas")
		w.Header().Set("WWW-Authenticate", `Basic realm="gateway-seguranca"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "falha na autenticação do cliente")
		return Client{}, r, false
	}
	// A partir daqui, os logs desta requisição já trazem o client_id autenticado.
	return client, r.WithContext(httpx.WithClientID(r.Context(), client.ID)), true
}

// writeOAuthError usa o formato de erro do OAuth2 (RFC 6749 §5.2).
func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// dedupe remove escopos repetidos mantendo a ordem (como list(dict.fromkeys(x)) no Python).
func dedupe(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, it := range items {
		if !seen[it] {
			seen[it] = true
			out = append(out, it)
		}
	}
	return out
}
