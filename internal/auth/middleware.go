// Caminho: internal/auth/middleware.go
//
// Middleware que exige um access token válido no cabeçalho
// "Authorization: Bearer <token>" (RFC 6750).
package auth

import (
	"context"
	"net/http"
	"strings"

	"gateway-seguranca/internal/httpx"
	"gateway-seguranca/internal/seclog"
)

type claimsKey struct{} // struct vazia como chave de contexto: tamanho zero e única

// ClaimsFrom devolve as claims do token validado (nil se não houver).
func ClaimsFrom(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsKey{}).(*Claims)
	return c
}

// WithClaims coloca as claims no contexto (também usado nos testes).
func WithClaims(ctx context.Context, c *Claims) context.Context {
	ctx = httpx.WithClientID(ctx, c.ClientID)
	return context.WithValue(ctx, claimsKey{}, c)
}

// RequireBearer rejeita a requisição se não houver token válido.
func RequireBearer(tokens *TokenService, reporter seclog.Reporter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, present := bearerToken(r)
			if !present {
				reporter.Report(r, seclog.EventAuthMissing, http.StatusUnauthorized, "requisição sem token Bearer")
				// Sem token: a RFC 6750 manda responder só com o realm, sem código de erro.
				w.Header().Set("WWW-Authenticate", `Bearer realm="gateway-seguranca"`)
				httpx.WriteError(w, r, http.StatusUnauthorized, "unauthorized", "token de acesso ausente")
				return
			}

			claims, err := tokens.Validate(raw)
			if err != nil {
				// O motivo detalhado (expirado, assinatura...) vai só para o log de segurança.
				reporter.Report(r, seclog.EventTokenInvalid, http.StatusUnauthorized, err.Error())
				w.Header().Set("WWW-Authenticate", `Bearer realm="gateway-seguranca", error="invalid_token"`)
				httpx.WriteError(w, r, http.StatusUnauthorized, "invalid_token", "token de acesso inválido ou expirado")
				return
			}

			next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
		})
	}
}

// bearerToken extrai o token. O esquema "Bearer" não diferencia maiúsculas de
// minúsculas (RFC 7235). Devolve present=false se o cabeçalho não existir
// ou não for do tipo Bearer.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	// strings.Cut divide no primeiro espaço: como h.partition(" ") no Python.
	scheme, token, found := strings.Cut(h, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	return strings.TrimSpace(token), true
}
