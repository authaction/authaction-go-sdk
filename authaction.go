// Package authaction provides JWT verification for AuthAction access tokens.
// It fetches public keys from the AuthAction JWKS endpoint and caches them
// with automatic rotation on unknown kid.
package authaction

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type contextKey string

// UserContextKey is the context key under which the verified JWT token is stored.
const UserContextKey contextKey = "authaction.user"

// Verifier validates AuthAction JWTs using JWKS.
type Verifier struct {
	issuer   string
	audience string
	jwksURI  string
	cache    *jwk.Cache
	ctx      context.Context
}

// New creates a Verifier.
// domain is the AuthAction tenant domain, e.g. "myapp.eu.authaction.com".
// audience is the API identifier, e.g. "https://api.myapp.com".
func New(domain, audience string) (*Verifier, error) {
	ctx := context.Background()
	jwksURI := fmt.Sprintf("https://%s/.well-known/jwks.json", domain)

	cache := jwk.NewCache(ctx)
	if err := cache.Register(jwksURI, jwk.WithRefreshInterval(time.Hour)); err != nil {
		return nil, fmt.Errorf("authaction: register JWKS: %w", err)
	}
	// Warm the cache so we fail fast on misconfiguration.
	if _, err := cache.Refresh(ctx, jwksURI); err != nil {
		return nil, fmt.Errorf("authaction: fetch JWKS: %w", err)
	}

	return &Verifier{
		issuer:   fmt.Sprintf("https://%s", domain),
		audience: audience,
		jwksURI:  jwksURI,
		cache:    cache,
		ctx:      ctx,
	}, nil
}

// newWithJWKSURI is used in tests to point at a custom JWKS endpoint.
func newWithJWKSURI(jwksURI, issuer, audience string) (*Verifier, error) {
	ctx := context.Background()
	cache := jwk.NewCache(ctx)
	if err := cache.Register(jwksURI, jwk.WithRefreshInterval(time.Hour)); err != nil {
		return nil, err
	}
	if _, err := cache.Refresh(ctx, jwksURI); err != nil {
		return nil, err
	}
	return &Verifier{issuer: issuer, audience: audience, jwksURI: jwksURI, cache: cache, ctx: ctx}, nil
}

// VerifyToken validates a raw JWT string and returns the decoded token.
// Returns *TokenExpiredError or *TokenInvalidError on failure.
func (v *Verifier) VerifyToken(tokenStr string) (jwt.Token, error) {
	keySet, err := v.cache.Get(v.ctx, v.jwksURI)
	if err != nil {
		return nil, &TokenInvalidError{Message: fmt.Sprintf("get JWKS: %s", err)}
	}

	token, err := jwt.Parse(
		[]byte(tokenStr),
		jwt.WithKeySet(keySet),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithValidate(true),
	)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "exp not satisfied") || strings.Contains(msg, "token is expired") {
			return nil, &TokenExpiredError{Message: msg}
		}
		return nil, &TokenInvalidError{Message: msg}
	}
	return token, nil
}

// VerifyRequest extracts the Bearer token from an HTTP request's Authorization
// header and verifies it. Returns nil when the header is absent or the token
// is invalid — never returns an error in that case.
func (v *Verifier) VerifyRequest(r *http.Request) (jwt.Token, error) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return nil, nil
	}
	return v.VerifyToken(strings.TrimSpace(header[7:]))
}

// TokenFromContext retrieves the verified JWT stored by Middleware.
func TokenFromContext(ctx context.Context) (jwt.Token, bool) {
	t, ok := ctx.Value(UserContextKey).(jwt.Token)
	return t, ok
}

// NewWithJWKSURIForTest is a test helper that creates a Verifier pointing at a
// custom JWKS URI (e.g. an httptest server). Not for production use.
func NewWithJWKSURIForTest(jwksURI, issuer, audience string) (*Verifier, error) {
	return newWithJWKSURI(jwksURI, issuer, audience)
}
