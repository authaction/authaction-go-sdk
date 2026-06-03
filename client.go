package authaction

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Client verifies AuthAction JWT access tokens using JWKS.
type Client struct {
	issuer   string
	audience string
	jwks     *jwksCache
}

// New creates a Client from the provided Config.
// Returns an error when Domain or Audience is empty.
func New(cfg Config) (*Client, error) {
	if cfg.Domain == "" {
		return nil, fmt.Errorf("authaction: domain is required")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("authaction: audience is required")
	}
	if cfg.JWKSCacheTTL <= 0 {
		cfg.JWKSCacheTTL = defaultCacheTTL
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: defaultFetchTimeout}
	}

	issuer := "https://" + cfg.Domain
	jwksURL := issuer + "/.well-known/jwks.json"

	return &Client{
		issuer:   issuer,
		audience: cfg.Audience,
		jwks:     newJWKSCache(jwksURL, cfg.JWKSCacheTTL, cfg.HTTPClient),
	}, nil
}

// VerifyToken parses and validates a raw JWT string.
//
// Checks: RS256 algorithm, issuer, audience, and expiry.
// Returns ErrTokenExpired, ErrTokenInvalid, or ErrJWKSUnavailable on failure.
func (c *Client) VerifyToken(ctx context.Context, tokenString string) (*TokenPayload, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(c.issuer),
		jwt.WithAudience(c.audience),
		jwt.WithExpirationRequired(),
	)

	token, err := parser.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		return c.jwks.getKey(ctx, kid)
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: %s", ErrTokenInvalid, err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}

	return mapToPayload(claims), nil
}

// VerifyRequest extracts the Bearer token from r's Authorization header and
// verifies it. Returns ErrTokenMissing when the header is absent or malformed.
func (c *Client) VerifyRequest(ctx context.Context, r *http.Request) (*TokenPayload, error) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return nil, ErrTokenMissing
	}
	raw := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if raw == "" {
		return nil, ErrTokenMissing
	}
	return c.VerifyToken(ctx, raw)
}

// mapToPayload converts jwt.MapClaims into a typed TokenPayload.
func mapToPayload(m jwt.MapClaims) *TokenPayload {
	p := &TokenPayload{Extra: make(map[string]interface{})}

	p.Sub, _ = m["sub"].(string)
	p.Iss, _ = m["iss"].(string)
	p.Scope, _ = m["scope"].(string)

	if v, ok := m["exp"].(float64); ok {
		p.Exp = int64(v)
	}
	if v, ok := m["iat"].(float64); ok {
		p.Iat = int64(v)
	}

	switch v := m["aud"].(type) {
	case string:
		p.Aud = []string{v}
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok {
				p.Aud = append(p.Aud, s)
			}
		}
	}

	standard := map[string]bool{
		"sub": true, "iss": true, "aud": true,
		"exp": true, "iat": true, "nbf": true,
		"jti": true, "scope": true,
	}
	for k, v := range m {
		if !standard[k] {
			p.Extra[k] = v
		}
	}

	return p
}
