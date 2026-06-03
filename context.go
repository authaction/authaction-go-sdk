package authaction

import "context"

type contextKey struct{}

// WithClaims returns a copy of ctx carrying the verified token payload.
// Called by the middleware after successful token verification.
func WithClaims(ctx context.Context, claims *TokenPayload) context.Context {
	return context.WithValue(ctx, contextKey{}, claims)
}

// ClaimsFromContext retrieves the verified token payload attached by middleware.
// Returns (nil, false) when no claims are present in ctx.
func ClaimsFromContext(ctx context.Context) (*TokenPayload, bool) {
	v, ok := ctx.Value(contextKey{}).(*TokenPayload)
	return v, ok && v != nil
}
