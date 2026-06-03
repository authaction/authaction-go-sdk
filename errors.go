package authaction

import "errors"

var (
	// ErrTokenMissing is returned when the Authorization header is absent or
	// does not contain a Bearer token.
	ErrTokenMissing = errors.New("authaction: missing Bearer token")

	// ErrTokenInvalid is returned when the token fails signature or claims
	// validation (wrong issuer, audience, algorithm, etc.).
	ErrTokenInvalid = errors.New("authaction: token is invalid")

	// ErrTokenExpired is returned when a structurally valid token has passed
	// its expiry time.
	ErrTokenExpired = errors.New("authaction: token has expired")

	// ErrJWKSUnavailable is returned when the JWKS endpoint cannot be reached
	// or returns a non-200 response.
	ErrJWKSUnavailable = errors.New("authaction: JWKS endpoint unavailable")
)
