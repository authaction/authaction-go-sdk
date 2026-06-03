package authaction

import "errors"

// ErrTokenExpired is returned when the JWT exp claim is in the past.
var ErrTokenExpired = errors.New("authaction: token expired")

// ErrTokenInvalid is returned when the JWT signature, issuer, audience, or structure is invalid.
var ErrTokenInvalid = errors.New("authaction: token invalid")

// ErrTokenMissing is returned when no Bearer token is present in the request.
var ErrTokenMissing = errors.New("authaction: token missing")

// ErrJWKSUnavailable is returned when the JWKS endpoint cannot be reached and no cached keys are available.
var ErrJWKSUnavailable = errors.New("authaction: JWKS unavailable")
