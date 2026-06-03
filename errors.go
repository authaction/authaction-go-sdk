package authaction

import "fmt"

// TokenExpiredError is returned when the JWT exp claim is in the past.
type TokenExpiredError struct{ Message string }

func (e *TokenExpiredError) Error() string { return fmt.Sprintf("authaction: token expired: %s", e.Message) }

// TokenInvalidError is returned when the JWT signature, issuer, audience, or structure is invalid.
type TokenInvalidError struct{ Message string }

func (e *TokenInvalidError) Error() string { return fmt.Sprintf("authaction: invalid token: %s", e.Message) }
