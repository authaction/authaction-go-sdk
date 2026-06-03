package authaction

import (
	"net/http"
	"time"
)

const (
	defaultCacheTTL     = time.Hour
	defaultFetchTimeout = 10 * time.Second
	rotationCooldown    = 5 * time.Minute
)

// Config holds the settings for the AuthAction JWT verifier.
type Config struct {
	// Domain is the AuthAction tenant domain, e.g. "acme.eu.authaction.com".
	Domain string

	// Audience is the API identifier (audience claim) registered in AuthAction.
	Audience string

	// JWKSCacheTTL controls how long signing keys are cached. Default: 1 hour.
	JWKSCacheTTL time.Duration

	// HTTPClient is used to fetch the JWKS endpoint.
	// Defaults to a client with a 10-second timeout.
	HTTPClient *http.Client
}
