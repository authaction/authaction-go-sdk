package authaction

import (
	"encoding/json"
	"errors"
	"net/http"
)

// RequireAuth returns an http.Handler middleware that enforces a valid Bearer
// token. On missing or invalid token it responds 401 JSON and stops the chain.
// On success the verified claims are available via ClaimsFromContext.
//
//	mux.Handle("/api/", authaction.RequireAuth(client)(apiHandler))
func RequireAuth(c *Client) func(http.Handler) http.Handler {
	return buildMiddleware(c, true)
}

// OptionalAuth returns an http.Handler middleware that attaches claims when a
// valid Bearer token is present, but passes unauthenticated requests through.
//
//	mux.Handle("/public/", authaction.OptionalAuth(client)(publicHandler))
func OptionalAuth(c *Client) func(http.Handler) http.Handler {
	return buildMiddleware(c, false)
}

func buildMiddleware(c *Client, required bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := c.VerifyRequest(r.Context(), r)
			if err != nil {
				if errors.Is(err, ErrTokenMissing) && !required {
					next.ServeHTTP(w, r)
					return
				}
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error":   "Unauthorized",
					"message": errMessage(err),
				})
				return
			}
			next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
		})
	}
}

func errMessage(err error) string {
	switch {
	case errors.Is(err, ErrTokenExpired):
		return "Token has expired"
	case errors.Is(err, ErrTokenMissing):
		return "Missing Bearer token"
	default:
		return "Invalid token"
	}
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
