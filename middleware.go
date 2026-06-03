package authaction

import (
	"context"
	"encoding/json"
	"net/http"
)

// Middleware returns a standard net/http middleware that validates the Bearer
// JWT and stores the token in the request context under UserContextKey.
//
// Example:
//
//	mux := http.NewServeMux()
//	mux.Handle("/api/", verifier.Middleware()(apiHandler))
func (v *Verifier) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := v.VerifyRequest(r)
			if err != nil || token == nil {
				msg := "Missing Bearer token"
				if err != nil {
					msg = err.Error()
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("WWW-Authenticate", "Bearer")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized", "message": msg})
				return
			}
			ctx := context.WithValue(r.Context(), UserContextKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
