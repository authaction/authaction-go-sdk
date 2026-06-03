// Package authaction provides JWT verification for APIs protected by AuthAction.
//
// # Quickstart
//
//	client, err := authaction.New(authaction.Config{
//	    Domain:   "acme.eu.authaction.com",
//	    Audience: "https://api.example.com",
//	})
//	if err != nil { ... }
//
//	// Verify a raw token
//	claims, err := client.VerifyToken(ctx, tokenString)
//
//	// Protect a route group (net/http)
//	mux.Handle("/api/", authaction.RequireAuth(client)(apiHandler))
//
//	// Read verified claims from the request context
//	claims, ok := authaction.ClaimsFromContext(r.Context())
//
// # Framework integrations
//
// Gin middleware is available in the authaction-go-sdk/gin sub-package.
// Echo middleware is available in the authaction-go-sdk/echo sub-package.
package authaction
