# authaction-go-sdk

Go SDK for verifying AuthAction JWT access tokens in backend APIs.

Handles JWKS fetching, key caching, key rotation, and provides drop-in middleware for `net/http`, Gin, and Echo.

[![CI](https://github.com/authaction/authaction-go-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/authaction/authaction-go-sdk/actions/workflows/ci.yml)

---

## Installation

```sh
go get github.com/authaction/authaction-go-sdk
```

Framework integrations are separate import paths within the same module:

```sh
# Gin
go get github.com/authaction/authaction-go-sdk/gin

# Echo
go get github.com/authaction/authaction-go-sdk/echo
```

---

## Quick start

```go
package main

import (
    "log"
    "net/http"

    authaction "github.com/authaction/authaction-go-sdk"
)

func main() {
    client, err := authaction.New(authaction.Config{
        Domain:   "acme.eu.authaction.com",
        Audience: "https://api.example.com",
    })
    if err != nil {
        log.Fatal(err)
    }

    mux := http.NewServeMux()

    // All routes under /api require a valid Bearer token
    mux.Handle("/api/", authaction.RequireAuth(client)(http.HandlerFunc(apiHandler)))

    log.Fatal(http.ListenAndServe(":8080", mux))
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
    claims, _ := authaction.ClaimsFromContext(r.Context())
    w.Write([]byte("Hello, " + claims.Sub))
}
```

---

## Configuration

```go
client, err := authaction.New(authaction.Config{
    // Required: your AuthAction tenant domain
    Domain: "acme.eu.authaction.com",

    // Required: the API identifier registered in AuthAction
    Audience: "https://api.example.com",

    // Optional: how long signing keys are cached (default: 1 hour)
    JWKSCacheTTL: 30 * time.Minute,

    // Optional: custom HTTP client for JWKS fetches (e.g. with proxy)
    HTTPClient: &http.Client{Timeout: 5 * time.Second},
})
```

---

## Verifying tokens manually

```go
// Verify a raw JWT string
claims, err := client.VerifyToken(ctx, tokenString)
if err != nil {
    switch {
    case errors.Is(err, authaction.ErrTokenExpired):
        // token is structurally valid but past its expiry
    case errors.Is(err, authaction.ErrTokenInvalid):
        // bad signature, wrong issuer/audience, unsupported algorithm
    case errors.Is(err, authaction.ErrJWKSUnavailable):
        // could not reach the JWKS endpoint
    }
}

// Extract and verify from an *http.Request Authorization header
claims, err := client.VerifyRequest(ctx, r)
if errors.Is(err, authaction.ErrTokenMissing) {
    // no Bearer token present
}
```

---

## Middleware

### net/http (also works with chi, gorilla/mux)

```go
mux := http.NewServeMux()

// 401 when token is missing or invalid
mux.Handle("/api/", authaction.RequireAuth(client)(apiHandler))

// Attaches claims when present; lets unauthenticated requests through
mux.Handle("/public/", authaction.OptionalAuth(client)(publicHandler))
```

Read claims inside a handler:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    claims, ok := authaction.ClaimsFromContext(r.Context())
    if !ok {
        // no authenticated user (only possible behind OptionalAuth)
        return
    }
    fmt.Fprintf(w, "sub=%s scope=%s", claims.Sub, claims.Scope)
}
```

### Gin

```go
import (
    authaction    "github.com/authaction/authaction-go-sdk"
    authactiongin "github.com/authaction/authaction-go-sdk/gin"
)

r := gin.New()

// Apply globally
r.Use(authactiongin.RequireAuth(client))

// Or per-route group
api := r.Group("/api")
api.Use(authactiongin.RequireAuth(client))
api.GET("/me", func(c *gin.Context) {
    claims, _ := authactiongin.ClaimsFromContext(c)
    c.JSON(http.StatusOK, gin.H{"sub": claims.Sub})
})

// Optionally authenticated
r.GET("/feed", authactiongin.OptionalAuth(client), func(c *gin.Context) {
    claims, ok := authactiongin.ClaimsFromContext(c)
    // ok is false for anonymous requests
})
```

### Echo

```go
import (
    authaction     "github.com/authaction/authaction-go-sdk"
    authactionecho "github.com/authaction/authaction-go-sdk/echo"
)

e := echo.New()

// Apply globally
e.Use(authactionecho.RequireAuth(client))

// Or per-route group
api := e.Group("/api")
api.Use(authactionecho.RequireAuth(client))
api.GET("/me", func(c echo.Context) error {
    claims, _ := authactionecho.ClaimsFromContext(c)
    return c.JSON(http.StatusOK, map[string]string{"sub": claims.Sub})
})
```

---

## Token payload

`VerifyToken` and `VerifyRequest` return a `*TokenPayload`:

```go
type TokenPayload struct {
    Sub   string                 // subject (user or M2M client ID)
    Iss   string                 // issuer
    Aud   []string               // audience
    Exp   int64                  // expiry (Unix seconds)
    Iat   int64                  // issued-at (Unix seconds)
    Scope string                 // space-separated OAuth2 scopes
    Extra map[string]interface{} // any additional claims
}
```

Check scopes:

```go
if !claims.HasScope("read:reports") {
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}
```

---

## Errors

| Sentinel | When |
|----------|------|
| `ErrTokenMissing` | No `Authorization: Bearer …` header |
| `ErrTokenInvalid` | Bad signature, wrong issuer/audience, unsupported algorithm |
| `ErrTokenExpired` | Token structure is valid but `exp` is in the past |
| `ErrJWKSUnavailable` | JWKS endpoint returned an error or non-200 status |

All errors wrap the sentinel so `errors.Is` works through the chain:

```go
if errors.Is(err, authaction.ErrTokenInvalid) { ... }
```

---

## JWKS caching and key rotation

The SDK fetches `https://{domain}/.well-known/jwks.json` on the first request and caches the signing keys for `JWKSCacheTTL` (default 1 hour).

**Key rotation** is handled automatically: if a token arrives with a `kid` not present in the cache, the SDK re-fetches the JWKS endpoint immediately (at most once per 5-minute cooldown window). If the endpoint is temporarily unreachable, the last-known keys are served as a fallback so in-flight requests continue to work.

---

## Requirements

- Go 1.22+
- AuthAction tenant with RS256-signed access tokens
