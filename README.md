# authaction-go-sdk

AuthAction JWT verification SDK for Go. Works with **net/http**, **Gin**, and any other Go HTTP framework.

## Installation

```bash
go get github.com/authaction/authaction-go-sdk
```

## Quick start

```go
import "github.com/authaction/authaction-go-sdk"

verifier, err := authaction.New("myapp.eu.authaction.com", "https://api.myapp.com")
if err != nil { log.Fatal(err) }

// Verify a raw token
token, err := verifier.VerifyToken(tokenStr)

// Verify from a request header (nil, nil on missing)
token, err := verifier.VerifyRequest(r)
fmt.Println(token.Subject())
```

## net/http middleware

```go
mux := http.NewServeMux()
mux.Handle("/api/", verifier.Middleware()(apiHandler))
http.ListenAndServe(":8080", mux)

// In handlers — read the token from context
token, _ := authaction.TokenFromContext(r.Context())
fmt.Println(token.Subject())
```

## Gin

```go
r := gin.Default()
r.Use(verifier.GinMiddleware())

r.GET("/protected", func(c *gin.Context) {
    tok, _ := authaction.TokenFromGin(c)
    c.JSON(200, gin.H{"sub": tok.(jwt.Token).Subject()})
})
```

## Error types

```go
switch err.(type) {
case *authaction.TokenExpiredError:  // exp in the past
case *authaction.TokenInvalidError:  // bad signature / issuer / audience
}
```

## Environment variables

```bash
AUTHACTION_DOMAIN=your-tenant.eu.authaction.com
AUTHACTION_AUDIENCE=https://api.your-app.com
```

## License

MIT
