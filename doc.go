// Package authaction provides JWT verification for AuthAction access tokens.
//
// # Installation
//
//	go get github.com/authaction/authaction-go-sdk
//
// # Basic usage
//
//	client, err := authaction.New(authaction.Config{
//	    Domain:   "your-tenant.eu.authaction.com",
//	    Audience: "https://api.your-app.com",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	payload, err := client.VerifyToken(ctx, tokenString)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(payload.Sub)
//
// # net/http middleware
//
//	mux := http.NewServeMux()
//	mux.Handle("/api/", client.Middleware()(apiHandler))
//	http.ListenAndServe(":8080", mux)
//
//	// Read token in handlers
//	func apiHandler(w http.ResponseWriter, r *http.Request) {
//	    payload, _ := authaction.TokenFromContext(r.Context())
//	    fmt.Fprintln(w, payload.Sub)
//	}
//
// # Gin middleware
//
//	r := gin.Default()
//	r.Use(authaction.GinMiddleware(client))
//
//	r.GET("/protected", func(c *gin.Context) {
//	    payload, _ := authaction.TokenFromGin(c)
//	    c.JSON(200, gin.H{"sub": payload.Sub})
//	})
//
// # Echo middleware
//
//	e := echo.New()
//	e.Use(authaction.EchoMiddleware(client))
//
//	e.GET("/protected", func(c echo.Context) error {
//	    payload, _ := authaction.TokenFromEcho(c)
//	    return c.JSON(200, map[string]string{"sub": payload.Sub})
//	})
//
// # Error handling
//
//	payload, err := client.VerifyToken(ctx, tokenString)
//	switch {
//	case errors.Is(err, authaction.ErrTokenExpired):
//	    // token expired
//	case errors.Is(err, authaction.ErrTokenMissing):
//	    // no token in request
//	case errors.Is(err, authaction.ErrTokenInvalid):
//	    // bad signature, issuer, or audience
//	}
package authaction
