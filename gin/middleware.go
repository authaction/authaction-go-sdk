// Package authactiongin provides Gin middleware for AuthAction JWT verification.
//
//	import (
//	    authaction "github.com/authaction/authaction-go-sdk"
//	    authactiongin "github.com/authaction/authaction-go-sdk/gin"
//	)
//
//	client, _ := authaction.New(authaction.Config{...})
//
//	r := gin.New()
//	r.Use(authactiongin.RequireAuth(client))
//
//	r.GET("/me", func(c *gin.Context) {
//	    claims, _ := authactiongin.ClaimsFromContext(c)
//	    c.JSON(200, gin.H{"sub": claims.Sub})
//	})
package authactiongin

import (
	"errors"
	"net/http"

	authaction "github.com/authaction/authaction-go-sdk"
	"github.com/gin-gonic/gin"
)

const claimsKey = "authaction_claims"

// RequireAuth returns a Gin middleware that enforces a valid Bearer token.
// On missing or invalid token it aborts with 401 JSON.
// On success the verified claims are stored in the Gin context under
// "authaction_claims" and retrievable via ClaimsFromContext.
func RequireAuth(c *authaction.Client) gin.HandlerFunc {
	return buildMiddleware(c, true)
}

// OptionalAuth returns a Gin middleware that attaches claims when a valid
// Bearer token is present, but allows unauthenticated requests through.
func OptionalAuth(c *authaction.Client) gin.HandlerFunc {
	return buildMiddleware(c, false)
}

func buildMiddleware(c *authaction.Client, required bool) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		claims, err := c.VerifyRequest(ctx.Request.Context(), ctx.Request)
		if err != nil {
			if errors.Is(err, authaction.ErrTokenMissing) && !required {
				ctx.Next()
				return
			}
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": errMessage(err),
			})
			return
		}
		ctx.Set(claimsKey, claims)
		ctx.Next()
	}
}

// ClaimsFromContext retrieves the verified token claims stored by middleware.
// Returns (nil, false) when no claims are present.
func ClaimsFromContext(ctx *gin.Context) (*authaction.TokenPayload, bool) {
	v, ok := ctx.Get(claimsKey)
	if !ok {
		return nil, false
	}
	claims, ok := v.(*authaction.TokenPayload)
	return claims, ok
}

func errMessage(err error) string {
	switch {
	case errors.Is(err, authaction.ErrTokenExpired):
		return "Token has expired"
	case errors.Is(err, authaction.ErrTokenMissing):
		return "Missing Bearer token"
	default:
		return "Invalid token"
	}
}
