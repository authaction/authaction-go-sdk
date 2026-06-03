package authaction

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// GinMiddleware returns a Gin middleware handler that validates the Bearer JWT
// and stores the decoded token in the Gin context under "authaction.user".
//
// Example:
//
//	r := gin.Default()
//	r.Use(verifier.GinMiddleware())
//	r.GET("/protected", func(c *gin.Context) {
//	    token, _ := authaction.TokenFromGin(c)
//	    c.JSON(200, gin.H{"sub": token.Subject()})
//	})
func (v *Verifier) GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := v.VerifyRequest(c.Request)
		if err != nil || token == nil {
			msg := "Missing Bearer token"
			if err != nil {
				msg = err.Error()
			}
			c.Header("WWW-Authenticate", "Bearer")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized", "message": msg})
			return
		}
		c.Set(string(UserContextKey), token)
		c.Next()
	}
}

// TokenFromGin retrieves the verified JWT stored by GinMiddleware.
func TokenFromGin(c *gin.Context) (interface{}, bool) {
	return c.Get(string(UserContextKey))
}
