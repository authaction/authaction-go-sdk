// Package authactionecho provides Echo middleware for AuthAction JWT verification.
//
//	import (
//	    authaction "github.com/authaction/authaction-go-sdk"
//	    authactionecho "github.com/authaction/authaction-go-sdk/echo"
//	)
//
//	client, _ := authaction.New(authaction.Config{...})
//
//	e := echo.New()
//	e.Use(authactionecho.RequireAuth(client))
//
//	e.GET("/me", func(c echo.Context) error {
//	    claims, _ := authactionecho.ClaimsFromContext(c)
//	    return c.JSON(200, map[string]string{"sub": claims.Sub})
//	})
package authactionecho

import (
	"errors"
	"net/http"

	authaction "github.com/authaction/authaction-go-sdk"
	"github.com/labstack/echo/v4"
)

const claimsKey = "authaction_claims"

// RequireAuth returns an Echo middleware that enforces a valid Bearer token.
// On missing or invalid token it returns an HTTP 401 error.
// On success the verified claims are stored in the Echo context and retrievable
// via ClaimsFromContext.
func RequireAuth(c *authaction.Client) echo.MiddlewareFunc {
	return buildMiddleware(c, true)
}

// OptionalAuth returns an Echo middleware that attaches claims when a valid
// Bearer token is present, but allows unauthenticated requests through.
func OptionalAuth(c *authaction.Client) echo.MiddlewareFunc {
	return buildMiddleware(c, false)
}

func buildMiddleware(c *authaction.Client, required bool) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			claims, err := c.VerifyRequest(ctx.Request().Context(), ctx.Request())
			if err != nil {
				if errors.Is(err, authaction.ErrTokenMissing) && !required {
					return next(ctx)
				}
				return echo.NewHTTPError(http.StatusUnauthorized, errMessage(err))
			}
			ctx.Set(claimsKey, claims)
			return next(ctx)
		}
	}
}

// ClaimsFromContext retrieves the verified token claims stored by middleware.
// Returns (nil, false) when no claims are present.
func ClaimsFromContext(ctx echo.Context) (*authaction.TokenPayload, bool) {
	v := ctx.Get(claimsKey)
	if v == nil {
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
