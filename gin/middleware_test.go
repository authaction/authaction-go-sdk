package authactiongin_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	authaction "github.com/authaction/authaction-go-sdk"
	authactiongin "github.com/authaction/authaction-go-sdk/gin"
	"github.com/gin-gonic/gin"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

// ── Package-level test fixtures ───────────────────────────────────────────────

var (
	privKey *rsa.PrivateKey
	kid     = "gin-test-key"
)

const (
	domain   = "acme.eu.authaction.com"
	audience = "https://api.example.com"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	var err error
	privKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

// ── helpers ───────────────────────────────────────────────────────────────────

func mockJWKS(pub *rsa.PublicKey, kid string) *httptest.Server {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(new(big.Int).SetInt64(int64(pub.E)).Bytes())
	body, _ := json.Marshal(map[string]interface{}{
		"keys": []map[string]interface{}{
			{"kty": "RSA", "kid": kid, "n": n, "e": e, "use": "sig", "alg": "RS256"},
		},
	})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}

func signJWT(t *testing.T, claims jwtlib.MapClaims) string {
	t.Helper()
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(privKey)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return s
}

func validClaims() jwtlib.MapClaims {
	return jwtlib.MapClaims{
		"sub": "gin-user",
		"iss": "https://" + domain,
		"aud": audience,
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"iat": float64(time.Now().Unix()),
	}
}

func newClient(t *testing.T, srv *httptest.Server) *authaction.Client {
	t.Helper()
	// Build a client using internal fields to point at the test JWKS server.
	// (Access via exported New() would require a real domain or DNS mocking.)
	c, err := authaction.New(authaction.Config{
		Domain:   domain,
		Audience: audience,
		HTTPClient: &http.Client{
			Transport: &fixedHostTransport{base: srv.Client().Transport, target: srv.URL},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// fixedHostTransport rewrites requests to always hit target regardless of Host.
type fixedHostTransport struct {
	base   http.RoundTripper
	target string
}

func (f *fixedHostTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.URL.Host = f.target[len("http://"):]
	r2.URL.Scheme = "http"
	return f.base.RoundTrip(r2)
}

// ── RequireAuth ───────────────────────────────────────────────────────────────

func TestGinRequireAuth_AllowsValidToken(t *testing.T) {
	srv := mockJWKS(&privKey.PublicKey, kid)
	defer srv.Close()
	c := newClient(t, srv)

	router := gin.New()
	router.GET("/api", authactiongin.RequireAuth(c), func(ctx *gin.Context) {
		claims, _ := authactiongin.ClaimsFromContext(ctx)
		ctx.String(http.StatusOK, claims.Sub)
	})

	tok := signJWT(t, validClaims())
	r := httptest.NewRequest(http.MethodGet, "/api", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if rr.Body.String() != "gin-user" {
		t.Errorf("body = %q, want gin-user", rr.Body.String())
	}
}

func TestGinRequireAuth_Rejects_MissingToken(t *testing.T) {
	srv := mockJWKS(&privKey.PublicKey, kid)
	defer srv.Close()
	c := newClient(t, srv)

	router := gin.New()
	router.GET("/api", authactiongin.RequireAuth(c), func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/api", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, r)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestGinRequireAuth_Rejects_InvalidToken(t *testing.T) {
	srv := mockJWKS(&privKey.PublicKey, kid)
	defer srv.Close()
	c := newClient(t, srv)

	router := gin.New()
	router.GET("/api", authactiongin.RequireAuth(c), func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/api", nil)
	r.Header.Set("Authorization", "Bearer bad.token.here")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, r)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestGinRequireAuth_Rejects_ExpiredToken(t *testing.T) {
	srv := mockJWKS(&privKey.PublicKey, kid)
	defer srv.Close()
	c := newClient(t, srv)

	router := gin.New()
	router.GET("/api", authactiongin.RequireAuth(c), func(ctx *gin.Context) {
		ctx.Status(http.StatusOK)
	})

	claims := validClaims()
	claims["exp"] = float64(time.Now().Add(-time.Hour).Unix())
	tok := signJWT(t, claims)

	r := httptest.NewRequest(http.MethodGet, "/api", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, r)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

// ── OptionalAuth ──────────────────────────────────────────────────────────────

func TestGinOptionalAuth_PassesThroughWithoutToken(t *testing.T) {
	srv := mockJWKS(&privKey.PublicKey, kid)
	defer srv.Close()
	c := newClient(t, srv)

	router := gin.New()
	router.GET("/public", authactiongin.OptionalAuth(c), func(ctx *gin.Context) {
		_, ok := authactiongin.ClaimsFromContext(ctx)
		if ok {
			ctx.String(http.StatusInternalServerError, "unexpected claims")
			return
		}
		ctx.String(http.StatusOK, "anonymous")
	})

	r := httptest.NewRequest(http.MethodGet, "/public", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestGinOptionalAuth_AttachesClaimsWhenPresent(t *testing.T) {
	srv := mockJWKS(&privKey.PublicKey, kid)
	defer srv.Close()
	c := newClient(t, srv)

	router := gin.New()
	router.GET("/public", authactiongin.OptionalAuth(c), func(ctx *gin.Context) {
		claims, ok := authactiongin.ClaimsFromContext(ctx)
		if !ok {
			ctx.String(http.StatusUnauthorized, "no claims")
			return
		}
		ctx.String(http.StatusOK, claims.Sub)
	})

	tok := signJWT(t, validClaims())
	r := httptest.NewRequest(http.MethodGet, "/public", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if rr.Body.String() != "gin-user" {
		t.Errorf("body = %q, want gin-user", rr.Body.String())
	}
}

// ── ClaimsFromContext ─────────────────────────────────────────────────────────

func TestGinClaimsFromContext_ReturnsFalseWhenAbsent(t *testing.T) {
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	_, ok := authactiongin.ClaimsFromContext(ctx)
	if ok {
		t.Error("expected ok=false when no claims stored")
	}
}
