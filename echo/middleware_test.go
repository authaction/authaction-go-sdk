package authactionecho_test

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
	authactionecho "github.com/authaction/authaction-go-sdk/echo"
	"github.com/labstack/echo/v4"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

// ── Package-level test fixtures ───────────────────────────────────────────────

var (
	privKey *rsa.PrivateKey
	kid     = "echo-test-key"
)

const (
	domain   = "acme.eu.authaction.com"
	audience = "https://api.example.com"
)

func TestMain(m *testing.M) {
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
		"sub": "echo-user",
		"iss": "https://" + domain,
		"aud": audience,
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"iat": float64(time.Now().Unix()),
	}
}

func newClient(t *testing.T, srv *httptest.Server) *authaction.Client {
	t.Helper()
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

func newEchoRequest(token string) (*http.Request, *httptest.ResponseRecorder) {
	r := httptest.NewRequest(http.MethodGet, "/api", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r, httptest.NewRecorder()
}

// ── RequireAuth ───────────────────────────────────────────────────────────────

func TestEchoRequireAuth_AllowsValidToken(t *testing.T) {
	srv := mockJWKS(&privKey.PublicKey, kid)
	defer srv.Close()
	c := newClient(t, srv)

	e := echo.New()
	e.Use(authactionecho.RequireAuth(c))
	e.GET("/api", func(ctx echo.Context) error {
		claims, _ := authactionecho.ClaimsFromContext(ctx)
		return ctx.String(http.StatusOK, claims.Sub)
	})

	tok := signJWT(t, validClaims())
	r, rr := newEchoRequest(tok)
	e.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if rr.Body.String() != "echo-user" {
		t.Errorf("body = %q, want echo-user", rr.Body.String())
	}
}

func TestEchoRequireAuth_Rejects_MissingToken(t *testing.T) {
	srv := mockJWKS(&privKey.PublicKey, kid)
	defer srv.Close()
	c := newClient(t, srv)

	e := echo.New()
	e.Use(authactionecho.RequireAuth(c))
	e.GET("/api", func(ctx echo.Context) error {
		return ctx.NoContent(http.StatusOK)
	})

	r, rr := newEchoRequest("")
	e.ServeHTTP(rr, r)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestEchoRequireAuth_Rejects_InvalidToken(t *testing.T) {
	srv := mockJWKS(&privKey.PublicKey, kid)
	defer srv.Close()
	c := newClient(t, srv)

	e := echo.New()
	e.Use(authactionecho.RequireAuth(c))
	e.GET("/api", func(ctx echo.Context) error {
		return ctx.NoContent(http.StatusOK)
	})

	r, rr := newEchoRequest("bad.token.here")
	e.ServeHTTP(rr, r)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestEchoRequireAuth_Rejects_ExpiredToken(t *testing.T) {
	srv := mockJWKS(&privKey.PublicKey, kid)
	defer srv.Close()
	c := newClient(t, srv)

	e := echo.New()
	e.Use(authactionecho.RequireAuth(c))
	e.GET("/api", func(ctx echo.Context) error {
		return ctx.NoContent(http.StatusOK)
	})

	claims := validClaims()
	claims["exp"] = float64(time.Now().Add(-time.Hour).Unix())
	tok := signJWT(t, claims)

	r, rr := newEchoRequest(tok)
	e.ServeHTTP(rr, r)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

// ── OptionalAuth ──────────────────────────────────────────────────────────────

func TestEchoOptionalAuth_PassesThroughWithoutToken(t *testing.T) {
	srv := mockJWKS(&privKey.PublicKey, kid)
	defer srv.Close()
	c := newClient(t, srv)

	e := echo.New()
	e.Use(authactionecho.OptionalAuth(c))
	e.GET("/public", func(ctx echo.Context) error {
		_, ok := authactionecho.ClaimsFromContext(ctx)
		if ok {
			return ctx.String(http.StatusInternalServerError, "unexpected claims")
		}
		return ctx.String(http.StatusOK, "anonymous")
	})

	r, rr := newEchoRequest("")
	e.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestEchoOptionalAuth_AttachesClaimsWhenPresent(t *testing.T) {
	srv := mockJWKS(&privKey.PublicKey, kid)
	defer srv.Close()
	c := newClient(t, srv)

	e := echo.New()
	e.Use(authactionecho.OptionalAuth(c))
	e.GET("/public", func(ctx echo.Context) error {
		claims, ok := authactionecho.ClaimsFromContext(ctx)
		if !ok {
			return ctx.String(http.StatusUnauthorized, "no claims")
		}
		return ctx.String(http.StatusOK, claims.Sub)
	})

	tok := signJWT(t, validClaims())
	r, rr := newEchoRequest(tok)
	e.ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if rr.Body.String() != "echo-user" {
		t.Errorf("body = %q, want echo-user", rr.Body.String())
	}
}

// ── ClaimsFromContext ─────────────────────────────────────────────────────────

func TestEchoClaimsFromContext_ReturnsFalseWhenAbsent(t *testing.T) {
	e := echo.New()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	ctx := e.NewContext(r, rr)

	_, ok := authactionecho.ClaimsFromContext(ctx)
	if ok {
		t.Error("expected ok=false when no claims stored")
	}
}
