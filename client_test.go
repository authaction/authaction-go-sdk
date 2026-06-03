package authaction

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testDomain   = "acme.eu.authaction.com"
	testAudience = "https://api.example.com"
)

// ── New ───────────────────────────────────────────────────────────────────────

func TestNew_RequiresDomain(t *testing.T) {
	if _, err := New(Config{Audience: testAudience}); err == nil {
		t.Error("expected error when domain is empty")
	}
}

func TestNew_RequiresAudience(t *testing.T) {
	if _, err := New(Config{Domain: testDomain}); err == nil {
		t.Error("expected error when audience is empty")
	}
}

func TestNew_SetsIssuerFromDomain(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)
	if c.issuer != "https://"+testDomain {
		t.Errorf("issuer = %q, want %q", c.issuer, "https://"+testDomain)
	}
}

// ── VerifyToken ───────────────────────────────────────────────────────────────

func TestVerifyToken_ValidToken(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	tok := makeJWT(t, validClaims(testDomain, testAudience))
	payload, err := c.VerifyToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if payload.Sub != "user-123" {
		t.Errorf("Sub = %q, want %q", payload.Sub, "user-123")
	}
	if payload.Iss != "https://"+testDomain {
		t.Errorf("Iss = %q, want https://%s", payload.Iss, testDomain)
	}
}

func TestVerifyToken_ExpiredToken(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	claims := validClaims(testDomain, testAudience)
	claims["exp"] = float64(time.Now().Add(-time.Hour).Unix())
	tok := makeJWT(t, claims)

	_, err := c.VerifyToken(context.Background(), tok)
	if err != ErrTokenExpired {
		t.Errorf("err = %v, want ErrTokenExpired", err)
	}
}

func TestVerifyToken_WrongIssuer(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	claims := validClaims(testDomain, testAudience)
	claims["iss"] = "https://evil.example.com"
	tok := makeJWT(t, claims)

	if _, err := c.VerifyToken(context.Background(), tok); err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestVerifyToken_WrongAudience(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	claims := validClaims(testDomain, testAudience)
	claims["aud"] = "https://other-api.example.com"
	tok := makeJWT(t, claims)

	if _, err := c.VerifyToken(context.Background(), tok); err == nil {
		t.Fatal("expected error for wrong audience")
	}
}

func TestVerifyToken_WrongSigningKey(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tok := makeJWTWithKey(t, validClaims(testDomain, testAudience), otherKey, testKID)

	if _, err := c.VerifyToken(context.Background(), tok); err == nil {
		t.Fatal("expected error for wrong signing key")
	}
}

func TestVerifyToken_MalformedToken(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	if _, err := c.VerifyToken(context.Background(), "not.a.valid.jwt"); err == nil {
		t.Fatal("expected error for malformed token")
	}
}

func TestVerifyToken_RejectsHS256(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(validClaims(testDomain, testAudience)))
	signed, _ := tok.SignedString([]byte("secret"))

	if _, err := c.VerifyToken(context.Background(), signed); err == nil {
		t.Fatal("expected error for HS256 token — only RS256 allowed")
	}
}

func TestVerifyToken_ExtractsStandardAndExtraClaims(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	claims := validClaims(testDomain, testAudience)
	claims["scope"] = "read:data write:data"
	claims["email"] = "user@example.com"
	tok := makeJWT(t, claims)

	payload, err := c.VerifyToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if payload.Scope != "read:data write:data" {
		t.Errorf("Scope = %q", payload.Scope)
	}
	if payload.Extra["email"] != "user@example.com" {
		t.Errorf("Extra[email] = %v", payload.Extra["email"])
	}
}

func TestVerifyToken_ArrayAudience(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	claims := validClaims(testDomain, testAudience)
	claims["aud"] = []interface{}{testAudience, "https://other.example.com"}
	tok := makeJWT(t, claims)

	payload, err := c.VerifyToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if len(payload.Aud) != 2 {
		t.Errorf("len(Aud) = %d, want 2", len(payload.Aud))
	}
}

// ── VerifyRequest ─────────────────────────────────────────────────────────────

func TestVerifyRequest_ValidBearerToken(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	tok := makeJWT(t, validClaims(testDomain, testAudience))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)

	payload, err := c.VerifyRequest(context.Background(), r)
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	if payload.Sub != "user-123" {
		t.Errorf("Sub = %q", payload.Sub)
	}
}

func TestVerifyRequest_MissingHeader(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := c.VerifyRequest(context.Background(), r)
	if err != ErrTokenMissing {
		t.Errorf("err = %v, want ErrTokenMissing", err)
	}
}

func TestVerifyRequest_NonBearerScheme(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	_, err := c.VerifyRequest(context.Background(), r)
	if err != ErrTokenMissing {
		t.Errorf("err = %v, want ErrTokenMissing", err)
	}
}

func TestVerifyRequest_EmptyBearerValue(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer   ")
	_, err := c.VerifyRequest(context.Background(), r)
	if err != ErrTokenMissing {
		t.Errorf("err = %v, want ErrTokenMissing", err)
	}
}

// ── HasScope ──────────────────────────────────────────────────────────────────

func TestHasScope(t *testing.T) {
	p := &TokenPayload{Scope: "openid profile email"}

	for _, s := range []string{"openid", "profile", "email"} {
		if !p.HasScope(s) {
			t.Errorf("HasScope(%q) = false, want true", s)
		}
	}
	if p.HasScope("admin") {
		t.Error("HasScope(admin) = true, want false")
	}
}

func TestHasScope_NilPayload(t *testing.T) {
	if (*TokenPayload)(nil).HasScope("openid") {
		t.Error("nil payload HasScope should return false")
	}
}

// ── ClaimsFromContext ─────────────────────────────────────────────────────────

func TestClaimsFromContext_RoundTrip(t *testing.T) {
	want := &TokenPayload{Sub: "u1"}
	ctx := WithClaims(context.Background(), want)

	got, ok := ClaimsFromContext(ctx)
	if !ok {
		t.Fatal("ClaimsFromContext: ok = false")
	}
	if got.Sub != want.Sub {
		t.Errorf("Sub = %q, want %q", got.Sub, want.Sub)
	}
}

func TestClaimsFromContext_EmptyContext(t *testing.T) {
	if _, ok := ClaimsFromContext(context.Background()); ok {
		t.Error("ClaimsFromContext on empty context should return ok=false")
	}
}
