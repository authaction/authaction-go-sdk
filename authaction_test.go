package authaction_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/authaction/authaction-go-sdk"
)

// ── Test fixtures ─────────────────────────────────────────────────────────────

const (
	testDomain   = "acme.eu.authaction.com"
	testAudience = "https://api.acme.com"
	testIssuer   = "https://" + testDomain
)

type testEnv struct {
	privateKey *rsa.PrivateKey
	publicKey  jwk.Key
	server     *httptest.Server
	verifier   *authaction.Verifier
}

func setup(t *testing.T) *testEnv {
	t.Helper()

	// Generate RSA key pair
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubKey, err := jwk.PublicKeyOf(jwk.NewSymmetricKey())
	if err != nil {
		t.Fatalf("import public key: %v", err)
	}
	rawPub, _ := jwk.PublicRawKeyOf(priv)
	pubJWK, _ := jwk.FromRaw(rawPub)
	_ = pubJWK.Set(jwk.KeyIDKey, "test-kid")
	_ = pubJWK.Set(jwk.AlgorithmKey, jwa.RS256)
	_ = pubKey

	keySet := jwk.NewSet()
	_ = keySet.AddKey(pubJWK)

	jwksBytes, _ := json.Marshal(keySet)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))

	v, err := authaction.NewWithJWKSURIForTest(server.URL+"/.well-known/jwks.json", testIssuer, testAudience)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	return &testEnv{privateKey: priv, server: server, verifier: v}
}

func (e *testEnv) makeToken(t *testing.T, sub string, expiry time.Time) string {
	t.Helper()
	privJWK, _ := jwk.FromRaw(e.privateKey)
	_ = privJWK.Set(jwk.KeyIDKey, "test-kid")
	_ = privJWK.Set(jwk.AlgorithmKey, jwa.RS256)

	tok, _ := jwt.NewBuilder().
		Subject(sub).
		Issuer(testIssuer).
		Audience([]string{testAudience}).
		IssuedAt(time.Now()).
		Expiration(expiry).
		Build()

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privJWK))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}

// ── VerifyToken ───────────────────────────────────────────────────────────────

func TestVerifyToken_ValidToken(t *testing.T) {
	env := setup(t)
	defer env.server.Close()

	tokenStr := env.makeToken(t, "user-1", time.Now().Add(time.Hour))
	tok, err := env.verifier.VerifyToken(tokenStr)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.Subject() != "user-1" {
		t.Errorf("got sub %q, want %q", tok.Subject(), "user-1")
	}
}

func TestVerifyToken_ExpiredToken(t *testing.T) {
	env := setup(t)
	defer env.server.Close()

	tokenStr := env.makeToken(t, "user-1", time.Now().Add(-time.Hour))
	_, err := env.verifier.VerifyToken(tokenStr)

	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if _, ok := err.(*authaction.TokenExpiredError); !ok {
		t.Errorf("expected TokenExpiredError, got %T: %v", err, err)
	}
}

func TestVerifyToken_InvalidToken(t *testing.T) {
	env := setup(t)
	defer env.server.Close()

	_, err := env.verifier.VerifyToken("not.a.jwt")

	if err == nil {
		t.Fatal("expected error for malformed token")
	}
	if _, ok := err.(*authaction.TokenInvalidError); !ok {
		t.Errorf("expected TokenInvalidError, got %T: %v", err, err)
	}
}

// ── VerifyRequest ─────────────────────────────────────────────────────────────

func TestVerifyRequest_ValidBearerHeader(t *testing.T) {
	env := setup(t)
	defer env.server.Close()

	tokenStr := env.makeToken(t, "user-1", time.Now().Add(time.Hour))
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)

	tok, err := env.verifier.VerifyRequest(req)
	if err != nil || tok == nil {
		t.Fatalf("expected token, got err=%v tok=%v", err, tok)
	}
}

func TestVerifyRequest_MissingHeader_ReturnsNil(t *testing.T) {
	env := setup(t)
	defer env.server.Close()

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	tok, err := env.verifier.VerifyRequest(req)

	if err != nil || tok != nil {
		t.Errorf("expected (nil, nil), got (%v, %v)", tok, err)
	}
}

func TestVerifyRequest_NonBearerScheme_ReturnsNil(t *testing.T) {
	env := setup(t)
	defer env.server.Close()

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	tok, err := env.verifier.VerifyRequest(req)
	if err != nil || tok != nil {
		t.Errorf("expected (nil, nil), got (%v, %v)", tok, err)
	}
}

// ── TokenFromContext ──────────────────────────────────────────────────────────

func TestTokenFromContext(t *testing.T) {
	env := setup(t)
	defer env.server.Close()

	tokenStr := env.makeToken(t, "user-1", time.Now().Add(time.Hour))
	tok, _ := env.verifier.VerifyToken(tokenStr)

	ctx := context.WithValue(context.Background(), authaction.UserContextKey, tok)
	retrieved, ok := authaction.TokenFromContext(ctx)

	if !ok || retrieved == nil {
		t.Error("expected token from context")
	}
}
