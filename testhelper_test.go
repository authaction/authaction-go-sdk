package authaction

// testhelper_test.go — shared utilities used by all *_test.go files in this package.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Package-level RSA key pair generated once in TestMain to avoid per-test overhead.
var (
	testPrivKey *rsa.PrivateKey
	testKID     = "test-key-1"
)

func TestMain(m *testing.M) {
	var err error
	testPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate test RSA key: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// makeJWT signs a JWT with testPrivKey and testKID.
func makeJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = testKID
	signed, err := tok.SignedString(testPrivKey)
	if err != nil {
		t.Fatalf("makeJWT: %v", err)
	}
	return signed
}

// makeJWTWithKey signs a JWT with an arbitrary RSA key and kid.
func makeJWTWithKey(t *testing.T, claims jwt.MapClaims, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("makeJWTWithKey: %v", err)
	}
	return signed
}

// validClaims returns a standard valid claim set for domain/audience.
func validClaims(domain, audience string) jwt.MapClaims {
	return jwt.MapClaims{
		"sub": "user-123",
		"iss": "https://" + domain,
		"aud": audience,
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"iat": float64(time.Now().Unix()),
	}
}

// jwksResponse builds the JSON body for a mock JWKS endpoint serving pub under kid.
func jwksResponse(pub *rsa.PublicKey, kid string) []byte {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(new(big.Int).SetInt64(int64(pub.E)).Bytes())
	body, _ := json.Marshal(map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": kid,
				"n":   n,
				"e":   e,
				"use": "sig",
				"alg": "RS256",
			},
		},
	})
	return body
}

// serveMockJWKS starts an httptest.Server that serves JWKS for pub/kid.
func serveMockJWKS(t *testing.T, pub *rsa.PublicKey, kid string) *httptest.Server {
	t.Helper()
	body := jwksResponse(pub, kid)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newTestClient builds a Client pointed at the given JWKS test server URL.
func newTestClient(t *testing.T, srv *httptest.Server, domain, audience string) *Client {
	t.Helper()
	c := &Client{
		issuer:   "https://" + domain,
		audience: audience,
		jwks: newJWKSCache(
			srv.URL+"/.well-known/jwks.json",
			time.Hour,
			srv.Client(),
		),
	}
	return c
}
