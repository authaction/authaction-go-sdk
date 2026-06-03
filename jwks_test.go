package authaction

import (
	"context"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestJWKSCache_ReturnsCorrectKey(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	cache := newJWKSCache(srv.URL, time.Hour, srv.Client())

	key, err := cache.getKey(context.Background(), testKID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key.N.Cmp(testPrivKey.N) != 0 {
		t.Error("returned key modulus does not match expected public key")
	}
	if key.E != testPrivKey.PublicKey.E {
		t.Error("returned key exponent does not match expected public key")
	}
}

func TestJWKSCache_CachesAfterFirstFetch(t *testing.T) {
	var fetchCount atomic.Int32
	body := jwksResponse(&testPrivKey.PublicKey, testKID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	cache := newJWKSCache(srv.URL, time.Hour, srv.Client())

	for i := 0; i < 5; i++ {
		if _, err := cache.getKey(context.Background(), testKID); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}

	if n := fetchCount.Load(); n != 1 {
		t.Errorf("expected 1 HTTP fetch for 5 calls, got %d", n)
	}
}

func TestJWKSCache_RefetchesWhenTTLExpires(t *testing.T) {
	var fetchCount atomic.Int32
	body := jwksResponse(&testPrivKey.PublicKey, testKID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	cache := newJWKSCache(srv.URL, time.Millisecond, srv.Client())

	if _, err := cache.getKey(context.Background(), testKID); err != nil {
		t.Fatalf("first fetch: %v", err)
	}

	time.Sleep(10 * time.Millisecond) // let TTL expire

	if _, err := cache.getKey(context.Background(), testKID); err != nil {
		t.Fatalf("post-TTL fetch: %v", err)
	}

	if n := fetchCount.Load(); n < 2 {
		t.Errorf("expected ≥2 HTTP fetches after TTL expiry, got %d", n)
	}
}

func TestJWKSCache_RefetchesOnKeyRotation(t *testing.T) {
	var fetchCount atomic.Int32
	body := jwksResponse(&testPrivKey.PublicKey, testKID)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	// Long TTL — TTL path won't trigger; rotation-cooldown path will.
	cache := newJWKSCache(srv.URL, time.Hour, srv.Client())

	// Prime the cache.
	if _, err := cache.getKey(context.Background(), testKID); err != nil {
		t.Fatalf("priming fetch: %v", err)
	}

	// Wind back fetchedAt to simulate rotationCooldown having elapsed.
	cache.mu.Lock()
	cache.fetchedAt = time.Now().Add(-(rotationCooldown + time.Second))
	cache.mu.Unlock()

	// Ask for an unknown kid — should trigger a rotation re-fetch.
	_, err := cache.getKey(context.Background(), "rotated-kid")
	if err == nil {
		t.Fatal("expected error for unknown kid after rotation, got nil")
	}
	if n := fetchCount.Load(); n < 2 {
		t.Errorf("expected ≥2 HTTP fetches (rotation re-fetch), got %d", n)
	}
}

func TestJWKSCache_ServesStaleKeyOnFetchFailure(t *testing.T) {
	body := jwksResponse(&testPrivKey.PublicKey, testKID)
	var fail atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	cache := newJWKSCache(srv.URL, time.Millisecond, srv.Client())

	// Populate cache successfully.
	if _, err := cache.getKey(context.Background(), testKID); err != nil {
		t.Fatalf("initial fetch: %v", err)
	}

	// Bring JWKS endpoint down and let TTL expire.
	fail.Store(true)
	time.Sleep(10 * time.Millisecond)

	// Should serve the stale cached key rather than returning an error.
	key, err := cache.getKey(context.Background(), testKID)
	if err != nil {
		t.Fatalf("expected stale key on fetch failure, got: %v", err)
	}
	if key == nil {
		t.Error("expected non-nil stale key")
	}
}

func TestJWKSCache_ErrorWhenEndpointUnreachable(t *testing.T) {
	cache := newJWKSCache("http://127.0.0.1:0/jwks.json", time.Hour, &http.Client{Timeout: time.Second})
	_, err := cache.getKey(context.Background(), testKID)
	if err == nil {
		t.Error("expected error for unreachable JWKS endpoint, got nil")
	}
}

func TestJWKSCache_SkipsNonRSAAndEncryptionKeys(t *testing.T) {
	// JWKS with one EC key and one RSA encryption key — both should be skipped.
	ecAndEncBody := []byte(`{
		"keys": [
			{"kty":"EC","kid":"ec-key","use":"sig"},
			{"kty":"RSA","kid":"enc-key","use":"enc","n":"abc","e":"AQAB"}
		]
	}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(ecAndEncBody)
	}))
	t.Cleanup(srv.Close)

	cache := newJWKSCache(srv.URL, time.Hour, srv.Client())
	_, err := cache.getKey(context.Background(), "ec-key")
	if err == nil {
		t.Error("expected error: EC keys should be skipped")
	}
}

func TestRSAPublicKeyFromJWK_RoundTrip(t *testing.T) {
	// Convert testPrivKey.PublicKey → jwkKey → *rsa.PublicKey and compare.
	pub := &testPrivKey.PublicKey
	jwk := jwkKey{
		Kty: "RSA",
		Kid: "rt",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(new(big.Int).SetInt64(int64(pub.E)).Bytes()),
		Use: "sig",
	}

	got, err := rsaPublicKeyFromJWK(jwk)
	if err != nil {
		t.Fatalf("rsaPublicKeyFromJWK: %v", err)
	}
	if got.N.Cmp(pub.N) != 0 {
		t.Error("modulus mismatch after round-trip")
	}
	if got.E != pub.E {
		t.Error("exponent mismatch after round-trip")
	}
}

func TestRSAPublicKeyFromJWK_RejectsInvalidBase64(t *testing.T) {
	bad := jwkKey{Kty: "RSA", Kid: "x", N: "!!not-base64!!", E: "AQAB", Use: "sig"}
	if _, err := rsaPublicKeyFromJWK(bad); err == nil {
		t.Error("expected error for invalid base64 in N")
	}
}
