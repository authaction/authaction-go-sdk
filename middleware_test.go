package authaction

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// sentinel handler that writes 200 + the subject from context
func okHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok {
			w.WriteHeader(http.StatusNoContent) // 204 = no claims
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(claims.Sub))
	})
}

func doRequest(t *testing.T, handler http.Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	return rr
}

// ── RequireAuth ───────────────────────────────────────────────────────────────

func TestRequireAuth_AllowsValidToken(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)
	tok := makeJWT(t, validClaims(testDomain, testAudience))

	rr := doRequest(t, RequireAuth(c)(okHandler(t)), tok)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if rr.Body.String() != "user-123" {
		t.Errorf("body = %q, want %q", rr.Body.String(), "user-123")
	}
}

func TestRequireAuth_Rejects_MissingToken(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	rr := doRequest(t, RequireAuth(c)(okHandler(t)), "")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	assertJSONError(t, rr, "Missing Bearer token")
}

func TestRequireAuth_Rejects_InvalidToken(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	rr := doRequest(t, RequireAuth(c)(okHandler(t)), "totally.invalid.token")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	assertJSONError(t, rr, "Invalid token")
}

func TestRequireAuth_Rejects_ExpiredToken(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	claims := validClaims(testDomain, testAudience)
	claims["exp"] = float64(0) // epoch — definitely expired
	tok := makeJWT(t, claims)

	rr := doRequest(t, RequireAuth(c)(okHandler(t)), tok)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	assertJSONError(t, rr, "Token has expired")
}

func TestRequireAuth_SetsContentTypeJSON(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	rr := doRequest(t, RequireAuth(c)(okHandler(t)), "")

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestRequireAuth_DoesNotCallNextOnFailure(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	doRequest(t, RequireAuth(c)(next), "")

	if called {
		t.Error("next handler should not be called when token is missing")
	}
}

// ── OptionalAuth ──────────────────────────────────────────────────────────────

func TestOptionalAuth_AllowsValidToken(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)
	tok := makeJWT(t, validClaims(testDomain, testAudience))

	rr := doRequest(t, OptionalAuth(c)(okHandler(t)), tok)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestOptionalAuth_PassesThroughWithoutToken(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	rr := doRequest(t, OptionalAuth(c)(okHandler(t)), "")

	if rr.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204 (no claims)", rr.Code)
	}
}

func TestOptionalAuth_Rejects_InvalidToken(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)

	// OptionalAuth still rejects a malformed token (not just missing).
	rr := doRequest(t, OptionalAuth(c)(okHandler(t)), "bad.token.here")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for invalid (non-missing) token", rr.Code)
	}
}

func TestOptionalAuth_AttachesClaimsToContext(t *testing.T) {
	srv := serveMockJWKS(t, &testPrivKey.PublicKey, testKID)
	c := newTestClient(t, srv, testDomain, testAudience)
	tok := makeJWT(t, validClaims(testDomain, testAudience))

	var gotSub string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if claims, ok := ClaimsFromContext(r.Context()); ok {
			gotSub = claims.Sub
		}
		w.WriteHeader(http.StatusOK)
	})

	doRequest(t, OptionalAuth(c)(next), tok)

	if gotSub != "user-123" {
		t.Errorf("Sub = %q, want user-123", gotSub)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func assertJSONError(t *testing.T, rr *httptest.ResponseRecorder, wantMessage string) {
	t.Helper()
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body["error"] != "Unauthorized" {
		t.Errorf(`JSON error = %q, want "Unauthorized"`, body["error"])
	}
	if body["message"] != wantMessage {
		t.Errorf("JSON message = %q, want %q", body["message"], wantMessage)
	}
}
