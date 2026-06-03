package authaction_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMiddleware_ValidToken_CallsNext(t *testing.T) {
	env := setup(t)
	defer env.server.Close()

	tokenStr := env.makeToken(t, "user-1", time.Now().Add(time.Hour))
	called := false
	handler := env.verifier.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("handler was not called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("got status %d, want 200", rec.Code)
	}
}

func TestMiddleware_MissingToken_Returns401(t *testing.T) {
	env := setup(t)
	defer env.server.Close()

	handler := env.verifier.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want 401", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "Unauthorized") {
		t.Errorf("body missing 'Unauthorized': %s", body)
	}
}

func TestMiddleware_ExpiredToken_Returns401(t *testing.T) {
	env := setup(t)
	defer env.server.Close()

	tokenStr := env.makeToken(t, "user-1", time.Now().Add(-time.Hour))
	handler := env.verifier.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want 401", rec.Code)
	}
}

func TestMiddleware_TokenStoredInContext(t *testing.T) {
	env := setup(t)
	defer env.server.Close()

	tokenStr := env.makeToken(t, "user-42", time.Now().Add(time.Hour))
	var sub string
	handler := env.verifier.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tok, ok := authaction.TokenFromContext(r.Context()); ok {
			sub = tok.Subject()
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if sub != "user-42" {
		t.Errorf("got sub %q, want 'user-42'", sub)
	}
}
