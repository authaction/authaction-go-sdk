package authaction

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

type jwkSet struct {
	Keys []jwkKey `json:"keys"`
}

type jwksCache struct {
	mu         sync.Mutex
	keys       map[string]*rsa.PublicKey
	fetchedAt  time.Time
	ttl        time.Duration
	url        string
	httpClient *http.Client
}

func newJWKSCache(url string, ttl time.Duration, hc *http.Client) *jwksCache {
	return &jwksCache{
		keys:       make(map[string]*rsa.PublicKey),
		ttl:        ttl,
		url:        url,
		httpClient: hc,
	}
}

// getKey returns the RSA public key for the given kid.
//
// Logic:
//  1. If the cache is stale (or empty), fetch fresh keys.
//  2. If kid is found, return it.
//  3. If kid is still unknown AND more than rotationCooldown has elapsed since
//     the last fetch, do one extra fetch to handle key rotation.
func (c *jwksCache) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stale := c.fetchedAt.IsZero() || time.Since(c.fetchedAt) >= c.ttl

	if stale {
		if err := c.fetchLocked(ctx); err != nil {
			// Serve stale key on transient fetch failure
			if key, ok := c.keys[kid]; ok {
				return key, nil
			}
			return nil, fmt.Errorf("%w: %s", ErrJWKSUnavailable, err)
		}
	}

	if key, ok := c.keys[kid]; ok {
		return key, nil
	}

	// Key not found — could be key rotation. Re-fetch if outside cooldown.
	if time.Since(c.fetchedAt) >= rotationCooldown {
		_ = c.fetchLocked(ctx) // best-effort; error checked below
		if key, ok := c.keys[kid]; ok {
			return key, nil
		}
	}

	return nil, fmt.Errorf("authaction: signing key %q not found in JWKS", kid)
}

// fetchLocked performs an HTTP GET to the JWKS URL and repopulates c.keys.
// Caller must hold c.mu.
func (c *jwksCache) fetchLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
	}

	var set jwkSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("malformed JWKS response: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue // skip encryption keys
		}
		pub, err := rsaPublicKeyFromJWK(k)
		if err != nil {
			continue // skip malformed keys
		}
		keys[k.Kid] = pub
	}

	c.keys = keys
	c.fetchedAt = time.Now()
	return nil
}

// rsaPublicKeyFromJWK converts a JWK with kty=RSA into an *rsa.PublicKey.
func rsaPublicKeyFromJWK(k jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("invalid modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("invalid exponent: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())
	return &rsa.PublicKey{N: n, E: e}, nil
}
