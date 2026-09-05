package httpserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func writeSigningKey(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 3)
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

// No signing key means no source at all, rather than a source that
// always fails. The Locator reads nil as "not configured" and stays
// quiet, which is right for a deployment that never set one up.
func TestMirrorTokenSourceAbsentWithoutAKey(t *testing.T) {
	h := &Handler{trustDomain: "example.org"}
	if h.mirrorTokenSource() != nil {
		t.Error("a handler with no signing key should offer no token source")
	}
	h = &Handler{signingKeyPath: "/tmp/POOL"}
	if h.mirrorTokenSource() != nil {
		t.Error("a handler with no trust domain should offer no token source")
	}
}

// The minted token has to be one htcondordb will accept: the daemon's
// identity, the pool's trust domain as issuer, and READ -- which is what
// its session command requires.
func TestMirrorTokenSourceMintsAReadTokenForTheDaemon(t *testing.T) {
	h := &Handler{signingKeyPath: writeSigningKey(t), trustDomain: "flock.example.org"}

	src := h.mirrorTokenSource()
	if src == nil {
		t.Fatal("no token source")
	}
	raw, err := src(context.Background())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}

	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		t.Fatalf("the minted token does not parse: %v", err)
	}
	if sub, _ := claims["sub"].(string); sub != "condor@flock.example.org" {
		t.Errorf("sub = %q, want the daemon identity in the trust domain", sub)
	}
	if iss, _ := claims["iss"].(string); iss != "flock.example.org" {
		t.Errorf("iss = %q, want the trust domain", iss)
	}
	// scope carries the authz limits; READ is what DBSession needs.
	scope, _ := claims["scope"].(string)
	if !strings.Contains(strings.ToUpper(scope), "READ") {
		t.Errorf("scope = %q, want READ", scope)
	}
}

// The operator owns the mirror's ALLOW_READ, so they can name the
// identity the token asserts.
func TestMirrorTokenSubjectIsConfigurable(t *testing.T) {
	h := &Handler{
		signingKeyPath:       writeSigningKey(t),
		trustDomain:          "flock.example.org",
		dbMirrorTokenSubject: "apdaemon@other.domain",
	}
	raw, err := h.mirrorTokenSource()(context.Background())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sub, _ := claims["sub"].(string); sub != "apdaemon@other.domain" {
		t.Errorf("sub = %q, want the configured subject", sub)
	}
}

// Short-lived on purpose: it authenticates one connection and is never
// handed out.
func TestMirrorTokenIsShortLived(t *testing.T) {
	h := &Handler{signingKeyPath: writeSigningKey(t), trustDomain: "flock.example.org"}
	raw, err := h.mirrorTokenSource()(context.Background())
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		t.Fatalf("parse: %v", err)
	}
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if lifetime := exp - iat; lifetime > 3600 {
		t.Errorf("token lifetime is %.0fs; it authenticates one connection and should be short", lifetime)
	}
}
