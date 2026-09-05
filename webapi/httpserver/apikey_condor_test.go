package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// condorTestHandler is authTestHandler plus the signing material an
// IDTOKEN needs.
func condorTestHandler(t *testing.T) *Handler {
	t.Helper()
	h := authTestHandler(t)
	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "POOL")
	// The on-disk format is the raw key XOR 0xdeadbeef; the minter
	// unscrambles it, so scramble a known key here.
	raw := []byte("this-is-a-test-signing-key-0123456789")
	deadbeef := []byte{0xde, 0xad, 0xbe, 0xef}
	scrambled := make([]byte, len(raw))
	for i := range raw {
		scrambled[i] = raw[i] ^ deadbeef[i%len(deadbeef)]
	}
	if err := os.WriteFile(keyPath, scrambled, 0o600); err != nil {
		t.Fatalf("write signing key: %v", err)
	}
	h.signingKeyPath = keyPath
	h.trustDomain = "test.example.org"
	return h
}

// tokenScope pulls the `scope` claim out of a minted IDTOKEN.
func tokenScope(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	scope, _ := claims["scope"].(string)
	return scope
}

// tokenFromContext digs the minted credential back out of the request
// context so a test can inspect what the schedd would be handed.
func tokenFromContext(ctx context.Context, t *testing.T) string {
	t.Helper()
	cfg, ok := htcondor.GetSecurityConfigFromContext(ctx)
	if !ok {
		t.Fatal("no SecurityConfig on the context")
	}
	return cfg.Token
}

// TestAPIKeyReadScopeCannotWrite is the property this feature exists
// for: a read-only key's credential must be unable to write, enforced
// by the token itself rather than by a check in this process.
func TestAPIKeyReadScopeCannotWrite(t *testing.T) {
	h := condorTestHandler(t)
	row := &apiKeyRow{KeyID: "k-read", Creator: "alice@test.example.org", Scopes: []string{"condor:/READ"}}

	ctx, err := h.apiKeySecurityContext(context.Background(), row)
	if err != nil {
		t.Fatalf("apiKeySecurityContext: %v", err)
	}
	if ctx == nil {
		t.Fatal("a condor:/READ key should get a credential")
	}

	scope := tokenScope(t, tokenFromContext(ctx, t))
	if !strings.Contains(scope, "condor:/READ") {
		t.Errorf("scope claim %q is missing condor:/READ", scope)
	}
	if strings.Contains(scope, "condor:/WRITE") {
		t.Errorf("scope claim %q grants WRITE to a read-only key", scope)
	}
}

// TestAPIKeyWriteScopeCarriesWrite is the counterpart: the limit is a
// real mapping, not a hardcoded READ.
func TestAPIKeyWriteScopeCarriesWrite(t *testing.T) {
	h := condorTestHandler(t)
	row := &apiKeyRow{KeyID: "k-rw", Creator: "alice@test.example.org",
		Scopes: []string{"condor:/READ", "condor:/WRITE"}}

	ctx, err := h.apiKeySecurityContext(context.Background(), row)
	if err != nil {
		t.Fatalf("apiKeySecurityContext: %v", err)
	}
	scope := tokenScope(t, tokenFromContext(ctx, t))
	for _, want := range []string{"condor:/READ", "condor:/WRITE"} {
		if !strings.Contains(scope, want) {
			t.Errorf("scope claim %q is missing %s", scope, want)
		}
	}
}

// TestAPIKeyMetricsOnlyGetsNoCredential pins the property the original
// design had and this change must not erode: a metrics key still cannot
// reach the schedd at all.
func TestAPIKeyMetricsOnlyGetsNoCredential(t *testing.T) {
	h := condorTestHandler(t)
	row := &apiKeyRow{KeyID: "k-metrics", Creator: "alice@test.example.org", Scopes: []string{"metrics"}}

	ctx, err := h.apiKeySecurityContext(context.Background(), row)
	if err != nil {
		t.Fatalf("apiKeySecurityContext: %v", err)
	}
	if ctx != nil {
		t.Error("a metrics-only key must not receive a schedd credential")
	}
}

// TestAPIKeyUnknownCondorScopeRefuses checks the fail-closed direction:
// an unrecognized condor:/* scope must not silently become an
// unrestricted token.
func TestAPIKeyUnknownCondorScopeRefuses(t *testing.T) {
	h := condorTestHandler(t)
	row := &apiKeyRow{KeyID: "k-bogus", Creator: "alice@test.example.org",
		Scopes: []string{"condor:/NOT_A_REAL_LEVEL"}}

	ctx, err := h.apiKeySecurityContext(context.Background(), row)
	if err == nil {
		t.Fatalf("expected refusal, got ctx=%v", ctx != nil)
	}
	if ctx != nil {
		t.Error("no credential should be returned alongside an error")
	}
}

// TestAPIKeySessionTagsAreDistinct guards the cedar session-cache
// keying: two keys must not share a cached session, or one key could
// resume a session another authenticated and inherit its authorizations.
func TestAPIKeySessionTagsAreDistinct(t *testing.T) {
	h := condorTestHandler(t)
	mk := func(id string) string {
		row := &apiKeyRow{KeyID: id, Creator: "alice@test.example.org", Scopes: []string{"condor:/READ"}}
		ctx, err := h.apiKeySecurityContext(context.Background(), row)
		if err != nil {
			t.Fatalf("apiKeySecurityContext(%s): %v", id, err)
		}
		cfg, ok := htcondor.GetSecurityConfigFromContext(ctx)
		if !ok {
			t.Fatalf("no SecurityConfig for %s", id)
		}
		return cfg.SecurityTag
	}
	a, b := mk("key-one"), mk("key-two")
	if a == "" {
		t.Error("SecurityTag must not be empty; an empty tag shares one cache entry across callers")
	}
	if a == b {
		t.Errorf("two keys share SecurityTag %q", a)
	}
}

// TestAPIKeyMissingSigningKeyRefuses covers the misconfigured server:
// a condor-scoped key must fail loudly rather than degrade to a
// credential-less context that reads as "no schedd auth".
func TestAPIKeyMissingSigningKeyRefuses(t *testing.T) {
	h := condorTestHandler(t)
	h.signingKeyPath = ""
	row := &apiKeyRow{KeyID: "k-read", Creator: "alice@test.example.org", Scopes: []string{"condor:/READ"}}

	if _, err := h.apiKeySecurityContext(context.Background(), row); err == nil {
		t.Error("expected an error when no signing key is configured")
	}
}
