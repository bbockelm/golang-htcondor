package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/apikey"
	"github.com/bbockelm/golang-htcondor/webapi/mcpserver"
)

// credTestKey writes a scrambled pool signing key and returns its path.
func credTestKey(t *testing.T) string {
	t.Helper()
	raw := []byte("credential-session-test-signing-key")
	deadbeef := []byte{0xde, 0xad, 0xbe, 0xef}
	scrambled := make([]byte, len(raw))
	for i := range raw {
		scrambled[i] = raw[i] ^ deadbeef[i%len(deadbeef)]
	}
	keyPath := filepath.Join(t.TempDir(), "POOL")
	if err := os.WriteFile(keyPath, scrambled, 0o600); err != nil {
		t.Fatalf("write signing key: %v", err)
	}
	return keyPath
}

// credSessTestHandler is a Handler that can mint, with the per-credential
// session caches NewHandler installs.
func credSessTestHandler(t *testing.T) *Handler {
	t.Helper()
	return &Handler{
		logger:             testLogger(t),
		signingKeyPath:     credTestKey(t),
		trustDomain:        "test.htcondor.org",
		uidDomain:          "test.htcondor.org",
		tokenCache:         NewTokenCache(),
		credentialSessions: newTokenCache(""),
	}
}

// credTestSecConfig returns the security config ctx carries and checks that
// it uses a private session cache -- never cedar's global one -- under a
// non-empty tag.
func credTestSecConfig(ctx context.Context, t *testing.T, label string) security.SecurityConfig {
	t.Helper()
	cfg, ok := htcondor.GetSecurityConfigFromContext(ctx)
	if !ok {
		t.Fatalf("%s: no security config attached", label)
	}
	if cfg.SessionCache == nil || cfg.SessionCache == security.GetSessionCache() {
		t.Fatalf("%s: uses cedar's global session cache", label)
	}
	if cfg.SecurityTag == "" {
		t.Fatalf("%s: empty session tag", label)
	}
	return cfg
}

// credTestDistinct fails unless a and b differ in both tag and cache.
func credTestDistinct(t *testing.T, what string, a, b security.SecurityConfig) {
	t.Helper()
	if a.SecurityTag == b.SecurityTag {
		t.Errorf("%s share the session tag %q", what, a.SecurityTag)
	}
	if a.SessionCache == b.SessionCache {
		t.Errorf("%s share a session cache", what)
	}
}

// credTestSame fails unless a and b share tag and cache, so sessions are
// still resumed.
func credTestSame(t *testing.T, what string, a, b security.SecurityConfig) {
	t.Helper()
	if a.SecurityTag != b.SecurityTag || a.SessionCache != b.SessionCache {
		t.Errorf("%s do not share a session tag and cache; nothing would be resumed", what)
	}
}

// TestCondorCredentialSessionsKeyedByGrant covers the MCP OAuth2 path and
// the SSH gateway, which share withCondorCredential. Tokens are minted per
// call, so the tag must come from the grant: a READ-only grant must not land
// on the session a READ+WRITE grant of the same user negotiated, since the
// schedd bounds a session by the token that negotiated it.
func TestCondorCredentialSessionsKeyedByGrant(t *testing.T) {
	h := credSessTestHandler(t)
	ctx := context.Background()

	mcp := func(user string, scopes ...string) security.SecurityConfig {
		c, err := h.withCondorCredential(ctx, user, scopes)
		if err != nil {
			t.Fatalf("withCondorCredential(%s, %v): %v", user, scopes, err)
		}
		return credTestSecConfig(c, t, "mcp "+user)
	}
	ssh := func(user string, scopes ...string) security.SecurityConfig {
		c, err := h.sshGatewayCredential(ctx, user, scopes)
		if err != nil {
			t.Fatalf("sshGatewayCredential(%s, %v): %v", user, scopes, err)
		}
		return credTestSecConfig(c, t, "ssh "+user)
	}

	read := mcp("alice", "condor:/READ")
	readWrite := mcp("alice", "condor:/READ", "condor:/WRITE")
	credTestDistinct(t, "alice's READ and READ+WRITE grants", read, readWrite)
	credTestDistinct(t, "alice and bob", readWrite, mcp("bob", "condor:/READ", "condor:/WRITE"))
	credTestSame(t, "two requests of one grant", readWrite, mcp("alice", "condor:/WRITE", "condor:/READ"))

	sshRW := ssh("alice", sshGatewayScopes...)
	credTestDistinct(t, "alice's SSH READ-only and READ+WRITE credentials", ssh("alice", "condor:/READ"), sshRW)
	credTestSame(t, "two SSH channels of one grant", sshRW, ssh("alice", sshGatewayScopes...))
	if sshRW.SecurityTag == "alice" || strings.Contains(sshRW.SecurityTag, "alice") {
		t.Errorf("SSH gateway tag %q is the bare username", sshRW.SecurityTag)
	}
}

// TestForwardedTokenSessionsArePrivate covers the MCP forwarded-token
// branch through mcpAuthContext: the tag is the bearer's digest, so tokens
// with different authorization limits differ, and the cache is private.
func TestForwardedTokenSessionsArePrivate(t *testing.T) {
	const trustDomain = "flock.example.org"
	// With a signing key, as a deployment serving both MCP branches has.
	s := newMCPServer(t, credTestKey(t), trustDomain)
	// NewHandler's wiring: a keyspace of its own, apart from bearers and
	// session-cookie users.
	if s.credentialSessions == nil || s.credentialSessions == s.tokenCache || s.credentialSessions == s.cookieSessionCaches {
		t.Fatal("credentialSessions is not a TokenCache of its own")
	}

	auth := func(token string) security.SecurityConfig {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", mcpserver.AcceptHeader)
		rec := httptest.NewRecorder()
		ctx, _, ok := s.mcpAuthContext(rec, req)
		if !ok {
			t.Fatalf("forwarded token refused: %d %s", rec.Code, rec.Body.String())
		}
		return credTestSecConfig(ctx, t, "forwarded token")
	}

	readTok := scopedPoolIDToken(trustDomain, "alice", "condor:/READ")
	rwTok := scopedPoolIDToken(trustDomain, "alice", "condor:/READ condor:/WRITE")
	rw := auth(rwTok)
	credTestDistinct(t, "alice's READ and READ+WRITE tokens", auth(readTok), rw)
	credTestSame(t, "two requests with one token", rw, auth(rwTok))
}

// scopedPoolIDToken is poolIDToken with a scope claim.
func scopedPoolIDToken(issuer, subject, scope string) string {
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			panic(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]string{"alg": "HS256", "kid": "POOL"})
	claims := enc(map[string]string{"iss": issuer, "sub": subject, "scope": scope})
	return header + "." + claims + "." + base64.RawURLEncoding.EncodeToString([]byte("not-verified-here"))
}

// TestAPIKeySessionsArePrivate covers API keys through authenticateAPIKey:
// each key's sessions are in a cache of their own, so a READ key and a
// READ+WRITE key of the same creator never share one.
func TestAPIKeySessionsArePrivate(t *testing.T) {
	h := condorTestHandler(t)
	h.credentialSessions = newTokenCache("")

	mint := func(scopes ...string) string {
		minted, err := apikey.Mint()
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		if _, err := h.apiKeyStore.Insert(context.Background(),
			minted.KeyID, minted.SecretHash, "test", "alice@test.example.org", scopes, nil); err != nil {
			t.Fatalf("Insert: %v", err)
		}
		return minted.Full
	}
	auth := func(key string) security.SecurityConfig {
		ctx, err := h.authenticateAPIKey(requestWithBearer(t, key), key)
		if err != nil {
			t.Fatalf("authenticateAPIKey: %v", err)
		}
		return credTestSecConfig(ctx, t, "api key")
	}

	readKey := mint("condor:/READ")
	rwKey := mint("condor:/READ", "condor:/WRITE")
	rw := auth(rwKey)
	credTestDistinct(t, "a READ key and a READ+WRITE key", auth(readKey), rw)
	credTestSame(t, "two requests with one key", rw, auth(rwKey))
}

// TestImpersonationSessionsArePrivate covers superuser mode through
// impersonate. Its token always carries superuserAuthz, so the tag keeps
// naming identity and target; what changes is that the cache is private.
func TestImpersonationSessionsArePrivate(t *testing.T) {
	h := superuserTestHandler(t, []string{"condor@example.org"})
	h.signingKeyPath = credTestKey(t)
	h.superuserArmed = newSuperuserSessions(time.Hour)
	h.credentialSessions = newTokenCache("")

	imp := func(target string) security.SecurityConfig {
		ctx, _, err := h.impersonate(context.Background(), armedSession{identity: "condor@example.org"}, "bob", target)
		if err != nil {
			t.Fatalf("impersonate: %v", err)
		}
		return credTestSecConfig(ctx, t, "impersonation")
	}
	alice := imp("alice")
	credTestDistinct(t, "impersonations of alice and carol", alice, imp("carol"))
	credTestSame(t, "two impersonations of alice", alice, imp("alice"))
}

// TestUserHeaderSessionsArePrivate covers user-header mode through
// createAuthenticatedContext: the cache is private to what the token was
// minted for, not cedar's global one.
func TestUserHeaderSessionsArePrivate(t *testing.T) {
	h := taggingHandler(t)
	h.credentialSessions = newTokenCache("")

	auth := func(user string) security.SecurityConfig {
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/jobs", nil)
		r.Header.Set("X-Test-User", user)
		ctx, err := h.createAuthenticatedContext(r)
		if err != nil {
			t.Fatalf("createAuthenticatedContext: %v", err)
		}
		return credTestSecConfig(ctx, t, "user header "+user)
	}
	alice := auth("alice")
	credTestDistinct(t, "alice and bob", alice, auth("bob"))
	credTestSame(t, "two requests from alice", alice, auth("alice"))
	if alice.SecurityTag == "alice" {
		t.Error("user-header tag is the bare header value")
	}
}

// TestAuthzProbeSessionsArePrivate covers the schedd-ACL oracle through
// Check: the probe's session cache comes from the handler's private caches,
// keyed by the probe token's grant, not the bare username.
func TestAuthzProbeSessionsArePrivate(t *testing.T) {
	pool := newTokenCache("")
	var minted []string
	o := &ScheddACLOracle{
		// Nothing listens here; the probe fails after building its config.
		Schedd: func() *htcondor.Schedd { return htcondor.NewSchedd("probe-test", "<127.0.0.1:1>") },
		MintToken: func(username string, _ []string) (string, error) {
			tok := scopedPoolIDToken("test.htcondor.org", username+"@test.htcondor.org", "")
			minted = append(minted, tok)
			return tok, nil
		},
		Logger:   testLogger(t),
		Sessions: pool,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = o.Check(ctx, "alice", []string{"condor:/READ"})
	_, _ = o.Check(ctx, "bob", []string{"condor:/READ"})

	if len(minted) != 2 {
		t.Fatalf("minted %d probe tokens, want 2", len(minted))
	}
	if pool.Size() != 2 {
		t.Fatalf("probe session caches = %d, want one per user (2)", pool.Size())
	}
	aliceTag := mintedCredentialSessionTag("authz-probe", minted[0])
	if _, ok := pool.Get("session:" + aliceTag); !ok {
		t.Error("alice's probe did not use the cache for its grant's tag")
	}
	if _, ok := pool.Get("session:authz-probe:alice"); ok {
		t.Error("probe cache keyed by the bare username")
	}
	if aliceTag == mintedCredentialSessionTag("user", minted[0]) {
		t.Error("probe and data-path tags coincide for the same token")
	}
}

func TestMintedCredentialSessionTag(t *testing.T) {
	const iss = "test.htcondor.org"
	tag := func(kind, sub, scope string) string {
		return mintedCredentialSessionTag(kind, scopedPoolIDToken(iss, sub, scope))
	}
	if tag("user", "alice", "condor:/READ condor:/WRITE") != tag("user", "alice", "condor:/WRITE condor:/READ") {
		t.Error("scope order changes the tag")
	}
	if tag("user", "alice", "condor:/READ") == tag("user", "alice", "condor:/READ condor:/WRITE") {
		t.Error("READ and READ+WRITE share a tag")
	}
	if tag("user", "alice", "") == tag("user", "alice", "condor:/READ") {
		t.Error("an unlimited token and a READ token share a tag")
	}
	if tag("user", "alice", "condor:/READ") == tag("user", "bob", "condor:/READ") {
		t.Error("two users share a tag")
	}
	if tag("user", "alice", "") == tag("rest", "alice", "") {
		t.Error("two kinds share a tag")
	}
	// Per-request claims (jti, iat) do not change it.
	a, err := generateMCPAccessJWT(filepath.Dir(credTestKey(t)), "POOL", "alice@x", iss, 1, 2, []string{"READ"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := generateMCPAccessJWT(filepath.Dir(credTestKey(t)), "POOL", "alice@x", iss, 3, 4, []string{"READ"})
	if err != nil {
		t.Fatal(err)
	}
	if mintedCredentialSessionTag("user", a) != mintedCredentialSessionTag("user", b) {
		t.Error("two tokens minted for one grant get different tags")
	}
	if mintedCredentialSessionTag("user", "opaque") == mintedCredentialSessionTag("user", "opaque2") {
		t.Error("unreadable tokens share a tag")
	}
}
