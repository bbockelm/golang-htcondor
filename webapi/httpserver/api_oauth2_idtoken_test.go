package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ory/fosite"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// newRESTOAuth2Handler builds a Handler with a real fosite provider, a
// signing key and a token cache: everything createAuthenticatedContext
// needs to turn a bearer into a cedar SecurityConfig, and nothing that
// requires a live schedd.
func newRESTOAuth2Handler(t *testing.T) *Handler {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	provider, err := NewOAuth2Provider(OAuth2ProviderOptions{
		DB:                   newTestDB(t, filepath.Join(t.TempDir(), "rest-oauth2.db")),
		Issuer:               "https://api.example.com",
		AccessTokenLifespan:  time.Hour,
		RefreshTokenLifespan: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewOAuth2Provider: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	return &Handler{
		oauth2Provider: provider,
		logger:         logger,
		tokenCache:     NewTokenCache(),
		signingKeyPath: writeSigningKey(t),
		trustDomain:    "pool.example.com",
		uidDomain:      "example.com",
	}
}

// mintRESTAccessToken issues a real opaque access token for subject with
// the given granted scopes, the way the standard flows do, so
// introspection in createAuthenticatedContext succeeds.
func mintRESTAccessToken(t *testing.T, h *Handler, subject string, scopes []string) string {
	t.Helper()
	ctx := context.Background()
	// getTokenSession reloads the client by id, so it must exist.
	if _, err := h.oauth2Provider.GetStorage().GetDB().ExecContext(ctx,
		`INSERT OR IGNORE INTO oauth2_clients (id, client_secret, redirect_uris, grant_types, response_types, scopes, public)
		 VALUES ('vscode-client', '', '[]', '["authorization_code"]', '["code"]', '[]', 1)`); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	session := DefaultOpenIDConnectSession(subject)
	ar := fosite.NewAccessRequest(session)
	ar.Client = &fosite.DefaultClient{ID: "vscode-client"}
	for _, s := range scopes {
		ar.GrantScope(s)
	}
	setStandardTokenExpiries(ctx, h.oauth2Provider.config, session)
	strategy := h.oauth2Provider.GetStrategy()
	tok, _, err := strategy.GenerateAccessToken(ctx, ar)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	if err := h.oauth2Provider.GetStorage().CreateAccessTokenSession(ctx,
		strategy.AccessTokenSignature(ctx, tok), ar); err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}
	return tok
}

// TestOpaqueOAuth2TokenBecomesCondorIDToken pins the credential the REST
// surface hands to cedar when the caller authenticated with an OAuth2
// access token this server issued.
//
// The access token is opaque: it carries no signature the schedd knows,
// and ConfigureSecurityForTokenWithCacheAndFallback strips the FS
// fallback, so forwarding it verbatim offers the schedd a credential it
// can only reject. Every REST endpoint that dials the schedd therefore
// failed for precisely the callers who HAD authenticated correctly,
// while /api/v1/whoami -- which reads the token cache and never dials --
// answered with their name. What must reach cedar is a minted HTCondor
// IDTOKEN, exactly as the MCP data path already does.
func TestOpaqueOAuth2TokenBecomesCondorIDToken(t *testing.T) {
	h := newRESTOAuth2Handler(t)
	opaque := mintRESTAccessToken(t, h, "alice", []string{"condor:/READ", "condor:/WRITE"})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs", nil)
	req.Header.Set("Authorization", "Bearer "+opaque)

	ctx, err := h.createAuthenticatedContext(req)
	if err != nil {
		t.Fatalf("createAuthenticatedContext: %v", err)
	}

	secConfig, ok := htcondor.GetSecurityConfigFromContext(ctx)
	if !ok {
		t.Fatal("no SecurityConfig in context")
	}
	if secConfig.Token == "" {
		t.Fatal("SecurityConfig carries no token")
	}
	if secConfig.Token == opaque {
		t.Fatal("SecurityConfig carries the opaque access token verbatim; " +
			"the schedd cannot verify it, so every schedd-backed endpoint 401s")
	}

	// It must be a HTCondor IDTOKEN this pool's schedd will accept:
	// signed, issued by our trust domain, for the qualified user.
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).
		ParseUnverified(secConfig.Token, claims); err != nil {
		t.Fatalf("minted credential is not a JWT: %v", err)
	}
	if got := claims["iss"]; got != "pool.example.com" {
		t.Errorf("iss = %v, want pool.example.com", got)
	}
	if got := claims["sub"]; got != "alice@example.com" {
		t.Errorf("sub = %v, want alice@example.com (UID_DOMAIN qualified)", got)
	}

	// The grant's scopes must bound it. condor:/WRITE is what
	// GET_JOB_CONNECT_INFO (ssh-to-job) requires at the schedd.
	authz, _ := claims["scope"].(string)
	if authz == "" {
		t.Fatalf("minted token carries no limit_authz scope claim; claims=%v", claims)
	}
	if !strings.Contains(authz, "WRITE") {
		t.Errorf("scope = %q, want it to carry WRITE for a condor:/WRITE grant", authz)
	}
}

// TestOpaqueOAuth2TokenHonoursUsernameClaim pins that the REST surface
// reads the operator's configured username claim, as /mcp/message does.
// Reading GetSubject() directly meant one grant authenticated as two
// different people depending on which door it came through.
func TestOpaqueOAuth2TokenHonoursUsernameClaim(t *testing.T) {
	h := newRESTOAuth2Handler(t)
	h.oauth2UsernameClaim = "preferred_username"
	opaque := mintRESTAccessToken(t, h, "alice", []string{"condor:/READ"})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs", nil)
	req.Header.Set("Authorization", "Bearer "+opaque)

	ctx, err := h.createAuthenticatedContext(req)
	if err != nil {
		t.Fatalf("createAuthenticatedContext: %v", err)
	}
	secConfig, ok := htcondor.GetSecurityConfigFromContext(ctx)
	if !ok {
		t.Fatal("no SecurityConfig in context")
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).
		ParseUnverified(secConfig.Token, claims); err != nil {
		t.Fatalf("minted credential is not a JWT: %v", err)
	}
	// No preferred_username on the session, so extractUsernameFromToken
	// falls back to the subject -- the point is that it went through the
	// claim-aware path at all rather than reading GetSubject() blind.
	if got := claims["sub"]; got != "alice@example.com" {
		t.Errorf("sub = %v, want alice@example.com", got)
	}
}

// TestSigningKeyPathDirectoryIsExplained: HTTP_API_SIGNING_KEY names
// the key FILE, and every minting path splits it into a directory and
// a kid. Pointed at the passwords.d directory instead, the split makes
// a key name that is itself a directory, and the JWT library complains
// about a path the operator never typed. Two integration tests were
// configured that way and only failed once the REST surface started
// minting, so the mistake is one people actually make.
func TestSigningKeyPathDirectoryIsExplained(t *testing.T) {
	h := newRESTOAuth2Handler(t)
	// Point at the directory holding the key rather than the key.
	h.signingKeyPath = filepath.Dir(h.signingKeyPath)

	_, err := h.generateHTCondorTokenWithScopes("alice", []string{"condor:/READ"})
	if err == nil {
		t.Fatal("minting accepted a signing key path that names a directory")
	}
	if !strings.Contains(err.Error(), "is a directory") ||
		!strings.Contains(err.Error(), "must name the key file") {
		t.Errorf("error %q does not say the setting names a directory and what to use instead", err)
	}
}
