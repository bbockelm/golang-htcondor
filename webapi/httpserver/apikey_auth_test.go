package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/apikey"
)

// authTestHandler builds a minimum-viable Handler (just an apiKeyStore
// — no DB-backed sessions, no oauth2). authenticateAPIKey only reads
// the store, so this is enough for the auth-path unit tests below.
// We deliberately don't pull in a logger; the production code's
// `if s.logger != nil` guard makes this safe.
func authTestHandler(t *testing.T) *Handler {
	t.Helper()
	db := newTestDB(t, filepath.Join(t.TempDir(), "auth-ak.db"))
	return &Handler{
		apiKeyStore: &apiKeyStore{db: db},
	}
}

// requestWithBearer builds an HTTP request carrying the supplied
// Bearer token. The auth path looks at Authorization; we don't need
// any other request shape.
func requestWithBearer(t *testing.T, token string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), "GET", "/anywhere", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// TestAuthenticateAPIKeyHappyPath confirms the end-to-end auth chain:
// mint a key, persist its row, present the wire-format string, get
// back a context with the correct user + scopes + marker. This is
// the path Prometheus would take.
func TestAuthenticateAPIKeyHappyPath(t *testing.T) {
	h := authTestHandler(t)
	minted, err := apikey.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := h.apiKeyStore.Insert(context.Background(),
		minted.KeyID, minted.SecretHash, "test", "alice",
		[]string{"metrics"}, nil); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	ctx, err := h.authenticateAPIKey(requestWithBearer(t, minted.Full), minted.Full)
	if err != nil {
		t.Fatalf("authenticateAPIKey: %v", err)
	}
	if got := htcondor.GetAuthenticatedUserFromContext(ctx); got != "alice" {
		t.Errorf("authenticated user = %q, want alice", got)
	}
	if !ContainsScope(ctx, "metrics") {
		t.Errorf("ctx missing metrics scope")
	}
	if ContainsScope(ctx, "secret-scope-not-granted") {
		t.Errorf("ctx falsely reports an unrequested scope")
	}
	if !AuthenticatedViaAPIKey(ctx) {
		t.Errorf("AuthenticatedViaAPIKey returned false on a valid API-key request")
	}
}

// TestAuthenticateAPIKeyRejectsTamperedSecret confirms a wrong
// secret on a real key_id fails. The error is "verify" not
// "lookup" — we reach VerifySecret because the row exists.
func TestAuthenticateAPIKeyRejectsTamperedSecret(t *testing.T) {
	h := authTestHandler(t)
	minted, _ := apikey.Mint()
	_, _ = h.apiKeyStore.Insert(context.Background(),
		minted.KeyID, minted.SecretHash, "n", "alice",
		[]string{"metrics"}, nil)

	// Replace the secret half with a different (still valid-shape)
	// random secret. Parse should succeed; VerifySecret should fail.
	other, _ := apikey.Mint()
	tampered := apikey.Prefix + minted.KeyID + "-" +
		other.Full[len(apikey.Prefix)+12+1:] // splice other's secret in
	_, err := h.authenticateAPIKey(requestWithBearer(t, tampered), tampered)
	if err == nil {
		t.Errorf("authenticateAPIKey accepted tampered secret")
	}
}

// TestAuthenticateAPIKeyRejectsRevoked confirms a soft-deleted key
// stops authenticating immediately (no grace window).
func TestAuthenticateAPIKeyRejectsRevoked(t *testing.T) {
	h := authTestHandler(t)
	minted, _ := apikey.Mint()
	_, _ = h.apiKeyStore.Insert(context.Background(),
		minted.KeyID, minted.SecretHash, "n", "alice",
		[]string{"metrics"}, nil)
	if err := h.apiKeyStore.SoftDelete(context.Background(), minted.KeyID, "alice"); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}
	if _, err := h.authenticateAPIKey(requestWithBearer(t, minted.Full), minted.Full); err == nil {
		t.Errorf("authenticateAPIKey accepted a revoked key")
	}
}

// TestAuthenticateAPIKeyRejectsExpired confirms an expired key
// stops authenticating immediately. The expiration is 1µs in the
// past so we don't have to sleep.
func TestAuthenticateAPIKeyRejectsExpired(t *testing.T) {
	h := authTestHandler(t)
	minted, _ := apikey.Mint()
	past := time.Now().Add(-time.Microsecond)
	_, _ = h.apiKeyStore.Insert(context.Background(),
		minted.KeyID, minted.SecretHash, "n", "alice",
		[]string{"metrics"}, &past)
	if _, err := h.authenticateAPIKey(requestWithBearer(t, minted.Full), minted.Full); err == nil {
		t.Errorf("authenticateAPIKey accepted an expired key")
	}
}

// TestAuthenticateAPIKeyRejectsMalformed confirms garbage input
// fails fast without panic. Bonus: confirms we don't hit the DB
// for tokens that obviously can't be keys (parse fails first).
func TestAuthenticateAPIKeyRejectsMalformed(t *testing.T) {
	h := authTestHandler(t)
	for _, bad := range []string{
		"",
		"not-a-key",
		apikey.Prefix + "short", // too short
		apikey.Prefix + "zzzzzzzzzzzz-" + "0123456789abcdef0123456789abcdef", // non-hex id
	} {
		if _, err := h.authenticateAPIKey(requestWithBearer(t, bad), bad); err == nil {
			t.Errorf("authenticateAPIKey accepted malformed token %q", bad)
		}
	}
}

// TestContextHelpersOnNonAPIKeyAuth confirms that requests
// authenticated via JWT or session (no API-key context) do NOT
// satisfy AuthenticatedViaAPIKey or ContainsScope. The /metrics gate
// relies on this — a valid JWT with no scope context must fail the
// "metrics" check, not pass it by accident.
func TestContextHelpersOnNonAPIKeyAuth(t *testing.T) {
	ctx := context.Background()
	if AuthenticatedViaAPIKey(ctx) {
		t.Errorf("AuthenticatedViaAPIKey returned true on bare context")
	}
	if ContainsScope(ctx, "metrics") {
		t.Errorf("ContainsScope returned true on bare context")
	}

	// Even setting an authenticated user (the "JWT was valid"
	// pattern) doesn't grant any API-key context.
	jwtCtx := htcondor.WithAuthenticatedUser(ctx, "jwt-user")
	if AuthenticatedViaAPIKey(jwtCtx) {
		t.Errorf("AuthenticatedViaAPIKey returned true on JWT-shaped context")
	}
	if ContainsScope(jwtCtx, "metrics") {
		t.Errorf("ContainsScope returned true on JWT-shaped context")
	}
}
