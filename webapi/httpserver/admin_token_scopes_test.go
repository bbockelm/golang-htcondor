package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// asAdmin gives the fixture's server an admin group and returns a
// request-maker carrying a session in it, which is what requireAdmin
// checks.
func asAdmin(t *testing.T, f *reauthFixture) func(method, target, body string) *http.Request {
	t.Helper()
	f.server.webuiAdminGroups = newGroupSet("condor-admins")
	return func(method, target, body string) *http.Request {
		sid, _, err := f.server.sessionStore.Create("operator", []string{"condor-admins"})
		if err != nil {
			t.Fatalf("session create: %v", err)
		}
		var r *http.Request
		if body == "" {
			r = httptest.NewRequestWithContext(context.Background(), method, target, nil)
		} else {
			r = httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		}
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec
		return r
	}
}

// setScopes drives the endpoint the admin page calls.
func setScopes(t *testing.T, f *reauthFixture, kind, fingerprint string, scopes []string) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(AdminSetTokenScopesRequest{
		Kind: kind, Fingerprint: fingerprint, Scopes: scopes,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := asAdmin(t, f)(http.MethodPost, "/api/v1/admin/oauth2/tokens/scopes", string(body))
	rec := httptest.NewRecorder()
	f.server.handleAdminSetTokenScopes(rec, req)

	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// TestNarrowingAGrantSurvivesTheRefresh is the point of the whole
// feature. Narrowing only the access token would be undone minutes later
// by a client that still holds a refresh token carrying the old set --
// the same reason revocation applies to the whole grant.
func TestNarrowingAGrantSurvivesTheRefresh(t *testing.T) {
	f := newReauthFixture(t, Config{})
	_, refreshToken, scope := f.grant(t, "alice", nil)
	if !strings.Contains(scope, "mcp:write") {
		t.Fatalf("fixture did not grant mcp:write; got %q", scope)
	}

	sig := signatureFor(t, f, "oauth2_access_tokens", "alice")
	status, body := setScopes(t, f, "access", sig[:8], []string{"openid", "offline_access", "mcp:read"})
	if status != http.StatusOK {
		t.Fatalf("narrowing failed with %d: %v", status, body)
	}

	// The refresh row itself must carry the narrowed set, not merely
	// behave as though it does: that is the difference between writing
	// the whole grant and writing only the row the operator clicked.
	refreshSig := signatureFor(t, f, "oauth2_refresh_tokens", "alice")
	var refreshGranted string
	if err := f.server.oauth2Provider.GetStorage().GetDB().QueryRowContext(context.Background(),
		"SELECT granted_scopes FROM oauth2_refresh_tokens WHERE signature = ?", refreshSig,
	).Scan(&refreshGranted); err != nil {
		t.Fatalf("reading the refresh row: %v", err)
	}
	if strings.Contains(refreshGranted, "mcp:write") {
		t.Errorf("the refresh token still carries mcp:write: %s", refreshGranted)
	}

	status, refreshed := f.refresh(t, refreshToken)
	if status != http.StatusOK {
		t.Fatalf("the grant stopped working entirely: %d %v", status, refreshed)
	}
	got, _ := refreshed["scope"].(string)
	if strings.Contains(got, "mcp:write") {
		t.Errorf("the refreshed token still carries mcp:write; the narrowing was undone: %q", got)
	}
	if !strings.Contains(got, "mcp:read") {
		t.Errorf("the refreshed token lost a scope that was kept: %q", got)
	}
}

// TestNarrowingRefusesToWiden is a boundary, not a convenience. A
// token's scopes are what the client asked for, the user consented to,
// and the policy allowed. Adding one here would have none of those
// behind it: an operator could hand an agent mcp:superuser its owner
// never approved, which is the escalation the unchecked consent box
// exists to prevent.
func TestNarrowingRefusesToWiden(t *testing.T) {
	f := newReauthFixture(t, Config{})
	f.grant(t, "alice", nil)
	sig := signatureFor(t, f, "oauth2_access_tokens", "alice")

	status, body := setScopes(t, f, "access", sig[:8],
		[]string{"openid", "offline_access", "mcp:read", "mcp:write", "mcp:superuser"})
	if status != http.StatusBadRequest {
		t.Fatalf("widening was accepted with %d: %v", status, body)
	}
	// The reason is in "message"; "error" carries the status text.
	if msg, _ := body["message"].(string); !strings.Contains(msg, "mcp:superuser") {
		t.Errorf("the refusal does not name the scope it refused: %v", body)
	}

	// And it changed nothing.
	storage := f.server.oauth2Provider.GetStorage()
	grant, err := storage.FindGrantBySignaturePrefix(context.Background(), "access", sig[:8])
	if err != nil {
		t.Fatal(err)
	}
	after, err := storage.GrantScopes(context.Background(), grant.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range after {
		if s == "mcp:superuser" {
			t.Fatal("a refused widening was written anyway")
		}
	}
}

// The listing has to report what a token can DO. The `scopes` column is
// what the client ASKED for, and the two differ whenever a request was
// refused something -- now the normal case, since a client may ask for
// mcp:admin without being in the group for it. Reporting the request
// made a refused privilege look granted.
func TestListingReportsGrantedNotRequestedScopes(t *testing.T) {
	f := newReauthFixture(t, Config{})
	f.grant(t, "alice", nil)

	db := f.server.oauth2Provider.GetStorage().GetDB()
	// A request that asked for more than it got, which is what an
	// advertised-but-ungranted privileged scope looks like.
	if _, err := db.ExecContext(context.Background(),
		`UPDATE oauth2_access_tokens SET scopes = ? WHERE subject = ?`,
		`["openid","mcp:read","mcp:superuser"]`, "alice"); err != nil {
		t.Fatal(err)
	}

	req := asAdmin(t, f)(http.MethodGet, "/api/v1/admin/oauth2/tokens", "")
	rec := httptest.NewRecorder()
	f.server.handleAdminListTokens(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("listing failed with %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "mcp:superuser") {
		t.Errorf("the listing shows a scope the token was refused:\n%s", rec.Body.String())
	}
}

// TestARemovedScopeCanBePutBack is the whole reason this is a toggle.
//
// Removal used to be a one-way door behind a single click: an operator who
// mis-clicked could not undo it, and the grant had to be revoked and
// re-authorized -- which for an unattended agent means finding somebody to
// approve it again.
//
// Restoring is safe because the bound is what the authorization ENDED with:
// the user already agreed to it. Granting something they never agreed to is
// still refused, which the next test covers.
func TestARemovedScopeCanBePutBack(t *testing.T) {
	f := newReauthFixture(t, Config{})
	_, refreshToken, _ := f.grant(t, "alice", nil)
	sig := signatureFor(t, f, "oauth2_access_tokens", "alice")

	status, body := setScopes(t, f, "access", sig[:8], []string{"openid", "offline_access", "mcp:read"})
	if status != http.StatusOK {
		t.Fatalf("narrowing failed with %d: %v", status, body)
	}

	// Put it back.
	// Addressed by the REFRESH token's fingerprint this time: either row
	// names the same grant, and an operator clicks whichever one the
	// listing happened to show them.
	refreshSig := signatureFor(t, f, "oauth2_refresh_tokens", "alice")
	status, body = setScopes(t, f, "refresh", refreshSig[:8],
		[]string{"openid", "offline_access", "mcp:read", "mcp:write"})
	if status != http.StatusOK {
		t.Fatalf("restoring a scope this grant was authorized with failed with %d: %v", status, body)
	}

	// And it is really back: the client refreshes and carries it again.
	status, refreshed := f.refresh(t, refreshToken)
	if status != http.StatusOK {
		t.Fatalf("the grant stopped working: %d %v", status, refreshed)
	}
	if got, _ := refreshed["scope"].(string); !strings.Contains(got, "mcp:write") {
		t.Errorf("the restored scope did not survive the refresh: %q", got)
	}
}

// Restoring is bounded by what the authorization ended with, so a scope the
// user never agreed to is still refused -- including one they unticked at
// the consent page, which never enters the authorized set.
func TestRestoringCannotExceedTheAuthorization(t *testing.T) {
	f := newReauthFixture(t, Config{})
	f.grant(t, "alice", nil)
	sig := signatureFor(t, f, "oauth2_access_tokens", "alice")

	status, body := setScopes(t, f, "access", sig[:8],
		[]string{"openid", "offline_access", "mcp:read", "mcp:write", "mcp:superuser"})
	if status != http.StatusBadRequest {
		t.Fatalf("a scope outside the authorization was accepted with %d: %v", status, body)
	}
	if msg, _ := body["message"].(string); !strings.Contains(msg, "mcp:superuser") {
		t.Errorf("the refusal does not name the scope it refused: %v", body)
	}
}

// The page cannot offer a toggle without knowing what to toggle back ON, so
// the listing reports both sets.
func TestListingReportsWhatCanBeRestored(t *testing.T) {
	f := newReauthFixture(t, Config{})
	f.grant(t, "alice", nil)
	sig := signatureFor(t, f, "oauth2_access_tokens", "alice")

	if status, body := setScopes(t, f, "access", sig[:8],
		[]string{"openid", "offline_access", "mcp:read"}); status != http.StatusOK {
		t.Fatalf("narrowing failed with %d: %v", status, body)
	}

	req := asAdmin(t, f)(http.MethodGet, "/api/v1/admin/oauth2/tokens", "")
	rec := httptest.NewRecorder()
	f.server.handleAdminListTokens(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("listing failed with %d: %s", rec.Code, rec.Body.String())
	}

	var listed struct {
		Tokens []AdminToken `json:"tokens"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tok := range listed.Tokens {
		if tok.Subject != "alice" {
			continue
		}
		found = true
		if containsString(tok.Scopes, "mcp:write") {
			t.Errorf("a switched-off scope is still reported as in force: %v", tok.Scopes)
		}
		if !containsString(tok.AuthorizedScopes, "mcp:write") {
			t.Errorf("the page has no way to switch mcp:write back on: authorized=%v",
				tok.AuthorizedScopes)
		}
	}
	if !found {
		t.Fatal("the listing returned no token for alice; this asserted nothing")
	}
}
