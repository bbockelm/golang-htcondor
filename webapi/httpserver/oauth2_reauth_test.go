package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"golang.org/x/crypto/bcrypt"
)

// --- session plumbing ---------------------------------------------------

// TestSessionCloneDeepPreservesFields guards the Clone override in
// oauth2_session.go. If Clone is deleted, openid.DefaultSession's own Clone
// promotes through the embedded pointer, returns a *openid.DefaultSession,
// and silently drops Groups and AuthTime. fosite's refresh handler clones the
// stored session on every refresh, so that regression would quietly disable
// every check in reauthorizeRefreshGrant rather than failing loudly.
func TestSessionCloneDeepPreservesFields(t *testing.T) {
	authTime := time.Now().UTC().Add(-3 * time.Hour).Round(time.Second)
	orig := DefaultOpenIDConnectSession("alice").WithGroups([]string{"condor-writers"})
	orig.AuthTime = authTime

	cloned, ok := orig.Clone().(*Session)
	if !ok {
		t.Fatalf("Clone returned %T, want *Session — the embedded DefaultSession.Clone is being promoted", orig.Clone())
	}
	if cloned.AuthTime != authTime {
		t.Errorf("AuthTime lost through Clone: got %v want %v", cloned.AuthTime, authTime)
	}
	if len(cloned.Groups) != 1 || cloned.Groups[0] != "condor-writers" {
		t.Errorf("Groups lost through Clone: got %v", cloned.Groups)
	}
	if cloned.GetSubject() != "alice" {
		t.Errorf("Subject lost through Clone: got %q", cloned.GetSubject())
	}

	// Deep, not shallow: mutating the clone must not reach the original.
	cloned.Groups[0] = "mutated"
	if orig.Groups[0] != "condor-writers" {
		t.Errorf("Clone shares the Groups backing array with the original")
	}
}

// TestSessionSurvivesJSONRoundTrip covers the other half of the path: the
// session is marshaled into the token row and unmarshaled into whatever
// concrete type the caller hands storage. A caller passing a bare
// openid.DefaultSession would decode the extra fields into nothing.
func TestSessionSurvivesJSONRoundTrip(t *testing.T) {
	authTime := time.Now().UTC().Add(-30 * time.Minute).Round(time.Second)
	orig := DefaultOpenIDConnectSession("bob").WithGroups([]string{"g1", "g2"})
	orig.AuthTime = authTime

	blob, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := newEmptySession()
	if err := json.Unmarshal(blob, got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.AuthTime != authTime {
		t.Errorf("AuthTime lost in round trip: got %v want %v", got.AuthTime, authTime)
	}
	if strings.Join(got.Groups, ",") != "g1,g2" {
		t.Errorf("Groups lost in round trip: got %v", got.Groups)
	}
	if got.GetSubject() != "bob" {
		t.Errorf("Subject lost in round trip: got %q", got.GetSubject())
	}

	// And confirm the failure mode the type exists to prevent, so the
	// test documents why every call site had to change.
	bare := &openid.DefaultSession{}
	if err := json.Unmarshal(blob, bare); err != nil {
		t.Fatalf("unmarshal into bare session: %v", err)
	}
	if bare.GetSubject() != "bob" {
		t.Errorf("sanity: bare session should still decode the subject")
	}
}

// --- harness ------------------------------------------------------------

type reauthFixture struct {
	server       *Server
	clientID     string
	clientSecret string
}

func newReauthFixture(t *testing.T, cfg Config) *reauthFixture {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	cfg.ScheddName = "test-schedd"
	cfg.ScheddAddr = "localhost:9618"
	cfg.Logger = logger
	cfg.EnableMCP = true
	cfg.OAuth2Issuer = "http://localhost:8080"
	if cfg.OAuth2DBPath == "" {
		cfg.OAuth2DBPath = t.TempDir() + "/oauth2.db"
	}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	clientID := "reauth-client"
	clientSecret := "reauth-secret" //nolint:gosec // G101: fixed test credential for an in-process fixture
	hashed, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashed,
		RedirectURIs:  []string{"http://localhost:8080/callback"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "offline_access", "mcp:read", "mcp:write"},
	}
	if err := server.oauth2Provider.GetStorage().CreateClient(context.Background(), client); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	return &reauthFixture{server: server, clientID: clientID, clientSecret: clientSecret}
}

// consent drives authorize + consent as username with the given groups and
// returns the authorization code.
func (f *reauthFixture) consent(t *testing.T, username string, groups []string, scopes string) string {
	t.Helper()
	ctx := context.Background()
	authorizeReq := httptest.NewRequestWithContext(ctx, http.MethodGet, "/mcp/oauth2/authorize", nil)
	authorizeReq.URL.RawQuery = url.Values{
		"response_type": {"code"},
		"client_id":     {f.clientID},
		"redirect_uri":  {"http://localhost:8080/callback"},
		"scope":         {scopes},
		"state":         {"teststate1234567890"},
		"nonce":         {"noncevalue1234567890"},
	}.Encode()
	ar, err := f.server.oauth2Provider.GetProvider().NewAuthorizeRequest(ctx, authorizeReq)
	if err != nil {
		t.Fatalf("NewAuthorizeRequest: %v", err)
	}
	state, err := f.server.oauth2StateStore.GenerateState()
	if err != nil {
		t.Fatalf("GenerateState: %v", err)
	}
	f.server.oauth2StateStore.StoreWithUsername(state, ar, "", username, groups)

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp/oauth2/consent",
		strings.NewReader(url.Values{"state": {state}, "action": {"approve"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.server.handleOAuth2Consent(w, req)
	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Fatalf("consent status %d: %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no authorization code in redirect %q", loc)
	}
	return code
}

// token posts to the token endpoint and returns the decoded body plus status.
func (f *reauthFixture) token(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	form.Set("client_id", f.clientID)
	form.Set("client_secret", f.clientSecret)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/mcp/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.server.handleOAuth2Token(w, req)
	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return resp.StatusCode, out
}

// grant runs a full consent + code exchange and returns the refresh token.
func (f *reauthFixture) grant(t *testing.T, username string, groups []string) (accessToken, refreshToken, scope string) {
	t.Helper()
	code := f.consent(t, username, groups, "openid offline_access mcp:read mcp:write")
	status, body := f.token(t, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"http://localhost:8080/callback"},
	})
	if status != http.StatusOK {
		t.Fatalf("code exchange failed with %d: %v", status, body)
	}
	accessToken, _ = body["access_token"].(string)
	refreshToken, _ = body["refresh_token"].(string)
	scope, _ = body["scope"].(string)
	if refreshToken == "" {
		t.Fatalf("no refresh token issued: %v", body)
	}
	return accessToken, refreshToken, scope
}

func (f *reauthFixture) refresh(t *testing.T, refreshToken string) (int, map[string]any) {
	t.Helper()
	return f.token(t, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
}

func hasScope(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

// --- behavior -----------------------------------------------------------

// TestRefreshNarrowsScopesWhenGroupPolicyChanges is the core regression: a
// user who loses write entitlement must stop receiving mcp:write on refresh,
// while keeping the rest of their grant.
func TestRefreshNarrowsScopesWhenGroupPolicyChanges(t *testing.T) {
	f := newReauthFixture(t, Config{MCPWriteGroup: "condor-writers"})

	_, refreshToken, scope := f.grant(t, "alice", []string{"condor-writers"})
	if !hasScope(scope, "mcp:write") {
		t.Fatalf("expected mcp:write at consent time, got %q", scope)
	}

	// alice loses write entitlement.
	f.server.mcpWriteGroup = "condor-writers-v2"

	status, body := f.refresh(t, refreshToken)
	if status != http.StatusOK {
		t.Fatalf("refresh should succeed with narrowed scopes, got %d: %v", status, body)
	}
	newScope, _ := body["scope"].(string)
	if hasScope(newScope, "mcp:write") {
		t.Errorf("refreshed grant still carries mcp:write: %q", newScope)
	}
	if !hasScope(newScope, "mcp:read") {
		t.Errorf("refreshed grant should keep mcp:read: %q", newScope)
	}
	if !hasScope(newScope, "offline_access") {
		t.Errorf("refreshed grant should keep offline_access so the client can refresh again: %q", newScope)
	}

	// The narrowing must stick on the token itself, not just the response
	// body — otherwise the client keeps write access in practice.
	newAccess, _ := body["access_token"].(string)
	_, ar, err := f.server.oauth2Provider.GetProvider().IntrospectToken(
		context.Background(), newAccess, fosite.AccessToken, newEmptySession())
	if err != nil {
		t.Fatalf("introspect refreshed access token: %v", err)
	}
	if ar.GetGrantedScopes().Has("mcp:write") {
		t.Errorf("introspected token still grants mcp:write: %v", ar.GetGrantedScopes())
	}
}

// TestRefreshRevokedWhenAccessGroupLost covers the harder denial: losing the
// blanket access group kills the grant outright rather than narrowing it.
func TestRefreshRevokedWhenAccessGroupLost(t *testing.T) {
	f := newReauthFixture(t, Config{MCPAccessGroup: "condor-users"})

	_, refreshToken, _ := f.grant(t, "alice", []string{"condor-users"})

	f.server.mcpAccessGroup = "condor-users-v2"

	status, body := f.refresh(t, refreshToken)
	if status == http.StatusOK {
		t.Fatalf("refresh should have been denied, got 200: %v", body)
	}
	if got, _ := body["error"].(string); got != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant (tells the client to re-authorize)", got)
	}

	// The whole chain must be dead, not just this one token.
	status2, _ := f.refresh(t, refreshToken)
	if status2 == http.StatusOK {
		t.Errorf("revoked refresh token still works on a second attempt")
	}
}

// TestRefreshRevokedPastLifetimeCap covers the backstop that applies even
// when no policy changed and no oracle objected.
func TestRefreshRevokedPastLifetimeCap(t *testing.T) {
	f := newReauthFixture(t, Config{OAuth2MaxGrantLifetime: time.Hour})

	_, refreshToken, _ := f.grant(t, "alice", []string{"condor-users"})

	// A refresh inside the cap works.
	status, body := f.refresh(t, refreshToken)
	if status != http.StatusOK {
		t.Fatalf("refresh inside the cap should succeed, got %d: %v", status, body)
	}
	refreshToken, _ = body["refresh_token"].(string)

	// Age the grant past the cap. AuthTime rides in the stored session, so
	// rewriting it is how the passage of time is simulated.
	backdateAuthTime(t, f, -2*time.Hour)

	status, body = f.refresh(t, refreshToken)
	if status == http.StatusOK {
		t.Fatalf("refresh past the lifetime cap should have been denied: %v", body)
	}
	if got, _ := body["error"].(string); got != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", got)
	}
	if desc, _ := body["error_description"].(string); !strings.Contains(desc, "maximum lifetime") {
		t.Errorf("error_description = %q, want it to name the lifetime cap", desc)
	}
}

// backdateAuthTime rewrites the persisted AuthTime on every live refresh row,
// simulating the passage of time without a clock injection point.
func backdateAuthTime(t *testing.T, f *reauthFixture, delta time.Duration) {
	t.Helper()
	ctx := context.Background()
	rows, err := f.server.db.QueryContext(ctx,
		`SELECT signature, session_data FROM oauth2_refresh_tokens WHERE active = 1`)
	if err != nil {
		t.Fatalf("select sessions: %v", err)
	}
	type row struct{ sig, data string }
	var found []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.sig, &r.data); err != nil {
			t.Fatalf("scan: %v", err)
		}
		found = append(found, r)
	}
	_ = rows.Close()
	if len(found) == 0 {
		t.Fatalf("no active refresh rows to backdate")
	}
	for _, r := range found {
		sess := newEmptySession()
		if err := json.Unmarshal([]byte(r.data), sess); err != nil {
			t.Fatalf("unmarshal session: %v", err)
		}
		if sess.AuthTime.IsZero() {
			t.Fatalf("stored session has no AuthTime; the consent path is not recording it")
		}
		sess.AuthTime = sess.AuthTime.Add(delta)
		blob, err := json.Marshal(sess)
		if err != nil {
			t.Fatalf("marshal session: %v", err)
		}
		if _, err := f.server.db.ExecContext(ctx,
			`UPDATE oauth2_refresh_tokens SET session_data = ? WHERE signature = ?`,
			string(blob), r.sig); err != nil {
			t.Fatalf("update session: %v", err)
		}
	}
}

// --- oracles ------------------------------------------------------------

type fakeOracle struct {
	name     string
	decision ReauthDecision
	err      error
	calls    int
}

func (o *fakeOracle) Name() string { return o.name }
func (o *fakeOracle) Check(_ context.Context, _ string, _ []string) (ReauthDecision, error) {
	o.calls++
	return o.decision, o.err
}

func TestRefreshRevokedByOracle(t *testing.T) {
	f := newReauthFixture(t, Config{})
	oracle := &fakeOracle{
		name:     "fake",
		decision: ReauthDecision{Status: UserStatusRevoked, Reason: "left the lab"},
	}
	f.server.revocationOracles = []RevocationOracle{oracle}

	_, refreshToken, _ := f.grant(t, "alice", nil)

	status, body := f.refresh(t, refreshToken)
	if status == http.StatusOK {
		t.Fatalf("oracle said revoked but refresh succeeded: %v", body)
	}
	if oracle.calls == 0 {
		t.Errorf("oracle was never consulted")
	}
	if desc, _ := body["error_description"].(string); !strings.Contains(desc, "left the lab") {
		t.Errorf("error_description = %q, want the oracle's reason surfaced", desc)
	}
}

func TestRefreshNarrowedByOracleDeniedScopes(t *testing.T) {
	f := newReauthFixture(t, Config{})
	f.server.revocationOracles = []RevocationOracle{&fakeOracle{
		name: "fake",
		decision: ReauthDecision{
			Status:       UserStatusActive,
			Reason:       "not in ALLOW_WRITE",
			DeniedScopes: []string{"mcp:write"},
		},
	}}

	_, refreshToken, scope := f.grant(t, "alice", nil)
	if !hasScope(scope, "mcp:write") {
		t.Fatalf("expected mcp:write initially, got %q", scope)
	}

	status, body := f.refresh(t, refreshToken)
	if status != http.StatusOK {
		t.Fatalf("a scope denial should narrow, not fail: %d %v", status, body)
	}
	newScope, _ := body["scope"].(string)
	if hasScope(newScope, "mcp:write") {
		t.Errorf("denied scope survived the refresh: %q", newScope)
	}
	if !hasScope(newScope, "mcp:read") {
		t.Errorf("unrelated scopes should survive: %q", newScope)
	}
}

// TestRefreshFailsOpenWhenOracleErrors pins the contract that keeps a flaky
// dependency from becoming an outage: an oracle that cannot answer is ignored,
// and the lifetime cap remains the backstop.
func TestRefreshFailsOpenWhenOracleErrors(t *testing.T) {
	f := newReauthFixture(t, Config{})
	oracle := &fakeOracle{name: "broken", err: errors.New("schedd unreachable")}
	f.server.revocationOracles = []RevocationOracle{oracle}

	_, refreshToken, _ := f.grant(t, "alice", nil)

	status, body := f.refresh(t, refreshToken)
	if status != http.StatusOK {
		t.Fatalf("a broken oracle must not deny the refresh, got %d: %v", status, body)
	}
	if oracle.calls == 0 {
		t.Errorf("oracle was never consulted")
	}
}

// TestUnknownOracleVerdictDoesNotRevoke pins the other half of failing open:
// "no record of this user" is not a denial. HTCondor creates a user record on
// first submit, so a user who has never submitted has no record at all.
func TestRefreshUnknownOracleVerdictDoesNotRevoke(t *testing.T) {
	f := newReauthFixture(t, Config{})
	f.server.revocationOracles = []RevocationOracle{&fakeOracle{
		name:     "fake",
		decision: ReauthDecision{Status: UserStatusUnknown},
	}}

	_, refreshToken, _ := f.grant(t, "alice", nil)

	status, body := f.refresh(t, refreshToken)
	if status != http.StatusOK {
		t.Fatalf("an unknown verdict must not revoke, got %d: %v", status, body)
	}
}

// TestAdminRevokeCutsOffRefresh covers the operator's unconditional lever:
// after an admin revokes a subject, their refresh token stops working even
// though no policy changed, no oracle objected, and the lifetime cap has not
// been reached.
func TestAdminRevokeCutsOffRefresh(t *testing.T) {
	f := newReauthFixture(t, Config{})
	_, refreshToken, _ := f.grant(t, "alice", nil)

	// Sanity: the grant works before revocation, or the test proves nothing.
	if status, body := f.refresh(t, refreshToken); status != http.StatusOK {
		t.Fatalf("refresh should work before revocation, got %d: %v", status, body)
	} else {
		refreshToken, _ = body["refresh_token"].(string)
	}

	n, err := f.server.oauth2Provider.GetStorage().RevokeAllForSubject(context.Background(), "alice")
	if err != nil {
		t.Fatalf("RevokeAllForSubject: %v", err)
	}
	if n == 0 {
		t.Fatalf("revoked 0 rows; the subject column is not being populated")
	}

	if status, body := f.refresh(t, refreshToken); status == http.StatusOK {
		t.Errorf("refresh still works after the subject was revoked: %v", body)
	}
}

// TestAdminRevokeLeavesOtherSubjectsAlone pins that revocation is scoped to
// the named subject.
func TestAdminRevokeLeavesOtherSubjectsAlone(t *testing.T) {
	f := newReauthFixture(t, Config{})
	_, aliceToken, _ := f.grant(t, "alice", nil)
	_, bobToken, _ := f.grant(t, "bob", nil)

	if _, err := f.server.oauth2Provider.GetStorage().RevokeAllForSubject(context.Background(), "alice"); err != nil {
		t.Fatalf("RevokeAllForSubject: %v", err)
	}

	if status, _ := f.refresh(t, aliceToken); status == http.StatusOK {
		t.Errorf("alice's grant should be dead")
	}
	if status, body := f.refresh(t, bobToken); status != http.StatusOK {
		t.Errorf("bob's grant should be untouched, got %d: %v", status, body)
	}
}
