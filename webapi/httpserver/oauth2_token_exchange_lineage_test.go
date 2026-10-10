package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
)

// An exchanged token is bound to the grant behind its subject token: it
// passes that grant's reauthorization when minted, and it ends, narrows and
// expires with that grant afterwards.

// exchangeFor exchanges subjectToken through the token endpoint as the actor
// client and returns the status and decoded body.
func exchangeFor(t *testing.T, server *Server, actor, secret, subjectToken, scope string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":         {tokenExchangeGrantType},
		"client_id":          {actor},
		"client_secret":      {secret},
		"subject_token":      {subjectToken},
		"subject_token_type": {tokenTypeAccessToken},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	rec := postTokenExchange(t, server, form)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode exchange response (%d): %v: %s", rec.Code, err, rec.Body.String())
	}
	return rec.Code, body
}

// mustExchange exchanges and returns the issued access token.
func mustExchange(t *testing.T, server *Server, actor, secret, subjectToken, scope string) string {
	t.Helper()
	status, body := exchangeFor(t, server, actor, secret, subjectToken, scope)
	if status != http.StatusOK {
		t.Fatalf("exchange status %d: %v", status, body)
	}
	tok, _ := body["access_token"].(string)
	if tok == "" {
		t.Fatalf("exchange returned no access token: %v", body)
	}
	return tok
}

// tokenActive reports whether an access token currently introspects active,
// which is what every bearer check on this server does.
func tokenActive(server *Server, tok string) bool {
	_, err := server.oauth2Provider.IntrospectAccessToken(context.Background(), tok)
	return err == nil
}

func introspectedScopes(t *testing.T, server *Server, tok string) []string {
	t.Helper()
	ar, err := server.oauth2Provider.IntrospectAccessToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	return ar.GetGrantedScopes()
}

func wantInvalidGrant(t *testing.T, status int, body map[string]any, what string) {
	t.Helper()
	if status != http.StatusBadRequest {
		t.Fatalf("%s: status %d, want 400: %v", what, status, body)
	}
	if got, _ := body["error"].(string); got != "invalid_grant" {
		t.Errorf("%s: error = %q, want invalid_grant", what, got)
	}
}

// adminRequest builds a request carrying an administrator's web session.
func adminRequest(t *testing.T, server *Server, method, target, body string) *http.Request {
	t.Helper()
	server.webuiAdminGroups = newGroupSet("condor-admins")
	sid, _, err := server.sessionStore.Create("root", []string{"condor-admins"})
	if err != nil {
		t.Fatalf("session create: %v", err)
	}
	r := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec // test cookie
	return r
}

// backdateGrant moves the stored AuthTime of every token row back by delta,
// the way oauth2_reauth_test.go simulates an aging grant.
func backdateGrant(t *testing.T, server *Server, delta time.Duration) {
	t.Helper()
	ctx := context.Background()
	for _, table := range []string{"oauth2_access_tokens", "oauth2_refresh_tokens"} {
		rows, err := server.db.QueryContext(ctx, "SELECT signature, session_data FROM "+table) //nolint:gosec // fixed table names
		if err != nil {
			t.Fatalf("select %s: %v", table, err)
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
		for _, r := range found {
			sess := newEmptySession()
			if err := json.Unmarshal([]byte(r.data), sess); err != nil {
				t.Fatalf("unmarshal session: %v", err)
			}
			sess.AuthTime = sess.AuthTime.Add(delta)
			blob, err := json.Marshal(sess)
			if err != nil {
				t.Fatalf("marshal session: %v", err)
			}
			if _, err := server.db.ExecContext(ctx,
				"UPDATE "+table+" SET session_data = ? WHERE signature = ?", //nolint:gosec // fixed table names
				string(blob), r.sig); err != nil {
				t.Fatalf("update session: %v", err)
			}
		}
	}
}

// The operator's "revoke this grant" must reach tokens exchanged from it,
// and only those.
func TestExchangedTokenIsRevokedWithItsSubjectGrant(t *testing.T) {
	f := newReauthFixture(t, Config{})
	secret := insertConfidentialClient(t, f.server, "actor",
		[]string{tokenExchangeGrantType}, []string{"mcp:read", "mcp:write"})

	aliceAccess, _, _ := f.grant(t, "alice", nil)
	bobAccess, _, _ := f.grant(t, "bob", nil)
	aliceExchanged := mustExchange(t, f.server, "actor", secret, aliceAccess, "")
	bobExchanged := mustExchange(t, f.server, "actor", secret, bobAccess, "")
	if !tokenActive(f.server, aliceExchanged) || !tokenActive(f.server, bobExchanged) {
		t.Fatal("exchanged tokens should be active before any revocation")
	}

	sig := f.server.oauth2Provider.GetStrategy().AccessTokenSignature(context.Background(), aliceAccess)
	rec := httptest.NewRecorder()
	f.server.handleAdminRevokeToken(rec, adminRequest(t, f.server, http.MethodPost,
		"/api/v1/admin/oauth2/tokens/revoke", `{"kind":"access","fingerprint":"`+sig+`"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("admin revoke status %d: %s", rec.Code, rec.Body.String())
	}

	if tokenActive(f.server, aliceExchanged) {
		t.Error("a token exchanged from a revoked grant still introspects active")
	}
	if !tokenActive(f.server, bobExchanged) {
		t.Error("revoking alice's grant killed a token exchanged from bob's")
	}
}

// Refresh rotation is not the end of a grant, so it must not end the
// exchanged token; refresh-token reuse is, so it must.
func TestExchangedTokenFollowsRefreshReuseRevocation(t *testing.T) {
	f := newReauthFixture(t, Config{})
	secret := insertConfidentialClient(t, f.server, "actor",
		[]string{tokenExchangeGrantType}, []string{"mcp:read"})

	access, firstRefresh, _ := f.grant(t, "alice", nil)
	exchanged := mustExchange(t, f.server, "actor", secret, access, "mcp:read")

	status, body := f.refresh(t, firstRefresh)
	if status != http.StatusOK {
		t.Fatalf("refresh: %d %v", status, body)
	}
	if !tokenActive(f.server, exchanged) {
		t.Fatal("an ordinary refresh of the subject grant ended the exchanged token")
	}

	// Replaying the rotated-away refresh token revokes the whole chain.
	if status, _ := f.refresh(t, firstRefresh); status == http.StatusOK {
		t.Fatal("refresh-token reuse was accepted")
	}
	if tokenActive(f.server, exchanged) {
		t.Error("refresh-token reuse revoked the grant but not the token exchanged from it")
	}
}

// Narrowing the subject grant narrows what an exchanged token can do.
func TestExchangedTokenNarrowsWithItsSubjectGrant(t *testing.T) {
	f := newReauthFixture(t, Config{})
	secret := insertConfidentialClient(t, f.server, "actor",
		[]string{tokenExchangeGrantType}, []string{"mcp:read", "mcp:write"})

	access, _, _ := f.grant(t, "alice", nil)
	exchanged := mustExchange(t, f.server, "actor", secret, access, "mcp:read mcp:write")
	if got := introspectedScopes(t, f.server, exchanged); !fosite.Arguments(got).Has("mcp:write") {
		t.Fatalf("exchanged scopes = %v, want mcp:write before narrowing", got)
	}

	storage := f.server.oauth2Provider.GetStorage()
	ar, err := f.server.oauth2Provider.IntrospectAccessToken(context.Background(), access)
	if err != nil {
		t.Fatalf("introspect subject: %v", err)
	}
	if _, err := storage.SetGrantScopes(context.Background(), ar.GetID(),
		[]string{"openid", "offline_access", "mcp:read"}); err != nil {
		t.Fatalf("SetGrantScopes: %v", err)
	}

	got := introspectedScopes(t, f.server, exchanged)
	if fosite.Arguments(got).Has("mcp:write") {
		t.Errorf("exchanged token kept mcp:write after its grant was narrowed: %v", got)
	}
	if !fosite.Arguments(got).Has("mcp:read") {
		t.Errorf("exchanged token lost mcp:read, which its grant still holds: %v", got)
	}
}

// An exchanged token cannot be exchanged again: that would mint a fresh
// lifetime from a token that is only meant to be as good as its grant.
func TestExchangeOfExchangedTokenRefused(t *testing.T) {
	server, _ := newProvenanceServer(t)
	secret := insertConfidentialClient(t, server, "actor",
		[]string{tokenExchangeGrantType}, []string{"mcp:read"})
	subject := mintSubjectToken(t, server, "alice", []string{"mcp:read"})

	exchanged := mustExchange(t, server, "actor", secret, subject, "")
	status, body := exchangeFor(t, server, "actor", secret, exchanged, "")
	wantInvalidGrant(t, status, body, "exchanging an exchanged token")

	// The original subject token is still exchangeable.
	mustExchange(t, server, "actor", secret, subject, "")
}

// A grant past its absolute lifetime cannot be exchanged, and a grant within
// it yields a token that expires at the cap rather than a full lifespan later.
func TestExchangeHonoursGrantLifetimeCap(t *testing.T) {
	f := newReauthFixture(t, Config{OAuth2MaxGrantLifetime: time.Hour})
	secret := insertConfidentialClient(t, f.server, "actor",
		[]string{tokenExchangeGrantType}, []string{"mcp:read"})
	access, refresh, _ := f.grant(t, "alice", nil)

	backdateGrant(t, f.server, -50*time.Minute)
	status, body := exchangeFor(t, f.server, "actor", secret, access, "")
	if status != http.StatusOK {
		t.Fatalf("exchange inside the cap: %d %v", status, body)
	}
	if exp, _ := body["expires_in"].(float64); exp <= 0 || exp > 11*60 {
		t.Errorf("expires_in = %v, want at most the ~10 minutes left on the grant", body["expires_in"])
	}

	backdateGrant(t, f.server, -20*time.Minute)
	status, body = exchangeFor(t, f.server, "actor", secret, access, "")
	wantInvalidGrant(t, status, body, "exchange past the lifetime cap")

	// The grant itself was revoked, as a refresh past the cap would.
	if status, _ := f.refresh(t, refresh); status == http.StatusOK {
		t.Error("the subject grant survived failing reauthorization at exchange")
	}
}

// mintGroupedSubjectToken is mintSubjectToken with the group list consent
// would have recorded.
func mintGroupedSubjectToken(t *testing.T, server *Server, subject string, groups, scopes []string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := server.oauth2Provider.GetStorage().GetDB().ExecContext(ctx,
		`INSERT OR IGNORE INTO oauth2_clients (id, client_secret, redirect_uris, grant_types, response_types, scopes, public)
		 VALUES ('origin-client', '', '[]', '["authorization_code"]', '["code"]', '[]', 1)`); err != nil {
		t.Fatalf("seed origin client: %v", err)
	}
	session := DefaultOpenIDConnectSession(subject).WithGroups(groups)
	ar := fosite.NewAccessRequest(session)
	ar.Client = &fosite.DefaultClient{ID: "origin-client"}
	for _, s := range scopes {
		ar.GrantScope(s)
	}
	setStandardTokenExpiries(ctx, server.oauth2Provider.config, session)
	strategy := server.oauth2Provider.GetStrategy()
	tok, _, err := strategy.GenerateAccessToken(ctx, ar)
	if err != nil {
		t.Fatalf("mint subject token: %v", err)
	}
	if err := server.oauth2Provider.GetStorage().CreateAccessTokenSession(ctx,
		strategy.AccessTokenSignature(ctx, tok), ar); err != nil {
		t.Fatalf("store subject token: %v", err)
	}
	return tok
}

// Exchange applies the current group policy to the subject, as refresh does.
func TestExchangeNarrowsToCurrentGroupPolicy(t *testing.T) {
	server, _ := newProvenanceServer(t)
	server.mcpAdminGroups = newGroupSet("condor-admins")
	secret := insertConfidentialClient(t, server, "actor",
		[]string{tokenExchangeGrantType}, []string{"mcp:read", "mcp:admin"})
	subject := mintGroupedSubjectToken(t, server, "alice",
		[]string{"condor-admins"}, []string{"mcp:read", "mcp:admin"})

	before := mustExchange(t, server, "actor", secret, subject, "")
	if got := introspectedScopes(t, server, before); !fosite.Arguments(got).Has("mcp:admin") {
		t.Fatalf("scopes = %v, want mcp:admin while the policy grants it", got)
	}

	// The admin group moves; alice's recorded groups no longer qualify.
	server.mcpAdminGroups = newGroupSet("pool-admins")
	status, body := exchangeFor(t, server, "actor", secret, subject, "")
	if status != http.StatusOK {
		t.Fatalf("exchange: %d %v", status, body)
	}
	scope, _ := body["scope"].(string)
	if hasScope(scope, "mcp:admin") {
		t.Errorf("exchange still granted mcp:admin after the policy dropped it: %q", scope)
	}
	if !hasScope(scope, "mcp:read") {
		t.Errorf("exchange should keep mcp:read: %q", scope)
	}
}

// A revocation oracle's verdict applies at exchange as it does at refresh.
func TestExchangeRefusedByOracle(t *testing.T) {
	server, _ := newProvenanceServer(t)
	secret := insertConfidentialClient(t, server, "actor",
		[]string{tokenExchangeGrantType}, []string{"mcp:read"})
	subject := mintSubjectToken(t, server, "alice", []string{"mcp:read"})
	server.revocationOracles = []RevocationOracle{&fakeOracle{
		name: "fake", decision: ReauthDecision{Status: UserStatusRevoked, Reason: "disabled"},
	}}

	status, body := exchangeFor(t, server, "actor", secret, subject, "")
	wantInvalidGrant(t, status, body, "exchange for a user the oracle revoked")
}

// registerClient posts a dynamic registration and returns the status and
// decoded body.
func registerClient(t *testing.T, server *Server, req map[string]any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/oauth2/register", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.handleOAuth2Register(rec, r)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode register response (%d): %v: %s", rec.Code, err, rec.Body.String())
	}
	return rec.Code, body
}

// Self-registration is limited to the interactive grants and the code
// response type; the operator-only grants are refused outright.
func TestDynamicRegistrationGrantAllowList(t *testing.T) {
	server, _ := newProvenanceServer(t)
	redirect := []string{"https://client.example/cb"}

	for _, tc := range []struct {
		name string
		req  map[string]any
	}{
		{"token exchange", map[string]any{"redirect_uris": redirect, "grant_types": []string{tokenExchangeGrantType}}},
		{"token exchange alongside code", map[string]any{"redirect_uris": redirect,
			"grant_types": []string{"authorization_code", tokenExchangeGrantType}}},
		{"client credentials", map[string]any{"redirect_uris": redirect, "grant_types": []string{"client_credentials"}}},
		{"implicit response type", map[string]any{"redirect_uris": redirect, "response_types": []string{"token"}}},
	} {
		status, body := registerClient(t, server, tc.req)
		if status != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400: %v", tc.name, status, body)
			continue
		}
		if got, _ := body["error"].(string); got != "invalid_client_metadata" {
			t.Errorf("%s: error = %q, want invalid_client_metadata", tc.name, got)
		}
	}

	// Defaults, and the device-code CLI's registration, still work.
	status, body := registerClient(t, server, map[string]any{"redirect_uris": redirect})
	if status != http.StatusCreated {
		t.Fatalf("default registration: %d %v", status, body)
	}
	if got, _ := json.Marshal(body["grant_types"]); string(got) != `["authorization_code","refresh_token"]` {
		t.Errorf("default grant_types = %s", got)
	}
	if got, _ := json.Marshal(body["response_types"]); string(got) != `["code"]` {
		t.Errorf("default response_types = %s", got)
	}
	status, body = registerClient(t, server, map[string]any{"redirect_uris": redirect,
		"grant_types": []string{deviceCodeGrant, "refresh_token"}})
	if status != http.StatusCreated {
		t.Fatalf("device-code registration: %d %v", status, body)
	}
}

// The supported way to obtain an actor client: register, then have an
// operator enable the grant.
func TestOperatorEnabledExchangeClientCanExchange(t *testing.T) {
	server, req := newProvenanceServer(t)
	status, body := registerClient(t, server, map[string]any{
		"redirect_uris": []string{"https://gw.example/cb"}, "scope": "mcp:read",
	})
	if status != http.StatusCreated {
		t.Fatalf("register: %d %v", status, body)
	}
	id, _ := body["client_id"].(string)
	secret, _ := body["client_secret"].(string)
	subject := mintSubjectToken(t, server, "alice", []string{"mcp:read"})

	// Not yet permitted.
	rec := postTokenExchange(t, server, url.Values{
		"grant_type": {tokenExchangeGrantType}, "client_id": {id}, "client_secret": {secret},
		"subject_token": {subject}, "subject_token_type": {tokenTypeAccessToken},
	})
	if rec.Code == http.StatusOK {
		t.Fatal("a self-registered client exchanged a token without the grant")
	}

	rec = httptest.NewRecorder()
	server.handleAdminUpdateClient(rec, req(http.MethodPatch, "/api/v1/admin/oauth2/clients/"+id,
		`{"grant_types":["authorization_code","refresh_token","`+tokenExchangeGrantType+`"]}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("admin enable token exchange: %d %s", rec.Code, rec.Body.String())
	}
	mustExchange(t, server, id, secret, subject, "mcp:read")
}
