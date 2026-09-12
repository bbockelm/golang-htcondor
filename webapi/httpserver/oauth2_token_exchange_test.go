package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

// insertConfidentialClient inserts a confidential client with a known secret and
// grant set, returning the plaintext secret.
func insertConfidentialClient(t *testing.T, server *Server, id string, grants, scopes []string) string {
	t.Helper()
	secret := "secret-for-" + id
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	gj, _ := json.Marshal(grants)
	sj, _ := json.Marshal(scopes)
	_, err = server.oauth2Provider.GetStorage().GetDB().ExecContext(context.Background(),
		`INSERT INTO oauth2_clients (id, client_secret, redirect_uris, grant_types, response_types, scopes, public)
		 VALUES (?, ?, '[]', ?, '["code"]', ?, 0)`, id, string(hash), string(gj), string(sj))
	if err != nil {
		t.Fatalf("insert client %s: %v", id, err)
	}
	return secret
}

// mintSubjectToken issues a real access token for subject with the given scopes,
// the way the standard flows do, so token exchange can consume it.
func mintSubjectToken(t *testing.T, server *Server, subject string, scopes []string) string {
	t.Helper()
	ctx := context.Background()
	// The stored token session reloads its client by id (getTokenSession), so the
	// subject token's client must exist in the table.
	_, err := server.oauth2Provider.GetStorage().GetDB().ExecContext(ctx,
		`INSERT OR IGNORE INTO oauth2_clients (id, client_secret, redirect_uris, grant_types, response_types, scopes, public)
		 VALUES ('origin-client', '', '[]', '["authorization_code"]', '["code"]', '[]', 1)`)
	if err != nil {
		t.Fatalf("seed origin client: %v", err)
	}
	session := DefaultOpenIDConnectSession(subject)
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
	sig := strategy.AccessTokenSignature(ctx, tok)
	if err := server.oauth2Provider.GetStorage().CreateAccessTokenSession(ctx, sig, ar); err != nil {
		t.Fatalf("store subject token: %v", err)
	}
	return tok
}

func postTokenExchange(t *testing.T, server *Server, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp/oauth2/token",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	server.handleOAuth2Token(rec, r)
	return rec
}

func TestTokenExchangeEndToEnd(t *testing.T) {
	server, _ := newProvenanceServer(t)
	secret := insertConfidentialClient(t, server, "actor",
		[]string{tokenExchangeGrantType}, []string{"mcp:read", "condor:/READ"})

	// Subject was granted a superset; the exchange narrows to condor:/READ.
	subjectToken := mintSubjectToken(t, server, "alice",
		[]string{"mcp:read", "condor:/READ", "condor:/WRITE"})

	rec := postTokenExchange(t, server, url.Values{
		"grant_type":         {tokenExchangeGrantType},
		"client_id":          {"actor"},
		"client_secret":      {secret},
		"subject_token":      {subjectToken},
		"subject_token_type": {tokenTypeAccessToken},
		"scope":              {"condor:/READ"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
		Scope           string `json:"scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.IssuedTokenType != tokenTypeAccessToken || resp.TokenType != "Bearer" {
		t.Errorf("issued_token_type=%q token_type=%q", resp.IssuedTokenType, resp.TokenType)
	}
	if resp.Scope != "condor:/READ" {
		t.Errorf("scope = %q, want scope-down to condor:/READ", resp.Scope)
	}

	// The issued token acts AS alice and records the actor (delegation).
	ar, err := server.oauth2Provider.IntrospectAccessToken(context.Background(), resp.AccessToken)
	if err != nil {
		t.Fatalf("introspect result: %v", err)
	}
	if ar.GetSession().GetSubject() != "alice" {
		t.Errorf("result subject = %q, want alice", ar.GetSession().GetSubject())
	}
	if got := []string(ar.GetGrantedScopes()); len(got) != 1 || got[0] != "condor:/READ" {
		t.Errorf("result scopes = %v, want [condor:/READ]", got)
	}
	if s, ok := ar.GetSession().(*Session); !ok || s.Actor != "actor" {
		t.Errorf("result act = %v (ok=%v), want actor", s, ok)
	}
}

func TestTokenExchangeRejections(t *testing.T) {
	server, _ := newProvenanceServer(t)
	// A confidential client WITHOUT the token_exchange grant.
	noGrantSecret := insertConfidentialClient(t, server, "nogrant",
		[]string{"authorization_code"}, []string{"mcp:read"})
	// A client WITH the grant.
	okSecret := insertConfidentialClient(t, server, "ex",
		[]string{tokenExchangeGrantType}, []string{"mcp:read"})
	subjectToken := mintSubjectToken(t, server, "bob", []string{"mcp:read"})

	// No token_exchange grant -> unauthorized_client.
	rec := postTokenExchange(t, server, url.Values{
		"grant_type": {tokenExchangeGrantType}, "client_id": {"nogrant"}, "client_secret": {noGrantSecret},
		"subject_token": {subjectToken}, "subject_token_type": {tokenTypeAccessToken},
	})
	if rec.Code == http.StatusOK {
		t.Error("a client without the token_exchange grant must be rejected")
	}

	// Bad client secret -> invalid_client.
	rec = postTokenExchange(t, server, url.Values{
		"grant_type": {tokenExchangeGrantType}, "client_id": {"ex"}, "client_secret": {"wrong"},
		"subject_token": {subjectToken}, "subject_token_type": {tokenTypeAccessToken},
	})
	if rec.Code == http.StatusOK {
		t.Error("bad client secret must be rejected")
	}

	// Garbage subject token -> invalid_grant.
	rec = postTokenExchange(t, server, url.Values{
		"grant_type": {tokenExchangeGrantType}, "client_id": {"ex"}, "client_secret": {okSecret},
		"subject_token": {"not-a-real-token"}, "subject_token_type": {tokenTypeAccessToken},
	})
	if rec.Code == http.StatusOK {
		t.Error("an invalid subject token must be rejected")
	}

	// Unsupported subject_token_type -> rejected (C1 only accepts access tokens).
	rec = postTokenExchange(t, server, url.Values{
		"grant_type": {tokenExchangeGrantType}, "client_id": {"ex"}, "client_secret": {okSecret},
		"subject_token": {subjectToken}, "subject_token_type": {"urn:ietf:params:oauth:token-type:jwt"},
	})
	if rec.Code == http.StatusOK {
		t.Error("an unsupported subject_token_type must be rejected in C1")
	}

	// Scope escalation beyond the subject's grant -> invalid_scope.
	rec = postTokenExchange(t, server, url.Values{
		"grant_type": {tokenExchangeGrantType}, "client_id": {"ex"}, "client_secret": {okSecret},
		"subject_token": {subjectToken}, "subject_token_type": {tokenTypeAccessToken},
		"scope": {"condor:/WRITE"}, // bob's token only has mcp:read
	})
	if rec.Code == http.StatusOK {
		t.Error("requesting a scope outside the subject token must be rejected")
	}
}

func TestTokenExchangeGrantIsConfidentialOnly(t *testing.T) {
	if err := validateGrantTypes([]string{tokenExchangeGrantType}, true); err == nil {
		t.Error("token_exchange on a public client must be rejected")
	}
	if err := validateGrantTypes([]string{tokenExchangeGrantType}, false); err != nil {
		t.Errorf("token_exchange on a confidential client should be allowed: %v", err)
	}
}
