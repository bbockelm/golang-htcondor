//go:build integration

package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/idmap"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

// The subject the provider asserts. It is deliberately nothing like a
// login name, so that a test passing by accident -- because the two
// happened to be equal -- is impossible.
const e2eAssertedSubject = "idmap.e2e.subject.9f3c"

// e2eLocalAccount returns an account that really exists on this machine,
// together with its real group membership. The fixture passwd file maps
// e2eAssertedSubject onto it, so the whole path -- subject to account to
// groups -- runs against a real user rather than an invented one.
func e2eLocalAccount(t *testing.T) (username, passwdPath string, realGroups []string) {
	t.Helper()
	u, err := user.Current()
	if err != nil || u.Username == "" {
		t.Skipf("cannot determine the current account: %v", err)
	}
	if _, err := exec.LookPath("id"); err != nil {
		t.Skip("id(1) is needed to read real group membership")
	}
	// id(1) is the test's oracle for real membership. The server under
	// test reaches the same answer without forking, which is the point.
	out, err := exec.CommandContext(t.Context(), "id", "-Gn", "--", u.Username).Output()
	if err != nil {
		t.Skipf("cannot read groups for %q: %v", u.Username, err)
	}
	groups := strings.Fields(string(out))
	if len(groups) == 0 {
		t.Skipf("%q has no groups", u.Username)
	}

	path := filepath.Join(t.TempDir(), "passwd")
	body := fmt.Sprintf("root:x:0:0:root:/root:/bin/bash\n%s:x:%s:%s:%s:%s:/bin/sh\n",
		u.Username, u.Uid, u.Gid, e2eAssertedSubject, u.HomeDir)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return u.Username, path, groups
}

// TestIdentityMappingEndToEnd drives a complete OIDC login -- authorize,
// SSO login, callback, code exchange -- against a server configured to
// resolve subjects locally, and then asks the server who it thinks the
// caller is.
//
// The assertion is deliberately made through /api/v1/whoami rather than
// by reading the session store: it is the answer every other endpoint
// acts on, so proving it is the mapped account proves the mapping
// reached the thing that matters.
func TestIdentityMappingEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("spins up a server and an SSO provider")
	}
	localAccount, passwdPath, realGroups := e2eLocalAccount(t)
	// Authorize on a group the account really is in, so that access is
	// granted only if the SYSTEM's group list reached the policy. A
	// token-sourced list could not contain it: the mock provider asserts
	// something else entirely.
	accessGroup := realGroups[0]

	ssoServer, ssoStorage, ssoBaseURL := setupMockSSOServer(t, "")
	t.Cleanup(func() { shutdownMockSSOServer(t, ssoServer) })

	// What the provider says about this person. The subject is not a
	// login name here, and the groups it asserts are deliberately wrong.
	ssoStorage.userInfos["ssouser"] = map[string]interface{}{
		"sub":    e2eAssertedSubject,
		"email":  "e2e@example.com",
		"name":   "End To End",
		"groups": []string{"a-group-the-account-is-not-in"},
	}

	server, baseURL := startIdentityMappedServer(t, ssoBaseURL, passwdPath, accessGroup, "")
	ssoStorage.callbackURL = baseURL + "/mcp/oauth2/callback"
	_ = server

	token := completeSSOLogin(t, baseURL, ssoBaseURL, "ssouser", "ssopassword")

	// Who does the server think this is?
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+"/api/v1/whoami", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var who WhoAmIResponse
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &who); err != nil {
		t.Fatalf("whoami returned %d: %s", resp.StatusCode, string(body))
	}
	if !who.Authenticated {
		t.Fatalf("whoami says unauthenticated after a complete login: %s", string(body))
	}
	if who.User != localAccount {
		t.Errorf("the server thinks the caller is %q; the asserted subject was %q and it maps to the account %q",
			who.User, e2eAssertedSubject, localAccount)
	}
	if who.User == e2eAssertedSubject {
		t.Errorf("the asserted subject reached the server unmapped")
	}
	t.Logf("subject %q resolved end to end to account %q (group %q from the system)",
		e2eAssertedSubject, who.User, accessGroup)
}

// TestIdentityMappingRefusesAnUnmappableLogin is the other half: a
// provider-authenticated caller who corresponds to no local account must
// not get a session, however valid their token is.
func TestIdentityMappingRefusesAnUnmappableLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("spins up a server and an SSO provider")
	}
	_, passwdPath, realGroups := e2eLocalAccount(t)

	ssoServer, ssoStorage, ssoBaseURL := setupMockSSOServer(t, "")
	t.Cleanup(func() { shutdownMockSSOServer(t, ssoServer) })

	// A perfectly good login at the provider, for somebody this access
	// point has never heard of.
	ssoStorage.userInfos["ssouser"] = map[string]interface{}{
		"sub":    "a.subject.no.account.carries",
		"email":  "stranger@example.com",
		"groups": []string{"admins"},
	}

	_, baseURL := startIdentityMappedServer(t, ssoBaseURL, passwdPath, realGroups[0], "")
	ssoStorage.callbackURL = baseURL + "/mcp/oauth2/callback"

	status, body := attemptSSOLogin(t, baseURL, ssoBaseURL, "ssouser", "ssopassword")
	if status == http.StatusOK || status == http.StatusFound {
		t.Fatalf("an unmappable caller was let in (status %d): %s", status, body)
	}
	if !strings.Contains(body, "does not correspond to a local account") {
		t.Errorf("status %d, but the reason is not the mapping failure: %s", status, body)
	}
	t.Logf("refused with %d: %s", status, strings.TrimSpace(body))
}

// startIdentityMappedServer starts a server that resolves subjects by
// GECOS and reads groups from the system.
func startIdentityMappedServer(t *testing.T, ssoBaseURL, passwdPath, accessGroup, usernameClaim string) (*Server, string) {
	t.Helper()
	tempDir := t.TempDir()

	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(passwordsDir, "POOL"), key, 0o600); err != nil {
		t.Fatal(err)
	}

	placeholder := "http://127.0.0.1:0"
	server, err := NewServer(Config{
		ListenAddr:          "127.0.0.1:0",
		ScheddName:          "local",
		ScheddAddr:          "127.0.0.1:9618",
		SigningKeyPath:      passwordsDir,
		TrustDomain:         "test.local",
		UIDDomain:           "test.local",
		EnableMCP:           true,
		OAuth2DBPath:        filepath.Join(tempDir, "oauth2.db"),
		OAuth2Issuer:        placeholder,
		OAuth2ClientID:      "mcp-client",
		OAuth2ClientSecret:  "mcp-secret",
		OAuth2AuthURL:       ssoBaseURL + "/authorize",
		OAuth2TokenURL:      ssoBaseURL + "/token",
		OAuth2RedirectURL:   placeholder + "/mcp/oauth2/callback",
		OAuth2UserInfoURL:   ssoBaseURL + "/userinfo",
		OAuth2GroupsClaim:   "groups",
		OAuth2UsernameClaim: usernameClaim,
		MCPAccessGroup:      accessGroup,

		// The thing under test.
		IdentityMapStrategies:    []idmap.Strategy{idmap.StrategyGecos},
		IdentityGroupsFromSystem: true,
		IdentityMapPasswdFile:    passwdPath,
		IdentityMapTTL:           time.Minute,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	errChan := make(chan error, 1)
	go func() { errChan <- server.Start() }()
	time.Sleep(500 * time.Millisecond)

	addr := server.GetAddr()
	if addr == "" {
		t.Fatal("server did not start")
	}
	baseURL := "http://" + addr
	server.UpdateOAuth2RedirectURL(baseURL + "/mcp/oauth2/callback")

	// The client the test drives the flow as. The server is both the
	// relying party to the mock SSO and an OAuth2 provider in its own
	// right, and this registers it with the latter.
	secret, err := bcrypt.GenerateFromPassword([]byte("mcp-secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.GetOAuth2Provider().GetStorage().CreateClient(context.Background(),
		&fosite.DefaultClient{
			ID:            "mcp-client",
			Secret:        secret,
			RedirectURIs:  []string{baseURL + "/callback"},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "mcp:read", "mcp:write", "offline_access"},
		}); err != nil {
		t.Fatalf("registering the test client: %v", err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	select {
	case err := <-errChan:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("server error: %v", err)
		}
	default:
	}
	return server, baseURL
}

// attemptSSOLogin runs the flow and returns whatever the callback
// answered, so a refusal can be inspected rather than fatal.
func attemptSSOLogin(t *testing.T, baseURL, ssoBaseURL, username, password string) (int, string) {
	t.Helper()
	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	authURL := fmt.Sprintf(
		"%s/mcp/oauth2/authorize?response_type=code&client_id=mcp-client&redirect_uri=%s/callback&scope=openid&state=e2estate",
		baseURL, baseURL)
	resp := mustGet(t, client, authURL, "start authorization")
	ssoAuth := location(t, resp, ssoBaseURL)

	resp = mustGet(t, client, ssoAuth, "follow to SSO")
	loginURL := location(t, resp, ssoBaseURL)

	loginResp, err := client.PostForm(loginURL, url.Values{
		"username": {username}, "password": {password},
	})
	if err != nil {
		t.Fatalf("submit login: %v", err)
	}
	defer func() { _ = loginResp.Body.Close() }()
	authorizeURL := location(t, loginResp, ssoBaseURL)

	resp = mustGet(t, client, authorizeURL, "authorize after login")
	callbackURL := location(t, resp, baseURL)

	cbResp, err := client.Get(callbackURL) //nolint:noctx // helper drives a redirect chain
	if err != nil {
		t.Fatalf("follow callback: %v", err)
	}
	defer func() { _ = cbResp.Body.Close() }()
	body, _ := io.ReadAll(cbResp.Body)
	if loc := cbResp.Header.Get("Location"); loc != "" {
		return cbResp.StatusCode, loc
	}
	return cbResp.StatusCode, string(body)
}

// completeSSOLogin runs the flow to a usable access token.
func completeSSOLogin(t *testing.T, baseURL, ssoBaseURL, username, password string) string {
	t.Helper()
	status, target := attemptSSOLogin(t, baseURL, ssoBaseURL, username, password)
	if status != http.StatusFound && status != http.StatusSeeOther {
		t.Fatalf("callback did not redirect back to the client: status %d, %s", status, target)
	}
	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("callback redirect %q: %v", target, err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("no authorization code in %q", target)
	}

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {baseURL + "/callback"},
		"client_id":    {"mcp-client"},
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		baseURL+"/mcp/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("mcp-client", "mcp-secret")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}
	return tok.AccessToken
}

func mustGet(t *testing.T, c *http.Client, rawURL, what string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func location(t *testing.T, resp *http.Response, base string) string {
	t.Helper()
	loc := resp.Header.Get("Location")
	if loc == "" {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected a redirect, got %d: %s", resp.StatusCode, string(body))
	}
	if strings.HasPrefix(loc, "/") {
		loc = base + loc
	}
	return loc
}

// Not every provider puts the name in `sub`. Federated identity commonly
// carries it in eduPersonPrincipalName, and `sub` is then an opaque
// pairwise identifier that matches no account anywhere.
//
// HTTP_API_OAUTH2_USERNAME_CLAIM selects which claim is read, and that
// claim is the INPUT to everything else here -- so this asserts the
// configured claim drives the mapping and that `sub` is ignored when it
// does. Nothing covered that before, in either feature.
func TestIdentityMappingReadsTheConfiguredClaim(t *testing.T) {
	if testing.Short() {
		t.Skip("spins up a server and an SSO provider")
	}
	localAccount, passwdPath, realGroups := e2eLocalAccount(t)

	ssoServer, ssoStorage, ssoBaseURL := setupMockSSOServer(t, "")
	t.Cleanup(func() { shutdownMockSSOServer(t, ssoServer) })

	// eppn carries the identity this access point knows; sub is an
	// opaque pairwise id that maps to nothing. If sub were read, the
	// login would be refused -- which is what makes this discriminating.
	ssoStorage.userInfos["ssouser"] = map[string]interface{}{
		"sub":    "f47ac10b-58cc-4372-a567-0e02b2c3d479",
		"eppn":   e2eAssertedSubject,
		"email":  "e2e@example.com",
		"groups": []string{"a-group-the-account-is-not-in"},
	}

	_, baseURL := startIdentityMappedServer(t, ssoBaseURL, passwdPath, realGroups[0], "eppn")
	ssoStorage.callbackURL = baseURL + "/mcp/oauth2/callback"

	token := completeSSOLogin(t, baseURL, ssoBaseURL, "ssouser", "ssopassword")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+"/api/v1/whoami", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var who WhoAmIResponse
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &who); err != nil {
		t.Fatalf("whoami returned %d: %s", resp.StatusCode, string(body))
	}
	if !who.Authenticated || who.User != localAccount {
		t.Fatalf("whoami = %+v, want the account %q reached via the eppn claim: %s",
			who, localAccount, string(body))
	}
	if strings.Contains(who.User, "f47ac10b") {
		t.Error("the opaque sub reached the session; the configured claim was not used")
	}
	t.Logf("eppn %q resolved to account %q while sub was ignored", e2eAssertedSubject, who.User)
}
