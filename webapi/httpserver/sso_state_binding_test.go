package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

// Values the fake IdP asserts that must never reach an Info log line.
const (
	ssoTestSubject = "alice"
	ssoTestEmail   = "alice.private@example.org"
	ssoTestGroup   = "grp-private-membership"
)

// newSSOBindingServer returns a server configured as an OAuth2 client of
// a fake IdP whose token endpoint accepts any code and whose userinfo
// endpoint answers for ssoTestSubject. Logging is at Debug so the test
// sees exactly what the admin log buffer (Info and above) keeps.
func newSSOBindingServer(t *testing.T) *Server {
	t.Helper()
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "upstream-access", "token_type": "Bearer", "expires_in": 3600,
			})
		case "/userinfo":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub": ssoTestSubject, "email": ssoTestEmail, "name": "Alice Private",
				"groups": []string{ssoTestGroup},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)

	logger, err := logging.New(&logging.Config{OutputPath: "stderr", DefaultLevel: logging.VerbosityDebug})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(Config{ //nolint:gosec // G101: test credentials
		Logger:             logger,
		EnableMCP:          true,
		ScheddName:         "test-schedd",
		ScheddAddr:         "127.0.0.1:9618",
		OAuth2DBPath:       t.TempDir() + "/oauth2.db",
		OAuth2Issuer:       "https://ap.example.org",
		OAuth2ClientID:     "ap-client",
		OAuth2ClientSecret: "ap-secret",
		OAuth2AuthURL:      idp.URL + "/authorize",
		OAuth2TokenURL:     idp.URL + "/token",
		OAuth2UserInfoURL:  idp.URL + "/userinfo",
		OAuth2RedirectURL:  "https://ap.example.org" + mcpCallbackPath,
		OAuth2GroupsClaim:  "groups",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	server.setupRoutes()
	return server
}

func serveSSO(server *Server, target string, cookies ...*http.Cookie) *http.Response {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	req.Header.Set("Accept", "text/html")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	return rec.Result()
}

func responseCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name && c.MaxAge >= 0 && c.Value != "" {
			return c
		}
	}
	return nil
}

// startSSOLogin begins a login at start and returns the state sent to
// the IdP and the binding cookie the browser was given.
func startSSOLogin(t *testing.T, server *Server, start string) (string, *http.Cookie) {
	t.Helper()
	resp := serveSSO(server, start)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET %s: status %d, want a redirect to the IdP", start, resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || !strings.HasSuffix(loc.Path, "/authorize") {
		t.Fatalf("GET %s redirected to %q, not the IdP", start, resp.Header.Get("Location"))
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatalf("no state in %s", loc)
	}
	binding := responseCookie(resp, loginBindingCookieName)
	if binding == nil {
		t.Fatalf("GET %s set no %s cookie", start, loginBindingCookieName)
	}
	if binding.SameSite != http.SameSiteLaxMode || !binding.Secure || !binding.HttpOnly {
		t.Errorf("binding cookie attributes: SameSite=%v Secure=%v HttpOnly=%v",
			binding.SameSite, binding.Secure, binding.HttpOnly)
	}
	return state, binding
}

func callbackURL(state string) string {
	return mcpCallbackPath + "?" + url.Values{"state": {state}, "code": {"idp-code"}}.Encode()
}

// registerSSOTestClient registers the OAuth2 client an MCP authorize
// request names.
func registerSSOTestClient(t *testing.T, server *Server) string {
	t.Helper()
	secret, err := bcrypt.GenerateFromPassword([]byte("client-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.GetOAuth2Provider().GetStorage().CreateClient(context.Background(), &fosite.DefaultClient{
		ID:            "binding-test-client",
		Secret:        secret,
		RedirectURIs:  []string{"https://client.example.org/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "mcp:read"},
	}); err != nil {
		t.Fatal(err)
	}
	return OAuth2EndpointPath("authorize") + "?" + url.Values{
		"response_type": {"code"},
		"client_id":     {"binding-test-client"},
		"redirect_uri":  {"https://client.example.org/cb"},
		"scope":         {"openid mcp:read"},
		"state":         {"client-state-0123456789"},
	}.Encode()
}

// Every path that sends a browser to the IdP binds the login to that
// browser, and the callback refuses the state from any other browser:
// no cookie, or somebody else's. The refused state is consumed, so it
// cannot be retried, and no session cookie is issued.
func TestSSOCallbackRequiresTheStartingBrowser(t *testing.T) {
	server := newSSOBindingServer(t)
	starts := map[string]string{
		"login":         "/login?return_to=/jobs",
		"device verify": mcpDeviceVerifyPath + "?user_code=ABCD-EFGH",
		"authorize":     registerSSOTestClient(t, server),
	}
	for name, start := range starts {
		t.Run(name, func(t *testing.T) {
			// Another browser's binding: a valid nonce, just not this login's.
			_, other := startSSOLogin(t, server, "/login")

			for _, tc := range []struct {
				name    string
				cookies []*http.Cookie
			}{
				{"missing cookie", nil},
				{"another browser's cookie", []*http.Cookie{other}},
			} {
				state, own := startSSOLogin(t, server, start)
				if own.Value == other.Value {
					t.Fatal("two browsers were given the same binding")
				}
				resp := serveSSO(server, callbackURL(state), tc.cookies...)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusBadRequest {
					t.Errorf("%s: callback status %d, want 400", tc.name, resp.StatusCode)
				}
				if c := responseCookie(resp, sessionCookieName); c != nil {
					t.Errorf("%s: callback issued a session cookie", tc.name)
				}
				// The entry is gone: the right browser cannot complete it now.
				resp = serveSSO(server, callbackURL(state), own)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusBadRequest || responseCookie(resp, sessionCookieName) != nil {
					t.Errorf("%s: refused state was still redeemable (status %d)", tc.name, resp.StatusCode)
				}
			}
		})
	}
}

// The browser that started the login completes it: a session for the
// browser flows, the consent step for an MCP authorization.
func TestSSOCallbackAcceptsTheStartingBrowser(t *testing.T) {
	server := newSSOBindingServer(t)

	for _, start := range []string{"/login?return_to=/jobs", mcpDeviceVerifyPath + "?user_code=ABCD-EFGH"} {
		state, binding := startSSOLogin(t, server, start)
		resp := serveSSO(server, callbackURL(state), binding)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: callback status %d, want the 200 page that finishes a browser login", start, resp.StatusCode)
		}
		session := responseCookie(resp, sessionCookieName)
		if session == nil {
			t.Fatalf("%s: no session cookie after a valid login", start)
		}
		data := server.sessionStore.Get(session.Value)
		if data == nil || data.Username != ssoTestSubject {
			t.Errorf("%s: session is for %+v, want %q", start, data, ssoTestSubject)
		}
	}

	// Two logins in flight in one browser share its binding, so the
	// second does not invalidate the first.
	first, binding := startSSOLogin(t, server, "/login")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/login", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(binding)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if again := responseCookie(rec.Result(), loginBindingCookieName); again == nil || again.Value != binding.Value {
		t.Errorf("a second login replaced the browser's binding")
	}
	resp := serveSSO(server, callbackURL(first), binding)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("first of two concurrent logins: callback status %d", resp.StatusCode)
	}

	state, binding := startSSOLogin(t, server, registerSSOTestClient(t, server))
	resp = serveSSO(server, callbackURL(state), binding)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "/consent?state=") {
		t.Errorf("authorize callback: status %d to %q, want the consent step", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// A completed login leaves the subject in the admin log view and nothing
// else the IdP said about the person.
func TestSSOLoginKeepsClaimsOutOfInfoLogs(t *testing.T) {
	server := newSSOBindingServer(t)
	state, binding := startSSOLogin(t, server, "/login")
	resp := serveSSO(server, callbackURL(state), binding)
	_ = resp.Body.Close()
	if responseCookie(resp, sessionCookieName) == nil {
		t.Fatalf("login did not complete (status %d)", resp.StatusCode)
	}

	sawSubject := false
	for _, e := range server.logBuffer.Entries(0) {
		line := fmt.Sprintf("%s %v", e.Message, e.Fields)
		for _, private := range []string{ssoTestEmail, ssoTestGroup, "Alice Private"} {
			if strings.Contains(line, private) {
				t.Errorf("%s line carries %q: %s", e.Level, private, line)
			}
		}
		if e.Message == "User authenticated via SSO" && e.Fields["subject"] == ssoTestSubject {
			sawSubject = true
		}
	}
	if !sawSubject {
		t.Error("no Info line names the subject; the buffer may not be capturing this flow")
	}
}

// The state store is filled by unauthenticated requests, so it holds at
// most maxOAuth2StateEntries, evicting the oldest, and a return URL too
// long to keep is dropped rather than stored.
func TestOAuth2StateStoreIsBounded(t *testing.T) {
	server := newSSOBindingServer(t)
	store := server.oauth2StateStore

	firstState, _ := startSSOLogin(t, server, "/login")
	total := 2 * maxOAuth2StateEntries
	var last string
	for i := 1; i < total; i++ {
		last, _ = startSSOLogin(t, server, "/login")
	}
	if n := store.Len(); n > maxOAuth2StateEntries {
		t.Errorf("%d states stored after %d logins, cap is %d", n, total, maxOAuth2StateEntries)
	}
	if _, _, _, ok := store.GetWithUsername(firstState); ok {
		t.Error("the oldest state survived past the cap")
	}
	if _, _, _, ok := store.GetWithUsername(last); !ok {
		t.Error("the newest state was evicted")
	}

	long := "/jobs?q=" + strings.Repeat("x", 4*maxOAuth2StateURLLen)
	state, binding := startSSOLogin(t, server, "/login?return_to="+url.QueryEscape(long))
	entry, ok := store.Take(state)
	if !ok {
		t.Fatal("state for a long return URL was not stored")
	}
	if len(entry.OriginalURL) > maxOAuth2StateURLLen {
		t.Errorf("stored a %d-byte return URL, cap is %d", len(entry.OriginalURL), maxOAuth2StateURLLen)
	}
	if entry.BrowserBinding != binding.Value {
		t.Error("stored binding does not match the cookie")
	}
}
