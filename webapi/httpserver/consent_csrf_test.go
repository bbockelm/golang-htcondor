package httpserver

import (
	"bytes"
	"context"

	"encoding/json"
	"github.com/PelicanPlatform/classad/collections/crypt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A token is bound to the person and to the request it was minted for.
//
// Those are the two confusions that matter: one person's token must not
// approve another's form, and a token for one authorization must not
// approve a different one.
func TestConsentCSRFTokenIsBoundToBothHalves(t *testing.T) {
	h := &Handler{}
	base := h.consentCSRFToken("alice", "state-1")

	if same := h.consentCSRFToken("alice", "state-1"); same != base {
		t.Fatal("the same person and request produced two different tokens")
	}
	if other := h.consentCSRFToken("bob", "state-1"); other == base {
		t.Error("another person's token verifies against this form")
	}
	if other := h.consentCSRFToken("alice", "state-2"); other == base {
		t.Error("a token for another request verifies against this form")
	}
	// Length-prefixed, so a crafted name cannot borrow part of the
	// binding: "alice" + "x-state" must not collide with "alicex" +
	// "-state".
	if h.consentCSRFToken("alice", "x-state") == h.consentCSRFToken("alicex", "-state") {
		t.Error("a crafted username can borrow part of the binding")
	}
}

// An absent token is refused, not grandfathered.
//
// A form with no field is a form from before this existed, and accepting
// one would leave the hole open to anybody who could replay an old page.
func TestConsentCSRFRefusesAnAbsentToken(t *testing.T) {
	h := &Handler{}
	r := formRequest(t, map[string]string{"state": "state-1", "action": "approve"})
	if h.checkConsentCSRF(r, "alice", "state-1") {
		t.Fatal("a form with no token was accepted")
	}
}

func TestConsentCSRFRefusesTheWrongToken(t *testing.T) {
	h := &Handler{}
	for _, tc := range []struct{ name, token, user, binding string }{
		{"another person's", h.consentCSRFToken("bob", "state-1"), "alice", "state-1"},
		{"another request's", h.consentCSRFToken("alice", "state-2"), "alice", "state-1"},
		{"nonsense", "not-a-token", "alice", "state-1"},
		{"empty", "", "alice", "state-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := formRequest(t, map[string]string{consentCSRFField: tc.token})
			if h.checkConsentCSRF(r, tc.user, tc.binding) {
				t.Fatalf("%s token was accepted", tc.name)
			}
		})
	}
}

// The refusal says the same thing whatever was wrong with the token, so
// probing it does not report which half was right.
func TestConsentRefusalDoesNotSayWhatWasWrong(t *testing.T) {
	h := &Handler{logger: testLogger(t)}
	var bodies []string
	for _, token := range []string{"", "not-a-token", h.consentCSRFToken("bob", "state-1")} {
		r := formRequest(t, map[string]string{consentCSRFField: token})
		w := newRecorder()
		h.refuseStaleConsent(w, r, "alice", "test")
		bodies = append(bodies, w.Body.String())
	}
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Fatalf("the refusal differs by what was wrong:\n%s\nvs\n%s", bodies[0], bodies[i])
		}
	}
	if strings.Contains(bodies[0], "alice") || strings.Contains(bodies[0], "state-1") {
		t.Errorf("the refusal echoes back what was posted: %s", bodies[0])
	}
}

func formRequest(t *testing.T, fields map[string]string) *http.Request {
	t.Helper()
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/mcp/oauth2/consent", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func newRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }

// The consent handler refuses a form that carries no token.
//
// At the handler, not at the helper. The helper's own tests passed
// against a build with the check deleted from both POST handlers --
// found by mutation, which is the whole reason this test exists.
func TestConsentHandlerRefusesAFormWithNoToken(t *testing.T) {
	server, oauth2Provider, clientID, ctx := setupTestOAuth2Server(t)
	t.Cleanup(func() { _ = oauth2Provider.Close() })

	state := storeConsentState(ctx, t, server, oauth2Provider, clientID, "testuser")

	// Everything a real approval carries, except the token.
	form := url.Values{"state": {state}, "action": {"approve"}}
	w := postConsent(t, server, form)

	if w.Code == http.StatusFound || w.Code == http.StatusSeeOther {
		t.Fatalf("a consent form with no token was approved: %d -> %s",
			w.Code, w.Header().Get("Location"))
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400: %s", w.Code, w.Body.String())
	}
}

// And one minted for somebody else is refused too -- the binding has to
// be enforced where it is used, not only where it is computed.
func TestConsentHandlerRefusesAnotherPersonsToken(t *testing.T) {
	server, oauth2Provider, clientID, ctx := setupTestOAuth2Server(t)
	t.Cleanup(func() { _ = oauth2Provider.Close() })

	state := storeConsentState(ctx, t, server, oauth2Provider, clientID, "testuser")
	w := postConsent(t, server, url.Values{
		"state":          {state},
		"action":         {"approve"},
		consentCSRFField: {server.consentCSRFToken("mallory", state)},
	})

	if w.Code == http.StatusFound || w.Code == http.StatusSeeOther {
		t.Fatalf("another person's token approved this form: %d -> %s",
			w.Code, w.Header().Get("Location"))
	}
}

// A correctly-minted token still gets through, so the tests above are
// not passing because approval is broken outright.
func TestConsentHandlerAcceptsTheRightToken(t *testing.T) {
	server, oauth2Provider, clientID, ctx := setupTestOAuth2Server(t)
	t.Cleanup(func() { _ = oauth2Provider.Close() })

	state := storeConsentState(ctx, t, server, oauth2Provider, clientID, "testuser")
	w := postConsent(t, server, url.Values{
		"state":          {state},
		"action":         {"approve"},
		consentCSRFField: {server.consentCSRFToken("testuser", state)},
	})

	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Fatalf("a correctly-minted token was refused: %d %s", w.Code, w.Body.String())
	}
}

func postConsent(t *testing.T, server *Server, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/mcp/oauth2/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	server.handleOAuth2Consent(w, req)
	return w
}

// storeConsentState builds an authorize request and parks it under a
// fresh state, the way handleOAuth2Authorize does before rendering.
func storeConsentState(ctx context.Context, t *testing.T, server *Server,
	provider *OAuth2Provider, clientID, username string) string {
	t.Helper()
	authorizeReq := httptest.NewRequestWithContext(ctx, http.MethodGet, "/mcp/oauth2/authorize", nil)
	authorizeReq.URL.RawQuery = url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {"http://localhost:8080/callback"},
		"scope":         {"openid"},
		"state":         {"teststate1234567890"},
		"nonce":         {"noncevalue1234567890"},
	}.Encode()
	ar, err := provider.GetProvider().NewAuthorizeRequest(ctx, authorizeReq)
	if err != nil {
		t.Fatalf("NewAuthorizeRequest: %v", err)
	}
	state, err := server.oauth2StateStore.GenerateState()
	if err != nil {
		t.Fatalf("GenerateState: %v", err)
	}
	server.oauth2StateStore.StoreWithUsername(state, ar, "", username)
	return state
}

// The device verification handler refuses an approval with no token.
//
// Its own mutation survived the helper's tests: deleting the check from
// this handler broke nothing, because every other test that posts here
// supplies a token. A tested primitive proves nothing about whether it
// is reached.
func TestDeviceVerifyRefusesAnApprovalWithNoToken(t *testing.T) {
	srv := startDeviceConsentServer(t)
	userCode := issueDeviceCode(t, srv)

	w := postDeviceVerify(t, srv, url.Values{
		"user_code": {userCode},
		"action":    {"approve"},
	})
	if w.Code == http.StatusFound || w.Code == http.StatusSeeOther {
		t.Fatalf("an approval with no token succeeded: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "no longer valid") {
		t.Errorf("status %d, body does not say the form is stale: %s", w.Code, w.Body.String())
	}
}

// And the correct token still gets through, so the test above is not
// passing because approval is broken outright.
func TestDeviceVerifyAcceptsTheRightToken(t *testing.T) {
	srv := startDeviceConsentServer(t)
	userCode := issueDeviceCode(t, srv)

	w := postDeviceVerify(t, srv, url.Values{
		"user_code":      {userCode},
		"action":         {"approve"},
		consentCSRFField: {srv.consentCSRFToken(deviceVerifyTestUser, userCode)},
	})
	if strings.Contains(w.Body.String(), "no longer valid") {
		t.Fatalf("a correctly-minted token was refused as stale: %d %s", w.Code, w.Body.String())
	}
}

// deviceVerifyTestUser is the name the user header carries, and so the
// name the token is bound to.
const deviceVerifyTestUser = "bbockelm"

// issueDeviceCode runs a real device authorization and returns its user
// code, so the handler sees a session it actually stored.
func issueDeviceCode(t *testing.T, srv *Server) string {
	t.Helper()
	form := url.Values{}
	form.Set("client_id", registerDeviceVerifyClient(t, srv))
	form.Set("scope", "openid")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/mcp/oauth2/device/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("device authorization failed: %d %s", w.Code, w.Body.String())
	}
	var got struct {
		UserCode string `json:"user_code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.UserCode == "" {
		t.Fatalf("no user_code in the response: %v (%s)", err, w.Body.String())
	}
	return got.UserCode
}

// postDeviceVerify posts to the verification handler as an identified
// browser user, through the user header the server trusts.
func postDeviceVerify(t *testing.T, srv *Server, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/mcp/oauth2/device/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Test-User", deviceVerifyTestUser)
	w := httptest.NewRecorder()
	srv.handleOAuth2DeviceVerify(w, req)
	return w
}

// startDeviceConsentServer is startDeviceVerifyServer plus the user
// header, so these tests can arrive as an identified browser user.
//
// Its own helper rather than a flag on the shared one: other tests
// depend on that server's exact shape, and a parameter nobody else
// passes is a parameter nobody else reads.
func startDeviceConsentServer(t *testing.T) *Server {
	t.Helper()
	cfg := newTestConfig(t)
	cfg.Logger = testLogger(t)
	cfg.EnableMCP = true
	cfg.OAuth2DBPath = t.TempDir() + "/oauth2.db"
	cfg.SigningKeyPath = writeSigningKey(t)
	cfg.TrustDomain = "flock.example.org"
	cfg.UIDDomain = "example.org"
	cfg.UserHeader = "X-Test-User"
	cfg.UserHeaderTrustAnyUnsafe = true // single-host test, no proxy in front
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := s.Handler.Start(t.Context(), ln, "http"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return s
}

// The key comes from the application master, so it survives a restart
// and is the same on every replica.
//
// Two Handlers over one master stand in for two pods, or for the same
// pod before and after a deploy. A per-process key -- what this used to
// be -- gives them different answers, so a form rendered by one would be
// refused by the other.
//
// The envelope itself (wrapping the master under each pool signing key,
// recovering it, rotating one in) is TestTheMasterKeySurvivesAndRotates'
// subject; this is about what hangs off it.
func TestConsentCSRFKeyComesFromTheMaster(t *testing.T) {
	master, err := crypt.NewMaster()
	if err != nil {
		t.Fatal(err)
	}
	first := masterBackedHandler(t, master)
	second := masterBackedHandler(t, master)

	a := first.consentCSRFToken("alice", "state-1")
	b := second.consentCSRFToken("alice", "state-1")
	if a != b {
		t.Fatalf("two Handlers over one master disagree:\n  %s\n  %s\n"+
			"a form rendered by one would be refused by the other", a, b)
	}

	// A different master gives different answers, so the test above is
	// not passing because the key is ignored.
	other, err := crypt.NewMaster()
	if err != nil {
		t.Fatal(err)
	}
	if c := masterBackedHandler(t, other).consentCSRFToken("alice", "state-1"); c == a {
		t.Error("a different master produced the same token; the key is not being used")
	}

	// Each purpose gets its own subkey, so a token minted for the SSH
	// approval screen cannot verify as a consent token.
	if bytes.Equal(first.consentCSRFKey(), first.sshApprovalKey()) {
		t.Error("the consent form and the SSH approval screen share a key")
	}
}

// Without pool signing keys there is no master, and the fallback is a
// per-process key: the page still works, and the log says what was lost.
func TestConsentCSRFFallsBackWithoutSigningKeys(t *testing.T) {
	a := (&Handler{logger: testLogger(t)}).consentCSRFToken("alice", "state-1")
	b := (&Handler{logger: testLogger(t)}).consentCSRFToken("alice", "state-1")
	if a == b {
		t.Fatal("two Handlers with no master produced the same key; " +
			"the fallback is supposed to be per-process")
	}
	if a == "" {
		t.Fatal("no token at all; the consent page would be unusable")
	}
}

// masterBackedHandler returns a Handler already holding master, as one
// that had opened the envelope would.
func masterBackedHandler(t *testing.T, master []byte) *Handler {
	t.Helper()
	h := &Handler{logger: testLogger(t)}
	h.masterKeyOnce.Do(func() { h.masterKeyBytes = master })
	return h
}
