package httpserver

import (
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"

	"golang.org/x/oauth2"
)

// offlineHandler is a Handler with just enough of the SSO wiring to
// drive the scope negotiation.
func offlineHandler(t *testing.T, scopes []string, optIn bool) *Handler {
	t.Helper()
	h := &Handler{
		oauth2Config: &oauth2.Config{
			ClientID:    "c",
			RedirectURL: "https://ap/callback",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp/authorize", TokenURL: "https://idp/token"},
			Scopes:      scopes,
		},
		oauth2StateStore:   NewOAuth2StateStore(),
		offlineAccessOptIn: optIn,
		logger:             testLogger(t),
	}
	return h
}

// scopeOf pulls the scope parameter out of an authorize URL.
func scopeOf(t *testing.T, raw string) []string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return strings.Fields(u.Query().Get("scope"))
}

// Until the provider objects, every sign-in asks for offline_access --
// that request is the only way a refresh token ever arrives, and
// without one upstreamUserInfoOracle has nothing to ask with.
func TestSignInAsksForOfflineAccess(t *testing.T) {
	h := offlineHandler(t, []string{"openid", "profile", "email", "offline_access"}, true)
	if got := scopeOf(t, h.authCodeURL("s1")); !slices.Contains(got, "offline_access") {
		t.Errorf("authorize URL scopes = %v, want offline_access among them", got)
	}
}

// A provider that refuses it must not take the pool's logins down with
// it. The refusal is absorbed: the browser is sent back where it was
// going, and the retry asks without the scope.
func TestRefusedOfflineAccessIsAbsorbedAndRetried(t *testing.T) {
	h := offlineHandler(t, []string{"openid", "email", "offline_access"}, true)

	state, err := h.oauth2StateStore.GenerateState()
	if err != nil {
		t.Fatalf("GenerateState: %v", err)
	}
	h.oauth2StateStore.StoreForBrowser(state, nil, "/jobs", "bind")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/callback?error=invalid_scope&state="+state, nil)
	if !h.dropOfflineAccessAndRetry(w, r, "invalid_scope", "", state) {
		t.Fatal("an invalid_scope refusal of a scope this server added was not absorbed")
	}
	if w.Code != 302 {
		t.Errorf("status = %d, want a redirect back into the retry", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/jobs" {
		t.Errorf("retry sent the browser to %q, want the page it was going to (/jobs)", got)
	}
	// And the retry asks for less, which is what stops it looping.
	if got := scopeOf(t, h.authCodeURL("s2")); slices.Contains(got, "offline_access") {
		t.Errorf("the sign-in after a refusal still asked for offline_access: %v", got)
	}
}

// Only once. A second invalid_scope is about some other scope, so it
// belongs on the error page where an operator can read it.
func TestSecondRefusalIsNotAbsorbed(t *testing.T) {
	h := offlineHandler(t, []string{"openid", "offline_access"}, true)
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/callback?error=invalid_scope", nil)
	if !h.dropOfflineAccessAndRetry(w1, r1, "invalid_scope", "", "") {
		t.Fatal("first refusal was not absorbed")
	}
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/callback?error=invalid_scope", nil)
	if h.dropOfflineAccessAndRetry(w2, r2, "invalid_scope", "", "") {
		t.Error("a second refusal was absorbed too; it is about a scope this server did not add")
	}
}

// A scope the OPERATOR configured is not this server's to withdraw.
// Dropping it would silently contradict their configuration, so the
// refusal is reported instead.
func TestOperatorConfiguredOfflineAccessIsNotDropped(t *testing.T) {
	h := offlineHandler(t, []string{"openid", "offline_access"}, false) // not opted in by us
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/callback?error=invalid_scope", nil)
	if h.dropOfflineAccessAndRetry(w, r, "invalid_scope", "", "") {
		t.Error("withdrew a scope the operator asked for")
	}
	if got := scopeOf(t, h.authCodeURL("s")); !slices.Contains(got, "offline_access") {
		t.Errorf("operator's scope went missing: %v", got)
	}
}

// Any other refusal is somebody else's problem and must reach the
// error page unchanged.
func TestOtherRefusalsAreNotAbsorbed(t *testing.T) {
	h := offlineHandler(t, []string{"openid", "offline_access"}, true)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/callback?error=access_denied", nil)
	if h.dropOfflineAccessAndRetry(w, r, "access_denied", "", "") {
		t.Error("absorbed a refusal that had nothing to do with scopes")
	}
}

// An open-redirect through the retry would be a nasty way to repay a
// provider error: the target comes from the stored state and is only
// used when it is local.
func TestRetryWillNotFollowAnOffsiteTarget(t *testing.T) {
	h := offlineHandler(t, []string{"openid", "offline_access"}, true)
	state, err := h.oauth2StateStore.GenerateState()
	if err != nil {
		t.Fatalf("GenerateState: %v", err)
	}
	h.oauth2StateStore.StoreForBrowser(state, nil, "https://evil.example/pwn", "bind")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/callback?error=invalid_scope&state="+state, nil)
	if !h.dropOfflineAccessAndRetry(w, r, "invalid_scope", "", state) {
		t.Fatal("refusal was not absorbed")
	}
	if got := w.Header().Get("Location"); got != "/" {
		t.Errorf("retry followed an offsite target: %q", got)
	}
}

// A refusal that names a DIFFERENT scope is not ours to absorb.
// Dropping offline_access would not change the provider's mind, and it
// would cost the operator the one message naming what to fix -- which
// is the CILogon failure this whole hint exists for.
func TestRefusalNamingAnotherScopeIsLeftAlone(t *testing.T) {
	h := offlineHandler(t, []string{"openid", "profile", "email", "offline_access"}, true)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/callback?error=invalid_scope", nil)
	desc := `Malformed scope parameter. Unrecognized scope "profile"`
	if h.dropOfflineAccessAndRetry(w, r, "invalid_scope", desc, "") {
		t.Error("absorbed a refusal that named profile; retrying without offline_access fixes nothing")
	}
	if h.offlineAccessRefused.Load() {
		t.Error("latched offline_access off over a refusal about another scope")
	}
}

// Named explicitly, it is absorbed.
func TestRefusalNamingOfflineAccessIsAbsorbed(t *testing.T) {
	h := offlineHandler(t, []string{"openid", "offline_access"}, true)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/callback?error=invalid_scope", nil)
	if !h.dropOfflineAccessAndRetry(w, r, "invalid_scope", `Unrecognized scope "offline_access"`, "") {
		t.Error("a refusal naming offline_access was not absorbed")
	}
}

// serverWithUpstreamRefresh builds a real server the way a deployment
// does -- no OAuth2Scopes set, so the defaults apply -- at the given
// HTTP_API_UPSTREAM_REFRESH mode.
func serverWithUpstreamRefresh(t *testing.T, mode string) *Server {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Config{ //nolint:gosec // G101: test credentials
		Logger:             logger,
		WebUIEnabled:       true,
		OAuth2ClientID:     "test-client",
		OAuth2ClientSecret: "test-secret",
		OAuth2AuthURL:      "https://idp.example.com/authorize",
		OAuth2TokenURL:     "https://idp.example.com/token",
		OAuth2RedirectURL:  "https://server.example.com" + webUICallbackPath,
		OAuth2Issuer:       "https://server.example.com",
		UpstreamRefresh:    mode,
		ScheddName:         "test-schedd",
		ScheddAddr:         "127.0.0.1:9618",
		OAuth2DBPath:       t.TempDir() + "/sessions.db",
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The feature, end to end through the real constructor: a server built
// the way a deployment builds one asks the provider for offline_access.
//
// Everything downstream is conditional on the token this request brings
// back -- the store only has a row because the provider returned one,
// and upstreamUserInfoOracle only has an opinion because the store has
// a row. Without the request the oracle is registered and permanently
// silent, which is exactly the state this change exists to fix.
func TestDefaultServerAsksForOfflineAccess(t *testing.T) {
	for _, mode := range []string{"", "auto", "on"} {
		t.Run("mode="+mode, func(t *testing.T) {
			s := serverWithUpstreamRefresh(t, mode)
			if !s.offlineAccessOptIn {
				t.Error("the server did not add offline_access, so nothing records that it may drop it again")
			}
			if got := scopeOf(t, s.authCodeURL("st")); !slices.Contains(got, "offline_access") {
				t.Errorf("authorize scopes = %v, want offline_access among them", got)
			}
		})
	}
}

// And off means off: a deployment that would rather not hold a key to
// somebody else's identity provider does not ask for one either.
func TestUpstreamRefreshOffDoesNotAsk(t *testing.T) {
	s := serverWithUpstreamRefresh(t, "off")
	if s.offlineAccessOptIn {
		t.Error("opted in to offline_access with upstream refresh off")
	}
	if got := scopeOf(t, s.authCodeURL("st")); slices.Contains(got, "offline_access") {
		t.Errorf("asked for offline_access with upstream refresh off: %v", got)
	}
}
