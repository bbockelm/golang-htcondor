package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/bbockelm/golang-htcondor/idmap"
)

// placementSSOServer is a server whose SSO goes to a fake provider and
// whose identity mapping finds no local account for the claims it returns.
func placementSSOServer(t *testing.T, claims map[string]any) *onboardingServer {
	t.Helper()
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600})
		case "/userinfo":
			_ = json.NewEncoder(w).Encode(claims)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)

	srv, err := NewServer(Config{
		Logger:         newTestLogger(t),
		ScheddName:     "ap.example",
		ScheddAddr:     "127.0.0.1:1",
		EnableMCP:      true,
		OAuth2DBPath:   t.TempDir() + "/oauth2.db",
		OAuth2Issuer:   "http://localhost:8080",
		SigningKeyPath: writeTestSigningKey(t),
		TrustDomain:    "test.domain",
		SessionTTL:     time.Hour,
		Placementd:     newOnboardFake(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.oauth2Config = &oauth2.Config{ClientID: "c", ClientSecret: "s",
		Endpoint: oauth2.Endpoint{AuthURL: idp.URL + "/auth", TokenURL: idp.URL + "/token"}}
	srv.oauth2UserInfoURL = idp.URL + "/userinfo"
	srv.localIdentity = newLocalIdentity([]idmap.Strategy{idmap.StrategyGecos}, nil, writePasswd(t), time.Minute, false, testLogger(t))
	srv.placementOnboard.identityClaims = []string{"eppn", "sub"}
	srv.setupRoutes()
	return &onboardingServer{Server: srv, fake: srv.placementd.(*onboardFake)}
}

func (s *onboardingServer) ssoCallback(t *testing.T, originalURL string) *httptest.ResponseRecorder {
	t.Helper()
	state, err := s.oauth2StateStore.GenerateState()
	if err != nil {
		t.Fatal(err)
	}
	s.oauth2StateStore.StoreForBrowser(state, nil, originalURL, "binding-nonce")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, webUICallbackPath+"?state="+state+"&code=c", nil)
	req.AddCookie(&http.Cookie{Name: loginBindingCookieName, Value: "binding-nonce"}) //nolint:gosec // G124: a request cookie in a test
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func sessionCookieFrom(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			return c
		}
	}
	return nil
}

// Somebody the provider vouches for but who has no local account gets a
// placement-only session, keyed on the configured claim, and is sent to
// the placement page.
func TestUnmappedLoginGetsAPlacementOnlySession(t *testing.T) {
	srv := placementSSOServer(t, map[string]any{
		"sub": "http://cilogon.org/serverA/users/99", "eppn": "zoe@uni.example", "name": "Zoe Q",
	})
	rec := srv.ssoCallback(t, "/placement/device?user_code=BCDF-GHJK")
	c := sessionCookieFrom(rec)
	if c == nil {
		t.Fatalf("no session: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "/placement/device?user_code=BCDF-GHJK") {
		t.Errorf("not sent back to the device page: %s", rec.Body.String())
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.AddCookie(c)
	sess, ok := srv.getAnySessionFromRequest(req)
	if !ok || !sess.IsPlacementOnly() || sess.Username != "" || sess.PlacementForeignID != "zoe@uni.example" || sess.DisplayName != "Zoe Q" {
		t.Errorf("session = %+v", sess)
	}
}

// Elsewhere than /placement, the login lands on /placement.
func TestUnmappedLoginLandsOnPlacement(t *testing.T) {
	srv := placementSSOServer(t, map[string]any{"sub": "nobody-here"})
	rec := srv.ssoCallback(t, "/jobs")
	if sessionCookieFrom(rec) == nil || !strings.Contains(rec.Body.String(), `"/placement"`) {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
}

// With no placementd the refusal is what it always was.
func TestUnmappedLoginRefusedWithoutAPlacementd(t *testing.T) {
	srv := placementSSOServer(t, map[string]any{"sub": "nobody-here"})
	srv.placementd = nil
	srv.placementdAvailable.Store(false)
	rec := srv.ssoCallback(t, "/")
	if rec.Code != http.StatusForbidden || sessionCookieFrom(rec) != nil {
		t.Errorf("%d cookie=%v", rec.Code, sessionCookieFrom(rec))
	}
}
