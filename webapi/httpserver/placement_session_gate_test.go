package httpserver

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// placementOnlyExpectedAllowed is the complete list of what a
// placement-only session may reach, written out here independently of the
// gate's own tables so that widening the gate fails this test.
func placementOnlyExpectedAllowed(path string) bool {
	switch path {
	case "/api/v1/auth/me", "/api/v1/auth/logout", "/login", "/logout",
		"/auth/device_authorization", "/auth/code", "/auth/cancel_device",
		"/placement", "/placement/", "/placement/device", "/placement/device/":
		return true
	}
	return path == "/api/v1/placement/me" || strings.HasPrefix(path, "/api/v1/placement/me/")
}

// TestPlacementOnlySessionIsRefusedEverywhereElse walks every route the
// server registers, with every method, carrying a placement-only session,
// and requires every request outside the placement allowlist to be refused
// before a handler runs: 403, or for a page load a redirect to /placement.
func TestPlacementOnlySessionIsRefusedEverywhereElse(t *testing.T) {
	srv, err := NewServer(Config{
		Logger:         newTestLogger(t),
		ScheddName:     "ap.example",
		ScheddAddr:     "127.0.0.1:1",
		EnableMCP:      true,
		EnableIDP:      true,
		OAuth2DBPath:   t.TempDir() + "/oauth2.db",
		OAuth2Issuer:   "http://localhost:8080",
		SigningKeyPath: writeTestSigningKey(t),
		TrustDomain:    "test.domain",
		UIDDomain:      "d",
		SessionTTL:     time.Hour,
		Placementd:     newOnboardFake(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.webuiAdminGroups = newGroupSet("condor-admins")
	srv.placementOnboard.records = &fakeRecords{}
	srv.setupRoutes()
	if len(srv.routePatterns) < 60 {
		t.Fatalf("only %d routes recorded; the walk would prove little", len(srv.routePatterns))
	}

	// In the admin group, so a refusal cannot be the admin gate's doing.
	sid, _, err := srv.sessionStore.CreateSession(SessionData{
		PlacementForeignID: aliceFID, Groups: []string{"condor-admins"}, Scope: sessionScopePlacement,
	})
	if err != nil {
		t.Fatal(err)
	}

	probe := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/jobs", nil)
	probe.AddCookie(testSessionCookie(sid))
	if s, ok := srv.getAnySessionFromRequest(probe); !ok || !s.IsPlacementOnly() {
		t.Fatalf("the placement-only session is not found: %v %+v", ok, s)
	}

	var paths []string
	for _, p := range srv.routePatterns {
		paths = append(paths, p)
		if strings.HasSuffix(p, "/") {
			paths = append(paths, p+"x", p+"1.0/stdout")
		}
	}
	paths = append(paths, "/jobs", "/admin/placement", "/api/v1/placement/users", "/api/v1/placement/login",
		"/api/v1/placement/status", "/api/v1/placement/records/projects", "/api/v1/placement/tokens")

	refused := 0
	for _, path := range paths {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			// The allowed routes are exercised elsewhere; running them
			// here would let a logout delete the session mid-walk.
			if placementOnlyExpectedAllowed(strings.SplitN(path, "?", 2)[0]) {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			req := httptest.NewRequestWithContext(ctx, method, path, bytes.NewReader([]byte("{}")))
			req.AddCookie(testSessionCookie(sid))
			req.Header.Set("X-Requested-With", "XMLHttpRequest")
			rec := httptest.NewRecorder()
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Errorf("%s %s panicked: %v", method, path, p)
					}
				}()
				srv.ServeHTTP(rec, req)
			}()
			cancel()
			refused++
			redirected := rec.Code == http.StatusFound && rec.Header().Get("Location") == "/placement"
			if rec.Code != http.StatusForbidden && !redirected {
				t.Errorf("%s %s = %d (Location %q); a placement-only session must be refused",
					method, path, rec.Code, rec.Header().Get("Location"))
			}
		}
	}
	if refused < 300 {
		t.Errorf("only %d requests were checked for refusal", refused)
	}
}

// The allowlisted routes do work for a placement-only session.
func TestPlacementOnlySessionReachesPlacement(t *testing.T) {
	srv := newOnboardingServer(t, newOnboardFake())
	c := srv.placementCookie(t, aliceFID)
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/api/v1/auth/me", http.StatusOK},
		{http.MethodGet, "/api/v1/placement/me", http.StatusOK},
		{http.MethodPost, "/api/v1/placement/me/token", http.StatusBadRequest}, // empty body: reached the handler
		{http.MethodGet, "/auth/code?user_code=BCDF-GHJK", http.StatusFound},
	} {
		if rec := srv.do(t, c, tc.method, tc.path, ""); rec.Code != tc.want {
			t.Errorf("%s %s = %d, want %d: %s", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	// Static assets of the web UI are not pages.
	if !placementOnlyAllowed("/_next/static/chunks/app.js", "/") || placementOnlyAllowed("/jobs", "/") {
		t.Error("asset/page classification is wrong")
	}
}

// An ordinary session is untouched by the gate.
func TestPlacementGateLeavesOrdinarySessionsAlone(t *testing.T) {
	srv := newOnboardingServer(t, newOnboardFake())
	c := srv.userCookie(t, "root", "", "condor-admins")
	if rec := srv.do(t, c, http.MethodGet, "/api/v1/placement/users", ""); rec.Code != http.StatusOK {
		t.Errorf("admin users list: %d %s", rec.Code, rec.Body.String())
	}
}

// An unmapped login gets a placement-only session when the placementd is
// there, and is refused as before when it is not.
func TestPlacementOnlySessionNeedsAPlacementd(t *testing.T) {
	srv := newOnboardingServer(t, newOnboardFake())
	if !srv.placementOnboardingEnabled(context.Background()) {
		t.Error("onboarding disabled with a placementd")
	}
	srv.placementdAvailable.Store(false)
	srv.placementd = htcondor.PlacementdClient(nil)
	if srv.placementOnboardingEnabled(context.Background()) {
		t.Error("onboarding enabled with no placementd")
	}
}
