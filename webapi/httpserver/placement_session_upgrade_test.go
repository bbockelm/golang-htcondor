package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/idmap"
)

const (
	newbieSubject  = "http://cilogon.org/serverA/users/77"
	newbieIdentity = "newbie@idp.example"
	newbieAcct     = "physnewbie@ap.example"
)

// newbieServer is an SSO server where newbie signs in before anybody has
// onboarded them: the returned cookie is their placement-only session.
func newbieServer(t *testing.T, claims map[string]any, strategies ...idmap.Strategy) (*onboardingServer, *http.Cookie) {
	t.Helper()
	if claims == nil {
		claims = map[string]any{"sub": newbieSubject, "eppn": newbieIdentity, "name": "Newbie"}
	}
	s := placementSSOServer(t, claims)
	if len(strategies) == 0 {
		strategies = []idmap.Strategy{idmap.StrategyPlacementd}
	}
	mapWith(s, strategies...)
	rec := s.ssoCallback(t, "/placement")
	c := sessionCookieFrom(rec)
	if c == nil || !strings.HasPrefix(c.Value, placementSessionPrefix) {
		t.Fatalf("newbie did not get a placement-only session: %d %s", rec.Code, rec.Body.String())
	}
	return s, testSessionCookie(c.Value)
}

// onboard is what the Directory's "Onboard user" does for newbie, as the
// placementd then answers for the identity.
func (s *onboardingServer) onboard(authz ...string) {
	if len(authz) == 0 {
		authz = []string{"READ", "WRITE"}
	}
	s.fake.users = append(s.fake.users, htcondor.PlacementUser{
		UserName: newbieIdentity, APUserID: newbieAcct, Projects: []string{"Physics"},
		Authorizations: authz, Authorized: true,
	})
}

// me calls GET /api/v1/auth/me with c, letting the throttle through first:
// each call here is a check that is due.
func (s *onboardingServer) me(t *testing.T, c *http.Cookie) (AuthMeResponse, *httptest.ResponseRecorder) {
	t.Helper()
	s.placementUpgrades.mu.Lock()
	s.placementUpgrades.last = nil
	s.placementUpgrades.mu.Unlock()
	return s.meThrottled(t, c)
}

// meThrottled calls GET /api/v1/auth/me without touching the throttle.
func (s *onboardingServer) meThrottled(t *testing.T, c *http.Cookie) (AuthMeResponse, *httptest.ResponseRecorder) {
	t.Helper()
	rec := s.do(t, c, http.MethodGet, "/api/v1/auth/me", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/v1/auth/me = %d %s", rec.Code, rec.Body.String())
	}
	var resp AuthMeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp, rec
}

// newbieQueries counts the placementd queries that named newbie.
func (s *onboardingServer) newbieQueries() int {
	s.fake.mu.Lock()
	defer s.fake.mu.Unlock()
	n := 0
	for _, name := range s.fake.names {
		if name == newbieIdentity {
			n++
		}
	}
	return n
}

// requireStillPlacementOnly checks that /api/v1/auth/me left c alone.
func requireStillPlacementOnly(t *testing.T, s *onboardingServer, c *http.Cookie) {
	t.Helper()
	resp, rec := s.me(t, c)
	if !resp.PlacementOnly || resp.Username != "" {
		t.Errorf("the session changed: %+v", resp)
	}
	if nc := sessionCookieFrom(rec); nc != nil {
		t.Errorf("a new session cookie was set: %v", nc)
	}
	if sd, ok := s.getAnySessionFromRequest(cookieRequest(c)); !ok || !sd.IsPlacementOnly() {
		t.Errorf("the placement-only session is gone or changed: %v %+v", ok, sd)
	}
}

func cookieRequest(c *http.Cookie) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.AddCookie(c)
	return req
}

// jobsCode is what GET /api/v1/jobs answers c, within a short deadline: the
// schedd is not there, so a request the gates admit fails later and
// differently.
func (s *onboardingServer) jobsCode(t *testing.T, c *http.Cookie) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/jobs", nil)
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// The whole feature: newbie signs in unmapped, an admin onboards them, and
// their next /api/v1/auth/me makes them that account -- under a new session
// id, with the old one dead everywhere.
func TestPlacementOnlySessionUpgradesAfterOnboarding(t *testing.T) {
	s, old := newbieServer(t, nil)
	oldSD, _ := s.getAnySessionFromRequest(cookieRequest(old))
	if oldSD == nil || oldSD.IDPSubject != newbieSubject {
		t.Fatalf("the placement-only session does not keep the provider's subject: %+v", oldSD)
	}

	// Not yet onboarded: nothing changes.
	requireStillPlacementOnly(t, s, old)
	if code, body := s.jobsCode(t, old); code != http.StatusForbidden {
		t.Fatalf("a placement-only session reached /api/v1/jobs: %d %s", code, body)
	}

	s.onboard()
	resp, rec := s.me(t, old)
	if !resp.Authenticated || resp.PlacementOnly || resp.Username != newbieAcct {
		t.Fatalf("not upgraded: %+v", resp)
	}
	if resp.Placement == nil || resp.Placement.Identity != newbieIdentity || resp.Placement.Account != newbieAcct ||
		strings.Join(resp.Placement.Levels, ",") != "READ,WRITE" || resp.Placement.Project != "Physics" {
		t.Errorf("placement in the response = %+v", resp.Placement)
	}

	fresh := requireRotatedCookie(t, rec, old)
	newSD, ok := s.getSessionFromRequest(cookieRequest(fresh))
	if !ok || !newSD.IsPlacementd() || newSD.Username != newbieAcct || newSD.PlacementIdentity != newbieIdentity {
		t.Fatalf("new session = %v %+v", ok, newSD)
	}
	if newSD.ExpiresAt.After(oldSD.ExpiresAt) {
		t.Errorf("the new session outlives the sign-in: %v > %v", newSD.ExpiresAt, oldSD.ExpiresAt)
	}
	requireDeadEverywhere(t, s, old)
	requireFullSession(t, s, fresh)

	// Tokens minted for the account stay within what it holds.
	bound, err := s.placementSubjectBound(context.Background(), newbieAcct)
	if err != nil || bound == nil || bound.Identity != newbieIdentity {
		t.Errorf("the account was not recorded for bounded grants: %+v %v", bound, err)
	}
}

// requireRotatedCookie returns the new session cookie rec set: a new id, set
// like a login's.
func requireRotatedCookie(t *testing.T, rec *httptest.ResponseRecorder, old *http.Cookie) *http.Cookie {
	t.Helper()
	nc := sessionCookieFrom(rec)
	if nc == nil {
		t.Fatal("no new session cookie")
	}
	if nc.Value == old.Value || strings.HasPrefix(nc.Value, placementSessionPrefix) {
		t.Fatalf("the session id was not rotated: old %q new %q", old.Value, nc.Value)
	}
	if !nc.HttpOnly || !nc.Secure || nc.SameSite != http.SameSiteStrictMode || nc.Path != "/" || nc.MaxAge <= 0 {
		t.Errorf("cookie attributes differ from a login's: %+v", nc)
	}
	return testSessionCookie(nc.Value)
}

// requireDeadEverywhere checks that the session c names works nowhere.
func requireDeadEverywhere(t *testing.T, s *onboardingServer, c *http.Cookie) {
	t.Helper()
	if _, ok := s.getAnySessionFromRequest(cookieRequest(c)); ok {
		t.Error("the placement-only session survived the upgrade")
	}
	if r, _ := s.meThrottled(t, c); r.Authenticated {
		t.Errorf("the old id still authenticates /api/v1/auth/me: %+v", r)
	}
	if rec := s.do(t, c, http.MethodGet, "/api/v1/placement/me", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("the old id reached /api/v1/placement/me: %d %s", rec.Code, rec.Body.String())
	}
	if code, body := s.jobsCode(t, c); code != http.StatusUnauthorized {
		t.Errorf("the old id at /api/v1/jobs = %d %s", code, body)
	}
}

// requireFullSession checks that c passes the gates an ordinary session
// passes.
func requireFullSession(t *testing.T, s *onboardingServer, c *http.Cookie) {
	t.Helper()
	if r, rec := s.meThrottled(t, c); !r.Authenticated || r.PlacementOnly || r.Username != newbieAcct ||
		sessionCookieFrom(rec) != nil {
		t.Errorf("the new session's /api/v1/auth/me = %+v", r)
	}
	// Admitted, a token is minted for it and the schedd is called.
	if code, body := s.jobsCode(t, c); !strings.Contains(body, "schedd at 127.0.0.1:1") {
		t.Errorf("the upgraded session did not reach the schedd from /api/v1/jobs: %d %s", code, body)
	}
	if rec := s.do(t, c, http.MethodGet, "/api/v1/placement/me", ""); rec.Code != http.StatusOK {
		t.Errorf("the upgraded session's /api/v1/placement/me = %d %s", rec.Code, rec.Body.String())
	}
}

// An account that holds neither READ nor WRITE is no account to sign in
// as, at login or after.
func TestPlacementOnlySessionStaysWithoutJobLevels(t *testing.T) {
	s, c := newbieServer(t, nil)
	s.onboard("INSTRUCTOR", "WEBADMIN")
	requireStillPlacementOnly(t, s, c)
}

// The web UI's access group applies to an upgrade exactly as to a login.
func TestPlacementOnlySessionUpgradeNeedsTheWebUIAccessGroup(t *testing.T) {
	s, c := newbieServer(t, nil)
	s.webuiAccessGroups = newGroupSet("ap-users")
	s.onboard()
	requireStillPlacementOnly(t, s, c)

	// In the group, the same onboarding upgrades.
	s, c = newbieServer(t, map[string]any{"sub": newbieSubject, "eppn": newbieIdentity, "groups": []string{"ap-users"}})
	s.webuiAccessGroups = newGroupSet("ap-users")
	s.onboard()
	if resp, _ := s.me(t, c); resp.PlacementOnly || resp.Username != newbieAcct {
		t.Errorf("a member of the access group was not upgraded: %+v", resp)
	}
}

func TestPlacementOnlySessionStaysForAnExpiredIdentity(t *testing.T) {
	s, c := newbieServer(t, nil)
	s.onboard()
	s.fake.users[len(s.fake.users)-1].MappingExpiration = time.Now().Add(-time.Minute)
	requireStillPlacementOnly(t, s, c)

	s.fake.users[len(s.fake.users)-1].Authorized = false
	s.fake.users[len(s.fake.users)-1].MappingExpiration = time.Time{}
	requireStillPlacementOnly(t, s, c)
}

// Without placementd in HTTP_API_IDENTITY_MAP, a placement-only session is
// never re-mapped, and the placementd is not asked.
func TestPlacementOnlySessionNeverUpgradesWithoutPlacementdMapping(t *testing.T) {
	s, c := newbieServer(t, nil, idmap.StrategyGecos)
	s.onboard()
	before := s.newbieQueries()
	requireStillPlacementOnly(t, s, c)
	if after := s.newbieQueries(); after != before {
		t.Errorf("the placementd was asked %d times", after-before)
	}
}

// gecos,placementd: the local strategy is tried first, with the subject the
// sign-in carried, and the placementd after it.
func TestPlacementOnlySessionUpgradeFollowsMappingOrder(t *testing.T) {
	s, c := newbieServer(t, nil, idmap.StrategyGecos, idmap.StrategyPlacementd)
	s.onboard()
	if resp, _ := s.me(t, c); resp.PlacementOnly || resp.Username != newbieAcct {
		t.Errorf("gecos,placementd: %+v", resp)
	}
}

// One check per session per placementUpgradeEvery, however often the page
// asks.
func TestPlacementOnlySessionUpgradeIsThrottled(t *testing.T) {
	s, c := newbieServer(t, nil)
	before := s.newbieQueries()
	for range 5 {
		s.meThrottled(t, c)
	}
	if n := s.newbieQueries() - before; n != 1 {
		t.Fatalf("five /api/v1/auth/me calls asked the placementd %d times, want 1", n)
	}

	// Onboarded within the interval: not seen until it has passed.
	s.onboard()
	if resp, rec := s.meThrottled(t, c); !resp.PlacementOnly || sessionCookieFrom(rec) != nil {
		t.Fatalf("upgraded inside the interval: %+v", resp)
	}
	key := sessionKey(c.Value)
	s.placementUpgrades.mu.Lock()
	s.placementUpgrades.last[key] = time.Now().Add(-placementUpgradeEvery)
	s.placementUpgrades.mu.Unlock()
	if resp, _ := s.meThrottled(t, c); resp.PlacementOnly || resp.Username != newbieAcct {
		t.Errorf("not upgraded once the interval passed: %+v", resp)
	}
}

// Nothing in the request chooses who the session becomes: not a query
// parameter, a header, a bearer token, nor the identity cookie's hint. The
// placementd is asked about the session's own identity and no other.
func TestPlacementOnlySessionUpgradeIgnoresTheRequest(t *testing.T) {
	s, c := newbieServer(t, nil, idmap.StrategyGecos, idmap.StrategyPlacementd)
	s.onboard()
	s.fake.mu.Lock()
	s.fake.names = nil
	s.fake.mu.Unlock()
	s.placementUpgrades.last = nil

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/api/v1/auth/me?identity=mallory@idp.example&username=mallory&sub=tatannen&user=tannenba", nil)
	req.AddCookie(c)
	// The identity cookie's hint for a local account, and headers that
	// name somebody else.
	s.setIdentityCookieOn(t, req, newbieSubject, "tannenba")
	req.Header.Set("X-Remote-User", "mallory")
	req.Header.Set("X-Forwarded-User", "mallory@idp.example")
	req.Header.Set("Authorization", "Bearer mallory")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	var resp AuthMeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Username != newbieAcct || resp.Placement == nil || resp.Placement.Identity != newbieIdentity {
		t.Errorf("upgraded to %+v", resp)
	}
	s.fake.mu.Lock()
	names := append([]string(nil), s.fake.names...)
	s.fake.mu.Unlock()
	for _, n := range names {
		if n != newbieIdentity {
			t.Errorf("the placementd was asked about %q", n)
		}
	}
	if len(names) == 0 {
		t.Error("the placementd was not asked at all")
	}
}

// setIdentityCookieOn adds to req the identity cookie a browser would hold
// after subject had signed in as account.
func (s *onboardingServer) setIdentityCookieOn(t *testing.T, req *http.Request, subject, account string) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.setIdentityCookie(rec, subject, account)
	for _, ck := range rec.Result().Cookies() {
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value}) //nolint:gosec // G124: a request cookie in a test
	}
}

// A placement-only session from before the provider's subject was kept is
// not re-mapped.
func TestPlacementOnlySessionWithoutSubjectStays(t *testing.T) {
	s, _ := newbieServer(t, nil)
	s.onboard()
	sid, _, err := s.sessionStore.CreateSession(SessionData{
		PlacementIdentity: newbieIdentity, Scope: sessionScopePlacement,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireStillPlacementOnly(t, s, testSessionCookie(sid))
}

// Rotate replaces a placement-only session once: a second rotation of the
// same id, as two concurrent checks would attempt, stores nothing.
func TestSessionRotateReplacesOnce(t *testing.T) {
	s, c := newbieServer(t, nil)
	data := SessionData{Username: "someone"}
	id1, _, err := s.sessionStore.Rotate(c.Value, data)
	if err != nil {
		t.Fatal(err)
	}
	before := s.sessionStore.Size()
	if _, _, err := s.sessionStore.Rotate(c.Value, data); err == nil {
		t.Fatal("a placement-only session was rotated twice")
	}
	if s.sessionStore.Size() != before {
		t.Error("a failed rotation stored a session")
	}
	// Only a placement-only session is rotated.
	if _, _, err := s.sessionStore.Rotate(id1, data); err == nil {
		t.Error("a full session was rotated")
	}
}
