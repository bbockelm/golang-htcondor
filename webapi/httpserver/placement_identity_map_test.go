package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/idmap"
)

// mapWith configures HTTP_API_IDENTITY_MAP on an SSO test server.
func mapWith(s *onboardingServer, strategies ...idmap.Strategy) {
	local, first, on := splitPlacementdStrategy(strategies)
	s.placementOnboard.mapIdentity, s.placementOnboard.mapIdentityFirst = on, first
	if len(local) == 0 {
		s.localIdentity = nil
	}
}

func sessionOf(t *testing.T, s *onboardingServer, rec *httptest.ResponseRecorder) (string, *SessionData) {
	t.Helper()
	c := sessionCookieFrom(rec)
	if c == nil {
		t.Fatalf("no session: %d %s", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.AddCookie(c)
	sd, ok := s.getAnySessionFromRequest(req)
	if !ok {
		t.Fatal("the session cannot be read back")
	}
	return c.Value, sd
}

func TestPlacementdMappingSignsInAsTheAccount(t *testing.T) {
	s := placementSSOServer(t, map[string]any{"sub": "x", "eppn": aliceIdentity, "name": "Alice"})
	mapWith(s, idmap.StrategyPlacementd)
	_, sd := sessionOf(t, s, s.ssoCallback(t, "/jobs"))
	if !sd.IsPlacementd() || sd.IsPlacementOnly() || sd.Username != aliceAcct || sd.PlacementIdentity != aliceIdentity {
		t.Fatalf("session = %+v", sd)
	}
	if sd.Placement.Project != "ProjA" || !slices.Equal(sd.Placement.Levels(), []string{"READ", "WRITE"}) {
		t.Errorf("account = %+v levels %v", sd.Placement, sd.Placement.Levels())
	}
}

func TestPlacementdMappingFallsBackToPlacementOnly(t *testing.T) {
	s := placementSSOServer(t, map[string]any{"sub": "nobody", "eppn": "stranger@idp.example"})
	mapWith(s, idmap.StrategyPlacementd)
	sid, sd := sessionOf(t, s, s.ssoCallback(t, "/"))
	if !sd.IsPlacementOnly() || !strings.HasPrefix(sid, placementSessionPrefix) {
		t.Errorf("an unmapped identity got %+v", sd)
	}
}

// An account with no READ or WRITE grant cannot sign in as itself: it would
// reach nothing, so it gets the placement page only.
func TestPlacementdAccountWithoutLevelsIsPlacementOnly(t *testing.T) {
	s := placementSSOServer(t, map[string]any{"sub": "x", "eppn": aliceIdentity})
	s.fake.users[0].Authorizations = []string{"INSTRUCTOR"}
	mapWith(s, idmap.StrategyPlacementd)
	_, sd := sessionOf(t, s, s.ssoCallback(t, "/"))
	if !sd.IsPlacementOnly() {
		t.Errorf("an account with no levels got %+v", sd)
	}
}

func TestPlacementdMappingOrder(t *testing.T) {
	// tatannen is GECOS for the local tannenba, and also a placement
	// identity mapped to an AP account.
	identityFake := func(s *onboardingServer) {
		s.fake.users = append(s.fake.users, htcondor.PlacementUser{UserName: "tatannen", APUserID: "tt@ap.example",
			Authorizations: []string{"READ"}, Projects: []string{"P"}, Authorized: true})
	}
	s := placementSSOServer(t, map[string]any{"sub": "tatannen"})
	identityFake(s)
	s.placementOnboard.identityClaims = []string{"sub"}
	mapWith(s, idmap.StrategyPlacementd, idmap.StrategyGecos)
	if _, sd := sessionOf(t, s, s.ssoCallback(t, "/")); sd.Username != "tt@ap.example" {
		t.Errorf("placementd,gecos chose %q", sd.Username)
	}

	s = placementSSOServer(t, map[string]any{"sub": "tatannen"})
	identityFake(s)
	s.placementOnboard.identityClaims = []string{"sub"}
	mapWith(s, idmap.StrategyGecos, idmap.StrategyPlacementd)
	if _, sd := sessionOf(t, s, s.ssoCallback(t, "/")); sd.Username != "tannenba" || sd.IsPlacementd() {
		t.Errorf("gecos,placementd chose %+v", sd)
	}

	// Not in GECOS: gecos fails, placementd maps it.
	s = placementSSOServer(t, map[string]any{"sub": "x", "eppn": aliceIdentity})
	mapWith(s, idmap.StrategyGecos, idmap.StrategyPlacementd)
	if _, sd := sessionOf(t, s, s.ssoCallback(t, "/")); sd.Username != aliceAcct {
		t.Errorf("gecos,placementd fallback chose %q", sd.Username)
	}
}

func mintedClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	claims := decodePlacementTokenClaims(token)
	if claims == nil {
		t.Fatalf("token %q does not decode", token)
	}
	return claims
}

// The request token of a placementd session: the account, its levels, its
// project -- nothing more.
func TestPlacementdSessionTokenIsBounded(t *testing.T) {
	s := placementSSOServer(t, map[string]any{"sub": "x", "eppn": aliceIdentity})
	mapWith(s, idmap.StrategyPlacementd)
	sid, sd := sessionOf(t, s, s.ssoCallback(t, "/"))

	token, subject, err := s.mintPlacementSessionToken(context.Background(), sid, sd)
	if err != nil {
		t.Fatal(err)
	}
	c := mintedClaims(t, token)
	if subject != aliceAcct || c["sub"] != aliceAcct {
		t.Errorf("subject = %q / %v", subject, c["sub"])
	}
	if c["scope"] != "condor:/READ condor:/WRITE" {
		t.Errorf("scope = %v", c["scope"])
	}
	if c["project"] != "ProjA" {
		t.Errorf("project = %v", c["project"])
	}

	// Through the ordinary session path too, so no request escapes it.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs", nil)
	req.AddCookie(testSessionCookie(sid))
	tok, mintedFor, err := s.extractOrGenerateToken(req)
	if err != nil || mintedFor != aliceAcct || mintedClaims(t, tok)["project"] != "ProjA" {
		t.Errorf("extractOrGenerateToken = %q %v", mintedFor, err)
	}
}

func TestPlacementdSessionReadOnlyAccount(t *testing.T) {
	s := placementSSOServer(t, map[string]any{"sub": "x", "eppn": aliceIdentity})
	s.fake.users[0].Authorizations = []string{"READ", "INSTRUCTOR", "WEBADMIN"}
	mapWith(s, idmap.StrategyPlacementd)
	sid, sd := sessionOf(t, s, s.ssoCallback(t, "/"))
	token, _, err := s.mintPlacementSessionToken(context.Background(), sid, sd)
	if err != nil {
		t.Fatal(err)
	}
	if c := mintedClaims(t, token); c["scope"] != "condor:/READ" {
		t.Errorf("scope = %v; non-level grants and absent levels must not appear", c["scope"])
	}
}

func TestPlacementdSessionRevalidation(t *testing.T) {
	stale := func(t *testing.T, s *onboardingServer, sid string) *SessionData {
		t.Helper()
		sd := s.sessionStore.Get(sid)
		info := *sd.Placement
		info.CheckedAt = time.Now().Add(-placementRevalidateEvery - time.Second)
		if err := s.sessionStore.UpdatePlacement(sid, &info, sd.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		return s.sessionStore.Get(sid)
	}
	for _, tc := range []struct {
		name  string
		edit  func(*onboardingServer)
		ended bool
		check func(*testing.T, *SessionData)
	}{
		{"removed", func(s *onboardingServer) { s.fake.users = s.fake.users[1:] }, true, nil},
		{"re-pointed", func(s *onboardingServer) { s.fake.users[0].APUserID = "other@ap.example" }, true, nil},
		{"expired", func(s *onboardingServer) { s.fake.users[0].MappingExpiration = time.Now().Add(-time.Minute) }, true, nil},
		{"grants narrowed", func(s *onboardingServer) { s.fake.users[0].Authorizations = []string{"READ"} }, false,
			func(t *testing.T, sd *SessionData) {
				if !slices.Equal(sd.Placement.Levels(), []string{"READ"}) {
					t.Errorf("levels = %v", sd.Placement.Levels())
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := placementSSOServer(t, map[string]any{"sub": "x", "eppn": aliceIdentity})
			mapWith(s, idmap.StrategyPlacementd)
			sid, _ := sessionOf(t, s, s.ssoCallback(t, "/"))
			sd := stale(t, s, sid)
			tc.edit(s)
			token, _, err := s.mintPlacementSessionToken(context.Background(), sid, sd)
			if tc.ended {
				if !errors.Is(err, errPlacementSessionEnded) || s.sessionStore.Get(sid) != nil {
					t.Errorf("err = %v; session still there = %v", err, s.sessionStore.Get(sid) != nil)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c := mintedClaims(t, token); c["scope"] != "condor:/READ" {
				t.Errorf("scope after narrowing = %v", c["scope"])
			}
			tc.check(t, s.sessionStore.Get(sid))
		})
	}
}

func TestPlacementdSessionNeverOutlivesItsMapping(t *testing.T) {
	s := placementSSOServer(t, map[string]any{"sub": "x", "eppn": aliceIdentity})
	soon := time.Now().Add(10 * time.Minute).Truncate(time.Second)
	s.fake.users[0].MappingExpiration = soon
	mapWith(s, idmap.StrategyPlacementd)
	_, sd := sessionOf(t, s, s.ssoCallback(t, "/"))
	if sd.ExpiresAt.After(soon) {
		t.Errorf("session expires %v, after its mapping %v", sd.ExpiresAt, soon)
	}
}

func TestPlacementdProjectSwitch(t *testing.T) {
	s := placementSSOServer(t, map[string]any{"sub": "x", "eppn": aliceIdentity})
	mapWith(s, idmap.StrategyPlacementd)
	sid, _ := sessionOf(t, s, s.ssoCallback(t, "/"))
	c := testSessionCookie(sid)
	if rec := s.do(t, c, http.MethodPost, "/api/v1/placement/me/project", `{"project":"nope"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown project: %d", rec.Code)
	}
	if rec := s.do(t, c, http.MethodPost, "/api/v1/placement/me/project", `{"project":"projb"}`); rec.Code != http.StatusOK {
		t.Fatalf("switch: %d %s", rec.Code, rec.Body.String())
	}
	sd := s.sessionStore.Get(sid)
	token, _, err := s.mintPlacementSessionToken(context.Background(), sid, sd)
	if err != nil || mintedClaims(t, token)["project"] != "ProjB" {
		t.Errorf("project after switch: %v %v", err, sd.Placement.Project)
	}
	rec := s.do(t, c, http.MethodGet, "/api/v1/auth/me", "")
	var me AuthMeResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	if me.Placement == nil || me.Placement.Project != "ProjB" || len(me.Placement.Projects) != 2 || me.Placement.Account != aliceAcct {
		t.Errorf("auth/me placement = %+v", me.Placement)
	}
}

// An OAuth2 grant of a placementd account is held to the account's levels
// and carries its project, whatever scopes the grant holds.
func TestPlacementdOAuthSubjectIsBounded(t *testing.T) {
	s := placementSSOServer(t, map[string]any{"sub": "x", "eppn": aliceIdentity})
	s.fake.users[0].Authorizations = []string{"READ"}
	mapWith(s, idmap.StrategyPlacementd)
	sessionOf(t, s, s.ssoCallback(t, "/"))

	token, err := s.generateHTCondorTokenWithScopes(aliceAcct, []string{"mcp:read", "mcp:write"})
	if err != nil {
		t.Fatal(err)
	}
	c := mintedClaims(t, token)
	if c["scope"] != "condor:/READ" || c["project"] != "ProjA" || c["sub"] != aliceAcct {
		t.Errorf("claims = %v", c)
	}
	if _, err := s.generateHTCondorTokenWithScopes(aliceAcct, []string{"condor:/WRITE"}); !errors.Is(err, errNoAuthorizationLimits) {
		t.Errorf("a WRITE-only grant for a READ account minted: %v", err)
	}
	// Another subject is not affected.
	if c := mintedClaims(t, mustMint(t, s, "bob@ap.example", []string{"mcp:write"})); c["project"] != nil {
		t.Errorf("an unrelated subject got %v", c)
	}
}

func mustMint(t *testing.T, s *onboardingServer, user string, scopes []string) string {
	t.Helper()
	tok, err := s.generateHTCondorTokenWithScopes(user, scopes)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// Features that need a local account refuse a placementd session cleanly.
func TestPlacementdSessionRefusesLocalAccountFeatures(t *testing.T) {
	s := placementSSOServer(t, map[string]any{"sub": "x", "eppn": aliceIdentity})
	s.fake.users[0].APUserID = "alice@elsewhere.example"
	mapWith(s, idmap.StrategyPlacementd)
	sid, sd := sessionOf(t, s, s.ssoCallback(t, "/"))
	c := testSessionCookie(sid)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/creds/user?cred_type=Kerberos"},
		{http.MethodGet, "/api/v1/creds/service"},
		{http.MethodPost, "/api/v1/ssh/certificate"},
		{http.MethodPost, "/api/v1/jobs/1.0/output/share"},
	} {
		rec := s.do(t, c, tc.method, tc.path, "{}")
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "not available to accounts") {
			t.Errorf("%s %s = %d %s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
	if s.superuserScopeFor(sd).allowed() {
		t.Error("a placementd session may use superuser mode")
	}
}

// An OAuth2 grant of a placementd account is re-checked against the
// placementd at refresh: re-pointed ends it and clears the account's bound.
func TestPlacementdOAuthSubjectRefreshCheck(t *testing.T) {
	s := placementSSOServer(t, map[string]any{"sub": "x", "eppn": aliceIdentity})
	mapWith(s, idmap.StrategyPlacementd)
	sessionOf(t, s, s.ssoCallback(t, "/"))
	ctx := context.Background()
	if reason, err := s.reauthorizePlacementIdentity(ctx, aliceIdentity, aliceAcct); err != nil || reason != "" {
		t.Fatalf("mapped: %q %v", reason, err)
	}
	s.fake.users[0].APUserID = "other@ap.example"
	if reason, _ := s.reauthorizePlacementIdentity(ctx, aliceIdentity, aliceAcct); reason == "" {
		t.Error("a re-pointed identity kept its grant")
	}
	if b, err := s.placementSubjectBound(ctx, aliceAcct); err != nil || b == nil || len(b.Levels) != 0 {
		t.Errorf("bound after re-pointing = %+v %v", b, err)
	}
	if _, err := s.generateHTCondorTokenWithScopes(aliceAcct, []string{"mcp:read"}); !errors.Is(err, errNoAuthorizationLimits) {
		t.Errorf("minted for a subject whose identity moved: %v", err)
	}
}
