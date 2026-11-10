package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"

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

	token, err := s.generateGrantHTCondorToken(aliceAcct, aliceIdentity, []string{"mcp:read", "mcp:write"})
	if err != nil {
		t.Fatal(err)
	}
	c := mintedClaims(t, token)
	if c["scope"] != "condor:/READ" || c["project"] != "ProjA" || c["sub"] != aliceAcct {
		t.Errorf("claims = %v", c)
	}
	if _, err := s.generateGrantHTCondorToken(aliceAcct, aliceIdentity, []string{"condor:/WRITE"}); !errors.Is(err, errNoAuthorizationLimits) {
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
	if b, err := s.placementSubjectBound(ctx, aliceAcct, aliceIdentity); err != nil || b == nil || len(b.Levels) != 0 {
		t.Errorf("bound after re-pointing = %+v %v", b, err)
	}
	if _, err := s.generateGrantHTCondorToken(aliceAcct, aliceIdentity, []string{"mcp:read"}); !errors.Is(err, errNoAuthorizationLimits) {
		t.Errorf("minted for a subject whose identity moved: %v", err)
	}
}

const carolIdentity = "carol@idp.example"

// sharedAccountServer is an SSO server where two identities map to one
// account: alice with READ and project ProjA, carol with READ and WRITE and
// project ProjC. signIn signs either in through the provider and returns
// the session cookie.
func sharedAccountServer(t *testing.T) (*onboardingServer, func(identity string) *http.Cookie) {
	t.Helper()
	claims := map[string]any{"sub": "x", "eppn": aliceIdentity}
	s := placementSSOServer(t, claims)
	s.fake.users = []htcondor.PlacementUser{
		{UserName: aliceIdentity, APUserID: aliceAcct, Projects: []string{"ProjA"}, Authorizations: []string{"READ"}, Authorized: true},
		{UserName: carolIdentity, APUserID: aliceAcct, Projects: []string{"ProjC"}, Authorizations: []string{"READ", "WRITE"}, Authorized: true},
	}
	mapWith(s, idmap.StrategyPlacementd)
	if err := s.oauth2Provider.GetStorage().CreateClient(context.Background(), &fosite.DefaultClient{
		ID:         "shared-device-client",
		GrantTypes: []string{deviceCodeGrant, "refresh_token"},
		Scopes:     []string{"openid", "mcp:read", "mcp:write", "offline_access"},
		Public:     true,
	}); err != nil {
		t.Fatal(err)
	}
	signIn := func(identity string) *http.Cookie {
		t.Helper()
		claims["eppn"] = identity
		_, sd := sessionOf(t, s, s.ssoCallback(t, "/"))
		if !sd.IsPlacementd() || sd.PlacementIdentity != identity || sd.Username != aliceAcct {
			t.Fatalf("%s signed in as %+v", identity, sd)
		}
		return sessionCookieFrom(s.ssoCallback(t, "/"))
	}
	return s, signIn
}

// deviceGrant runs the device flow for an MCP client, approved by the
// session behind approver, and returns the access and refresh tokens.
func deviceGrant(t *testing.T, s *onboardingServer, approver *http.Cookie) (access, refresh string) {
	t.Helper()
	rec := s.form(t, nil, s.oauth2EndpointPath("device/authorize"), url.Values{
		"client_id": {"shared-device-client"}, "scope": {"openid mcp:read mcp:write offline_access"},
	})
	var dev DeviceAuthorizationResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &dev) != nil {
		t.Fatalf("device authorize: %d %s", rec.Code, rec.Body.String())
	}
	rec = s.form(t, approver, s.deviceVerifyPath(), url.Values{
		"user_code": {dev.UserCode}, "action": {"approve"},
		consentCSRFField: {s.consentCSRFToken(aliceAcct, dev.UserCode)},
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Authorization Complete") {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	rec = s.form(t, nil, s.oauth2EndpointPath("token"), url.Values{
		"grant_type": {deviceCodeGrant}, "device_code": {dev.DeviceCode}, "client_id": {"shared-device-client"},
	})
	var tok map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &tok) != nil {
		t.Fatalf("token: %d %s", rec.Code, rec.Body.String())
	}
	access, _ = tok["access_token"].(string)
	refresh, _ = tok["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("token response = %v", tok)
	}
	return access, refresh
}

// mintForBearer is the HTCondor token the REST path mints for an access
// token of this server's own, minted afresh rather than taken from the
// cache of an earlier request's.
func mintForBearer(s *onboardingServer, access string) (map[string]any, error) {
	s.tokenCache.Remove(access)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	ctx, err := s.createAuthenticatedContext(req)
	if err != nil {
		return nil, err
	}
	sc, ok := htcondor.GetSecurityConfigFromContext(ctx)
	if !ok || sc.Token == "" {
		return nil, errors.New("no HTCondor token was minted")
	}
	claims := decodePlacementTokenClaims(sc.Token)
	if claims == nil {
		return nil, errors.New("the minted token does not decode")
	}
	return claims, nil
}

// mintedLevels is a minted token's scope claim as a sorted list.
func mintedLevels(c map[string]any) []string {
	scope, _ := c["scope"].(string)
	levels := strings.Fields(scope)
	slices.Sort(levels)
	return levels
}

// refreshGrant presents a refresh token and returns the new access token,
// or the failed response.
func refreshGrant(t *testing.T, s *onboardingServer, refresh string) (access string, rec *httptest.ResponseRecorder) {
	t.Helper()
	rec = s.form(t, nil, s.oauth2EndpointPath("token"), url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {"shared-device-client"},
	})
	if rec.Code != http.StatusOK {
		return "", rec
	}
	var tok map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	access, _ = tok["access_token"].(string)
	return access, rec
}

// Two identities mapped to one account each keep their own bound: one
// signing in never widens or re-points the other's grants, and each is
// re-checked against its own identity at refresh.
func TestPlacementBoundIsPerIdentity(t *testing.T) {
	s, signIn := sharedAccountServer(t)
	aliceAccess, aliceRefresh := deviceGrant(t, s, signIn(aliceIdentity))

	// carol signs in and authorizes a grant of her own.
	carolAccess, carolRefresh := deviceGrant(t, s, signIn(carolIdentity))

	c, err := mintForBearer(s, aliceAccess)
	if err != nil {
		t.Fatalf("alice's grant after carol signed in: %v", err)
	}
	readOnly, readWrite := []string{"condor:/READ"}, []string{"condor:/READ", "condor:/WRITE"}
	if !slices.Equal(mintedLevels(c), readOnly) || c["project"] != "ProjA" || c["sub"] != aliceAcct {
		t.Errorf("alice's grant minted %v; want READ only and ProjA", c)
	}
	c, err = mintForBearer(s, carolAccess)
	if err != nil {
		t.Fatalf("carol's grant: %v", err)
	}
	if !slices.Equal(mintedLevels(c), readWrite) || c["project"] != "ProjC" {
		t.Errorf("carol's grant minted %v; want READ and WRITE and ProjC", c)
	}

	// alice signing in again does not narrow carol's grant either.
	signIn(aliceIdentity)
	if c, err := mintForBearer(s, carolAccess); err != nil || !slices.Equal(mintedLevels(c), readWrite) || c["project"] != "ProjC" {
		t.Errorf("carol's grant after alice signed in again: %v %v", c, err)
	}

	// alice loses her mapping: her grant ends at refresh, carol's does not.
	s.fake.users[0].Authorized = false
	if _, rec := refreshGrant(t, s, aliceRefresh); rec.Code == http.StatusOK {
		t.Errorf("alice's refresh succeeded after her identity was unauthorized: %s", rec.Body.String())
	}
	if _, err := s.oauth2Provider.IntrospectAccessToken(context.Background(), aliceAccess); err == nil {
		t.Error("alice's access token is still live after her grant was revoked")
	}
	access, rec := refreshGrant(t, s, carolRefresh)
	if rec.Code != http.StatusOK {
		t.Fatalf("carol's refresh failed: %d %s", rec.Code, rec.Body.String())
	}
	if c, err := mintForBearer(s, access); err != nil || !slices.Equal(mintedLevels(c), readWrite) || c["project"] != "ProjC" {
		t.Errorf("carol's refreshed grant minted %v %v", c, err)
	}
}

// A grant that names no identity, for a subject a placementd-mapped
// session authorized, is refused rather than minted unbounded or under
// some other identity's bound.
func TestPlacementBoundRefusesGrantWithoutIdentity(t *testing.T) {
	s, signIn := sharedAccountServer(t)
	signIn(aliceIdentity)

	access := mintRESTAccessToken(t, s.Handler, aliceAcct, []string{"mcp:read"})
	if c, err := mintForBearer(s, access); err == nil {
		t.Errorf("a grant naming no identity minted %v", c)
	}

	session := DefaultOpenIDConnectSession(aliceAcct)
	session.AuthTime = time.Now()
	ar := fosite.NewAccessRequest(session)
	ar.Client = &fosite.DefaultClient{ID: "vscode-client"}
	ar.GrantScope("mcp:read")
	if scopes, err := s.reauthorizeGrant(context.Background(), ar); err == nil {
		t.Errorf("a grant naming no identity refreshed with %v", scopes)
	}
}

// The authorization-code flow records the approving identity on the grant
// too: a grant alice approved stays within alice's bound after carol, on
// the same account, signs in.
func TestPlacementBoundAuthorizationCodeGrant(t *testing.T) {
	s, signIn := sharedAccountServer(t)
	const clientID, redirect = "shared-code-client", "http://127.0.0.1/callback"
	if err := s.oauth2Provider.GetStorage().CreateClient(context.Background(), &fosite.DefaultClient{
		ID:            clientID,
		RedirectURIs:  []string{redirect},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "mcp:read", "mcp:write", "offline_access"},
		Public:        true,
	}); err != nil {
		t.Fatal(err)
	}
	alice := signIn(aliceIdentity)

	verifier := "a-code-verifier-long-enough-for-pkce-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, s.oauth2EndpointPath("authorize")+"?"+url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"scope": {"openid mcp:read mcp:write"}, "state": {"clientstate123"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}.Encode(), nil)
	req.AddCookie(alice)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Query().Get("state") == "" {
		t.Fatalf("authorize: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	state := loc.Query().Get("state")
	rec = s.form(t, alice, s.oauth2EndpointPath("consent"), url.Values{
		"state": {state}, "action": {"approve"}, consentCSRFField: {s.consentCSRFToken(aliceAcct, state)},
	})
	loc, err = url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("consent: %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	rec = s.form(t, nil, s.oauth2EndpointPath("token"), url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "client_id": {clientID},
		"redirect_uri": {redirect}, "code_verifier": {verifier},
	})
	var tok map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &tok) != nil {
		t.Fatalf("token: %d %s", rec.Code, rec.Body.String())
	}
	access, _ := tok["access_token"].(string)

	signIn(carolIdentity)
	c, err := mintForBearer(s, access)
	if err != nil {
		t.Fatalf("alice's grant after carol signed in: %v", err)
	}
	if !slices.Equal(mintedLevels(c), []string{"condor:/READ"}) || c["project"] != "ProjA" {
		t.Errorf("alice's grant minted %v; want READ only and ProjA", c)
	}
}

// An MCP authorization that signs in through the provider on the way to
// consent carries the placementd identity it mapped through to the consent
// step, and only a placementd mapping does.
func TestPlacementBoundSSOConsentCarriesIdentity(t *testing.T) {
	s, _ := sharedAccountServer(t)
	if err := s.oauth2Provider.GetStorage().CreateClient(context.Background(), &fosite.DefaultClient{
		ID: "shared-code-client", RedirectURIs: []string{"http://127.0.0.1/callback"},
		GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
		Scopes: []string{"openid", "mcp:read"}, Public: true,
	}); err != nil {
		t.Fatal(err)
	}
	authorize := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/mcp/oauth2/authorize?"+url.Values{
		"response_type": {"code"}, "client_id": {"shared-code-client"}, "redirect_uri": {"http://127.0.0.1/callback"},
		"scope": {"openid mcp:read"}, "state": {"clientstate123"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"},
	}.Encode(), nil)
	ar, err := s.oauth2Provider.GetProvider().NewAuthorizeRequest(context.Background(), authorize)
	if err != nil {
		t.Fatal(err)
	}
	state, err := s.oauth2StateStore.GenerateState()
	if err != nil {
		t.Fatal(err)
	}
	s.oauth2StateStore.StoreForBrowser(state, ar, "", "binding-nonce")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, webUICallbackPath+"?state="+state+"&code=c", nil)
	req.AddCookie(&http.Cookie{Name: loginBindingCookieName, Value: "binding-nonce"}) //nolint:gosec // G124: a request cookie in a test
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Query().Get("state") == "" {
		t.Fatalf("callback: %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if got := s.oauth2StateStore.PlacementIdentity(loc.Query().Get("state")); got != aliceIdentity {
		t.Errorf("consent state carries identity %q, want %q", got, aliceIdentity)
	}
}
