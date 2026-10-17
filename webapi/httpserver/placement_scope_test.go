package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// placementOAuthServer is an onboarding server with this server's own OAuth2
// provider, so placement_client and the placement scope exist.
func placementOAuthServer(t *testing.T, fake *onboardFake) *onboardingServer {
	t.Helper()
	srv, err := NewServer(Config{
		Logger:         newTestLogger(t),
		ScheddName:     "ap.example",
		ScheddAddr:     "127.0.0.1:1",
		EnableMCP:      true,
		OAuth2DBPath:   t.TempDir() + "/oauth2.db",
		OAuth2Issuer:   "http://localhost:8080",
		SigningKeyPath: writeTestSigningKey(t),
		TrustDomain:    "test.domain",
		UIDDomain:      "ap.example",
		SessionTTL:     time.Hour,
		Placementd:     fake,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.webuiAdminGroups = newGroupSet("condor-admins")
	recs := &fakeRecords{}
	srv.placementOnboard.records = recs
	srv.setupRoutes()
	return &onboardingServer{Server: srv, fake: fake, records: recs}
}

func (s *onboardingServer) form(t *testing.T, c *http.Cookie, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func (s *onboardingServer) bearer(t *testing.T, token, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

var csrfFieldRE = regexp.MustCompile(`name="` + consentCSRFField + `" value="([^"]+)"`)

// placementDeviceTokens runs placement-client's whole device flow, approved
// by approver, and returns the token response.
func placementDeviceTokens(t *testing.T, s *onboardingServer, approver *http.Cookie, scope string) map[string]any {
	t.Helper()
	rec := s.form(t, nil, oauth2EndpointPathFor(false, "device/authorize"),
		url.Values{"client_id": {placementClientID}, "scope": {scope}})
	var dev DeviceAuthorizationResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &dev) != nil {
		t.Fatalf("device authorize: %d %s", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		mcpDeviceVerifyPath+"?user_code="+url.QueryEscape(dev.UserCode), nil)
	req.AddCookie(approver)
	page := httptest.NewRecorder()
	s.ServeHTTP(page, req)
	m := csrfFieldRE.FindStringSubmatch(page.Body.String())
	if page.Code != http.StatusOK || m == nil {
		t.Fatalf("verify page: %d %s", page.Code, page.Body.String())
	}
	rec = s.form(t, approver, mcpDeviceVerifyPath, url.Values{
		"user_code": {dev.UserCode}, "action": {"approve"}, consentCSRFField: {m[1]},
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "approved") {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}

	rec = s.form(t, nil, oauth2EndpointPathFor(false, "token"), url.Values{
		"grant_type": {deviceCodeGrant}, "device_code": {dev.DeviceCode}, "client_id": {placementClientID},
	})
	var tok map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &tok) != nil {
		t.Fatalf("token: %d %s", rec.Code, rec.Body.String())
	}
	return tok
}

func TestPlacementClientIsSeeded(t *testing.T) {
	s := placementOAuthServer(t, newOnboardFake())
	c, err := s.oauth2Provider.GetStorage().GetClient(context.Background(), placementClientID)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsPublic() || !slices.Equal(c.GetScopes(), placementClientScopes) ||
		!slices.Contains(c.GetGrantTypes(), deviceCodeGrant) || !slices.Contains(c.GetGrantTypes(), "refresh_token") {
		t.Errorf("placement_client = public %v scopes %v grants %v", c.IsPublic(), c.GetScopes(), c.GetGrantTypes())
	}
	if !slices.Contains(oauth2AdvertisedScopes, placementScope) {
		t.Error("the placement scope is not advertised")
	}
}

func TestPlacementScopeCannotBeMixed(t *testing.T) {
	s := placementOAuthServer(t, newOnboardFake())
	rec := s.form(t, nil, oauth2EndpointPathFor(false, "device/authorize"),
		url.Values{"client_id": {placementClientID}, "scope": {"placement mcp:write"}})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_scope") {
		t.Errorf("mixed device request: %d %s", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		oauth2EndpointPathFor(false, "authorize")+"?client_id=x&response_type=code&scope=placement", nil)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_scope") {
		t.Errorf("placement through the code flow: %d %s", rr.Code, rr.Body.String())
	}
	// And no group policy ever grants it on its own.
	if got := s.getScopesForGroups([]string{"anyone"}, []string{placementScope, "mcp:read"}); slices.Contains(got, placementScope) {
		t.Errorf("getScopesForGroups granted %v", got)
	}
}

// The whole standard device flow: a placement-only session approves placement-client's
// device request, and the resulting bearer acts for that identity, and only
// on /me and /me/token.
func TestPlacementDeviceGrantActsForTheApprovingIdentity(t *testing.T) {
	fake := newOnboardFake()
	s := placementOAuthServer(t, fake)
	tok := placementDeviceTokens(t, s, s.placementCookie(t, aliceIdentity), "placement offline_access")
	access, _ := tok["access_token"].(string)
	if access == "" || tok["refresh_token"] == nil || !strings.Contains(tok["scope"].(string), placementScope) {
		t.Fatalf("token response = %v", tok)
	}

	rec := s.bearer(t, access, http.MethodGet, "/api/v1/placement/me", "")
	var me placementMeResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &me) != nil || me.Identity != aliceIdentity {
		t.Fatalf("/me with the bearer: %d %s", rec.Code, rec.Body.String())
	}
	rec = s.bearer(t, access, http.MethodPost, "/api/v1/placement/me/token",
		`{"project":"ProjA","authorizations":["READ"],"identity":"mallory@idp.example"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a bearer body naming another identity: %d", rec.Code)
	}
	rec = s.bearer(t, access, http.MethodPost, "/api/v1/placement/me/token", `{"project":"ProjA","authorizations":["READ"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("/me/token with the bearer: %d %s", rec.Code, rec.Body.String())
	}
	last := fake.logins[len(fake.logins)-1]
	if last.UserName != aliceIdentity || last.Requester != aliceIdentity {
		t.Errorf("login = %+v", last)
	}
	for _, n := range fake.names {
		if n != aliceIdentity && n != "" {
			t.Errorf("the placementd was asked about %q", n)
		}
	}
}

// A bearer holding the placement scope is refused on every other route.
func TestPlacementBearerIsRefusedEverywhereElse(t *testing.T) {
	s := placementOAuthServer(t, newOnboardFake())
	// Approved by an ordinary session, so its subject is a real local
	// user: the gate, not an empty subject, is what keeps it out.
	tok := placementDeviceTokens(t, s, s.userCookie(t, "alice", aliceIdentity), "placement")
	access := tok["access_token"].(string)

	var paths []string
	for _, p := range s.routePatterns {
		paths = append(paths, p)
		if strings.HasSuffix(p, "/") {
			paths = append(paths, p+"x", p+"1.0/stdout")
		}
	}
	paths = append(paths, "/api/v1/jobs/1.0", "/api/v1/placement/users", "/api/v1/placement/me/project",
		"/api/v1/placement/me/device/BCDF-GHJK")
	refused := 0
	for _, path := range paths {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			if placementBearerAllowed(method, path) {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			req := httptest.NewRequestWithContext(ctx, method, path, bytes.NewReader([]byte("{}")))
			req.Header.Set("Authorization", "Bearer "+access)
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, req)
			cancel()
			refused++
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s = %d with a placement bearer, want 403", method, path, rec.Code)
			}
		}
	}
	if refused < 300 {
		t.Errorf("only %d requests checked", refused)
	}
}

// A placement-only session approves placement requests and nothing else.
func TestPlacementOnlySessionCannotApproveOtherDeviceRequests(t *testing.T) {
	s := placementOAuthServer(t, newOnboardFake())
	rec := s.form(t, nil, oauth2EndpointPathFor(false, "device/authorize"),
		url.Values{"client_id": {sshGatewayClientID}, "scope": {"openid mcp:read"}})
	if rec.Code != http.StatusOK {
		// The SSH gateway client exists only with the gateway; any
		// device-capable non-placement client will do.
		if err := s.seedSSHGatewayClient(context.Background()); err != nil {
			t.Fatal(err)
		}
		rec = s.form(t, nil, oauth2EndpointPathFor(false, "device/authorize"),
			url.Values{"client_id": {sshGatewayClientID}, "scope": {"openid"}})
	}
	var dev DeviceAuthorizationResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &dev) != nil {
		t.Fatalf("device authorize: %d %s", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		mcpDeviceVerifyPath+"?user_code="+url.QueryEscape(dev.UserCode), nil)
	req.AddCookie(s.placementCookie(t, aliceIdentity))
	page := httptest.NewRecorder()
	s.ServeHTTP(page, req)
	if !strings.Contains(page.Body.String(), "can only approve placement") {
		t.Errorf("placement-only session on another request: %d %s", page.Code, page.Body.String())
	}
	rec = s.form(t, s.placementCookie(t, aliceIdentity), mcpDeviceVerifyPath,
		url.Values{"user_code": {dev.UserCode}, "action": {"approve"}})
	if !strings.Contains(rec.Body.String(), "can only approve placement") {
		t.Errorf("placement-only approve of another request: %d %s", rec.Code, rec.Body.String())
	}
}

// Refresh re-reads the identity: gone, or its account disabled at the schedd,
// ends the grant.
func TestPlacementGrantRefreshFollowsThePlacementd(t *testing.T) {
	for _, tc := range []struct {
		name    string
		breakIt func(*onboardingServer)
	}{
		{"identity removed", func(s *onboardingServer) { s.fake.users = s.fake.users[1:] }},
		{"mapping expired", func(s *onboardingServer) { s.fake.users[0].MappingExpiration = time.Now().Add(-time.Minute) }},
		{"account disabled", func(s *onboardingServer) {
			s.records.owners = []htcondor.UserRecord{{User: aliceAcct, Enabled: boolp(false), DisableReason: "left"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newOnboardFake()
			s := placementOAuthServer(t, fake)
			tok := placementDeviceTokens(t, s, s.placementCookie(t, aliceIdentity), "placement offline_access")
			refresh := tok["refresh_token"].(string)
			refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {placementClientID}}

			rec := s.form(t, nil, oauth2EndpointPathFor(false, "token"), refreshForm)
			if rec.Code != http.StatusOK {
				t.Fatalf("refresh while mapped: %d %s", rec.Code, rec.Body.String())
			}
			var next map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &next)

			tc.breakIt(s)
			refreshForm.Set("refresh_token", next["refresh_token"].(string))
			rec = s.form(t, nil, oauth2EndpointPathFor(false, "token"), refreshForm)
			if rec.Code == http.StatusOK {
				t.Fatalf("refresh after %s succeeded: %s", tc.name, rec.Body.String())
			}
			// Revoked, not just refused: the access token is dead too.
			if r := s.bearer(t, next["access_token"].(string), http.MethodGet, "/api/v1/placement/me", ""); r.Code == http.StatusOK {
				t.Errorf("the grant's access token still works after %s", tc.name)
			}
		})
	}
}
