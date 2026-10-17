package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// onboardFake is the placementd for onboarding tests. It records every
// foreign ID any call named, so a test can assert that the session's is the
// only one that ever reaches the daemon.
type onboardFake struct {
	fakePlacementd
	mu       sync.Mutex
	names    []string
	logins   []htcondor.PlacementLoginRequest
	tokenExp time.Time
}

func (f *onboardFake) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.names = append(f.names, name)
}

func (f *onboardFake) Login(_ context.Context, req htcondor.PlacementLoginRequest) (*htcondor.PlacementLoginResult, error) {
	f.record(req.UserName)
	f.record(req.Requester)
	f.mu.Lock()
	f.logins = append(f.logins, req)
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return &htcondor.PlacementLoginResult{Token: testPlacementJWT(req.UserName, f.tokenExp)}, nil
}

func (f *onboardFake) QueryUsers(_ context.Context, userName string) ([]htcondor.PlacementUser, error) {
	f.record(userName)
	return f.users, f.err
}

func (f *onboardFake) QueryTokens(_ context.Context, q htcondor.PlacementTokenQuery) ([]htcondor.PlacementToken, error) {
	f.record(q.UserName)
	return f.tokens, f.err
}

func (f *onboardFake) QueryAuthorizations(_ context.Context, userName string) ([]htcondor.PlacementAuthorization, error) {
	f.record(userName)
	return f.authz, f.err
}

// testPlacementJWT is an unsigned token with the claims the handlers read.
func testPlacementJWT(sub string, exp time.Time) string {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := fmt.Sprintf(`{"sub":%q,"iat":%d,"exp":%d,"jti":"jti-1"}`, "ap-"+sub+"@ap.example", exp.Add(-time.Hour).Unix(), exp.Unix())
	return header + "." + enc.EncodeToString([]byte(claims)) + ".sig"
}

// fakeRecords stands in for the schedd's user and project records.
type fakeRecords struct {
	owners, projects []htcondor.UserRecord
	disabled         []string
	enabled          []string
	reasons          []string
	err              error
}

func (f *fakeRecords) QueryUserRecords(context.Context, *htcondor.UserRecordQueryOptions) ([]htcondor.UserRecord, error) {
	return f.owners, f.err
}

func (f *fakeRecords) QueryProjectRecords(context.Context, *htcondor.UserRecordQueryOptions) ([]htcondor.UserRecord, error) {
	return f.projects, f.err
}

func (f *fakeRecords) EnableUserRecord(_ context.Context, kind htcondor.UserRecordKind, name string) (*htcondor.UserRecordActionResult, error) {
	f.enabled = append(f.enabled, string(kind)+":"+name)
	return &htcondor.UserRecordActionResult{NumAds: 1}, f.err
}

func (f *fakeRecords) DisableUserRecord(_ context.Context, kind htcondor.UserRecordKind, name, reason string) (*htcondor.UserRecordActionResult, error) {
	f.disabled = append(f.disabled, string(kind)+":"+name)
	f.reasons = append(f.reasons, reason)
	return &htcondor.UserRecordActionResult{NumAds: 1}, f.err
}

func boolp(b bool) *bool { return &b }

const (
	aliceFID  = "alice@idp.example"
	aliceAcct = "alice@ap.example"
)

func newOnboardFake() *onboardFake {
	f := &onboardFake{tokenExp: time.Now().Add(6 * time.Hour).Truncate(time.Second)}
	f.users = []htcondor.PlacementUser{
		{UserName: aliceFID, APUserID: aliceAcct, Projects: []string{"ProjA", "ProjB"}, Authorizations: []string{"READ", "WRITE", "INSTRUCTOR"}, Authorized: true},
		{UserName: "mallory@idp.example", APUserID: "mallory@ap.example", Projects: []string{"ProjM"}, Authorizations: []string{"READ"}, Authorized: true},
	}
	f.authz = []htcondor.PlacementAuthorization{
		{Name: "READ", Label: "Read", Color: "normal", Description: "Read jobs"},
		{Name: "WRITE", Label: "Write", Color: "warning", Description: "Submit jobs"},
	}
	return f
}

type onboardingServer struct {
	*Server
	fake    *onboardFake
	records *fakeRecords
}

func newOnboardingServer(t *testing.T, fake *onboardFake) *onboardingServer {
	t.Helper()
	server, err := NewServer(Config{
		ListenAddr:   "127.0.0.1:0",
		ScheddName:   "ap.example",
		ScheddAddr:   "127.0.0.1:9618",
		SessionTTL:   time.Hour,
		OAuth2DBPath: t.TempDir() + "/t.db",
		Placementd:   fake,
		Logger:       newTestLogger(t),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	server.webuiAdminGroups = newGroupSet("condor-admins")
	recs := &fakeRecords{}
	server.placementOnboard.records = recs
	server.placementOnboard.collectorHost = "cm.example"
	server.setupRoutes()
	return &onboardingServer{Server: server, fake: fake, records: recs}
}

// placementCookie creates a placement-only session for foreignID.
func (s *onboardingServer) placementCookie(t *testing.T, foreignID string) *http.Cookie {
	t.Helper()
	sid, _, err := s.sessionStore.CreateSession(SessionData{
		PlacementForeignID: foreignID, DisplayName: "Alice", Scope: sessionScopePlacement,
	})
	if err != nil {
		t.Fatal(err)
	}
	return testSessionCookie(sid)
}

// userCookie creates an ordinary session.
func (s *onboardingServer) userCookie(t *testing.T, user, foreignID string, groups ...string) *http.Cookie {
	t.Helper()
	sid, _, err := s.sessionStore.CreateSession(SessionData{Username: user, Groups: groups, PlacementForeignID: foreignID})
	if err != nil {
		t.Fatal(err)
	}
	return testSessionCookie(sid)
}

func (s *onboardingServer) do(t *testing.T, c *http.Cookie, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequestWithContext(context.Background(), method, target, nil)
	} else {
		req = httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
	}
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestPlacementMeReportsTheSessionsIdentity(t *testing.T) {
	srv := newOnboardingServer(t, newOnboardFake())
	srv.records.projects = []htcondor.UserRecord{{User: "projb", Enabled: boolp(false)}}
	srv.records.owners = []htcondor.UserRecord{{User: aliceAcct, Enabled: boolp(false)}}

	rec := srv.do(t, srv.placementCookie(t, aliceFID), http.MethodGet, "/api/v1/placement/me", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var got placementMeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ForeignID != aliceFID || !got.Authorized || got.Expired || got.Account != aliceAcct {
		t.Errorf("me = %+v", got)
	}
	if len(got.Authorizations) != 2 || got.Authorizations[1].Color != "warning" {
		t.Errorf("authorizations = %+v", got.Authorizations)
	}
	want := []placementMeProject{{Name: "ProjA", Default: true, Enabled: true}, {Name: "ProjB", Enabled: false}}
	if fmt.Sprint(got.Projects) != fmt.Sprint(want) {
		t.Errorf("projects = %+v, want %+v", got.Projects, want)
	}
	if got.AccountEnabled || !got.RecordsAvailable {
		t.Errorf("account_enabled=%v records_available=%v", got.AccountEnabled, got.RecordsAvailable)
	}
}

func TestPlacementMeUnmappedIdentity(t *testing.T) {
	srv := newOnboardingServer(t, newOnboardFake())
	rec := srv.do(t, srv.placementCookie(t, "stranger@idp.example"), http.MethodGet, "/api/v1/placement/me", "")
	var got placementMeResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if got.Authorized || got.Account != "" {
		t.Errorf("an unmapped identity read as %+v", got)
	}
}

func TestPlacementMeExpiredMapping(t *testing.T) {
	fake := newOnboardFake()
	fake.users[0].MappingExpiration = time.Now().Add(-time.Hour)
	srv := newOnboardingServer(t, fake)
	rec := srv.do(t, srv.placementCookie(t, aliceFID), http.MethodGet, "/api/v1/placement/me", "")
	var got placementMeResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Authorized || !got.Expired {
		t.Errorf("expired mapping read as %+v", got)
	}
}

// The invariant this whole feature rests on: whatever the body says, the
// placementd is asked about, and mints for, the session's identity.
func TestPlacementTokenIsAlwaysForTheSessionIdentity(t *testing.T) {
	fake := newOnboardFake()
	srv := newOnboardingServer(t, fake)
	cookie := srv.placementCookie(t, aliceFID)

	for _, body := range []string{
		`{"project":"ProjA","authorizations":["READ"],"username":"mallory@idp.example"}`,
		`{"project":"ProjA","authorizations":["READ"],"requester":"mallory@idp.example"}`,
		`{"project":"ProjA","authorizations":["READ"],"foreign_id":"mallory@idp.example"}`,
	} {
		rec := srv.do(t, cookie, http.MethodPost, "/api/v1/placement/me/token", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("a body naming another identity got %d, want 400: %s", rec.Code, body)
		}
	}

	rec := srv.do(t, cookie, http.MethodPost, "/api/v1/placement/me/token", `{"project":"ProjA","authorizations":["read","WRITE"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if len(fake.logins) != 1 {
		t.Fatalf("%d logins", len(fake.logins))
	}
	login := fake.logins[0]
	if login.UserName != aliceFID || login.Requester != aliceFID {
		t.Errorf("login = %+v; UserName and Requester must both be the session's identity", login)
	}
	if login.Project != "ProjA" || strings.Join(login.Authorizations, ",") != "READ,WRITE" {
		t.Errorf("login = %+v", login)
	}
	for _, n := range fake.names {
		if n != aliceFID && n != "" {
			t.Errorf("the placementd was asked about %q", n)
		}
	}

	var got placementMeTokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Token == "" || got.APUserID != "ap-"+aliceFID+"@ap.example" || got.ExpiresAt == nil || !got.ExpiresAt.Equal(fake.tokenExp) {
		t.Errorf("token response = %+v", got)
	}
	if got.UserConfig != "SCHEDD_HOST = ap.example\nCOLLECTOR_HOST = cm.example" {
		t.Errorf("user_config = %q", got.UserConfig)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
}

// Only the authorizations offered as checkboxes may be asked for: a grant
// the operator did not make requestable stays out of self-service tokens.
func TestPlacementTokenRefusesUnofferedAuthorization(t *testing.T) {
	fake := newOnboardFake()
	srv := newOnboardingServer(t, fake)
	rec := srv.do(t, srv.placementCookie(t, aliceFID), http.MethodPost, "/api/v1/placement/me/token",
		`{"project":"ProjA","authorizations":["INSTRUCTOR"]}`)
	if rec.Code != http.StatusBadRequest || len(fake.logins) != 0 {
		t.Errorf("status %d, logins %d: %s", rec.Code, len(fake.logins), rec.Body.String())
	}
}

func TestPlacementTokenRequiresProjectAndAuthorizations(t *testing.T) {
	srv := newOnboardingServer(t, newOnboardFake())
	c := srv.placementCookie(t, aliceFID)
	for _, body := range []string{`{"authorizations":["READ"]}`, `{"project":"ProjA","authorizations":[]}`} {
		if rec := srv.do(t, c, http.MethodPost, "/api/v1/placement/me/token", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", body, rec.Code)
		}
	}
}

func TestPlacementTokenRefusesUnauthorizedIdentity(t *testing.T) {
	fake := newOnboardFake()
	srv := newOnboardingServer(t, fake)
	rec := srv.do(t, srv.placementCookie(t, "stranger@idp.example"), http.MethodPost, "/api/v1/placement/me/token",
		`{"project":"ProjA","authorizations":["READ"]}`)
	if rec.Code != http.StatusForbidden || len(fake.logins) != 0 {
		t.Errorf("status %d, logins %d", rec.Code, len(fake.logins))
	}
}

func TestPlacementTokenNeedsRequestedWithHeader(t *testing.T) {
	srv := newOnboardingServer(t, newOnboardFake())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/placement/me/token",
		strings.NewReader(`{"project":"ProjA","authorizations":["READ"]}`))
	req.AddCookie(srv.placementCookie(t, aliceFID))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status %d without X-Requested-With", rec.Code)
	}
}

// An ordinary session with a placement identity uses the same endpoints.
func TestPlacementMeForAnOrdinarySession(t *testing.T) {
	fake := newOnboardFake()
	srv := newOnboardingServer(t, fake)
	c := srv.userCookie(t, "alice", aliceFID)
	if rec := srv.do(t, c, http.MethodGet, "/api/v1/placement/me", ""); rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	rec := srv.do(t, c, http.MethodGet, "/api/v1/auth/me", "")
	var me AuthMeResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	if me.Username != "alice" || me.PlacementOnly || me.Placement == nil || me.Placement.ForeignID != aliceFID {
		t.Errorf("auth/me = %+v", me)
	}
}

func TestAuthMeForPlacementOnlySession(t *testing.T) {
	srv := newOnboardingServer(t, newOnboardFake())
	rec := srv.do(t, srv.placementCookie(t, aliceFID), http.MethodGet, "/api/v1/auth/me", "")
	var me AuthMeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if !me.Authenticated || !me.PlacementOnly || me.Username != "" || me.IsAdmin || me.Placement == nil ||
		me.Placement.ForeignID != aliceFID || me.Placement.DisplayName != "Alice" {
		t.Errorf("auth/me = %+v", me)
	}
}

func TestPlacementOnlySessionIsInvisibleToOrdinaryLookups(t *testing.T) {
	srv := newOnboardingServer(t, newOnboardFake())
	c := srv.placementCookie(t, aliceFID)
	if !strings.HasPrefix(c.Value, placementSessionPrefix) {
		t.Errorf("placement session cookie %q lacks its prefix", c.Value)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.AddCookie(c)
	if _, ok := srv.getSessionFromRequest(req); ok {
		t.Error("getSessionFromRequest returned a placement-only session")
	}
	if s, ok := srv.getAnySessionFromRequest(req); !ok || !s.IsPlacementOnly() {
		t.Error("getAnySessionFromRequest did not return the placement-only session")
	}
	// Stripping the prefix does not turn it into an ordinary session.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.AddCookie(testSessionCookie(strings.TrimPrefix(c.Value, placementSessionPrefix)))
	if _, ok := srv.getAnySessionFromRequest(req); ok {
		t.Error("a placement cookie with its prefix removed still found a session")
	}
	if _, _, err := srv.sessionStore.CreateSession(SessionData{Username: "alice", Scope: sessionScopePlacement}); err == nil {
		t.Error("a placement-only session was created with a username")
	}
}

// --- admin record views ---

func TestPlacementRecordsSuspendAccount(t *testing.T) {
	srv := newOnboardingServer(t, newOnboardFake())
	srv.records.owners = []htcondor.UserRecord{{User: aliceAcct, Enabled: boolp(true)}}
	admin := srv.userCookie(t, "root", "", "condor-admins")

	rec := srv.do(t, admin, http.MethodPost, "/api/v1/placement/records/accounts/"+aliceAcct+"/suspend", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if len(srv.records.disabled) != 1 || srv.records.disabled[0] != "Owner:"+aliceAcct ||
		srv.records.reasons[0] != "suspended by root via web UI" {
		t.Errorf("disabled=%v reasons=%v", srv.records.disabled, srv.records.reasons)
	}

	rec = srv.do(t, admin, http.MethodPost, "/api/v1/placement/records/projects/ProjB/unsuspend", "")
	if rec.Code != http.StatusOK || len(srv.records.enabled) != 1 || srv.records.enabled[0] != "Project:ProjB" {
		t.Errorf("unsuspend: %d %v %s", rec.Code, srv.records.enabled, rec.Body.String())
	}
}

func TestPlacementRecordsOnlyForPlacementNames(t *testing.T) {
	srv := newOnboardingServer(t, newOnboardFake())
	admin := srv.userCookie(t, "root", "", "condor-admins")
	rec := srv.do(t, admin, http.MethodPost, "/api/v1/placement/records/accounts/root@ap.example/suspend", "")
	if rec.Code != http.StatusNotFound || len(srv.records.disabled) != 0 {
		t.Errorf("suspending a name the placementd does not hand out: %d %v", rec.Code, srv.records.disabled)
	}
}

func TestPlacementRecordsAreAdminOnly(t *testing.T) {
	srv := newOnboardingServer(t, newOnboardFake())
	user := srv.userCookie(t, "alice", aliceFID)
	rec := srv.do(t, user, http.MethodPost, "/api/v1/placement/records/accounts/"+aliceAcct+"/suspend", "")
	if rec.Code != http.StatusForbidden || len(srv.records.disabled) != 0 {
		t.Errorf("non-admin suspend: %d", rec.Code)
	}
}

func TestPlacementRecordStats(t *testing.T) {
	srv := newOnboardingServer(t, newOnboardFake())
	ad := mustAd(t, `[Name = "ProjA"; NumIdle = 3; NumRunning = 2; TotalCompletedJobs = 40; Enabled = 0; DisableReason = "over quota"]`)
	srv.records.projects = []htcondor.UserRecord{{User: "ProjA", Enabled: boolp(false), DisableReason: "over quota", Ad: ad}}
	admin := srv.userCookie(t, "root", "", "condor-admins")
	rec := srv.do(t, admin, http.MethodGet, "/api/v1/placement/records/projects/ProjA", "")
	var got placementRecordResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if !got.Found || got.Enabled || got.DisableReason != "over quota" || got.Stats["NumIdle"] != 3 ||
		got.Stats["TotalCompletedJobs"] != 40 || len(got.Members) != 1 || got.Members[0] != aliceAcct {
		t.Errorf("record = %+v", got)
	}

	rec = srv.do(t, admin, http.MethodGet, "/api/v1/placement/records/projects", "")
	var list struct {
		Projects []placementProjectSummary `json:"projects"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list.Projects) != 3 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if list.Projects[0].Name != "ProjA" || list.Projects[0].Enabled || !list.Projects[1].Enabled {
		t.Errorf("projects = %+v", list.Projects)
	}
}

func TestOpenAPIDocumentsPlacementOnboarding(t *testing.T) {
	var doc struct {
		Paths map[string]any `json:"paths"`
	}
	if err := json.Unmarshal([]byte(openAPISchema), &doc); err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	for _, p := range []string{"/placement/me", "/placement/me/token", "/placement/me/device/{user_code}",
		"/placement/me/device/{user_code}/deny", "/placement/records/projects",
		"/placement/records/{kind}/{name}", "/placement/records/{kind}/{name}/{action}"} {
		if _, ok := doc.Paths[p]; !ok {
			t.Errorf("OpenAPI has no %s", p)
		}
	}
}

// testSessionCookie is the session cookie a browser would send.
func testSessionCookie(value string) *http.Cookie {
	return &http.Cookie{Name: sessionCookieName, Value: value} //nolint:gosec // G124: a request cookie in a test
}
