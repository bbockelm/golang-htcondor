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
)

// fakePlacementd stands in for the daemon so the handler tests exercise
// routing, the admin gate, and the error mapping without a CEDAR peer.
type fakePlacementd struct {
	users  []htcondor.PlacementUser
	tokens []htcondor.PlacementToken
	authz  []htcondor.PlacementAuthorization
	// err, when set, is returned by every method.
	err error

	// What the handler passed down, for asserting query translation.
	gotUserName   string
	gotTokenQuery htcondor.PlacementTokenQuery
	gotLogin      htcondor.PlacementLoginRequest
}

func (f *fakePlacementd) Login(_ context.Context, req htcondor.PlacementLoginRequest) (*htcondor.PlacementLoginResult, error) {
	f.gotLogin = req
	if f.err != nil {
		return nil, f.err
	}
	return &htcondor.PlacementLoginResult{Token: "issued.jwt.token"}, nil //nolint:gosec // G101: a fixed test string, not a credential
}

func (f *fakePlacementd) QueryUsers(_ context.Context, userName string) ([]htcondor.PlacementUser, error) {
	f.gotUserName = userName
	return f.users, f.err
}

func (f *fakePlacementd) QueryTokens(_ context.Context, q htcondor.PlacementTokenQuery) ([]htcondor.PlacementToken, error) {
	f.gotTokenQuery = q
	return f.tokens, f.err
}

func (f *fakePlacementd) QueryAuthorizations(_ context.Context, userName string) ([]htcondor.PlacementAuthorization, error) {
	f.gotUserName = userName
	return f.authz, f.err
}

// newPlacementTestServer returns a server wired to fake, with the admin group
// configured, plus helpers that build admin and non-admin requests.
func newPlacementTestServer(t *testing.T, fake htcondor.PlacementdClient) (*Server, func(method, target, body string) *http.Request, func(method, target string) *http.Request) {
	t.Helper()

	server, err := NewServer(Config{
		ListenAddr:   "127.0.0.1:0",
		ScheddName:   "test",
		ScheddAddr:   "127.0.0.1:9618",
		SessionTTL:   time.Hour,
		OAuth2DBPath: t.TempDir() + "/t.db",
		Placementd:   fake,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	server.webuiAdminGroup = "condor-admins"

	req := func(user string, groups []string) func(method, target, body string) *http.Request {
		return func(method, target, body string) *http.Request {
			sid, _, err := server.sessionStore.Create(user, groups)
			if err != nil {
				t.Fatalf("session create: %v", err)
			}
			var r *http.Request
			if body == "" {
				r = httptest.NewRequestWithContext(context.Background(), method, target, nil)
			} else {
				r = httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
			}
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec
			return r
		}
	}

	admin := req("root", []string{"condor-admins"})
	user := req("alice", nil)
	return server, admin, func(method, target string) *http.Request { return user(method, target, "") }
}

func TestPlacementUsersEndpoint(t *testing.T) {
	tokenExp := time.Now().Add(6 * time.Hour).Truncate(time.Second)
	fake := &fakePlacementd{users: []htcondor.PlacementUser{
		{
			UserName:        "student1@example.edu",
			APUserID:        "student1@ap.example.edu",
			TokenExpiration: tokenExp,
			Projects:        []string{"Chem101"},
			Authorizations:  []string{"READ", "WRITE"},
			Authorized:      true,
		},
	}}
	server, admin, _ := newPlacementTestServer(t, fake)

	rec := httptest.NewRecorder()
	server.handlePlacementPath(rec, admin("GET", "/api/v1/placement/users?username=student1@example.edu", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if fake.gotUserName != "student1@example.edu" {
		t.Errorf("username filter = %q", fake.gotUserName)
	}

	var got struct {
		Users []placementUserResponse `json:"users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Users) != 1 {
		t.Fatalf("got %d users", len(got.Users))
	}
	u := got.Users[0]
	if u.UserName != "student1@example.edu" || !u.Authorized {
		t.Errorf("user = %+v", u)
	}
	if u.TokenExpiration == nil || !u.TokenExpiration.Equal(tokenExp) {
		t.Errorf("token_expiration = %v, want %v", u.TokenExpiration, tokenExp)
	}
	// The user has no mapping expiration; it must be omitted rather than
	// serialized as year 1.
	if u.MappingExpiration != nil {
		t.Errorf("mapping_expiration = %v, want absent", u.MappingExpiration)
	}
	if strings.Contains(rec.Body.String(), "mapping_expiration") {
		t.Errorf("absent expiration leaked into the body: %s", rec.Body.String())
	}
}

func TestPlacementTokensEndpoint(t *testing.T) {
	past := time.Now().Add(-time.Hour).Truncate(time.Second)
	future := time.Now().Add(time.Hour).Truncate(time.Second)
	fake := &fakePlacementd{tokens: []htcondor.PlacementToken{
		{TokenID: "old", UserName: "a@example.edu", Expiration: past},
		{TokenID: "new", UserName: "a@example.edu", Expiration: future},
		{TokenID: "forever", UserName: "a@example.edu"},
	}}
	server, admin, _ := newPlacementTestServer(t, fake)

	rec := httptest.NewRecorder()
	server.handlePlacementPath(rec, admin("GET", "/api/v1/placement/tokens?username=a@example.edu&valid_only=true", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !fake.gotTokenQuery.ValidOnly || fake.gotTokenQuery.UserName != "a@example.edu" {
		t.Errorf("query = %+v", fake.gotTokenQuery)
	}

	var got struct {
		Tokens []placementTokenResponse `json:"tokens"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Tokens) != 3 {
		t.Fatalf("got %d tokens", len(got.Tokens))
	}
	if !got.Tokens[0].Expired {
		t.Error("a token with a past expiration must report expired")
	}
	if got.Tokens[1].Expired {
		t.Error("a token expiring in the future must not report expired")
	}
	// A token with no expiration never expires; the zero time must not be
	// read as "expired in 1970".
	if got.Tokens[2].Expired {
		t.Error("a token with no expiration must not report expired")
	}
}

// valid_only is opt-in: anything that is not an affirmative value leaves
// expired tokens in the result.
func TestPlacementTokensValidOnlyParsing(t *testing.T) {
	cases := map[string]bool{
		"true": true, "TRUE": true, "1": true, "yes": true,
		"false": false, "0": false, "": false, "banana": false,
	}
	for value, want := range cases {
		fake := &fakePlacementd{}
		server, admin, _ := newPlacementTestServer(t, fake)
		rec := httptest.NewRecorder()
		server.handlePlacementPath(rec, admin("GET", "/api/v1/placement/tokens?valid_only="+value, ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("valid_only=%q: status %d", value, rec.Code)
		}
		if fake.gotTokenQuery.ValidOnly != want {
			t.Errorf("valid_only=%q -> %v, want %v", value, fake.gotTokenQuery.ValidOnly, want)
		}
	}
}

func TestPlacementLoginEndpoint(t *testing.T) {
	fake := &fakePlacementd{}
	server, admin, _ := newPlacementTestServer(t, fake)

	body := `{"username":"student1@example.edu","authorizations":["READ"],"project":"Chem101","requester":"prof@example.edu"}`
	rec := httptest.NewRecorder()
	server.handlePlacementPath(rec, admin("POST", "/api/v1/placement/login", body))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if fake.gotLogin.UserName != "student1@example.edu" || fake.gotLogin.Project != "Chem101" ||
		fake.gotLogin.Requester != "prof@example.edu" || len(fake.gotLogin.Authorizations) != 1 {
		t.Errorf("login request = %+v", fake.gotLogin)
	}

	var got placementLoginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Token != "issued.jwt.token" {
		t.Errorf("token = %q", got.Token)
	}
	// A bearer credential must not be cached by anything between us and
	// the browser.
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

func TestPlacementLoginRequiresUsername(t *testing.T) {
	server, admin, _ := newPlacementTestServer(t, &fakePlacementd{})
	rec := httptest.NewRecorder()
	server.handlePlacementPath(rec, admin("POST", "/api/v1/placement/login", `{"project":"Chem101"}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
}

// The placementd registers every command at ADMINISTRATOR and we talk to it as
// the AP's own identity, so a non-admin session reaching any placement
// endpoint would be able to mint a token for any mapped identity.
func TestPlacementEndpointsRequireAdmin(t *testing.T) {
	fake := &fakePlacementd{}
	server, _, nonAdmin := newPlacementTestServer(t, fake)

	for _, target := range []string{
		"/api/v1/placement/users",
		"/api/v1/placement/tokens",
		"/api/v1/placement/authorizations",
		"/api/v1/placement/status",
	} {
		rec := httptest.NewRecorder()
		server.handlePlacementPath(rec, nonAdmin("GET", target))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", target, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/api/v1/placement/login",
		strings.NewReader(`{"username":"student1@example.edu"}`))
	sid, _, err := server.sessionStore.Create("alice", nil)
	if err != nil {
		t.Fatalf("session create: %v", err)
	}
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec
	server.handlePlacementPath(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("login: status = %d, want 403", rec.Code)
	}
	if fake.gotLogin.UserName != "" {
		t.Error("BYPASS: a non-admin session reached the daemon")
	}
}

// An unauthenticated caller gets 401, not 403: they may simply need to sign in.
func TestPlacementEndpointsRequireSession(t *testing.T) {
	server, _, _ := newPlacementTestServer(t, &fakePlacementd{})
	rec := httptest.NewRecorder()
	server.handlePlacementPath(rec,
		httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/placement/users", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// With no placementd the endpoints must say so rather than 500, and status
// must still answer — that is what a UI asks before deciding to show the page.
func TestPlacementUnavailable(t *testing.T) {
	server, admin, _ := newPlacementTestServer(t, &fakePlacementd{})
	// Simulate discovery having found nothing.
	server.placementd = nil
	server.placementdAvailable.Store(false)

	rec := httptest.NewRecorder()
	server.handlePlacementPath(rec, admin("GET", "/api/v1/placement/users", ""))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("users: status = %d, want 503", rec.Code)
	}

	rec = httptest.NewRecorder()
	server.handlePlacementPath(rec, admin("GET", "/api/v1/placement/status", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	var st placementStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if st.Available {
		t.Error("status must report unavailable")
	}
	if st.Reason == "" {
		t.Error("status must explain why it is unavailable")
	}
}

func TestPlacementUnknownPath(t *testing.T) {
	server, admin, _ := newPlacementTestServer(t, &fakePlacementd{})
	rec := httptest.NewRecorder()
	server.handlePlacementPath(rec, admin("GET", "/api/v1/placement/nope", ""))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// The daemon's policy refusals must reach the caller as an actionable status,
// not as a generic upstream failure.
func TestPlacementErrorStatusMapping(t *testing.T) {
	cases := map[int]int{
		htcondor.PlacementErrMissingUserName:         http.StatusBadRequest,
		htcondor.PlacementErrUserNotAuthorized:       http.StatusForbidden,
		htcondor.PlacementErrAuthorizationDenied:     http.StatusForbidden,
		htcondor.PlacementErrProjectNotAuthorized:    http.StatusForbidden,
		htcondor.PlacementErrRequesterNotInstructor:  http.StatusForbidden,
		htcondor.PlacementErrRequesterMappingExpired: http.StatusForbidden,
		htcondor.PlacementErrDatabase:                http.StatusInternalServerError,
		htcondor.PlacementErrNotEncrypted:            http.StatusInternalServerError,
		// The schedd leg, and any code the daemon forwards verbatim.
		htcondor.PlacementErrSchedd: http.StatusBadGateway,
		9999:                        http.StatusBadGateway,
	}
	for code, want := range cases {
		if got := placementErrorStatus(code); got != want {
			t.Errorf("code %d -> %d, want %d", code, got, want)
		}
	}
}

func TestPlacementLoginDaemonRefusal(t *testing.T) {
	fake := &fakePlacementd{err: &htcondor.PlacementError{
		Code:    htcondor.PlacementErrProjectNotAuthorized,
		Message: "User not authorized for project",
	}}
	server, admin, _ := newPlacementTestServer(t, fake)

	rec := httptest.NewRecorder()
	server.handlePlacementPath(rec,
		admin("POST", "/api/v1/placement/login", `{"username":"a@example.edu","project":"Bio200"}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not authorized for project") {
		t.Errorf("the daemon's reason should reach the caller: %s", rec.Body.String())
	}
}
