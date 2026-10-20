package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// requestsFake is the onboarding fake plus the directory commands an
// approval uses.
type requestsFake struct {
	*onboardFake
	apiVersion int

	mu sync.Mutex
	// identities and accounts answer keyed Identity and Account queries.
	identities map[string]*htcondor.PlacementIdentity
	accounts   map[string]*htcondor.PlacementAccount
	// modifications answer a Modification query by entity id.
	modifications map[string]*htcondor.PlacementModification
	// results and editErr, when set, are what Edit returns.
	results []htcondor.PlacementEditResult
	editErr error

	// onEdit, when set, runs at the start of every Edit, before the
	// batch is recorded: what happens while the daemon works.
	onEdit func()

	edits   [][]htcondor.PlacementOp
	opts    []htcondor.PlacementEditOptions
	queries []htcondor.PlacementQuery
}

func newRequestsFake() *requestsFake {
	return &requestsFake{
		onboardFake:   newOnboardFake(),
		apiVersion:    2,
		identities:    map[string]*htcondor.PlacementIdentity{},
		accounts:      map[string]*htcondor.PlacementAccount{},
		modifications: map[string]*htcondor.PlacementModification{},
	}
}

func (f *requestsFake) APIVersion(context.Context) (int, error) { return f.apiVersion, nil }

func (f *requestsFake) Query(_ context.Context, q htcondor.PlacementQuery) ([]htcondor.PlacementObject, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, q)
	switch q.TargetType {
	case htcondor.PlacementTargetIdentity:
		if i := f.identities[q.Key]; i != nil {
			return []htcondor.PlacementObject{{Type: q.TargetType, Identity: i}}, nil
		}
	case htcondor.PlacementTargetAccount:
		if a := f.accounts[q.Key]; a != nil {
			return []htcondor.PlacementObject{{Type: q.TargetType, Account: a}}, nil
		}
	case htcondor.PlacementTargetModification:
		if m := f.modifications[q.EntityID]; m != nil {
			return []htcondor.PlacementObject{{Type: q.TargetType, Modification: m}}, nil
		}
	}
	return []htcondor.PlacementObject{}, nil
}

func (f *requestsFake) Edit(_ context.Context, ops []htcondor.PlacementOp, opts htcondor.PlacementEditOptions) ([]htcondor.PlacementEditResult, error) {
	if f.onEdit != nil {
		f.onEdit()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.edits = append(f.edits, ops)
	f.opts = append(f.opts, opts)
	if f.results != nil || f.editErr != nil {
		return f.results, f.editErr
	}
	out := make([]htcondor.PlacementEditResult, len(ops))
	for i := range ops {
		out[i] = htcondor.PlacementEditResult{Index: i, ID: fmt.Sprintf("uuid-%d", i), Version: int64(40 + i)}
	}
	return out, nil
}

func (f *requestsFake) editCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.edits)
}

// requestsServer is an onboarding server whose placementd is a requestsFake.
type requestsServer struct {
	*Server
	fake *requestsFake
}

func newRequestsServer(t *testing.T, configure ...func(*Config)) *requestsServer {
	t.Helper()
	fake := newRequestsFake()
	cfg := Config{
		ListenAddr:   "127.0.0.1:0",
		ScheddName:   "ap.example",
		ScheddAddr:   "127.0.0.1:9618",
		SessionTTL:   time.Hour,
		OAuth2DBPath: t.TempDir() + "/t.db",
		Placementd:   fake,
		UIDDomain:    "ap.example",
		Logger:       newTestLogger(t),
	}
	for _, f := range configure {
		f(&cfg)
	}
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	server.webuiAdminGroups = newGroupSet("condor-admins")
	server.placementOnboard.records = &fakeRecords{}
	server.setupRoutes()
	return &requestsServer{Server: server, fake: fake}
}

const requesterIdentity = "newbie@idp.example"

// placementSession creates a placement-only session for identity.
func (s *requestsServer) placementSession(t *testing.T, identity string) *http.Cookie {
	t.Helper()
	sid, _, err := s.sessionStore.CreateSession(SessionData{
		PlacementIdentity: identity, DisplayName: "New Bie", Email: "newbie@example.edu", Scope: sessionScopePlacement,
	})
	if err != nil {
		t.Fatal(err)
	}
	return testSessionCookie(sid)
}

func (s *requestsServer) session(t *testing.T, user string, groups ...string) *http.Cookie {
	t.Helper()
	sid, _, err := s.sessionStore.CreateSession(SessionData{Username: user, Groups: groups})
	if err != nil {
		t.Fatal(err)
	}
	return testSessionCookie(sid)
}

func (s *requestsServer) admin(t *testing.T) *http.Cookie {
	return s.session(t, "root", "condor-admins")
}

func (s *requestsServer) do(t *testing.T, c *http.Cookie, method, target, body string, header ...string) *httptest.ResponseRecorder {
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
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func (s *requestsServer) stored(t *testing.T, identity string) *placementAccessRequest {
	t.Helper()
	req, err := s.placementOnboard.requests.latest(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func decodeMeRequest(t *testing.T, rec *httptest.ResponseRecorder) placementMeRequestResponse {
	t.Helper()
	var out placementMeRequestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
	return out
}

func mustStatus(t *testing.T, rec *httptest.ResponseRecorder, want int, what string) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("%s: status %d, want %d; body %s", what, rec.Code, want, rec.Body.String())
	}
}

// fileRequest files a request for the session's identity.
func (s *requestsServer) fileRequest(t *testing.T, c *http.Cookie) placementMeRequestResponse {
	t.Helper()
	rec := s.do(t, c, "POST", "/api/v1/placement/me/request", `{"projects":["Physics"],"note":"PhD student"}`)
	mustStatus(t, rec, http.StatusCreated, "file a request")
	return decodeMeRequest(t, rec)
}

func TestAccessRequestLifecycle(t *testing.T) {
	srv := newRequestsServer(t)
	newbie := srv.placementSession(t, requesterIdentity)

	rec := srv.do(t, newbie, "GET", "/api/v1/placement/me/request", "")
	mustStatus(t, rec, http.StatusOK, "first GET")
	got := decodeMeRequest(t, rec)
	if got.Request != nil || got.Identity != requesterIdentity || got.DisplayName != "New Bie" || got.Email != "newbie@example.edu" {
		t.Fatalf("before any request: %+v", got)
	}

	rec = srv.do(t, newbie, "POST", "/api/v1/placement/me/request",
		`{"projects":["Physics"," physics ","Chemistry",""],"note":"  PhD student\r\nin physics  "}`)
	mustStatus(t, rec, http.StatusCreated, "create")
	got = decodeMeRequest(t, rec)
	if got.Request == nil || got.Request.Status != accessRequestPending {
		t.Fatalf("created: %+v", got)
	}
	if strings.Join(got.Request.Projects, ",") != "Physics,Chemistry" || got.Request.Note != "PhD student\nin physics" {
		t.Errorf("projects %q note %q", got.Request.Projects, got.Request.Note)
	}
	stored := srv.stored(t, requesterIdentity)
	if stored.DisplayName != "New Bie" || stored.Email != "newbie@example.edu" {
		t.Errorf("stored %+v: display name and email come from the session", stored)
	}

	rec = srv.do(t, newbie, "POST", "/api/v1/placement/me/request", `{"projects":["Other"]}`)
	mustStatus(t, rec, http.StatusConflict, "a second pending request")

	rec = srv.do(t, newbie, "DELETE", "/api/v1/placement/me/request", "")
	mustStatus(t, rec, http.StatusOK, "withdraw")
	if r := decodeMeRequest(t, rec).Request; r == nil || r.Status != accessRequestWithdrawn {
		t.Fatalf("withdrawn: %+v", r)
	}
	rec = srv.do(t, newbie, "DELETE", "/api/v1/placement/me/request", "")
	mustStatus(t, rec, http.StatusNotFound, "withdraw with nothing pending")

	// A new request once the old one is withdrawn.
	srv.fileRequest(t, newbie)
}

func TestAccessRequestListAndDeny(t *testing.T) {
	srv := newRequestsServer(t, func(c *Config) { c.PlacementPrefillDomains = []string{"idp.example"} })
	newbie := srv.placementSession(t, requesterIdentity)
	srv.fileRequest(t, newbie)
	mustStatus(t, srv.do(t, newbie, "DELETE", "/api/v1/placement/me/request", ""), http.StatusOK, "withdraw")
	id := srv.fileRequest(t, newbie).Request.ID

	admin := srv.admin(t)
	rec := srv.do(t, admin, "GET", "/api/v1/placement/admin/requests", "")
	mustStatus(t, rec, http.StatusOK, "admin list")
	var list placementAccessRequestList
	decodeBody(t, rec, &list)
	if list.Pending != 1 || len(list.Requests) != 1 || list.Requests[0].ID != id || !list.CanApprove {
		t.Fatalf("list = %+v", list)
	}
	if r := list.Requests[0]; r.Identity != requesterIdentity || r.Email != "newbie@example.edu" ||
		r.DisplayName != "New Bie" || r.SuggestedAccount != "newbie@ap.example" {
		t.Errorf("listed request = %+v", r)
	}
	rec = srv.do(t, admin, "GET", "/api/v1/placement/admin/requests?status=all", "")
	decodeBody(t, rec, &list)
	if len(list.Requests) != 2 {
		t.Errorf("status=all lists %d requests, want 2", len(list.Requests))
	}
	rec = srv.do(t, admin, "GET", "/api/v1/placement/admin/requests/count", "")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"pending":1}` {
		t.Errorf("count = %d %s", rec.Code, rec.Body.String())
	}

	rec = srv.do(t, admin, "POST", fmt.Sprintf("/api/v1/placement/admin/requests/%d/deny", id), `{"reason":""}`)
	mustStatus(t, rec, http.StatusBadRequest, "deny without a reason")
	rec = srv.do(t, admin, "POST", fmt.Sprintf("/api/v1/placement/admin/requests/%d/deny", id), `{"reason":"Ask your PI to sponsor you."}`)
	mustStatus(t, rec, http.StatusOK, "deny")
	rec = srv.do(t, admin, "POST", fmt.Sprintf("/api/v1/placement/admin/requests/%d/deny", id), `{"reason":"again"}`)
	mustStatus(t, rec, http.StatusConflict, "deny twice")
	rec = srv.do(t, admin, "POST", fmt.Sprintf("/api/v1/placement/admin/requests/%d/approve", id), `{"account":"newbie@ap.example"}`)
	mustStatus(t, rec, http.StatusConflict, "approve a denied request")
	if srv.fake.editCount() != 0 {
		t.Error("approving a denied request reached the placementd")
	}

	rec = srv.do(t, newbie, "GET", "/api/v1/placement/me/request", "")
	got := decodeMeRequest(t, rec)
	if got.Request == nil || got.Request.Status != accessRequestDenied || got.Request.Reason != "Ask your PI to sponsor you." {
		t.Fatalf("after denial: %+v", got.Request)
	}
	if stored := srv.stored(t, requesterIdentity); stored.DecidedBy != "root" || stored.DecidedAt.IsZero() {
		t.Errorf("denial recorded as %+v", stored)
	}
	// Who decided is for admins; the requester sees the reason only.
	if strings.Contains(rec.Body.String(), "root") {
		t.Errorf("the requester's view names the admin: %s", rec.Body.String())
	}
}

// Whose request it is comes from the session, never the request.
func TestAccessRequestIdentityComesFromTheSession(t *testing.T) {
	srv := newRequestsServer(t)
	newbie := srv.placementSession(t, requesterIdentity)

	rec := srv.do(t, newbie, "POST", "/api/v1/placement/me/request",
		`{"identity":"mallory@idp.example","projects":["Physics"]}`)
	mustStatus(t, rec, http.StatusBadRequest, "a body naming an identity")
	for _, id := range []string{requesterIdentity, "mallory@idp.example"} {
		if r := srv.stored(t, id); r != nil {
			t.Errorf("a refused body stored a request for %s: %+v", id, r)
		}
	}

	// Query parameters and headers are not consulted.
	rec = srv.do(t, newbie, "POST", "/api/v1/placement/me/request?identity=mallory@idp.example",
		`{"projects":["Physics"]}`, "X-Placement-Identity", "mallory@idp.example", "X-Remote-User", "mallory@idp.example")
	mustStatus(t, rec, http.StatusCreated, "create with spoofing parameters")
	if got := decodeMeRequest(t, rec); got.Identity != requesterIdentity {
		t.Errorf("response names %q", got.Identity)
	}
	if r := srv.stored(t, "mallory@idp.example"); r != nil {
		t.Errorf("a request was stored for mallory: %+v", r)
	}
	if r := srv.stored(t, requesterIdentity); r == nil || r.Status != accessRequestPending {
		t.Fatalf("newbie's request = %+v", r)
	}
	// The placementd was asked about the session's identity only.
	for _, name := range srv.fake.names {
		if name != requesterIdentity {
			t.Errorf("the placementd was asked about %q", name)
		}
	}

	// Another person cannot see or withdraw it.
	other := srv.placementSession(t, "other@idp.example")
	rec = srv.do(t, other, "GET", "/api/v1/placement/me/request?identity="+requesterIdentity, "")
	if got := decodeMeRequest(t, rec); got.Request != nil {
		t.Errorf("another identity sees %+v", got.Request)
	}
	rec = srv.do(t, other, "DELETE", "/api/v1/placement/me/request?identity="+requesterIdentity, "")
	mustStatus(t, rec, http.StatusNotFound, "withdraw somebody else's request")
	if r := srv.stored(t, requesterIdentity); r.Status != accessRequestPending {
		t.Errorf("newbie's request is %s", r.Status)
	}

	// A browser request without the CSRF header is refused.
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/api/v1/placement/me/request", strings.NewReader(`{}`))
	req.AddCookie(other)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	mustStatus(t, rec, http.StatusForbidden, "no X-Requested-With")
}

// Only an identity without access may ask for it.
func TestAccessRequestOnlyForUnmappedIdentities(t *testing.T) {
	srv := newRequestsServer(t)

	rec := srv.do(t, srv.placementSession(t, aliceIdentity), "POST", "/api/v1/placement/me/request", `{"projects":["ProjA"]}`)
	mustStatus(t, rec, http.StatusConflict, "an authorized identity")
	if r := srv.stored(t, aliceIdentity); r != nil {
		t.Errorf("stored %+v", r)
	}

	// A session with no placement identity has nothing to ask for.
	rec = srv.do(t, srv.session(t, "bob"), "POST", "/api/v1/placement/me/request", `{}`)
	mustStatus(t, rec, http.StatusForbidden, "no placement identity")
	rec = srv.do(t, nil, "POST", "/api/v1/placement/me/request", `{}`)
	mustStatus(t, rec, http.StatusUnauthorized, "no session")
}

func TestAccessRequestAdminOnly(t *testing.T) {
	srv := newRequestsServer(t)
	newbie := srv.placementSession(t, requesterIdentity)
	id := srv.fileRequest(t, newbie).Request.ID
	user := srv.session(t, "alice")

	paths := []struct{ method, path, body string }{
		{"GET", "/api/v1/placement/admin/requests", ""},
		{"GET", "/api/v1/placement/admin/requests?status=all", ""},
		{"GET", "/api/v1/placement/admin/requests/count", ""},
		{"GET", fmt.Sprintf("/api/v1/placement/admin/requests/%d", id), ""},
		{"POST", fmt.Sprintf("/api/v1/placement/admin/requests/%d/approve", id), `{"account":"newbie@ap.example"}`},
		{"POST", fmt.Sprintf("/api/v1/placement/admin/requests/%d/deny", id), `{"reason":"no"}`},
		{"POST", fmt.Sprintf("/api/v1/placement/admin/requests/%d/resolve", id), `{}`},
	}
	for _, p := range paths {
		if rec := srv.do(t, user, p.method, p.path, p.body); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s as a non-admin = %d, want 403", p.method, p.path, rec.Code)
		}
		// A placement-only session -- the requester's own -- is turned
		// away before any handler.
		if rec := srv.do(t, newbie, p.method, p.path, p.body); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s as the requester = %d, want 403", p.method, p.path, rec.Code)
		}
		if rec := srv.do(t, nil, p.method, p.path, p.body); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with no session = %d, want 401", p.method, p.path, rec.Code)
		}
	}
	if srv.fake.editCount() != 0 {
		t.Error("a refused request reached PLACEMENT_EDIT")
	}
	if r := srv.stored(t, requesterIdentity); r.Status != accessRequestPending {
		t.Errorf("request is %s after refused decisions", r.Status)
	}
}

func approvePath(id int64) string {
	return fmt.Sprintf("/api/v1/placement/admin/requests/%d/approve", id)
}

// Approval is one PLACEMENT_EDIT batch for the request's identity, made on
// behalf of the signed-in admin, and the request records it.
func TestAccessRequestApproveBatch(t *testing.T) {
	srv := newRequestsServer(t)
	id := srv.fileRequest(t, srv.placementSession(t, requesterIdentity)).Request.ID
	srv.fake.modifications["uuid-1"] = &htcondor.PlacementModification{ID: 41, ChangesetID: 7, EntityID: "uuid-1"}
	admin := srv.admin(t)

	// The body can name neither the identity nor who is acting.
	for _, body := range []string{
		`{"account":"newbie@ap.example","identity":"mallory@idp.example"}`,
		`{"account":"newbie@ap.example","on_behalf_of":"someone-else"}`,
		`{"account":""}`,
	} {
		rec := srv.do(t, admin, "POST", approvePath(id), body)
		mustStatus(t, rec, http.StatusBadRequest, body)
	}
	if srv.fake.editCount() != 0 {
		t.Fatal("a refused approval reached PLACEMENT_EDIT")
	}

	rec := srv.do(t, admin, "POST", approvePath(id), `{
		"account":"newbie@ap.example","authorizations":["READ","WRITE"],
		"projects":["Physics","Chemistry"],"default_project":"Physics",
		"expires_at":"2030-01-02T03:04:05Z","display_name":"New Bie","comment":"welcome"}`)
	mustStatus(t, rec, http.StatusOK, "approve")
	var resp placementApproveResponse
	decodeBody(t, rec, &resp)
	if !resp.Committed || resp.Request == nil || resp.Request.Status != accessRequestApproved {
		t.Fatalf("response = %+v", resp)
	}

	if srv.fake.editCount() != 1 {
		t.Fatalf("%d PLACEMENT_EDIT batches, want 1", srv.fake.editCount())
	}
	ops, opts := srv.fake.edits[0], srv.fake.opts[0]
	if opts.OnBehalfOf != "root" {
		t.Errorf("OnBehalfOf = %q, want the signed-in admin", opts.OnBehalfOf)
	}
	if opts.Comment != fmt.Sprintf("access request #%d: welcome", id) {
		t.Errorf("Comment = %q", opts.Comment)
	}
	if opts.DryRun {
		t.Error("sent as a dry run")
	}
	if len(ops) != 2 {
		t.Fatalf("ops = %+v", ops)
	}
	acct, ident := ops[0], ops[1]
	if acct.Operation != htcondor.PlacementOpCreate || acct.TargetType != htcondor.PlacementTargetAccount ||
		acct.Fields["Name"] != "newbie@ap.example" || acct.Fields["DefaultProject"] != "Physics" ||
		strings.Join(acct.Fields["Authorizations"].([]string), ",") != "READ,WRITE" ||
		strings.Join(acct.Fields["Projects"].([]string), ",") != "Physics,Chemistry" {
		t.Errorf("account op = %+v", acct)
	}
	if ident.Operation != htcondor.PlacementOpCreate || ident.TargetType != htcondor.PlacementTargetIdentity ||
		ident.Fields["Identity"] != requesterIdentity || ident.Fields["Account"] != "newbie@ap.example" ||
		ident.Fields["DisplayName"] != "New Bie" {
		t.Errorf("identity op = %+v", ident)
	}
	if exp, ok := ident.Fields["ExpiresAt"].(time.Time); !ok || !exp.Equal(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("ExpiresAt = %v", ident.Fields["ExpiresAt"])
	}

	stored := srv.stored(t, requesterIdentity)
	if stored.Status != accessRequestApproved || stored.DecidedBy != "root" || stored.Account != "newbie@ap.example" ||
		stored.ChangesetID != 7 || stored.DecisionNote != "welcome" {
		t.Errorf("stored = %+v", stored)
	}

	// Approving again is a conflict, and sends nothing.
	rec = srv.do(t, admin, "POST", approvePath(id), `{"account":"newbie@ap.example"}`)
	mustStatus(t, rec, http.StatusConflict, "approve twice")
	if srv.fake.editCount() != 1 {
		t.Error("a second approval reached PLACEMENT_EDIT")
	}
}

func TestAccessRequestApproveDryRunChangesNothing(t *testing.T) {
	srv := newRequestsServer(t)
	id := srv.fileRequest(t, srv.placementSession(t, requesterIdentity)).Request.ID
	rec := srv.do(t, srv.admin(t), "POST", approvePath(id)+"?dry_run=1", `{"account":"newbie@ap.example","authorizations":["READ"]}`)
	mustStatus(t, rec, http.StatusOK, "dry run")
	if !srv.fake.opts[0].DryRun {
		t.Error("not sent as a dry run")
	}
	if r := srv.stored(t, requesterIdentity); r.Status != accessRequestPending {
		t.Errorf("a dry run left the request %s", r.Status)
	}
}

// The request is approved only when the batch committed.
func TestAccessRequestFailedBatchLeavesItPending(t *testing.T) {
	srv := newRequestsServer(t)
	id := srv.fileRequest(t, srv.placementSession(t, requesterIdentity)).Request.ID
	srv.fake.results = []htcondor.PlacementEditResult{
		{Index: 0, ErrorCode: htcondor.PlacementErrInvalidArgument, ErrorString: "ADMINISTRATOR may not be granted"},
		{Index: 1},
	}
	srv.fake.editErr = &htcondor.PlacementError{Code: htcondor.PlacementErrInvalidArgument, Message: "operation 0: ADMINISTRATOR may not be granted"}

	rec := srv.do(t, srv.admin(t), "POST", approvePath(id), `{"account":"newbie@ap.example","authorizations":["ADMINISTRATOR"]}`)
	mustStatus(t, rec, http.StatusBadRequest, "a refused batch")
	if r := srv.stored(t, requesterIdentity); r.Status != accessRequestPending || r.DecidedBy != "" || r.Account != "" {
		t.Errorf("after a refused batch the request is %+v", r)
	}

	// Nor when the daemon cannot be reached.
	srv.fake.results, srv.fake.editErr = nil, errors.New("connection refused")
	rec = srv.do(t, srv.admin(t), "POST", approvePath(id), `{"account":"newbie@ap.example"}`)
	mustStatus(t, rec, http.StatusBadGateway, "an unreachable placementd")
	if r := srv.stored(t, requesterIdentity); r.Status != accessRequestPending {
		t.Errorf("after a failed call the request is %s", r.Status)
	}
}

func TestAccessRequestApproveIdentityExists(t *testing.T) {
	srv := newRequestsServer(t)
	id := srv.fileRequest(t, srv.placementSession(t, requesterIdentity)).Request.ID
	admin := srv.admin(t)

	// Onboarded in the directory meanwhile: nothing is sent.
	srv.fake.identities[requesterIdentity] = &htcondor.PlacementIdentity{Identity: requesterIdentity, Account: "nb@ap.example"}
	rec := srv.do(t, admin, "POST", approvePath(id), `{"account":"newbie@ap.example"}`)
	mustStatus(t, rec, http.StatusConflict, "identity exists")
	var body placementIdentityExistsBody
	decodeBody(t, rec, &body)
	if !body.IdentityExists {
		t.Errorf("409 body = %+v", body)
	}
	if srv.fake.editCount() != 0 {
		t.Error("an approval for an existing identity reached PLACEMENT_EDIT")
	}

	// Or between the check and the batch: the daemon's duplicate.
	delete(srv.fake.identities, requesterIdentity)
	srv.fake.results = []htcondor.PlacementEditResult{{Index: 0}, {Index: 1, ErrorCode: htcondor.PlacementErrDuplicate, ErrorString: "duplicate"}}
	srv.fake.editErr = &htcondor.PlacementError{Code: htcondor.PlacementErrDuplicate, Message: "operation 1: duplicate"}
	rec = srv.do(t, admin, "POST", approvePath(id), `{"account":"newbie@ap.example"}`)
	mustStatus(t, rec, http.StatusConflict, "duplicate from the daemon")
	decodeBody(t, rec, &body)
	if !body.IdentityExists {
		t.Errorf("409 body = %+v", body)
	}
	if r := srv.stored(t, requesterIdentity); r.Status != accessRequestPending {
		t.Fatalf("request is %s", r.Status)
	}

	// Mark resolved: only once the identity really has access.
	resolve := fmt.Sprintf("/api/v1/placement/admin/requests/%d/resolve", id)
	rec = srv.do(t, admin, "POST", resolve, `{"comment":"onboarded by hand"}`)
	mustStatus(t, rec, http.StatusConflict, "resolve without access")
	srv.fake.users = append(srv.fake.users, htcondor.PlacementUser{
		UserName: requesterIdentity, APUserID: "nb@ap.example", Authorized: true,
	})
	rec = srv.do(t, admin, "POST", resolve, `{"comment":"onboarded by hand","account":"x"}`)
	mustStatus(t, rec, http.StatusBadRequest, "resolve with an account")
	rec = srv.do(t, admin, "POST", resolve, `{"comment":"onboarded by hand"}`)
	mustStatus(t, rec, http.StatusOK, "resolve")
	r := srv.stored(t, requesterIdentity)
	if r.Status != accessRequestApproved || r.Account != "nb@ap.example" || r.DecidedBy != "root" || r.ChangesetID != 0 {
		t.Errorf("resolved request = %+v", r)
	}
}

func TestAccessRequestApproveNeedsTheDirectory(t *testing.T) {
	srv := newRequestsServer(t)
	srv.fake.apiVersion = 1
	id := srv.fileRequest(t, srv.placementSession(t, requesterIdentity)).Request.ID
	admin := srv.admin(t)

	rec := srv.do(t, admin, "GET", "/api/v1/placement/admin/requests", "")
	mustStatus(t, rec, http.StatusOK, "list on API v1")
	var list placementAccessRequestList
	decodeBody(t, rec, &list)
	if list.CanApprove || len(list.Requests) != 1 {
		t.Errorf("list = %+v", list)
	}
	rec = srv.do(t, admin, "POST", approvePath(id), `{"account":"newbie@ap.example"}`)
	mustStatus(t, rec, http.StatusNotImplemented, "approve on API v1")
	if srv.fake.editCount() != 0 {
		t.Error("an approval on API v1 reached PLACEMENT_EDIT")
	}
}

func TestAccessRequestRateLimit(t *testing.T) {
	srv := newRequestsServer(t)
	newbie := srv.placementSession(t, requesterIdentity)
	for i := 0; i < accessRequestIdentityBurst; i++ {
		srv.fileRequest(t, newbie)
		mustStatus(t, srv.do(t, newbie, "DELETE", "/api/v1/placement/me/request", ""), http.StatusOK, "withdraw")
	}
	rec := srv.do(t, newbie, "POST", "/api/v1/placement/me/request", `{}`)
	mustStatus(t, rec, http.StatusTooManyRequests, "past the per-identity limit")
	if rec.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}

	// Many identities from one address.
	srv2 := newRequestsServer(t)
	for i := 0; i < accessRequestAddressBurst; i++ {
		srv2.fileRequest(t, srv2.placementSession(t, fmt.Sprintf("p%d@idp.example", i)))
	}
	rec = srv2.do(t, srv2.placementSession(t, "late@idp.example"), "POST", "/api/v1/placement/me/request", `{}`)
	mustStatus(t, rec, http.StatusTooManyRequests, "past the per-address limit")
	if r := srv2.stored(t, "late@idp.example"); r != nil {
		t.Errorf("a rate-limited request was stored: %+v", r)
	}
}

func TestAccessRequestTextLimits(t *testing.T) {
	srv := newRequestsServer(t)
	srv.placementOnboard.requestIdentityLimiter = NewLoginRateLimiter(1000, 1000)
	srv.placementOnboard.requestAddressLimiter = NewLoginRateLimiter(1000, 1000)
	newbie := srv.placementSession(t, requesterIdentity)

	projects := func(n, length int) string {
		var ps []string
		for i := 0; i < n; i++ {
			ps = append(ps, fmt.Sprintf("%q", fmt.Sprintf("%d", i)+strings.Repeat("é", length-len(fmt.Sprintf("%d", i)))))
		}
		return "[" + strings.Join(ps, ",") + "]"
	}
	for _, tc := range []struct {
		name, body string
	}{
		{"note over 2 KB", fmt.Sprintf(`{"note":%q}`, strings.Repeat("x", accessRequestMaxNote+1))},
		{"11 projects", fmt.Sprintf(`{"projects":%s}`, projects(11, 5))},
		{"a 65-character project", fmt.Sprintf(`{"projects":%s}`, projects(1, 65))},
		{"a control character", `{"note":"ring\u0007"}`},
		{"a control character in a project", `{"projects":["a\u001bb"]}`},
		{"not a list", `{"projects":"Physics"}`},
	} {
		rec := srv.do(t, newbie, "POST", "/api/v1/placement/me/request", tc.body)
		mustStatus(t, rec, http.StatusBadRequest, tc.name)
	}
	if r := srv.stored(t, requesterIdentity); r != nil {
		t.Fatalf("an over-limit request was stored: %+v", r)
	}
	body := fmt.Sprintf(`{"projects":%s,"note":%q}`, projects(10, 64), strings.Repeat("x", accessRequestMaxNote))
	mustStatus(t, srv.do(t, newbie, "POST", "/api/v1/placement/me/request", body), http.StatusCreated, "at the limits")
}

// What the requester typed reaches admins escaped.
func TestAccessRequestTextIsEscapedForAdmins(t *testing.T) {
	srv := newRequestsServer(t)
	sid, _, err := srv.sessionStore.CreateSession(SessionData{
		PlacementIdentity: requesterIdentity, DisplayName: `<img src=x onerror=alert(1)>`,
		Email: `"><script>x</script>@example.edu`, Scope: sessionScopePlacement,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := srv.do(t, testSessionCookie(sid), "POST", "/api/v1/placement/me/request",
		`{"projects":["<b>Physics</b>"],"note":"<script>alert(1)</script>"}`)
	mustStatus(t, rec, http.StatusCreated, "create")

	rec = srv.do(t, srv.admin(t), "GET", "/api/v1/placement/admin/requests", "")
	mustStatus(t, rec, http.StatusOK, "list")
	if strings.ContainsAny(rec.Body.String(), "<>") {
		t.Errorf("the listing carries raw markup: %s", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var list placementAccessRequestList
	decodeBody(t, rec, &list)
	if r := list.Requests[0]; r.Note != "<script>alert(1)</script>" || r.DisplayName != `<img src=x onerror=alert(1)>` {
		t.Errorf("round trip = %+v", r)
	}
}

func TestAccessRequestOnePendingPerIdentityInTheStore(t *testing.T) {
	srv := newRequestsServer(t)
	store := srv.placementOnboard.requests
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = store.create(ctx, placementAccessRequest{Identity: requesterIdentity})
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, errAccessRequestPending):
			t.Errorf("create: %v", err)
		}
	}
	if ok != 1 {
		t.Errorf("%d concurrent requests stored, want 1", ok)
	}
}

// From sign-in to access: an unmapped person signs in, asks for access, an
// admin approves, and their existing session becomes the account.
func TestAccessRequestApprovalUpgradesTheSession(t *testing.T) {
	s, newbie := newbieServer(t, map[string]any{
		"sub": newbieSubject, "eppn": newbieIdentity, "name": "Newbie",
		"email": "newbie@example.edu", "email_verified": true,
	})
	sd, ok := s.getAnySessionFromRequest(cookieRequest(newbie))
	if !ok || sd.Email != "newbie@example.edu" {
		t.Fatalf("the placement-only session does not keep the email: %+v", sd)
	}
	// The directory commands, over the same placementd.
	v2 := &requestsFake{
		onboardFake: s.fake, apiVersion: 2,
		identities: map[string]*htcondor.PlacementIdentity{}, accounts: map[string]*htcondor.PlacementAccount{},
		modifications: map[string]*htcondor.PlacementModification{},
	}
	s.placementd = v2
	s.webuiAdminGroups = newGroupSet("condor-admins")

	rec := s.do(t, newbie, "POST", "/api/v1/placement/me/request", `{"projects":["physics"],"note":"new student"}`)
	mustStatus(t, rec, http.StatusCreated, "request access")
	id := decodeMeRequest(t, rec).Request.ID
	stored, err := s.placementOnboard.requests.get(context.Background(), id)
	if err != nil || stored.IDPSubject != newbieSubject || stored.Email != "newbie@example.edu" || stored.DisplayName != "Newbie" {
		t.Fatalf("stored request = %+v, %v", stored, err)
	}

	admin := s.userCookie(t, "root", "", "condor-admins")
	rec = s.do(t, admin, "POST", approvePath(id),
		`{"account":"`+newbieAcct+`","authorizations":["READ","WRITE"],"projects":["Physics"],"default_project":"Physics"}`)
	mustStatus(t, rec, http.StatusOK, "approve")
	if ops := v2.edits[0]; ops[len(ops)-1].Fields["Identity"] != newbieIdentity || v2.opts[0].OnBehalfOf != "root" {
		t.Fatalf("batch = %+v %+v", ops, v2.opts[0])
	}
	// What the placementd now answers for the identity.
	s.onboard()

	resp, rec := s.me(t, newbie)
	if resp.PlacementOnly || resp.Username != newbieAcct {
		t.Fatalf("after approval /auth/me = %+v", resp)
	}
	upgraded := sessionCookieFrom(rec)
	if upgraded == nil || strings.HasPrefix(upgraded.Value, placementSessionPrefix) {
		t.Fatalf("no full session cookie: %v", upgraded)
	}
	full := testSessionCookie(upgraded.Value)
	if sd, ok := s.getSessionFromRequest(cookieRequest(full)); !ok || sd.Email != "newbie@example.edu" {
		t.Errorf("the upgraded session = %+v", sd)
	}
	rec = s.do(t, full, "GET", "/api/v1/placement/me/request", "")
	if got := decodeMeRequest(t, rec); got.Request == nil || got.Request.Status != accessRequestApproved || got.Request.Account != newbieAcct {
		t.Errorf("the upgraded session sees %+v", got.Request)
	}
	// Mapped now: no further requests.
	rec = s.do(t, full, "POST", "/api/v1/placement/me/request", `{}`)
	mustStatus(t, rec, http.StatusConflict, "request with access")
}
