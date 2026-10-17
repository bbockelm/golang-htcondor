package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// fakePlacementd predates the directory commands; these give it the two
// interface methods so the older tests keep compiling. They refuse, as a
// daemon without the commands would.
func (f *fakePlacementd) Query(context.Context, htcondor.PlacementQuery) ([]htcondor.PlacementObject, error) {
	return nil, errors.New("fakePlacementd: no PLACEMENT_QUERY")
}

func (f *fakePlacementd) Edit(context.Context, []htcondor.PlacementOp, bool) ([]htcondor.PlacementEditResult, error) {
	return nil, errors.New("fakePlacementd: no PLACEMENT_EDIT")
}

// fakePlacementdV2 adds the directory commands and an API version.
type fakePlacementdV2 struct {
	*fakePlacementd
	apiVersion int

	objects    []htcondor.PlacementObject
	queryErr   error
	results    []htcondor.PlacementEditResult
	editErr    error
	gotQuery   htcondor.PlacementQuery
	gotOps     []htcondor.PlacementOp
	gotDryRun  bool
	editCalled bool
}

func (f *fakePlacementdV2) APIVersion(context.Context) (int, error) { return f.apiVersion, nil }

func (f *fakePlacementdV2) Query(_ context.Context, q htcondor.PlacementQuery) ([]htcondor.PlacementObject, error) {
	f.gotQuery = q
	return f.objects, f.queryErr
}

func (f *fakePlacementdV2) Edit(_ context.Context, ops []htcondor.PlacementOp, dryRun bool) ([]htcondor.PlacementEditResult, error) {
	f.editCalled = true
	f.gotOps, f.gotDryRun = ops, dryRun
	if f.results != nil || f.editErr != nil {
		return f.results, f.editErr
	}
	out := make([]htcondor.PlacementEditResult, len(ops))
	for i := range ops {
		out[i] = htcondor.PlacementEditResult{Index: i, ID: "uuid-new", Version: 1}
	}
	return out, nil
}

func newFakeV2() *fakePlacementdV2 {
	return &fakePlacementdV2{fakePlacementd: &fakePlacementd{}, apiVersion: 2}
}

// serveAdmin sends a request through the full server, so the route
// registration is under test too.
func serveAdmin(t *testing.T, server *Server, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	routesOnce(server)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, r)
	return rec
}

// routesOnce registers the routes the first time a server is served.
func routesOnce(server *Server) {
	if _, done := routedServers.LoadOrStore(server, true); !done {
		server.setupRoutes()
	}
}

var routedServers sync.Map

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
}

func TestPlacementAdminRequiresAdmin(t *testing.T) {
	fake := newFakeV2()
	server, _, user := newPlacementTestServer(t, fake)
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/v1/placement/admin/identities"},
		{"POST", "/api/v1/placement/admin/accounts"},
		{"GET", "/api/v1/placement/admin/projects/u1"},
		{"PATCH", "/api/v1/placement/admin/projects/u1"},
		{"DELETE", "/api/v1/placement/admin/authorizations/u1"},
		{"POST", "/api/v1/placement/admin/accounts/u1/adopt"},
		{"POST", "/api/v1/placement/admin/adopt-all"},
		{"POST", "/api/v1/placement/admin/batch"},
		{"GET", "/api/v1/placement/admin/mapfile-status"},
	} {
		rec := serveAdmin(t, server, user(tc.method, tc.path))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s as non-admin = %d, want 403", tc.method, tc.path, rec.Code)
		}
	}
	if fake.editCalled || fake.gotQuery.TargetType != "" {
		t.Error("a non-admin request reached the daemon")
	}
}

func TestPlacementAdminRequiresAPIVersion2(t *testing.T) {
	fake := newFakeV2()
	fake.apiVersion = 1
	server, admin, _ := newPlacementTestServer(t, fake)

	rec := serveAdmin(t, server, admin("GET", "/api/v1/placement/admin/accounts", ""))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501; body %s", rec.Code, rec.Body.String())
	}
	rec = serveAdmin(t, server, admin("POST", "/api/v1/placement/admin/batch", `{"operations":[{"operation":"Adopt","target_type":"All"}]}`))
	if rec.Code != http.StatusNotImplemented || fake.editCalled {
		t.Fatalf("batch on v1 = %d, edit called %v", rec.Code, fake.editCalled)
	}

	// The status endpoint reports the version so the UI can hide the
	// directory.
	rec = serveAdmin(t, server, admin("GET", "/api/v1/placement/status", ""))
	var st placementStatusResponse
	decodeBody(t, rec, &st)
	if st.APIVersion != 1 {
		t.Errorf("status api_version = %d, want 1", st.APIVersion)
	}
	fake.apiVersion = 2
	rec = serveAdmin(t, server, admin("GET", "/api/v1/placement/status", ""))
	decodeBody(t, rec, &st)
	if st.APIVersion != 2 {
		t.Errorf("status api_version = %d, want 2", st.APIVersion)
	}
}

func TestPlacementAdminUnavailable(t *testing.T) {
	server, admin, _ := newPlacementTestServer(t, newFakeV2())
	server.placementdAvailable.Store(false)
	rec := serveAdmin(t, server, admin("GET", "/api/v1/placement/admin/accounts", ""))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestPlacementAdminList(t *testing.T) {
	fake := newFakeV2()
	exp := time.Unix(1767225600, 0)
	fake.objects = []htcondor.PlacementObject{{
		Type: "Identity",
		Identity: &htcondor.PlacementIdentity{
			PlacementEntityMeta: htcondor.PlacementEntityMeta{ID: "i1", Source: "mapfile", Version: 3},
			Name:                "alice@wisc.edu",
			Account:             "alice@ap",
			ExpiresAt:           exp,
		},
	}, {
		Type:     "Identity",
		Identity: &htcondor.PlacementIdentity{PlacementEntityMeta: htcondor.PlacementEntityMeta{ID: "i2"}, Name: "bob"},
	}}
	server, admin, _ := newPlacementTestServer(t, fake)

	rec := serveAdmin(t, server, admin("GET", `/api/v1/placement/admin/identities?constraint=Expired&limit=10&name=alice@wisc.edu`, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if fake.gotQuery.TargetType != "Identity" || fake.gotQuery.Requirements != "Expired" ||
		fake.gotQuery.Limit != 10 || fake.gotQuery.Name != "alice@wisc.edu" {
		t.Errorf("query = %+v", fake.gotQuery)
	}
	var got struct {
		Identities []placementIdentityJSON `json:"identities"`
	}
	decodeBody(t, rec, &got)
	if len(got.Identities) != 2 || got.Identities[0].Name != "alice@wisc.edu" || got.Identities[0].Version != 3 {
		t.Fatalf("identities = %+v", got.Identities)
	}
	if got.Identities[0].ExpiresAt == nil || !got.Identities[0].ExpiresAt.Equal(exp) {
		t.Errorf("expires_at = %v", got.Identities[0].ExpiresAt)
	}
	// Never-expiring is an absent field, and lists are [] not null.
	if got.Identities[1].ExpiresAt != nil {
		t.Errorf("expires_at for never = %v", got.Identities[1].ExpiresAt)
	}
	if !strings.Contains(rec.Body.String(), `"projects":[]`) {
		t.Errorf("empty list not rendered as []: %s", rec.Body.String())
	}

	rec = serveAdmin(t, server, admin("GET", "/api/v1/placement/admin/identities?limit=-3", ""))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad limit = %d", rec.Code)
	}
	rec = serveAdmin(t, server, admin("GET", "/api/v1/placement/admin/widgets", ""))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown kind = %d", rec.Code)
	}
}

func TestPlacementAdminGet(t *testing.T) {
	fake := newFakeV2()
	server, admin, _ := newPlacementTestServer(t, fake)

	rec := serveAdmin(t, server, admin("GET", "/api/v1/placement/admin/projects/p-uuid", ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing = %d", rec.Code)
	}
	if fake.gotQuery.ID != "p-uuid" || fake.gotQuery.TargetType != "Project" {
		t.Errorf("query = %+v", fake.gotQuery)
	}

	fake.objects = []htcondor.PlacementObject{{Type: "Project", Project: &htcondor.PlacementProject{
		PlacementEntityMeta: htcondor.PlacementEntityMeta{ID: "p-uuid", Source: "internal", Version: 2},
		Name:                "ProjA",
	}}}
	rec = serveAdmin(t, server, admin("GET", "/api/v1/placement/admin/projects/p-uuid", ""))
	var p placementProjectJSON
	decodeBody(t, rec, &p)
	if rec.Code != http.StatusOK || p.Name != "ProjA" || p.Source != "internal" {
		t.Fatalf("got %d %+v", rec.Code, p)
	}
}

func TestPlacementAdminCreate(t *testing.T) {
	fake := newFakeV2()
	server, admin, _ := newPlacementTestServer(t, fake)

	rec := serveAdmin(t, server, admin("POST", "/api/v1/placement/admin/identities",
		`{"name":"alice@wisc.edu","account":"alice@ap","expires_at":"2026-01-01T00:00:00Z","comment":null}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if len(fake.gotOps) != 1 {
		t.Fatalf("ops = %+v", fake.gotOps)
	}
	op := fake.gotOps[0]
	if op.Operation != "Create" || op.TargetType != "Identity" || op.ID != "" || op.Name != "" {
		t.Errorf("op = %+v", op)
	}
	if op.Fields["Name"] != "alice@wisc.edu" || op.Fields["Account"] != "alice@ap" {
		t.Errorf("fields = %+v", op.Fields)
	}
	if ts, ok := op.Fields["ExpiresAt"].(time.Time); !ok || ts.Unix() != 1767225600 {
		t.Errorf("ExpiresAt = %v", op.Fields["ExpiresAt"])
	}
	// On create, null is the same as leaving the field out.
	if _, ok := op.Fields["Comment"]; ok {
		t.Error("null on create should be omitted")
	}
	var resp placementBatchResponse
	decodeBody(t, rec, &resp)
	if !resp.Committed || len(resp.Results) != 1 || resp.Results[0].ID != "uuid-new" {
		t.Errorf("response = %+v", resp)
	}

	for _, body := range []string{
		`{"nickname":"x"}`,
		`{"name":5}`,
		`{"expires_at":"next tuesday"}`,
		`{}`,
		`not json`,
	} {
		rec := serveAdmin(t, server, admin("POST", "/api/v1/placement/admin/identities", body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s = %d, want 400", body, rec.Code)
		}
	}

	// Account lists go down as lists; requestable as a bool.
	rec = serveAdmin(t, server, admin("POST", "/api/v1/placement/admin/accounts?dry_run=true",
		`{"name":"alice@ap","authorizations":["READ"],"projects":[],"default_project":"P"}`))
	if rec.Code != http.StatusCreated || !fake.gotDryRun {
		t.Fatalf("status %d dry %v", rec.Code, fake.gotDryRun)
	}
	if l, ok := fake.gotOps[0].Fields["Projects"].([]string); !ok || l == nil || len(l) != 0 {
		t.Errorf("Projects = %#v", fake.gotOps[0].Fields["Projects"])
	}
	decodeBody(t, rec, &resp)
	if resp.Committed || !resp.DryRun {
		t.Errorf("dry run response = %+v", resp)
	}
	rec = serveAdmin(t, server, admin("POST", "/api/v1/placement/admin/authorizations",
		`{"name":"GPU","label":"GPU","requestable":false}`))
	if rec.Code != http.StatusCreated || fake.gotOps[0].Fields["Requestable"] != false {
		t.Errorf("authorization create %d fields %+v", rec.Code, fake.gotOps[0].Fields)
	}
}

func TestPlacementAdminUpdate(t *testing.T) {
	fake := newFakeV2()
	server, admin, _ := newPlacementTestServer(t, fake)

	rec := serveAdmin(t, server, admin("PATCH", "/api/v1/placement/admin/identities/i-uuid",
		`{"expected_version":7,"expires_at":null,"display_name":"Alice"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	op := fake.gotOps[0]
	if op.Operation != "Update" || op.ID != "i-uuid" {
		t.Errorf("op = %+v", op)
	}
	if op.ExpectedVersion != 7 {
		t.Errorf("ExpectedVersion = %d, want 7", op.ExpectedVersion)
	}
	// null clears: the client sends the literal undefined.
	if v, ok := op.Fields["ExpiresAt"]; !ok || v != nil {
		t.Errorf("ExpiresAt = %v (present %v), want nil", v, ok)
	}
	if _, ok := op.Fields["Name"]; ok {
		t.Error("a patch must carry only the fields it changes")
	}
	if len(op.Fields) != 2 {
		t.Errorf("fields = %+v", op.Fields)
	}

	for _, body := range []string{`{"expected_version":3}`, `{"expected_version":"x","comment":"c"}`, `{"expected_version":0,"comment":"c"}`} {
		rec := serveAdmin(t, server, admin("PATCH", "/api/v1/placement/admin/identities/i-uuid", body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s = %d, want 400", body, rec.Code)
		}
	}
}

func TestPlacementAdminDeleteAndAdopt(t *testing.T) {
	fake := newFakeV2()
	server, admin, _ := newPlacementTestServer(t, fake)

	rec := serveAdmin(t, server, admin("DELETE", "/api/v1/placement/admin/accounts/a-uuid?cascade=true&expected_version=4", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body.String())
	}
	if op := fake.gotOps[0]; op.Operation != "Delete" || op.ID != "a-uuid" || !op.Cascade || op.ExpectedVersion != 4 {
		t.Errorf("delete op = %+v", op)
	}
	rec = serveAdmin(t, server, admin("DELETE", "/api/v1/placement/admin/accounts/a-uuid", ""))
	if rec.Code != http.StatusOK || fake.gotOps[0].Cascade {
		t.Errorf("delete without cascade: %d %+v", rec.Code, fake.gotOps[0])
	}

	fake.results = []htcondor.PlacementEditResult{{Index: 0, ID: "a-uuid", Version: 5, Warning: "still in the mapfile"}}
	rec = serveAdmin(t, server, admin("POST", "/api/v1/placement/admin/accounts/a-uuid/adopt", `{"expected_version":4}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("adopt = %d %s", rec.Code, rec.Body.String())
	}
	if op := fake.gotOps[0]; op.Operation != "Adopt" || op.TargetType != "Account" || op.ID != "a-uuid" || op.ExpectedVersion != 4 {
		t.Errorf("adopt op = %+v", op)
	}
	var resp placementBatchResponse
	decodeBody(t, rec, &resp)
	if resp.Results[0].Warning != "still in the mapfile" {
		t.Errorf("warning lost: %+v", resp)
	}

	rec = serveAdmin(t, server, admin("POST", "/api/v1/placement/admin/adopt-all", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("adopt-all = %d", rec.Code)
	}
	if op := fake.gotOps[0]; op.Operation != "Adopt" || op.TargetType != "All" || op.ID != "" {
		t.Errorf("adopt-all op = %+v", op)
	}
	rec = serveAdmin(t, server, admin("GET", "/api/v1/placement/admin/adopt-all", ""))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET adopt-all = %d", rec.Code)
	}
}

func TestPlacementAdminBatch(t *testing.T) {
	fake := newFakeV2()
	server, admin, _ := newPlacementTestServer(t, fake)

	rec := serveAdmin(t, server, admin("POST", "/api/v1/placement/admin/batch", `{
		"dry_run": true,
		"operations": [
			{"operation":"Create","target_type":"Account","fields":{"name":"alice@ap","authorizations":["READ"],"projects":["P"],"default_project":"P"}},
			{"operation":"Create","target_type":"Identity","fields":{"name":"alice@wisc.edu","account":"alice@ap"}},
			{"operation":"Update","target_type":"Account","name":"bob@ap","expected_version":2,"fields":{"default_project":null}}
		]}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
	}
	if !fake.gotDryRun || len(fake.gotOps) != 3 {
		t.Fatalf("dry %v ops %+v", fake.gotDryRun, fake.gotOps)
	}
	if op := fake.gotOps[2]; op.Name != "bob@ap" || op.ExpectedVersion != 2 {
		t.Errorf("op 2 = %+v", op)
	} else if v, ok := op.Fields["DefaultProject"]; !ok || v != nil {
		t.Errorf("DefaultProject = %v, want cleared", v)
	}

	for _, body := range []string{
		`{"operations":[]}`,
		`{"operations":[{"operation":"Create","target_type":"Account","fields":{"bogus":1}}]}`,
		`{"operations":[{"operation":"Adopt","target_type":"All","fields":{"name":"x"}}]}`,
		`{"operations":[], "extra": 1}`,
	} {
		rec := serveAdmin(t, server, admin("POST", "/api/v1/placement/admin/batch", body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s = %d, want 400", body, rec.Code)
		}
	}
}

// Each directory error code maps to the status §7.4 names, with the hints a
// UI acts on.
func TestPlacementAdminErrorMapping(t *testing.T) {
	cases := []struct {
		code            int
		status          int
		ownedBy         string
		cascadeRequired bool
	}{
		{htcondor.PlacementErrNotFound, http.StatusNotFound, "", false},
		{htcondor.PlacementErrVersionMismatch, http.StatusConflict, "", false},
		{htcondor.PlacementErrOwnedBySource, http.StatusConflict, "mapfile", false},
		{htcondor.PlacementErrInvalidArgument, http.StatusBadRequest, "", false},
		{htcondor.PlacementErrStillReferenced, http.StatusConflict, "", true},
		{htcondor.PlacementErrDuplicate, http.StatusConflict, "", false},
		{htcondor.PlacementErrUnknownType, http.StatusBadRequest, "", false},
	}
	for _, tc := range cases {
		fake := newFakeV2()
		fake.results = []htcondor.PlacementEditResult{{Index: 0, ErrorCode: tc.code, ErrorString: "refused"}}
		fake.editErr = &htcondor.PlacementError{Code: tc.code, Message: "refused"}
		server, admin, _ := newPlacementTestServer(t, fake)

		rec := serveAdmin(t, server, admin("PATCH", "/api/v1/placement/admin/projects/p1", `{"expected_version":1,"description":"d"}`))
		if rec.Code != tc.status {
			t.Errorf("code %d -> %d, want %d", tc.code, rec.Code, tc.status)
			continue
		}
		var body placementAdminErrorBody
		decodeBody(t, rec, &body)
		if body.PlacementCode != tc.code || body.OwnedBy != tc.ownedBy || body.CascadeRequired != tc.cascadeRequired {
			t.Errorf("code %d body = %+v", tc.code, body)
		}
		if len(body.Results) != 1 || body.Results[0].ErrorCode != tc.code {
			t.Errorf("code %d results = %+v", tc.code, body.Results)
		}
	}

	// A transport failure is a bad gateway, not a client error.
	fake := newFakeV2()
	fake.queryErr = errors.New("connection refused")
	server, admin, _ := newPlacementTestServer(t, fake)
	rec := serveAdmin(t, server, admin("GET", "/api/v1/placement/admin/accounts", ""))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("transport failure = %d, want 502", rec.Code)
	}
	// Query errors map the same way.
	fake.queryErr = &htcondor.PlacementError{Code: htcondor.PlacementErrInvalidArgument, Message: "bad Requirements"}
	rec = serveAdmin(t, server, admin("GET", "/api/v1/placement/admin/accounts?constraint=x%3D%3D", ""))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("query code 16 = %d, want 400", rec.Code)
	}
}

func TestPlacementAdminMapfileStatus(t *testing.T) {
	fake := newFakeV2()
	fake.objects = []htcondor.PlacementObject{{Type: "MapfileStatus", MapfileStatus: &htcondor.PlacementMapfileStatus{
		LoadTime:    time.Unix(1760000000, 0),
		Quarantined: 2,
		Conflicts:   1,
		Problems:    []htcondor.PlacementMapfileProblem{{Kind: "malformed", Line: 7, Key: "carol", Message: "bad expiry"}},
	}}}
	server, admin, _ := newPlacementTestServer(t, fake)
	rec := serveAdmin(t, server, admin("GET", "/api/v1/placement/admin/mapfile-status", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if fake.gotQuery.TargetType != "MapfileStatus" {
		t.Errorf("query = %+v", fake.gotQuery)
	}
	var st placementMapfileStatusJSON
	decodeBody(t, rec, &st)
	if st.Quarantined != 2 || st.Conflicts != 1 || st.OK || len(st.Problems) != 1 || st.Problems[0].Line != 7 {
		t.Errorf("status = %+v", st)
	}
	if st.LoadAttemptTime != nil {
		t.Error("absent attempt time should be omitted")
	}
}

func TestPlacementAdminIsDocumented(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal([]byte(openAPISchema), &doc); err != nil {
		t.Fatalf("openapi does not parse: %v", err)
	}
	for path, methods := range map[string][]string{
		"/placement/admin/{kind}":            {"get", "post"},
		"/placement/admin/{kind}/{id}":       {"get", "patch", "delete"},
		"/placement/admin/{kind}/{id}/adopt": {"post"},
		"/placement/admin/adopt-all":         {"post"},
		"/placement/admin/batch":             {"post"},
		"/placement/admin/mapfile-status":    {"get"},
	} {
		for _, m := range methods {
			if _, ok := doc.Paths[path][m]; !ok {
				t.Errorf("%s %s missing from the OpenAPI paths", strings.ToUpper(m), path)
			}
		}
	}
}
