package httpserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// The admin a change is recorded against is the signed-in session's user.
// Nothing in the request -- body, query string or header -- may set it.
func TestPlacementAdminOnBehalfOfIsTheSessionUser(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
	}{
		{"create", "POST", "/api/v1/placement/admin/projects?on_behalf_of=mallory", `{"name":"P"}`},
		{"update", "PATCH", "/api/v1/placement/admin/projects/p1?on_behalf_of=mallory", `{"expected_version":3,"description":"d"}`},
		{"delete", "DELETE", "/api/v1/placement/admin/projects/p1?on_behalf_of=mallory", ``},
		{"adopt", "POST", "/api/v1/placement/admin/projects/p1/adopt?on_behalf_of=mallory", ``},
		{"adopt all", "POST", "/api/v1/placement/admin/adopt-all?on_behalf_of=mallory", ``},
		{"batch", "POST", "/api/v1/placement/admin/batch?on_behalf_of=mallory",
			`{"operations":[{"operation":"Delete","target_type":"Project","name":"P"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeV2()
			server, admin, _ := newPlacementTestServer(t, fake)
			req := admin(tc.method, tc.path, tc.body)
			req.Header.Set("X-On-Behalf-Of", "mallory")
			rec := serveAdmin(t, server, req)
			if rec.Code >= 300 {
				t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
			}
			if fake.gotOpts.OnBehalfOf != "root" {
				t.Errorf("OnBehalfOf = %q, want the session user root", fake.gotOpts.OnBehalfOf)
			}
		})
	}

	// A body that tries to name someone is refused outright.
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/api/v1/placement/admin/projects", `{"name":"P","on_behalf_of":"mallory"}`},
		{"POST", "/api/v1/placement/admin/batch", `{"on_behalf_of":"mallory","operations":[{"operation":"Adopt","target_type":"All"}]}`},
		{"DELETE", "/api/v1/placement/admin/projects/p1", `{"on_behalf_of":"mallory"}`},
	} {
		fake := newFakeV2()
		server, admin, _ := newPlacementTestServer(t, fake)
		rec := serveAdmin(t, server, admin(tc.method, tc.path, tc.body))
		if rec.Code != http.StatusBadRequest || fake.editCalled {
			t.Errorf("%s %s with on_behalf_of in the body = %d (edit called %v), want 400", tc.method, tc.path, rec.Code, fake.editCalled)
		}
	}
}

// change_comment is the audit-log comment for the change. It is not an
// entity field, so an identity's own comment field stays separate.
func TestPlacementAdminChangeComment(t *testing.T) {
	fake := newFakeV2()
	server, admin, _ := newPlacementTestServer(t, fake)

	rec := serveAdmin(t, server, admin("POST", "/api/v1/placement/admin/identities",
		`{"identity":"alice@wisc.edu","account":"alice@ap","comment":"TA","change_comment":"spring course"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
	}
	if fake.gotOpts.Comment != "spring course" {
		t.Errorf("change comment = %q", fake.gotOpts.Comment)
	}
	if fake.gotOps[0].Fields["Comment"] != "TA" {
		t.Errorf("identity comment field = %v", fake.gotOps[0].Fields["Comment"])
	}
	if _, ok := fake.gotOps[0].Fields["change_comment"]; ok {
		t.Error("change_comment leaked into the entity fields")
	}

	for _, tc := range []struct{ method, path, body string }{
		{"PATCH", "/api/v1/placement/admin/projects/p1", `{"expected_version":2,"description":"d","change_comment":"why"}`},
		{"DELETE", "/api/v1/placement/admin/projects/p1?cascade=true", `{"change_comment":"why"}`},
		{"POST", "/api/v1/placement/admin/projects/p1/adopt", `{"expected_version":2,"change_comment":"why"}`},
		{"POST", "/api/v1/placement/admin/adopt-all", `{"change_comment":"why"}`},
		{"POST", "/api/v1/placement/admin/batch", `{"change_comment":"why","operations":[{"operation":"Adopt","target_type":"All"}]}`},
	} {
		fake.gotOpts = htcondor.PlacementEditOptions{}
		rec := serveAdmin(t, server, admin(tc.method, tc.path, tc.body))
		if rec.Code >= 300 {
			t.Errorf("%s %s = %d %s", tc.method, tc.path, rec.Code, rec.Body.String())
			continue
		}
		if fake.gotOpts.Comment != "why" {
			t.Errorf("%s %s: change comment = %q", tc.method, tc.path, fake.gotOpts.Comment)
		}
	}

	for _, body := range []string{`{"change_comment":5,"name":"P"}`, `{"name":"P","change_comment":"` + strings.Repeat("x", placementMaxChangeComment+1) + `"}`} {
		rec := serveAdmin(t, server, admin("POST", "/api/v1/placement/admin/projects", body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("bad change_comment = %d, want 400", rec.Code)
		}
	}
	rec = serveAdmin(t, server, admin("DELETE", "/api/v1/placement/admin/projects/p1", `{"description":"x"}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("delete with an entity field = %d, want 400", rec.Code)
	}
}

func TestPlacementAdminHistory(t *testing.T) {
	fake := newFakeV2()
	fake.objects = []htcondor.PlacementObject{{Type: "Modification", Modification: &htcondor.PlacementModification{
		ID: 42, ChangesetID: 17, Time: time.Unix(1760000000, 0), Channel: "cedar", Actor: "condor@ap",
		OnBehalfOf: "root", Comment: "spring course", Operation: "update", EntityType: "account", EntityID: "a1",
		Changes: map[string]htcondor.PlacementFieldChange{
			"Projects":       {Old: []string{"A"}, New: []string{"A", "B"}},
			"DefaultProject": {Old: nil, New: "A"},
		},
	}}}
	server, admin, user := newPlacementTestServer(t, fake)

	rec := serveAdmin(t, server, admin("GET", "/api/v1/placement/admin/accounts/a1/history", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
	}
	if q := fake.gotQuery; q.TargetType != "Modification" || q.EntityID != "a1" || q.Limit != placementHistoryDefaultLimit {
		t.Errorf("query = %+v", q)
	}
	var got struct {
		History []placementModificationJSON `json:"history"`
	}
	decodeBody(t, rec, &got)
	if len(got.History) != 1 {
		t.Fatalf("history = %+v", got.History)
	}
	h := got.History[0]
	if h.ID != 42 || h.OnBehalfOf != "root" || h.Actor != "condor@ap" || h.Operation != "update" || h.Comment != "spring course" {
		t.Errorf("entry = %+v", h)
	}
	// Lists stay lists and an absent value is null.
	if !strings.Contains(rec.Body.String(), `"Projects":{"old":["A"],"new":["A","B"]}`) ||
		!strings.Contains(rec.Body.String(), `"DefaultProject":{"old":null,"new":"A"}`) {
		t.Errorf("changes = %s", rec.Body.String())
	}

	rec = serveAdmin(t, server, admin("GET", "/api/v1/placement/admin/history?entity_id=a1&limit=5&constraint=Operation%3D%3D%22delete%22", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if q := fake.gotQuery; q.EntityID != "a1" || q.Limit != 5 || q.Requirements != `Operation=="delete"` {
		t.Errorf("query = %+v", q)
	}
	rec = serveAdmin(t, server, admin("GET", "/api/v1/placement/admin/history", ""))
	if rec.Code != http.StatusOK || fake.gotQuery.EntityID != "" {
		t.Errorf("unfiltered = %d %+v", rec.Code, fake.gotQuery)
	}

	for _, path := range []string{"/api/v1/placement/admin/history?limit=0", "/api/v1/placement/admin/history?limit=5000"} {
		if rec := serveAdmin(t, server, admin("GET", path, "")); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", path, rec.Code)
		}
	}
	if rec := serveAdmin(t, server, admin("POST", "/api/v1/placement/admin/history", "")); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST history = %d", rec.Code)
	}
	for _, path := range []string{"/api/v1/placement/admin/history", "/api/v1/placement/admin/accounts/a1/history"} {
		if rec := serveAdmin(t, server, user("GET", path)); rec.Code != http.StatusForbidden {
			t.Errorf("non-admin %s = %d, want 403", path, rec.Code)
		}
	}

	fake.apiVersion = 1
	if rec := serveAdmin(t, server, admin("GET", "/api/v1/placement/admin/history", "")); rec.Code != http.StatusNotImplemented {
		t.Errorf("history on API v1 = %d, want 501", rec.Code)
	}
}

func TestPlacementAdminModificationIDInEntities(t *testing.T) {
	fake := newFakeV2()
	fake.objects = []htcondor.PlacementObject{{Type: "Project", Project: &htcondor.PlacementProject{
		PlacementEntityMeta: htcondor.PlacementEntityMeta{ID: "p1", Version: 42, ModificationID: 42},
		Name:                "ProjA",
	}}}
	server, admin, _ := newPlacementTestServer(t, fake)
	rec := serveAdmin(t, server, admin("GET", "/api/v1/placement/admin/projects/p1", ""))
	if !strings.Contains(rec.Body.String(), `"modification_id":42`) {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestPlacementHistoryIsDocumented(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal([]byte(openAPISchema), &doc); err != nil {
		t.Fatalf("openapi does not parse: %v", err)
	}
	for _, path := range []string{"/placement/admin/history", "/placement/admin/{kind}/{id}/history"} {
		if _, ok := doc.Paths[path]["get"]; !ok {
			t.Errorf("GET %s missing from the OpenAPI paths", path)
		}
	}
}
