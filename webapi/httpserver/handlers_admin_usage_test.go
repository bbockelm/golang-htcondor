package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/usagestats"
)

// usageRequest builds a GET for the usage endpoint carrying a session
// for user in groups. A nil groups list is a signed-in non-admin.
func usageRequest(t *testing.T, h *Handler, target, user string, groups []string) *http.Request {
	t.Helper()
	sid, _, err := h.sessionStore.Create(user, groups)
	if err != nil {
		t.Fatalf("session create: %v", err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec
	return r
}

func usageHandler(t *testing.T) *Handler {
	t.Helper()
	h := statsHandler(t)
	t.Cleanup(func() { h.StopUsageStats() })
	h.webuiAdminGroups = newGroupSet("condor-admins")
	h.setupRoutes()
	return h
}

// Through ServeHTTP rather than the handler method, so a route that was
// never registered fails here instead of falling through to the SPA.
func TestAdminUsageServesTheLiveCounts(t *testing.T) {
	h := usageHandler(t)
	h.toolStats.Record("query_jobs", "alice", "claude-code", usagestats.OutcomeOK, 50*time.Millisecond)
	h.toolStats.Record("query_jobs", "bob", "cursor", usagestats.OutcomeError, time.Second)
	h.toolStats.Record("submit_job", "alice", "claude-code", usagestats.OutcomeRefused, time.Millisecond)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, usageRequest(t, h, "/api/v1/admin/usage", "root", []string{"condor-admins"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var got struct {
		Enabled bool                  `json:"enabled"`
		Totals  usagestats.UsageRow   `json:"totals"`
		ByName  []usagestats.UsageRow `json:"by_name"`
		ByUser  []usagestats.UsageRow `json:"by_user"`
		Options usagestats.Options    `json:"options"`
		Filter  usagestats.Filter     `json:"filter"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, rec.Body.String())
	}
	if !got.Enabled {
		t.Fatalf("enabled = false with a store attached: %s", rec.Body.String())
	}
	if got.Totals.Calls != 3 || got.Totals.Outcomes[usagestats.OutcomeOK] != 1 || got.Totals.Outcomes[usagestats.OutcomeError] != 1 || got.Totals.Outcomes[usagestats.OutcomeRefused] != 1 {
		t.Errorf("totals = %+v, want 3 calls: 1 ok, 1 error, 1 refused", got.Totals)
	}
	// Real names, whatever /metrics is told to do with them.
	if got.Totals.Users != 2 || len(got.ByUser) != 2 {
		t.Errorf("users = %d, by_user = %+v; want alice and bob", got.Totals.Users, got.ByUser)
	}
	if len(got.ByName) != 2 || got.ByName[0].Name != "query_jobs" {
		t.Errorf("by_tool = %+v, want query_jobs first", got.ByName)
	}

	// A filter narrows the aggregates and is echoed back.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, usageRequest(t, h, "/api/v1/admin/usage?user=alice", "root", []string{"condor-admins"}))
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Totals.Calls != 2 || got.Filter.User != "alice" {
		t.Errorf("filtered to alice: calls = %d, filter = %+v; want 2, alice", got.Totals.Calls, got.Filter)
	}
	if len(got.Options.Users) != 2 {
		t.Errorf("options.users = %v, want both users while filtered", got.Options.Users)
	}
}

// Who called what is not for every signed-in user.
func TestAdminUsageRefusesANonAdmin(t *testing.T) {
	h := usageHandler(t)
	h.toolStats.Record("query_jobs", "alice", "claude-code", usagestats.OutcomeOK, time.Millisecond)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, usageRequest(t, h, "/api/v1/admin/usage", "alice", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/admin/usage", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous status = %d, want 401; body = %s", rec.Code, rec.Body.String())
	}
}

func TestAdminUsageRejectsOtherMethods(t *testing.T) {
	h := usageHandler(t)
	r := usageRequest(t, h, "/api/v1/admin/usage", "root", []string{"condor-admins"})
	r.Method = http.MethodPost
	rec := httptest.NewRecorder()
	h.handleAdminUsage(rec, r)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", rec.Code)
	}
}

// A server with no store says so, rather than reporting zero calls,
// which would read as "nobody uses this".
func TestAdminUsageWithoutAStoreIsDisabled(t *testing.T) {
	h := usageHandler(t)
	h.StopUsageStats()
	h.toolStats = nil

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, usageRequest(t, h, "/api/v1/admin/usage", "root", []string{"condor-admins"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["enabled"] != false || got["totals"] != nil {
		t.Errorf("body = %s, want enabled:false and no figures", rec.Body.String())
	}
}

// The kind parameter picks the vocabulary. Without it the endpoint
// answers about MCP, which is what it did before REST counting
// existed and what an older client still expects.
func TestAdminUsageSelectsTheKind(t *testing.T) {
	h := restStatsHandler(t)
	h.toolStats.Record("query_jobs", "alice", "claude-code", usagestats.OutcomeOK, time.Millisecond)
	h.restStats.Record("GET /api/v1/jobs", "bob", "curl", usagestats.OutcomeDenied, time.Millisecond)

	type resp struct {
		Enabled  bool                  `json:"enabled"`
		Kind     string                `json:"kind"`
		Noun     string                `json:"noun"`
		Title    string                `json:"title"`
		Outcomes []string              `json:"outcomes"`
		ByName   []usagestats.UsageRow `json:"by_name"`
		Kinds    []AdminUsageKind      `json:"kinds"`
	}
	get := func(target string) resp {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, usageRequest(t, h, target, "root", []string{"condor-admins"}))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, body = %s", target, rec.Code, rec.Body.String())
		}
		var got resp
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s: decode: %v\n%s", target, err, rec.Body.String())
		}
		return got
	}

	// No kind: MCP, as before.
	if got := get("/api/v1/admin/usage"); got.Kind != "mcp" || got.Noun != "tool" {
		t.Errorf("default kind = %q/%q, want mcp/tool", got.Kind, got.Noun)
	}

	rest := get("/api/v1/admin/usage?kind=rest")
	if rest.Kind != "rest" || rest.Noun != "endpoint" || rest.Title != "Endpoint" {
		t.Errorf("rest summary = %q/%q/%q, want rest/endpoint/Endpoint",
			rest.Kind, rest.Noun, rest.Title)
	}
	// Looked up rather than indexed: this page is itself a REST
	// endpoint, so loading it adds a row of its own.
	var jobs *usagestats.UsageRow
	for i, row := range rest.ByName {
		if row.Name == "GET /api/v1/jobs" {
			jobs = &rest.ByName[i]
		}
	}
	if jobs == nil {
		t.Fatalf("by_name = %+v, want a row for GET /api/v1/jobs", rest.ByName)
	}
	// The REST vocabulary, not MCP's: the page draws its columns from
	// this, so a wrong list is a wrong table.
	if jobs.Outcomes[usagestats.OutcomeDenied] != 1 {
		t.Errorf("denied = %d, want 1; outcomes = %+v",
			jobs.Outcomes[usagestats.OutcomeDenied], jobs.Outcomes)
	}
	for _, unwanted := range []string{usagestats.OutcomeRefused, usagestats.OutcomeUnknownTool} {
		for _, o := range rest.Outcomes {
			if o == unwanted {
				t.Errorf("the REST summary offers %q, which is an MCP outcome", unwanted)
			}
		}
	}
	// Both tabs are advertised whichever kind was asked for.
	if len(rest.Kinds) != 2 {
		t.Errorf("kinds = %+v, want both", rest.Kinds)
	}
}

// A kind nobody defines is refused. Answering about MCP instead would
// hand the caller figures for something it did not ask about.
func TestAdminUsageRejectsAnUnknownKind(t *testing.T) {
	h := restStatsHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, usageRequest(t, h, "/api/v1/admin/usage?kind=nonsense", "root", []string{"condor-admins"}))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
}

// The counters have to survive the process, through the handler's own
// lifecycle rather than through the store's API: a REST store that
// was never added to the flush would pass every usagestats test and
// persist nothing.
func TestRESTCountersSurviveARestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "app.db")

	first := statsHandlerWith(t, dbPath, true)
	first.restStats.Record("GET /api/v1/jobs", "alice", "curl", usagestats.OutcomeOK, time.Second)
	// StopUsageStats, not Stop: the final flush is what this test is
	// about, and it is the half of shutdown that writes.
	first.StopUsageStats()
	if err := first.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The second handler loads in startUsageStats, as the daemon does:
	// a REST store the lifecycle never read would show zero here even
	// though the rows are on disk.
	second := statsHandlerWith(t, dbPath, true)
	t.Cleanup(func() { second.StopUsageStats() })
	got := second.restStats.Snapshot()[usagestats.Key{
		Name: "GET /api/v1/jobs", User: "alice", Client: "curl", Outcome: usagestats.OutcomeOK,
	}]
	if got.Calls != 1 {
		t.Errorf("calls after a restart = %d, want 1; store holds %+v",
			got.Calls, second.restStats.Snapshot())
	}
}
