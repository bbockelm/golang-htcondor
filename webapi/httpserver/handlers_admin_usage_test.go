package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/toolstats"
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
	t.Cleanup(func() { h.StopToolStats() })
	h.webuiAdminGroups = newGroupSet("condor-admins")
	h.setupRoutes()
	return h
}

// Through ServeHTTP rather than the handler method, so a route that was
// never registered fails here instead of falling through to the SPA.
func TestAdminUsageServesTheLiveCounts(t *testing.T) {
	h := usageHandler(t)
	h.toolStats.Record("query_jobs", "alice", "claude-code", toolstats.OutcomeOK, 50*time.Millisecond)
	h.toolStats.Record("query_jobs", "bob", "cursor", toolstats.OutcomeError, time.Second)
	h.toolStats.Record("submit_job", "alice", "claude-code", toolstats.OutcomeRefused, time.Millisecond)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, usageRequest(t, h, "/api/v1/admin/usage", "root", []string{"condor-admins"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var got struct {
		Enabled bool                 `json:"enabled"`
		Totals  toolstats.UsageRow   `json:"totals"`
		ByTool  []toolstats.UsageRow `json:"by_tool"`
		ByUser  []toolstats.UsageRow `json:"by_user"`
		Options toolstats.Options    `json:"options"`
		Filter  toolstats.Filter     `json:"filter"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, rec.Body.String())
	}
	if !got.Enabled {
		t.Fatalf("enabled = false with a store attached: %s", rec.Body.String())
	}
	if got.Totals.Calls != 3 || got.Totals.OK != 1 || got.Totals.Error != 1 || got.Totals.Refused != 1 {
		t.Errorf("totals = %+v, want 3 calls: 1 ok, 1 error, 1 refused", got.Totals)
	}
	// Real names, whatever /metrics is told to do with them.
	if got.Totals.Users != 2 || len(got.ByUser) != 2 {
		t.Errorf("users = %d, by_user = %+v; want alice and bob", got.Totals.Users, got.ByUser)
	}
	if len(got.ByTool) != 2 || got.ByTool[0].Name != "query_jobs" {
		t.Errorf("by_tool = %+v, want query_jobs first", got.ByTool)
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
	h.toolStats.Record("query_jobs", "alice", "claude-code", toolstats.OutcomeOK, time.Millisecond)

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
	h.StopToolStats()
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
	if got["enabled"] != false || len(got) != 1 {
		t.Errorf("body = %s, want exactly {\"enabled\":false}", rec.Body.String())
	}
}
