package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// A read of a hub table names the APs whose stream of that table cannot
// vouch for their rows -- disconnected, failing, not federated -- in its
// sources block, rather than answering silently short.

func degradedFor(t *testing.T, body []byte, schedd string) *multiap.Degraded {
	t.Helper()
	var b struct {
		Sources *multiap.Sources `json:"sources"`
	}
	if err := json.Unmarshal(body, &b); err != nil || b.Sources == nil {
		t.Fatalf("no sources block in %s", body)
	}
	for i := range b.Sources.Degraded {
		if b.Sources.Degraded[i].Schedd == schedd {
			return &b.Sources.Degraded[i]
		}
	}
	return nil
}

func TestMultiAPEpochsReportAnAPsEpochStream(t *testing.T) {
	hub := epochsHub(t)
	hub.PutSourceAd(ap2, fmt.Sprintf("ScheddName = %q\nState = \"fresh\"\nJobsConnected = true\nStalenessSeconds = 1\n"+
		"HistoryConnected = true\nEpochHistoryConnected = false", ap2))
	srv := newMultiAPServer(t, multiAPService(t, hub, multiaptest.NewRegistry(ap1, ap2)))
	rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs/epochs")
	if rec.Code != http.StatusOK {
		t.Fatalf("epochs: %d %s", rec.Code, rec.Body.String())
	}
	if d := degradedFor(t, rec.Body.Bytes(), ap2); d == nil || !strings.Contains(d.Reason, "epoch_history") {
		t.Errorf("epochs with ap2's epoch stream down: degraded %+v, want ap2 named", d)
	}
	if d := degradedFor(t, rec.Body.Bytes(), ap1); d != nil {
		t.Errorf("ap1 reported degraded: %+v", d)
	}
}

func TestMultiAPIssuesReportAnAPsEpochStream(t *testing.T) {
	hub := issuesHub(t, true)
	hub.PutSourceAd(ap1, fmt.Sprintf("ScheddName = %q\nState = \"fresh\"\nJobsConnected = true\nStalenessSeconds = 1\n"+
		"HistoryConnected = true\nEpochHistoryConnected = true\nEpochHistoryLastError = \"EOF\"", ap1))
	srv := newMultiAPServer(t, multiAPService(t, hub, multiaptest.NewRegistry(ap1, ap2)))
	rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/issues")
	if rec.Code != http.StatusOK {
		t.Fatalf("issues: %d %s", rec.Code, rec.Body.String())
	}
	if d := degradedFor(t, rec.Body.Bytes(), ap1); d == nil || !strings.Contains(d.Reason, "epoch_history") {
		t.Errorf("issues with ap1's epoch stream failing: degraded %+v, want ap1 named", d)
	}
	sc, _ := mcpCallAs(t, srv, "alice", "analyze_issues", map[string]any{})
	b, _ := json.Marshal(sc)
	if d := degradedFor(t, b, ap1); d == nil {
		t.Errorf("analyze_issues does not name ap1's failing epoch stream: %s", b)
	}
}

func TestMultiAPDashboardReportsAnAPsHistoryStream(t *testing.T) {
	hub := dashboardHub(t)
	hub.PutSourceAd(ap1, fmt.Sprintf("ScheddName = %q\nState = \"fresh\"\nJobsConnected = true\nStalenessSeconds = 1\n"+
		"HistoryConnected = false", ap1))
	srv := newMultiAPServer(t, multiAPService(t, hub, multiaptest.NewRegistry(ap1, ap2)))
	rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/dashboard/activity")
	if rec.Code != http.StatusOK {
		t.Fatalf("activity: %d %s", rec.Code, rec.Body.String())
	}
	if d := degradedFor(t, rec.Body.Bytes(), ap1); d == nil || !strings.Contains(d.Reason, "history") {
		t.Errorf("activity with ap1's history stream down: degraded %+v, want ap1 named", d)
	}
	var a DashboardActivityResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &a)
	for _, ap := range a.APs {
		if ap.Schedd == ap1 && !ap.FinishedPartial {
			t.Errorf("%s finished count not marked partial with its history stream down", ap1)
		}
	}
}

// TestMultiAPEpochsNameAnAPWithoutEpochHistory: a spoke that keeps no
// epoch history is not a failing stream; the AP is listed in not_kept.
func TestMultiAPEpochsNameAnAPWithoutEpochHistory(t *testing.T) {
	hub := epochsHub(t)
	hub.PutSourceAd(ap2, fmt.Sprintf("ScheddName = %q\nState = \"fresh\"\nJobsConnected = true\nStalenessSeconds = 1\n"+
		"HistoryConnected = true\nEpochHistoryConnected = false\nEpochHistorySynced = false\nEpochHistoryMissing = true\n"+
		"EpochHistoryLastError = \"the spoke has no epoch_history table\"", ap2))
	srv := newMultiAPServer(t, multiAPService(t, hub, multiaptest.NewRegistry(ap1, ap2)))
	rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/jobs/epochs")
	if rec.Code != http.StatusOK {
		t.Fatalf("epochs: %d %s", rec.Code, rec.Body.String())
	}
	if d := degradedFor(t, rec.Body.Bytes(), ap2); d != nil {
		t.Errorf("ap2 keeps no epoch history and is reported degraded: %+v", d)
	}
	var b struct {
		Sources multiap.Sources `json:"sources"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	if len(b.Sources.NotKept) != 1 || b.Sources.NotKept[0].Schedd != ap2 || b.Sources.NotKept[0].Table != multiap.TableEpochHistory {
		t.Errorf("not_kept = %+v, want ap2's epoch_history", b.Sources.NotKept)
	}
	if b.Sources.Fresh != 2 {
		t.Errorf("fresh = %d, want 2", b.Sources.Fresh)
	}
}

// A spoke the hub reports has no jobs table (JobsMissing) is degraded,
// not "not kept": jobs, history and syncstatus are tables every spoke
// must have, and the dashboard would otherwise count that AP complete.
func TestMultiAPDashboardJobsMissingIsDegraded(t *testing.T) {
	hub := dashboardHub(t)
	hub.PutSourceAd(ap1, fmt.Sprintf("ScheddName = %q\nState = \"fresh\"\nStalenessSeconds = 1\n"+
		"JobsConnected = false\nJobsMissing = true\nJobsLastError = \"the spoke has no jobs table\"\nHistoryConnected = true", ap1))
	srv := newMultiAPServer(t, multiAPService(t, hub, multiaptest.NewRegistry(ap1, ap2)))
	rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/dashboard")
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard: %d %s", rec.Code, rec.Body.String())
	}
	if d := degradedFor(t, rec.Body.Bytes(), ap1); d == nil || !strings.Contains(d.Reason, "jobs") {
		t.Errorf("ap1 has no jobs stream (JobsMissing) and the dashboard calls it fresh: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"not_kept"`) {
		t.Errorf("a missing jobs table is listed as not kept: %s", rec.Body.String())
	}
}
