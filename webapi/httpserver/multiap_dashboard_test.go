package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// The dashboard in multi-AP mode, from an in-process hub. The departure
// counts run through the real feed following the hub's jobs table.

func dashboardHub(t *testing.T) *multiaptest.DB {
	t.Helper()
	hub := multiaptest.NewHub(t)
	hub.PutJob(ap1, "alice@d", 1, 0, "")
	hub.PutJob(ap1, "alice@d", 2, 0, "JobStatus = 2")
	hub.PutJob(ap2, "alice@d", 1, 0, "JobStatus = 5\nHoldReasonCode = 13\nEnteredCurrentStatus = "+strconv.FormatInt(time.Now().Unix(), 10))
	hub.PutJob(ap1, "bob@d", 3, 0, "")
	hub.PutSource(ap1, multiap.StateFresh, 2)
	hub.PutSource(ap2, multiap.StateStale, 400)
	return hub
}

// TestMultiAPDashboardCountsPerAP: counts in total and per AP, the
// caller's only, with each AP's state and the sources block.
func TestMultiAPDashboardCountsPerAP(t *testing.T) {
	srv := newMultiAPServer(t, multiAPService(t, dashboardHub(t), multiaptest.NewRegistry(ap1, ap2)))
	rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/dashboard")
	var d DashboardResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &d) != nil {
		t.Fatalf("dashboard: %d %s", rec.Code, rec.Body.String())
	}
	if d.JobsTotal != 3 || d.JobsByStatus["idle"] != 1 || d.JobsByStatus["running"] != 1 || d.JobsByStatus["held"] != 1 {
		t.Errorf("totals %d %v, want alice's three jobs and not bob's", d.JobsTotal, d.JobsByStatus)
	}
	if len(d.APs) != 2 {
		t.Fatalf("aps %+v", d.APs)
	}
	for _, ap := range d.APs {
		switch ap.Schedd {
		case ap1:
			if ap.JobsTotal != 2 || ap.State != multiap.StateFresh || ap.JobsByStatus["running"] != 1 {
				t.Errorf("%s: %+v", ap1, ap)
			}
		case ap2:
			if ap.JobsTotal != 1 || ap.State != multiap.StateStale || ap.JobsByStatus["held"] != 1 {
				t.Errorf("%s: %+v", ap2, ap)
			}
		}
	}
	if d.Sources == nil || d.Sources.APs != 2 || d.Sources.Fresh != 1 {
		t.Errorf("sources %+v", d.Sources)
	}
	if n := srv.multi.scheddCalls.Load(); n != 0 {
		t.Errorf("the single-schedd accessor was called %d times", n)
	}
}

// TestMultiAPDashboardFinishedIgnoresAStaleAPsDisappearances: a job
// leaving the hub's queue counts as finished only if its last ad said it
// completed -- not if it left idle or held, on a stale AP or a fresh one
// (that is what retiring or reconciling an AP looks like too) -- while a
// history record counts on either.
func TestMultiAPDashboardFinishedIgnoresAStaleAPsDisappearances(t *testing.T) {
	hub := dashboardHub(t)
	srv := newMultiAPServer(t, multiAPService(t, hub, multiaptest.NewRegistry(ap1, ap2)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.jobWatchFeed.RunResumable(ctx, srv.watchHubJobsTable) }()
	waitCond(t, "the feed to follow the hub", srv.jobWatchFeed.Warm)

	// Jobs appear and leave: completed and held on fresh ap1, idle on
	// stale ap2.
	hub.PutJob(ap1, "alice@d", 30, 0, "JobStatus = 4")
	hub.PutJob(ap1, "alice@d", 32, 0, "JobStatus = 5")
	hub.PutJob(ap2, "alice@d", 30, 0, "")
	hub.DeleteJob(ap1, 30, 0)
	hub.DeleteJob(ap1, 32, 0)
	hub.DeleteJob(ap2, 30, 0)
	waitCond(t, "the deletes to reach the feed", func() bool {
		return len(srv.jobWatchFeed.Terminal("alice", time.Now().Add(-time.Hour))) == 3
	})
	// And a history record on the stale AP.
	hub.PutHistory(ap2, "alice@d", 31, 0, time.Now().Unix())

	rec := doAs(t, srv, "alice", http.MethodGet, "/api/v1/dashboard/activity")
	var a DashboardActivityResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &a) != nil {
		t.Fatalf("activity: %d %s", rec.Code, rec.Body.String())
	}
	got := map[string]DashboardAPActivity{}
	for _, ap := range a.APs {
		got[ap.Schedd] = ap
	}
	if got[ap1].FinishedRecently != 1 || got[ap1].FinishedPartial {
		t.Errorf("%s: %+v, want its completed departure counted and not its held one", ap1, got[ap1])
	}
	if got[ap2].FinishedRecently != 1 || !got[ap2].FinishedPartial {
		t.Errorf("%s: %+v, want its history record counted, its disappearance not, and the count marked partial", ap2, got[ap2])
	}
	if a.Sources == nil || a.Sources.Fresh != 1 {
		t.Errorf("sources %+v", a.Sources)
	}
	held := false
	for _, j := range a.Activity.RecentlyHeld {
		held = held || (j.Schedd == ap2 && j.JobID == "1.0@"+ap2)
	}
	if !held {
		t.Errorf("recently held %+v lacks 1.0@%s with its AP", a.Activity.RecentlyHeld, ap2)
	}
}

func waitCond(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
