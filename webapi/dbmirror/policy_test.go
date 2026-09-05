package dbmirror

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
)

func TestHistoryRouteDecision(t *testing.T) {
	fresh := &Info{Address: "<10.0.0.1:9619>", SecondsSinceSync: 10}
	plain := &htcondor.HistoryQueryOptions{Backwards: true}

	cases := []struct {
		name       string
		info       *Info
		opts       *htcondor.HistoryQueryOptions
		wantUse    bool
		wantReason Reason
	}{
		{"fresh mirror, plain query", fresh, plain, true, ReasonServed},
		{"no info", nil, plain, false, ReasonNoMirror},
		{"no address", &Info{SecondsSinceSync: 10}, plain, false, ReasonNoMirror},
		{"history gap", &Info{Address: "<a>", HistoryGap: true}, plain, false, ReasonHistoryGap},
		{"too stale", &Info{Address: "<a>", SecondsSinceSync: 999}, plain, false, ReasonStale},
		{"since stop-scan", fresh, &htcondor.HistoryQueryOptions{Backwards: true, Since: "2026-01-01"}, false, ReasonUnsupportedQuery},
		{"scan_limit budget", fresh, &htcondor.HistoryQueryOptions{Backwards: true, ScanLimit: 5000}, false, ReasonUnsupportedQuery},
		{"forward scan", fresh, &htcondor.HistoryQueryOptions{Backwards: false}, false, ReasonUnsupportedQuery},
		{"nil opts ok", fresh, nil, true, ReasonServed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := HistoryDecision(c.info, c.opts)
			if d.Use != c.wantUse {
				t.Errorf("Use = %v (%q), want %v", d.Use, d.Note, c.wantUse)
			}
			// The Reason is a metric label and drives the status code in
			// required mode, so pin it rather than only checking Use.
			if d.Reason != c.wantReason {
				t.Errorf("Reason = %q, want %q", d.Reason, c.wantReason)
			}
			if d.Note == "" {
				t.Error("Note should never be empty")
			}
		})
	}
}

func TestHistoryRouteToleranceBoundary(t *testing.T) {
	// Exactly at tolerance is still fresh; one past it is stale.
	at := &Info{Address: "<a>", SecondsSinceSync: HistoryToleranceSecs}
	over := &Info{Address: "<a>", SecondsSinceSync: HistoryToleranceSecs + 1}
	if d := HistoryDecision(at, nil); !d.Use {
		t.Error("staleness exactly at tolerance should still route to the mirror")
	}
	if d := HistoryDecision(over, nil); d.Use {
		t.Error("staleness past tolerance should fall back to the schedd")
	}
}

// TestStalenessIsTheLagAtAdvertiseTime pins the thing that is easy to
// get backwards: the mirror measures its own lag when it builds the ad,
// and that measurement is what routing gates on. Deriving the lag from
// the local clock instead -- now minus the advertised LastSyncTime --
// adds the AD's age to the MIRROR's lag. Those are different quantities:
// a mirror advertises every few minutes but syncs continuously, so the
// derived number would climb through the whole advertise window and
// decline routing for a mirror that is perfectly current.
func TestStalenessIsTheLagAtAdvertiseTime(t *testing.T) {
	// An ad built when the syncer was 5s behind, whose absolute stamp is
	// long past both tolerances because the ad itself is old.
	old := &Info{
		Address:              "<a>",
		JobQueueCaughtUp:     true,
		HistoryLastSyncTime:  1_000_000 - 3600,
		SecondsSinceSync:     5,
		JobQueueLastSyncTime: 1_000_000 - 3600,
		JobQueueSecondsSync:  5,
	}
	if got := HistoryStaleness(old); got != 5 {
		t.Errorf("history staleness = %d, want the 5s measured at advertise time", got)
	}
	if got := JobQueueStaleness(old); got != 5 {
		t.Errorf("job-queue staleness = %d, want the 5s measured at advertise time", got)
	}
	if d := HistoryDecision(old, nil); !d.Use {
		t.Errorf("an aging ad is not a lagging mirror; history must still route: %s", d.Note)
	}
	if d := JobsDecision(old, ""); !d.Use {
		t.Errorf("an aging ad is not a lagging mirror; jobs must still route: %s", d.Note)
	}

	// A mirror whose syncer has actually fallen behind says so in its
	// next ad, and that is what closes the gate.
	lagging := &Info{
		Address:             "<a>",
		JobQueueCaughtUp:    true,
		SecondsSinceSync:    HistoryToleranceSecs + 1,
		JobQueueSecondsSync: JobsToleranceSecs + 1,
	}
	if d := HistoryDecision(lagging, nil); d.Use {
		t.Error("a mirror reporting itself past the history tolerance must not be routed to")
	} else if d.Reason != ReasonStale {
		t.Errorf("Reason = %q, want %q", d.Reason, ReasonStale)
	}
	if d := JobsDecision(lagging, ""); d.Use {
		t.Error("a mirror reporting itself past the jobs tolerance must not be routed to")
	} else if d.Reason != ReasonStale {
		t.Errorf("Reason = %q, want %q", d.Reason, ReasonStale)
	}

	// A negative lag would sail through every tolerance check.
	if got := HistoryStaleness(&Info{SecondsSinceSync: -30}); got != 0 {
		t.Errorf("negative lag should clamp to 0, got %d", got)
	}
	if got := HistoryStaleness(nil); got != 0 {
		t.Errorf("nil info = %d, want 0", got)
	}
	if got := JobQueueStaleness(nil); got != 0 {
		t.Errorf("nil info = %d, want 0", got)
	}
}

func TestRecencyKey(t *testing.T) {
	withStatus := classad.New()
	withStatus.InsertAttr("EnteredCurrentStatus", 2000)
	withStatus.InsertAttr("CompletionDate", 1000)
	if got := RecencyKey(withStatus); got != 2000 {
		t.Errorf("EnteredCurrentStatus should win: got %d, want 2000", got)
	}

	completionOnly := classad.New()
	completionOnly.InsertAttr("CompletionDate", 1500)
	if got := RecencyKey(completionOnly); got != 1500 {
		t.Errorf("CompletionDate fallback: got %d, want 1500", got)
	}

	if got := RecencyKey(classad.New()); got != 0 {
		t.Errorf("no timestamps: got %d, want 0", got)
	}
}

func TestRecencyOrdering(t *testing.T) {
	mk := func(entered int64) *classad.ClassAd {
		ad := classad.New()
		ad.InsertAttr("EnteredCurrentStatus", entered)
		return ad
	}
	records := []*classad.ClassAd{mk(100), mk(300), mk(200)}
	sort.SliceStable(records, func(i, j int) bool { return RecencyKey(records[i]) > RecencyKey(records[j]) })
	var got []int64
	for _, r := range records {
		got = append(got, RecencyKey(r))
	}
	if got[0] != 300 || got[1] != 200 || got[2] != 100 {
		t.Errorf("recent-first order = %v, want [300 200 100]", got)
	}
}

func TestJobsRouteDecision(t *testing.T) {
	caughtUp := &Info{Address: "<a>", JobQueueCaughtUp: true, JobQueueSecondsSync: 10}

	cases := []struct {
		name       string
		info       *Info
		page       string
		wantUse    bool
		wantReason Reason
	}{
		{"caught up, fresh", caughtUp, "", true, ReasonServed},
		{"no info", nil, "", false, ReasonNoMirror},
		{"no address", &Info{JobQueueCaughtUp: true}, "", false, ReasonNoMirror},
		{"not caught up", &Info{Address: "<a>", JobQueueCaughtUp: false}, "", false, ReasonNotCaughtUp},
		{"paginated", caughtUp, "tok", false, ReasonPageToken},
		{"too stale", &Info{Address: "<a>", JobQueueCaughtUp: true, JobQueueSecondsSync: 999}, "", false, ReasonStale},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := JobsDecision(c.info, c.page)
			if d.Use != c.wantUse {
				t.Errorf("Use = %v (%q), want %v", d.Use, d.Note, c.wantUse)
			}
			if d.Reason != c.wantReason {
				t.Errorf("Reason = %q, want %q", d.Reason, c.wantReason)
			}
			if d.Note == "" {
				t.Error("Note should never be empty")
			}
		})
	}
}

func TestJobQueueStaleness(t *testing.T) {
	// The lag the mirror measured on itself when it advertised, not
	// anything derived from the local clock.
	if got := JobQueueStaleness(&Info{JobQueueLastSyncTime: 1, JobQueueSecondsSync: 42}); got != 42 {
		t.Errorf("staleness = %d, want the 42s measured at advertise time", got)
	}
	if got := JobQueueStaleness(&Info{JobQueueSecondsSync: -1}); got != 0 {
		t.Errorf("negative lag should clamp to 0, got %d", got)
	}
}

func TestJobsRouteToleranceBoundary(t *testing.T) {
	at := &Info{Address: "<a>", JobQueueCaughtUp: true, JobQueueSecondsSync: JobsToleranceSecs}
	over := &Info{Address: "<a>", JobQueueCaughtUp: true, JobQueueSecondsSync: JobsToleranceSecs + 1}
	if d := JobsDecision(at, ""); !d.Use {
		t.Error("staleness exactly at tolerance should still route to the mirror")
	}
	if d := JobsDecision(over, ""); d.Use {
		t.Error("staleness past tolerance should fall back to the schedd")
	}
}

func TestParseAd(t *testing.T) {
	ad := classad.New()
	ad.InsertAttrString("Name", "htcondordb@ap40")
	ad.InsertAttrString("MyAddress", "<10.0.0.1:9619>")
	ad.InsertAttrBool("TimeTravelEnabled", true)
	ad.InsertAttrBool("HistoryGapDetected", true)
	ad.InsertAttr("HistoryLastSyncTime", 1699999958)
	ad.InsertAttr("HistorySecondsSinceSync", 42)
	ad.InsertAttrBool("JobQueueCaughtUp", true)
	ad.InsertAttr("JobQueueLastSyncTime", 1700000000)
	ad.InsertAttr("JobQueueSecondsSinceSync", 3)

	info := ParseAd(ad)
	if info.Name != "htcondordb@ap40" || info.Address != "<10.0.0.1:9619>" {
		t.Errorf("identity wrong: %+v", info)
	}
	if !info.TimeTravelEnabled || !info.HistoryGap || info.SecondsSinceSync != 42 {
		t.Errorf("capabilities/freshness wrong: %+v", info)
	}
	if info.HistoryLastSyncTime != 1699999958 {
		t.Errorf("history absolute sync stamp wrong: %+v", info)
	}
	if !info.JobQueueCaughtUp || info.JobQueueLastSyncTime != 1700000000 || info.JobQueueSecondsSync != 3 {
		t.Errorf("job-queue freshness wrong: %+v", info)
	}
}

// TestHistoryDecisionPaginationAndScanLimit covers the two cases the
// REST archive endpoint actually produces. A keyset-paginated request
// carries its cursor inside the constraint, so nothing about pagination
// should keep it off the mirror — the archive scans newest-first, which
// is the order that cursor walks. An explicit scan_limit does keep it
// off, because that budget describes the schedd's scan of the history
// file and the archive has no equivalent.
func TestHistoryDecisionPaginationAndScanLimit(t *testing.T) {
	fresh := &Info{Address: "<10.0.0.1:9619>", SecondsSinceSync: 5}

	paged := &htcondor.HistoryQueryOptions{
		Backwards: true,
		// What handleHistoryQuery builds from before_cluster/before_proc.
		Projection: []string{"ClusterId", "ProcId"},
	}
	if d := HistoryDecision(fresh, paged); !d.Use {
		t.Errorf("a paginated archive request must be served from the mirror, got: %s", d.Note)
	}

	budgeted := &htcondor.HistoryQueryOptions{Backwards: true, ScanLimit: 10000}
	if d := HistoryDecision(fresh, budgeted); d.Use {
		t.Error("an explicit scan_limit must keep the query on the schedd")
	}
}

// TestPollRecordsAttemptsWithoutTraffic is why polling exists. Discovery
// is otherwise lazy, so an idle daemon has never asked the collector
// anything: LastAttempt is zero, LastError is empty, and its status page
// cannot tell "no mirror is advertising" apart from "nobody has looked".
// One poll has to be enough to turn that into an answer.
func TestPollRecordsAttemptsWithoutTraffic(t *testing.T) {
	l := NewLocator(htcondor.NewCollector("collector.invalid:9618"), config.NewEmpty())
	if h := l.Health(); !h.LastAttempt.IsZero() {
		t.Fatal("nothing should have been attempted before Poll runs")
	}

	// Poll discovers once up front, so cancelling immediately after it
	// returns still leaves that first attempt recorded.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); l.Poll(ctx, func(*Info, error) { cancel() }) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Poll did not return after its context was cancelled")
	}

	h := l.Health()
	if h.LastAttempt.IsZero() {
		t.Error("a poll must record when it ran, even when it finds nothing")
	}
	if h.LastError == "" {
		t.Error("a poll that found nothing must record why, or the operator has nothing to debug")
	}
}

// A Locator that cannot route must not spin a goroutine or touch the
// network; Poll is called unconditionally by the daemon's startup.
func TestPollIsANoOpWhenRoutingIsOff(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		NewLocator(nil, nil).Poll(context.Background(), func(*Info, error) {
			t.Error("a disabled locator must not poll")
		})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Poll blocked on a locator that cannot route")
	}
}
