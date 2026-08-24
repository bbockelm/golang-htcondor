package dbmirror

import (
	"sort"
	"testing"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
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
	const now = 1_000_000
	caughtUp := &Info{Address: "<a>", JobQueueCaughtUp: true, JobQueueLastSyncTime: now - 10}

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
		{"not caught up", &Info{Address: "<a>", JobQueueCaughtUp: false, JobQueueLastSyncTime: now}, "", false, ReasonNotCaughtUp},
		{"paginated", caughtUp, "tok", false, ReasonPageToken},
		{"too stale", &Info{Address: "<a>", JobQueueCaughtUp: true, JobQueueLastSyncTime: now - 999}, "", false, ReasonStale},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := JobsDecision(c.info, c.page, now)
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
	const now = 1_000_000
	// Absolute last-sync time wins (accurate regardless of ad age).
	if got := JobQueueStaleness(&Info{JobQueueLastSyncTime: now - 30, JobQueueSecondsSync: 999}, now); got != 30 {
		t.Errorf("absolute staleness = %d, want 30", got)
	}
	// A clock skew (future last-sync) clamps to 0 rather than going negative.
	if got := JobQueueStaleness(&Info{JobQueueLastSyncTime: now + 5}, now); got != 0 {
		t.Errorf("future last-sync should clamp to 0, got %d", got)
	}
	// Falls back to the frozen SecondsSinceSync when no absolute stamp.
	if got := JobQueueStaleness(&Info{JobQueueSecondsSync: 42}, now); got != 42 {
		t.Errorf("frozen fallback = %d, want 42", got)
	}
}

func TestJobsRouteToleranceBoundary(t *testing.T) {
	const now = 1_000_000
	at := &Info{Address: "<a>", JobQueueCaughtUp: true, JobQueueLastSyncTime: now - JobsToleranceSecs}
	over := &Info{Address: "<a>", JobQueueCaughtUp: true, JobQueueLastSyncTime: now - JobsToleranceSecs - 1}
	if d := JobsDecision(at, "", now); !d.Use {
		t.Error("staleness exactly at tolerance should still route to the mirror")
	}
	if d := JobsDecision(over, "", now); d.Use {
		t.Error("staleness past tolerance should fall back to the schedd")
	}
}

func TestParseAd(t *testing.T) {
	ad := classad.New()
	ad.InsertAttrString("Name", "htcondordb@ap40")
	ad.InsertAttrString("MyAddress", "<10.0.0.1:9619>")
	ad.InsertAttrBool("TimeTravelEnabled", true)
	ad.InsertAttrBool("HistoryGapDetected", true)
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
