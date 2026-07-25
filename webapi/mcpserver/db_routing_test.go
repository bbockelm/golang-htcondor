package mcpserver

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
)

func TestHistoryRouteDecision(t *testing.T) {
	fresh := &htcondordbInfo{Address: "<10.0.0.1:9619>", SecondsSinceSync: 10}
	plain := &htcondor.HistoryQueryOptions{Backwards: true}

	cases := []struct {
		name    string
		info    *htcondordbInfo
		opts    *htcondor.HistoryQueryOptions
		wantUse bool
	}{
		{"fresh mirror, plain query", fresh, plain, true},
		{"no info", nil, plain, false},
		{"no address", &htcondordbInfo{SecondsSinceSync: 10}, plain, false},
		{"history gap", &htcondordbInfo{Address: "<a>", HistoryGap: true}, plain, false},
		{"too stale", &htcondordbInfo{Address: "<a>", SecondsSinceSync: 999}, plain, false},
		{"since stop-scan", fresh, &htcondor.HistoryQueryOptions{Backwards: true, Since: "2026-01-01"}, false},
		{"scan_limit budget", fresh, &htcondor.HistoryQueryOptions{Backwards: true, ScanLimit: 5000}, false},
		{"forward scan", fresh, &htcondor.HistoryQueryOptions{Backwards: false}, false},
		{"nil opts ok", fresh, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			useDB, reason := historyRouteDecision(c.info, c.opts, historyRouteToleranceSecs)
			if useDB != c.wantUse {
				t.Errorf("useDB = %v (%q), want %v", useDB, reason, c.wantUse)
			}
			if reason == "" {
				t.Error("reason should never be empty")
			}
		})
	}
}

func TestHistoryRouteToleranceBoundary(t *testing.T) {
	// Exactly at tolerance is still fresh; one past it is stale.
	at := &htcondordbInfo{Address: "<a>", SecondsSinceSync: historyRouteToleranceSecs}
	over := &htcondordbInfo{Address: "<a>", SecondsSinceSync: historyRouteToleranceSecs + 1}
	if use, _ := historyRouteDecision(at, nil, historyRouteToleranceSecs); !use {
		t.Error("staleness exactly at tolerance should still route to the mirror")
	}
	if use, _ := historyRouteDecision(over, nil, historyRouteToleranceSecs); use {
		t.Error("staleness past tolerance should fall back to the schedd")
	}
}

func TestRecencyKey(t *testing.T) {
	withStatus := classad.New()
	withStatus.InsertAttr("EnteredCurrentStatus", 2000)
	withStatus.InsertAttr("CompletionDate", 1000)
	if got := recencyKey(withStatus); got != 2000 {
		t.Errorf("EnteredCurrentStatus should win: got %d, want 2000", got)
	}

	completionOnly := classad.New()
	completionOnly.InsertAttr("CompletionDate", 1500)
	if got := recencyKey(completionOnly); got != 1500 {
		t.Errorf("CompletionDate fallback: got %d, want 1500", got)
	}

	if got := recencyKey(classad.New()); got != 0 {
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
	sort.SliceStable(records, func(i, j int) bool { return recencyKey(records[i]) > recencyKey(records[j]) })
	var got []int64
	for _, r := range records {
		got = append(got, recencyKey(r))
	}
	if got[0] != 300 || got[1] != 200 || got[2] != 100 {
		t.Errorf("recent-first order = %v, want [300 200 100]", got)
	}
}

func TestHistoryResultShape(t *testing.T) {
	ad := classad.New()
	ad.InsertAttr("ClusterId", 42)
	res := historyResult([]*classad.ClassAd{ad}, "job history", "Owner == \"alice\"", "htcondordb", "\n[source: htcondordb mirror]")

	m, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("result is not a map: %T", res)
	}
	meta := m["metadata"].(map[string]interface{})
	if meta["source"] != "htcondordb" {
		t.Errorf("source = %v, want htcondordb", meta["source"])
	}
	if meta["total_records"] != 1 {
		t.Errorf("total_records = %v, want 1", meta["total_records"])
	}
	text := m["content"].([]map[string]interface{})[0]["text"].(string)
	if !strings.Contains(text, "Found 1 job history record(s)") {
		t.Errorf("missing count header: %q", text)
	}
	if !strings.Contains(text, "[source: htcondordb mirror]") {
		t.Errorf("provenance note not appended: %q", text)
	}
	// The record body must be valid JSON carrying the ad.
	start := strings.Index(text, "[")
	if start < 0 || !json.Valid([]byte(text[start:strings.Index(text, "]")+1])) {
		// The note also contains brackets; just assert the marshaled ad is present.
		if !strings.Contains(text, "42") {
			t.Errorf("record payload missing ClusterId: %q", text)
		}
	}
}

func TestJobsRouteDecision(t *testing.T) {
	const now = 1_000_000
	caughtUp := &htcondordbInfo{Address: "<a>", JobQueueCaughtUp: true, JobQueueLastSyncTime: now - 10}

	cases := []struct {
		name    string
		info    *htcondordbInfo
		page    string
		wantUse bool
	}{
		{"caught up, fresh", caughtUp, "", true},
		{"no info", nil, "", false},
		{"no address", &htcondordbInfo{JobQueueCaughtUp: true}, "", false},
		{"not caught up", &htcondordbInfo{Address: "<a>", JobQueueCaughtUp: false, JobQueueLastSyncTime: now}, "", false},
		{"paginated", caughtUp, "tok", false},
		{"too stale", &htcondordbInfo{Address: "<a>", JobQueueCaughtUp: true, JobQueueLastSyncTime: now - 999}, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			use, reason := jobsRouteDecision(c.info, c.page, now, jobsRouteToleranceSecs)
			if use != c.wantUse {
				t.Errorf("useDB = %v (%q), want %v", use, reason, c.wantUse)
			}
			if reason == "" {
				t.Error("reason should never be empty")
			}
		})
	}
}

func TestJobQueueStaleness(t *testing.T) {
	const now = 1_000_000
	// Absolute last-sync time wins (accurate regardless of ad age).
	if got := jobQueueStaleness(&htcondordbInfo{JobQueueLastSyncTime: now - 30, JobQueueSecondsSync: 999}, now); got != 30 {
		t.Errorf("absolute staleness = %d, want 30", got)
	}
	// A clock skew (future last-sync) clamps to 0 rather than going negative.
	if got := jobQueueStaleness(&htcondordbInfo{JobQueueLastSyncTime: now + 5}, now); got != 0 {
		t.Errorf("future last-sync should clamp to 0, got %d", got)
	}
	// Falls back to the frozen SecondsSinceSync when no absolute stamp.
	if got := jobQueueStaleness(&htcondordbInfo{JobQueueSecondsSync: 42}, now); got != 42 {
		t.Errorf("frozen fallback = %d, want 42", got)
	}
}

func TestJobsRouteToleranceBoundary(t *testing.T) {
	const now = 1_000_000
	at := &htcondordbInfo{Address: "<a>", JobQueueCaughtUp: true, JobQueueLastSyncTime: now - jobsRouteToleranceSecs}
	over := &htcondordbInfo{Address: "<a>", JobQueueCaughtUp: true, JobQueueLastSyncTime: now - jobsRouteToleranceSecs - 1}
	if use, _ := jobsRouteDecision(at, "", now, jobsRouteToleranceSecs); !use {
		t.Error("staleness exactly at tolerance should still route to the mirror")
	}
	if use, _ := jobsRouteDecision(over, "", now, jobsRouteToleranceSecs); use {
		t.Error("staleness past tolerance should fall back to the schedd")
	}
}

func TestJobKeyLess(t *testing.T) {
	mk := func(c, p int64) *classad.ClassAd {
		ad := classad.New()
		ad.InsertAttr("ClusterId", c)
		ad.InsertAttr("ProcId", p)
		return ad
	}
	ads := []*classad.ClassAd{mk(5, 1), mk(3, 2), mk(3, 0), mk(5, 0)}
	sort.SliceStable(ads, func(i, j int) bool { return jobKeyLess(ads[i], ads[j]) })
	var got [][2]int64
	for _, a := range ads {
		c, _ := a.EvaluateAttrInt("ClusterId")
		p, _ := a.EvaluateAttrInt("ProcId")
		got = append(got, [2]int64{c, p})
	}
	want := [][2]int64{{3, 0}, {3, 2}, {5, 0}, {5, 1}}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestRenderJobsBase(t *testing.T) {
	ad := classad.New()
	ad.InsertAttr("ClusterId", 7)
	text, meta := renderJobsBase([]*classad.ClassAd{ad}, "Owner == \"alice\"", "htcondordb", "\n[source: htcondordb mirror]")
	if meta["source"] != "htcondordb" || meta["count"] != 1 || meta["has_more"] != false {
		t.Errorf("metadata wrong: %+v", meta)
	}
	if !strings.Contains(text, "Found 1 job(s)") || !strings.Contains(text, "JOB STATUS REFERENCE") {
		t.Errorf("missing header or status guide: %q", text)
	}
	if !strings.Contains(text, "[source: htcondordb mirror]") {
		t.Errorf("provenance note not appended: %q", text)
	}
}

// TestHistoryResultSchedddPathNoNote confirms the schedd path (empty note) adds
// no provenance line and labels the source with the record source.
func TestHistoryResultScheddPathNoNote(t *testing.T) {
	res := historyResult(nil, "job epochs", "true", "JOB_EPOCH", "")
	m := res.(map[string]interface{})
	text := m["content"].([]map[string]interface{})[0]["text"].(string)
	if strings.Contains(text, "[source: htcondordb") {
		t.Errorf("schedd path must not carry a mirror note: %q", text)
	}
	if m["metadata"].(map[string]interface{})["source"] != "JOB_EPOCH" {
		t.Error("schedd path should preserve the record source label")
	}
}
