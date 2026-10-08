package toolstats

import (
	"math"
	"testing"
	"time"
)

// entry builds an Entry with calls spread over the given bucket indexes.
// An index of -1 means "past the last boundary": counted in Calls, in
// no bucket, exactly as Record leaves it.
func entry(calls uint64, sum float64, last time.Time, at ...int) Entry {
	e := Entry{Calls: calls, DurationSum: sum, LastCall: last, Buckets: make([]uint64, len(DurationBuckets))}
	for _, i := range at {
		if i >= 0 {
			e.Buckets[i]++
		}
	}
	return e
}

// spread returns n copies of bucket index i, for entry's variadic.
func spread(n, i int) []int {
	out := make([]int, n)
	for j := range out {
		out[j] = i
	}
	return out
}

func find(t *testing.T, rows []UsageRow, name string) UsageRow {
	t.Helper()
	for _, r := range rows {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no row %q in %+v", name, rows)
	return UsageRow{}
}

var (
	t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	t1 = t0.Add(time.Hour)
	t2 = t0.Add(2 * time.Hour)
)

func fixture() map[Key]Entry {
	return map[Key]Entry{
		{Tool: "query_jobs", User: "alice", Client: "claude-code", Outcome: OutcomeOK}: entry(3, 0.3, t0, 2, 2, 2),
		{Tool: "query_jobs", User: "bob", Client: "cursor", Outcome: OutcomeError}:     entry(1, 2.0, t2, 6),
		{Tool: "submit_job", User: "alice", Client: "claude-code", Outcome: OutcomeRefused}: entry(
			2, 0.01, t1, 0, 0),
		{Tool: "bogus", User: UnknownUser, Client: UnknownClient, Outcome: OutcomeUnknownTool}: entry(
			1, 0.001, t0, 0),
	}
}

func TestSummarizeTotals(t *testing.T) {
	s := Summarize(fixture(), Filter{})
	tot := s.Totals
	if tot.Calls != 7 {
		t.Errorf("calls = %d, want 7", tot.Calls)
	}
	if tot.OK != 3 || tot.Error != 1 || tot.Refused != 2 || tot.UnknownTool != 1 {
		t.Errorf("outcomes ok/error/refused/unknown_tool = %d/%d/%d/%d, want 3/1/2/1",
			tot.OK, tot.Error, tot.Refused, tot.UnknownTool)
	}
	// "unknown" is the absence of an identity, not a third person.
	if tot.Users != 2 {
		t.Errorf("users = %d, want 2 (alice, bob)", tot.Users)
	}
	if tot.Clients != 2 {
		t.Errorf("clients = %d, want 2 (claude-code, cursor)", tot.Clients)
	}
	if tot.LastCall == nil || !tot.LastCall.Equal(t2) {
		t.Errorf("last call = %v, want %v", tot.LastCall, t2)
	}
}

func TestSummarizeByToolUserClient(t *testing.T) {
	s := Summarize(fixture(), Filter{})

	qj := find(t, s.ByTool, "query_jobs")
	if qj.Calls != 4 || qj.OK != 3 || qj.Error != 1 {
		t.Errorf("query_jobs calls/ok/error = %d/%d/%d, want 4/3/1", qj.Calls, qj.OK, qj.Error)
	}
	if qj.Users != 2 {
		t.Errorf("query_jobs users = %d, want 2", qj.Users)
	}
	if want := 2.3 / 4; math.Abs(qj.AvgSeconds-want) > 1e-9 {
		t.Errorf("query_jobs avg = %v, want %v", qj.AvgSeconds, want)
	}
	if qj.LastCall == nil || !qj.LastCall.Equal(t2) {
		t.Errorf("query_jobs last call = %v, want %v", qj.LastCall, t2)
	}

	alice := find(t, s.ByUser, "alice")
	if alice.Calls != 5 || alice.OK != 3 || alice.Refused != 2 {
		t.Errorf("alice calls/ok/refused = %d/%d/%d, want 5/3/2", alice.Calls, alice.OK, alice.Refused)
	}
	if alice.Clients != 1 {
		t.Errorf("alice clients = %d, want 1", alice.Clients)
	}

	cc := find(t, s.ByClient, "claude-code")
	if cc.Calls != 5 || cc.Users != 1 {
		t.Errorf("claude-code calls/users = %d/%d, want 5/1", cc.Calls, cc.Users)
	}

	bogus := find(t, s.ByTool, "bogus")
	if bogus.UnknownTool != 1 {
		t.Errorf("bogus unknown_tool = %d, want 1", bogus.UnknownTool)
	}

	// Busiest first.
	if s.ByTool[0].Name != "query_jobs" {
		t.Errorf("by_tool[0] = %q, want query_jobs", s.ByTool[0].Name)
	}
}

// TestSummarizeP95PicksTheBucketHoldingTheRank: 20 calls, 18 in the
// 0.1s bucket, one at 1s and one at 30s. The 95th percentile is the
// 19th call, which is the one in the 1s bucket -- not the 30s outlier,
// which a strict ">" on the running count would pick.
func TestSummarizeP95PicksTheBucketHoldingTheRank(t *testing.T) {
	at := append(spread(18, 2), 5, 9)
	snap := map[Key]Entry{
		{Tool: "t", User: "u", Client: "c", Outcome: OutcomeOK}: entry(20, 1, t0, at...),
	}
	r := Summarize(snap, Filter{}).Totals
	if r.P95Seconds == nil || *r.P95Seconds != 1 {
		t.Fatalf("p95 = %v (over %v), want 1", deref(r.P95Seconds), deref(r.P95OverSeconds))
	}
	if r.P95OverSeconds != nil {
		t.Errorf("p95_over = %v, want unset", *r.P95OverSeconds)
	}
}

// Half the calls ran past the last boundary, so the percentile is "longer
// than 300s", not 300s and not the last bucket that has anything in it.
func TestSummarizeP95BeyondTheLastBoundary(t *testing.T) {
	at := append(spread(5, 0), spread(5, -1)...)
	snap := map[Key]Entry{
		{Tool: "watch_jobs", User: "u", Client: "c", Outcome: OutcomeOK}: entry(10, 4000, t0, at...),
	}
	r := Summarize(snap, Filter{}).Totals
	if r.P95Seconds != nil {
		t.Errorf("p95 = %v, want nil", *r.P95Seconds)
	}
	last := DurationBuckets[len(DurationBuckets)-1]
	if r.P95OverSeconds == nil || *r.P95OverSeconds != last {
		t.Errorf("p95_over = %v, want %v", deref(r.P95OverSeconds), last)
	}
}

// A series whose distribution was lost on load contributes its count
// but not a percentile: otherwise every one of its calls would read as
// past the last boundary.
func TestSummarizeP95IgnoresASeriesWithNoDistribution(t *testing.T) {
	snap := map[Key]Entry{
		{Tool: "t", User: "u", Client: "c", Outcome: OutcomeOK}:    entry(10, 1, t0, spread(10, 1)...),
		{Tool: "t", User: "u", Client: "c", Outcome: OutcomeError}: {Calls: 100, DurationSum: 1, LastCall: t0},
	}
	r := Summarize(snap, Filter{}).Totals
	if r.Calls != 110 {
		t.Errorf("calls = %d, want 110", r.Calls)
	}
	if r.P95Seconds == nil || *r.P95Seconds != DurationBuckets[1] {
		t.Errorf("p95 = %v (over %v), want %v", deref(r.P95Seconds), deref(r.P95OverSeconds), DurationBuckets[1])
	}
}

func TestSummarizeFilter(t *testing.T) {
	s := Summarize(fixture(), Filter{User: "alice"})
	if s.Totals.Calls != 5 {
		t.Errorf("filtered calls = %d, want 5", s.Totals.Calls)
	}
	if len(s.ByUser) != 1 || s.ByUser[0].Name != "alice" {
		t.Errorf("filtered by_user = %+v, want only alice", s.ByUser)
	}
	qj := find(t, s.ByTool, "query_jobs")
	if qj.Calls != 3 || qj.Error != 0 {
		t.Errorf("alice's query_jobs calls/error = %d/%d, want 3/0", qj.Calls, qj.Error)
	}
	for _, r := range s.ByClient {
		if r.Name == "cursor" {
			t.Errorf("by_client includes cursor, which alice never used")
		}
	}
	// The choices are not narrowed by the filter, or there would be no
	// way to pick a different user without clearing it first.
	if len(s.Options.Users) != 3 {
		t.Errorf("options.users = %v, want all three", s.Options.Users)
	}

	both := Summarize(fixture(), Filter{User: "alice", Tool: "submit_job"})
	if both.Totals.Calls != 2 || both.Totals.Refused != 2 {
		t.Errorf("alice+submit_job calls/refused = %d/%d, want 2/2", both.Totals.Calls, both.Totals.Refused)
	}
}

func TestSummarizeEmpty(t *testing.T) {
	s := Summarize(map[Key]Entry{}, Filter{})
	if s.Totals.Calls != 0 || s.Totals.LastCall != nil || s.Totals.P95Seconds != nil {
		t.Errorf("empty totals = %+v", s.Totals)
	}
	// Empty slices, not nil: the page iterates them.
	if s.ByTool == nil || s.ByUser == nil || s.ByClient == nil || s.Options.Tools == nil {
		t.Errorf("empty summary has nil slices: %+v", s)
	}
}

func deref(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}
