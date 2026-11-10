package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/dbrpc"
)

// The query-shape tests below assert on the CONSTRUCTED query rather
// than on what it returns, and that is the point of them.
//
// All three properties they pin -- one group column, no per-aggregate
// filter, the window and bucket on EnteredHistoryTime -- are invisible
// in the result. Break any of them and the calendar still shows the
// right numbers, produced by a full record scan instead of out of the
// columnar blocks: measured on a 1M-record history archive, a 90-day
// series went from 51-95ms to 1.3-1.6s and a 365-day one from 183-335ms
// to 5.3-6.1s. A test on the numbers sees none of that. Only a test on
// the query does.
//
// The CompletionDate case is worse than slow and is checked hardest: a
// removed job has no CompletionDate at all, so bucketing or windowing on
// it drops every removal silently -- ~15 against a true 26,798 over a
// week of production history.

const testCalendarScope = `Owner == "alice"`

func testCalendarQueries(t *testing.T) []calendarQuery {
	t.Helper()
	// A fixed, bucket-aligned window, so the constraints are exact text
	// rather than something the test has to recompute.
	const start, end = int64(1700000000 / 86400 * 86400), int64(1700000000/86400*86400 + 90*86400)
	qs := calendarQueries(testCalendarScope, start, end)
	if len(qs) != 4 {
		t.Fatalf("got %d queries, want 4 (completed, removed, submitted from history, submitted from the queue)", len(qs))
	}
	return qs
}

// TestCalendarQueriesUseOneGroupColumn pins the group shape: exactly one
// bucketed day column per series. A second group column declines the
// grouped columnar path outright, which is why the series are separate
// queries rather than one grouped by day and status.
func TestCalendarQueriesUseOneGroupColumn(t *testing.T) {
	for _, q := range testCalendarQueries(t) {
		if len(q.Groups) != 1 {
			t.Errorf("%s groups by %d columns (%+v), want exactly 1 -- two decline the columnar path",
				q.Series, len(q.Groups), q.Groups)
			continue
		}
		if q.Groups[0].BucketWidth != 86400 {
			t.Errorf("%s buckets by %d seconds, want 86400 (one day)", q.Series, q.Groups[0].BucketWidth)
		}
	}
}

// TestCalendarQueriesCarryNoAggregateFilter pins the other cliff: a
// per-aggregate FILTER declines the columnar path, so the status split
// is done with a constraint instead.
func TestCalendarQueriesCarryNoAggregateFilter(t *testing.T) {
	for _, q := range testCalendarQueries(t) {
		if len(q.Aggs) != 1 {
			t.Errorf("%s asks for %d aggregates, want 1 COUNT(*)", q.Series, len(q.Aggs))
			continue
		}
		if q.Aggs[0].Func != dbrpc.AggCount || q.Aggs[0].Arg != "*" {
			t.Errorf("%s aggregate = %+v, want COUNT(*)", q.Series, q.Aggs[0])
		}
		if q.Aggs[0].Filter != "" {
			t.Errorf("%s carries a per-aggregate FILTER (%q), which declines the columnar path -- "+
				"split the status with a constraint instead", q.Series, q.Aggs[0].Filter)
		}
	}
}

// TestCalendarQueriesNeverTouchCompletionDate is the one that matters
// most: CompletionDate is undefined on a removed job, so a window or a
// bucket on it drops removals rather than mis-sorting them.
func TestCalendarQueriesNeverTouchCompletionDate(t *testing.T) {
	for _, q := range testCalendarQueries(t) {
		if strings.Contains(q.Constraint, "CompletionDate") {
			t.Errorf("%s windows on CompletionDate (%q) -- a removed job has none, so every removal drops out",
				q.Series, q.Constraint)
		}
		if q.Groups[0].Attr == "CompletionDate" {
			t.Errorf("%s buckets on CompletionDate -- a removed job has none", q.Series)
		}
	}
}

// TestCalendarQueriesWindowOnEnteredHistoryTime checks each series reads
// the table it has to, through the API that table needs, windowed on the
// attribute that prunes.
func TestCalendarQueriesWindowOnEnteredHistoryTime(t *testing.T) {
	byName := map[calendarSeries]calendarQuery{}
	for _, q := range testCalendarQueries(t) {
		byName[q.Series] = q
	}

	for _, series := range []calendarSeries{seriesCompleted, seriesRemoved, seriesSubmittedHistory} {
		q, ok := byName[series]
		if !ok {
			t.Fatalf("no %s query", series)
		}
		if q.Table != "history" || !q.Archive {
			t.Errorf("%s reads %q archive=%v, want the history ARCHIVE -- AggregateTable on that name "+
				"answers \"no such table\"", series, q.Table, q.Archive)
		}
		// Both ends: an open-ended window has no upper segment to prune
		// against, and one record ingested under a forward-skewed clock
		// would drag a bucket past the last day.
		if !strings.Contains(q.Constraint, "EnteredHistoryTime >=") ||
			!strings.Contains(q.Constraint, "EnteredHistoryTime <") {
			t.Errorf("%s is not windowed on EnteredHistoryTime at both ends: %q", series, q.Constraint)
		}
	}

	// Completed and removed are split by a constraint, one status each.
	if c := byName[seriesCompleted].Constraint; !strings.Contains(c, "JobStatus == 4") {
		t.Errorf("completed is not narrowed to JobStatus == 4: %q", c)
	}
	if c := byName[seriesRemoved].Constraint; !strings.Contains(c, "JobStatus == 3") {
		t.Errorf("removed is not narrowed to JobStatus == 3: %q", c)
	}

	// The submitted-from-history series is the one whose window and
	// bucket are deliberately on DIFFERENT attributes: windowed on the
	// zone-mapped EnteredHistoryTime so it prunes, bucketed on QDate so
	// a job counts on the day it was submitted. Windowing on QDate
	// instead prunes nothing -- 677ms against 83ms for the same answer.
	sub := byName[seriesSubmittedHistory]
	if sub.Groups[0].Attr != "QDate" {
		t.Errorf("submitted-from-history buckets on %q, want QDate (the day it was submitted)", sub.Groups[0].Attr)
	}
	if strings.Contains(sub.Constraint, "QDate") {
		t.Errorf("submitted-from-history windows on QDate (%q), which is not zone-mapped so the window prunes nothing",
			sub.Constraint)
	}

	// The live half of the submitted union: the mutable queue table,
	// where there is no EnteredHistoryTime to window on.
	live := byName[seriesSubmittedLive]
	if live.Table != "jobs" || live.Archive {
		t.Errorf("submitted-from-the-queue reads %q archive=%v, want the live jobs table", live.Table, live.Archive)
	}
	if live.Groups[0].Attr != "QDate" || !strings.Contains(live.Constraint, "QDate >=") {
		t.Errorf("submitted-from-the-queue = %+v, want a QDate window and bucket", live)
	}
}

// TestCalendarQueriesScopeEveryQuery checks the owner clause reaches
// every query. One unscoped series would publish another owner's counts
// into the caller's chart, and nothing downstream would notice: the
// mirror is read with this daemon's credential.
func TestCalendarQueriesScopeEveryQuery(t *testing.T) {
	for _, q := range testCalendarQueries(t) {
		if !strings.Contains(q.Constraint, testCalendarScope) {
			t.Errorf("%s is not owner-scoped: %q", q.Series, q.Constraint)
		}
		// Parenthesised, so a scope clause of its own cannot reach past
		// the AND that follows it.
		if !strings.HasPrefix(q.Constraint, "("+testCalendarScope+")") {
			t.Errorf("%s does not parenthesise the scope: %q", q.Series, q.Constraint)
		}
	}
}

// TestCalendarWindowAlignsToUTCMidnight checks the window the engine
// buckets against. The bucket floor is epoch-aligned, so the window has
// to be too or the first and last rows cover part of a day.
func TestCalendarWindowAlignsToUTCMidnight(t *testing.T) {
	now := time.Date(2023, 11, 14, 17, 43, 21, 0, time.UTC)
	start, end := calendarWindow(now, 7)
	if start%86400 != 0 || end%86400 != 0 {
		t.Errorf("window [%d,%d) is not day-aligned", start, end)
	}
	if end-start != 7*86400 {
		t.Errorf("window spans %d days, want 7", (end-start)/86400)
	}
	// end is exclusive and is tomorrow's midnight, so today's bucket is
	// the last one in the window rather than just outside it.
	if now.Unix() >= end || now.Unix() < end-86400 {
		t.Errorf("now (%d) is not in the last bucket [%d,%d)", now.Unix(), end-86400, end)
	}
}

// TestCalendarDaysFillsEveryDay checks that a day with nothing in it
// still gets a row. A gap and a zero are different facts and the panel
// has to be able to tell them apart, so nothing is omitted.
func TestCalendarDaysFillsEveryDay(t *testing.T) {
	const start = int64(1700000000 / 86400 * 86400)
	days := calendarDays(start, 5)
	if len(days) != 5 {
		t.Fatalf("got %d rows for a 5-day window", len(days))
	}
	for i, d := range days {
		if want := start + int64(i)*86400; d.Day != want {
			t.Errorf("days[%d].Day = %d, want %d", i, d.Day, want)
		}
		if d.Submitted != 0 || d.Completed != 0 || d.Removed != 0 {
			t.Errorf("days[%d] is not zeroed: %+v", i, d)
		}
	}
}

// TestDeriveQueueDepthAnchorsToTheLiveCount checks the one measured
// value in the series: the last day is the live queue count, not a
// derivation.
func TestDeriveQueueDepthAnchorsToTheLiveCount(t *testing.T) {
	days := calendarDays(1700000000/86400*86400, 3)
	if clamped := deriveQueueDepth(days, 64925); clamped {
		t.Error("an all-zero flow series should not have clamped")
	}
	if got := days[len(days)-1].InQueue; got != 64925 {
		t.Errorf("the last day is %d, want the live count 64925 -- the walk is anchored to it", got)
	}
	// No flows anywhere, so every earlier day equals the anchor.
	for i, d := range days {
		if d.InQueue != 64925 {
			t.Errorf("days[%d].InQueue = %d, want 64925 with no flows to walk through", i, d.InQueue)
		}
	}
}

// TestDeriveQueueDepthWalksBackwards checks the arithmetic:
// depth(D) = depth(D+1) - submitted(D+1) + completed(D+1) + removed(D+1).
func TestDeriveQueueDepthWalksBackwards(t *testing.T) {
	days := calendarDays(1700000000/86400*86400, 4)
	// Day 1 and day 3 move; day 2 is deliberately untouched, so the test
	// also covers a day with no history at all sitting mid-series.
	days[1].Submitted, days[1].Completed, days[1].Removed = 100, 40, 10
	days[3].Submitted, days[3].Completed, days[3].Removed = 5, 50, 5

	if clamped := deriveQueueDepth(days, 1000); clamped {
		t.Fatal("unexpected clamp")
	}
	want := []int{
		// 1000 (anchor, day 3) -> day 2: 1000 - 5 + 50 + 5 = 1050
		// day 2 -> day 1: 1050 (day 2 has no flows) = 1050
		// day 1 -> day 0: 1050 - 100 + 40 + 10 = 1000
		1000, 1050, 1050, 1000,
	}
	for i, d := range days {
		if d.InQueue != want[i] {
			t.Errorf("days[%d].InQueue = %d, want %d (series: %+v)", i, d.InQueue, want[i], days)
		}
	}
}

// TestDeriveQueueDepthReportsAClamp checks that a walk going negative is
// reported rather than quietly floored. Going negative means jobs left
// the queue without entering history, which is the one error this
// derivation accumulates, and flooring it silently is exactly how that
// error would stay invisible.
func TestDeriveQueueDepthReportsAClamp(t *testing.T) {
	days := calendarDays(1700000000/86400*86400, 3)
	// More submitted on the last day than the queue holds, so walking
	// back from the anchor goes under zero.
	days[2].Submitted = 500
	clamped := deriveQueueDepth(days, 10)
	if !clamped {
		t.Error("a walk that went below zero was not reported")
	}
	if days[1].InQueue != 0 {
		t.Errorf("days[1].InQueue = %d, want 0 -- a count cannot be negative", days[1].InQueue)
	}
	if days[2].InQueue != 10 {
		t.Errorf("the anchor was altered: %d, want 10", days[2].InQueue)
	}
}

// TestDeriveQueueDepthOnNoDays checks the empty window does not panic.
func TestDeriveQueueDepthOnNoDays(t *testing.T) {
	if clamped := deriveQueueDepth(nil, 7); clamped {
		t.Error("an empty series clamped")
	}
}

// TestCalendarDaysParamCapsRatherThanRefusing checks the window
// parameter: a default, a floor, and a cap that narrows rather than
// errors -- the response reports window_days as applied.
func TestCalendarDaysParamCapsRatherThanRefusing(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"", calendarDefaultDays, false},
		{"7", 7, false},
		{"90", 90, false},
		{fmt.Sprint(calendarMaxDays), calendarMaxDays, false},
		{fmt.Sprint(calendarMaxDays + 1000), calendarMaxDays, false},
		{"0", 0, true},
		{"-3", 0, true},
		{"a week", 0, true},
	}
	for _, c := range cases {
		got, err := calendarDaysParam(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("calendarDaysParam(%q) err=%v, wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("calendarDaysParam(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestCalendarCacheKeySeparatesOwnersAndWindows checks the cache key.
// Leaving the owner out would not waste a query, it would serve one
// user's calendar to another; leaving the window out would serve a
// 30-day answer as a 90-day one, which is not a prefix of it (the
// archive series are windowed, so the shorter is not a slice of the
// longer).
func TestCalendarCacheKeySeparatesOwnersAndWindows(t *testing.T) {
	seen := map[string]string{}
	for _, c := range []struct{ owner, label string }{{"alice", "alice"}, {"bob", "bob"}} {
		for _, days := range []int{30, 90} {
			k := calendarCacheKey(c.owner, true, days)
			label := fmt.Sprintf("%s/%d", c.label, days)
			if prev, dup := seen[k]; dup {
				t.Errorf("%s shares a cache key with %s: %q", label, prev, k)
			}
			seen[k] = label
		}
	}
	// The pool-wide view is the same answer for every administrator, so
	// it shares one key per window -- but never the owner's.
	all := calendarCacheKey("alice", false, 90)
	if _, dup := seen[all]; dup {
		t.Errorf("the pool-wide key %q collides with an owner's", all)
	}
	if all != calendarCacheKey("bob", false, 90) {
		t.Error("two administrators do not share the pool-wide calendar")
	}
}

// TestCalendarNoteListsEveryShortfall checks the note names all of what
// is missing rather than only the first: "no history archive" and "the
// depth ran negative" are different problems with different fixes.
func TestCalendarNoteListsEveryShortfall(t *testing.T) {
	one := calendarNote([]string{"completed"})
	if !strings.Contains(one, "completed") || !strings.HasSuffix(one, ".") {
		t.Errorf("single-shortfall note = %q", one)
	}
	two := calendarNote([]string{"completed", "removed"})
	if !strings.Contains(two, "completed") || !strings.Contains(two, "removed") {
		t.Errorf("note dropped a shortfall: %q", two)
	}
}

// TestCalendarReportsTheFeatureOffWithoutAMirror checks the no-mirror
// answer: 200 with enabled=false and no days, not an error. The schedd
// cannot answer this at all -- it keeps no history past the reaper and
// cannot group by anything -- so the page hides the panel rather than
// showing a failure for a feature this deployment does not have.
func TestCalendarReportsTheFeatureOffWithoutAMirror(t *testing.T) {
	f := twoOwnerScheddServer(t)
	if f.s.dbMirror.Enabled() {
		t.Fatal("the fixture has a mirror; this test is about not having one")
	}
	for _, auth := range []struct {
		name string
		fn   func(*http.Request)
	}{
		{"bearer", f.bearer(t, "bob")},
		{"session", f.session(t, "bob")},
	} {
		w := f.do(t, http.MethodGet, "/api/v1/calendar?days=30", "", auth.fn)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: GET /api/v1/calendar returned %d, want 200: %s", auth.name, w.Code, w.Body.String())
		}
		var resp CalendarResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: decoding %s: %v", auth.name, w.Body.String(), err)
		}
		if resp.Enabled {
			t.Errorf("%s: the calendar reports itself enabled with no mirror", auth.name)
		}
		if len(resp.Days) != 0 {
			t.Errorf("%s: %d days returned with no mirror", auth.name, len(resp.Days))
		}
		if resp.Note == "" {
			t.Errorf("%s: no note saying why the calendar is off", auth.name)
		}
	}
}

// TestCalendarRejectsABadWindow checks the parameter is validated rather
// than silently defaulted: a caller asking for "0 days" has a bug, and
// answering it with 90 hides that.
func TestCalendarRejectsABadWindow(t *testing.T) {
	f := twoOwnerScheddServer(t)
	w := f.do(t, http.MethodGet, "/api/v1/calendar?days=0", "", f.session(t, "bob"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("days=0 returned %d, want 400: %s", w.Code, w.Body.String())
	}
	w = f.do(t, http.MethodPost, "/api/v1/calendar", "", f.session(t, "bob"))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST returned %d, want 405", w.Code)
	}
}

// TestCalendarBucketedOnMatchesTheQueries checks the response's
// bucketed_on against the queries it describes.
//
// It is derived from them rather than written out separately, and this
// pins that: the only consumer is a drill-down that has to select the
// same set the figure counted, so a bucketed_on that said one attribute
// while the query grouped by another would send a panel to build a
// constraint over a different population and show a total that disagrees
// with the number clicked.
func TestCalendarBucketedOnMatchesTheQueries(t *testing.T) {
	queries := testCalendarQueries(t)
	got := calendarBucketedOn(queries)

	byAttr := map[calendarSeries]string{}
	for _, q := range queries {
		byAttr[q.Series] = q.Groups[0].Attr
	}
	if got.Completed != byAttr[seriesCompleted] {
		t.Errorf("bucketed_on.completed = %q, but the query groups by %q", got.Completed, byAttr[seriesCompleted])
	}
	if got.Removed != byAttr[seriesRemoved] {
		t.Errorf("bucketed_on.removed = %q, but the query groups by %q", got.Removed, byAttr[seriesRemoved])
	}
	// Both halves of the submitted union must agree, or one attribute
	// cannot describe the series at all.
	if byAttr[seriesSubmittedHistory] != byAttr[seriesSubmittedLive] {
		t.Fatalf("the two submitted queries bucket differently (%q and %q), so bucketed_on.submitted cannot describe both",
			byAttr[seriesSubmittedHistory], byAttr[seriesSubmittedLive])
	}
	if got.Submitted != byAttr[seriesSubmittedLive] {
		t.Errorf("bucketed_on.submitted = %q, but the queries group by %q", got.Submitted, byAttr[seriesSubmittedLive])
	}

	// And the values a drill-down will actually be handed. Named here
	// rather than only compared, because the whole point is that the
	// obvious guesses -- CompletionDate for a finished day,
	// EnteredCurrentStatus for a removed one -- are the wrong sets.
	if got.Completed != "EnteredHistoryTime" || got.Removed != "EnteredHistoryTime" {
		t.Errorf("finished/removed bucketed on %q/%q, want EnteredHistoryTime for both",
			got.Completed, got.Removed)
	}
	if got.Submitted != "QDate" {
		t.Errorf("submitted bucketed on %q, want QDate", got.Submitted)
	}
}

// TestDeriveQueueDepthKeepsTheAnchorAndLastDayEqual pins the guarantee
// the response documents: queue_depth.anchor and the last day's in_queue
// are one number reported twice. A panel renders the anchor as a figure
// and plots in_queue, so if they could drift the dot and the label
// beside it would disagree.
func TestDeriveQueueDepthKeepsTheAnchorAndLastDayEqual(t *testing.T) {
	for _, flows := range []CalendarDay{
		{},
		{Submitted: 7, Completed: 3, Removed: 1},
		// A last day busy enough to drive the walk negative behind it:
		// the clamp must not reach the anchor.
		{Submitted: 9000},
	} {
		days := calendarDays(1700000000/86400*86400, 4)
		days[3].Submitted, days[3].Completed, days[3].Removed = flows.Submitted, flows.Completed, flows.Removed
		const anchor = 42
		deriveQueueDepth(days, anchor)
		if got := days[len(days)-1].InQueue; got != anchor {
			t.Errorf("with last-day flows %+v the last day's in_queue = %d, want the anchor %d", flows, got, anchor)
		}
	}
}

// TestCalendarStepMatchesTheBucketWidth checks the step the response
// reports against the width the queries actually group by. A panel uses
// step to space the axis and to find gaps, so a step that disagreed with
// the bucketing would mislay every figure.
func TestCalendarStepMatchesTheBucketWidth(t *testing.T) {
	for _, q := range testCalendarQueries(t) {
		if q.Groups[0].BucketWidth != calendarBucket {
			t.Errorf("%s buckets by %d, but the response reports step=%d",
				q.Series, q.Groups[0].BucketWidth, calendarBucket)
		}
	}
	// And the step is the spacing between consecutive rows, which is
	// what a panel laying out an axis depends on.
	days := calendarDays(1700000000/86400*86400, 3)
	for i := 1; i < len(days); i++ {
		if got := days[i].Day - days[i-1].Day; got != calendarBucket {
			t.Errorf("days are %d seconds apart, but step says %d", got, calendarBucket)
		}
	}
}

// TestCalendarResponseJSONShape pins the wire field names.
//
// A separate front end is built against these, and Go's field names are
// not them: renaming a Go field or dropping a json tag changes the
// contract silently, and the panel's symptom is a chart of zeros rather
// than a build error.
func TestCalendarResponseJSONShape(t *testing.T) {
	resp := CalendarResponse{
		Enabled:    true,
		WindowDays: 90,
		Step:       calendarBucket,
		Days:       []CalendarDay{{Day: 1700000000, Submitted: 120, Completed: 98, Removed: 4, InQueue: 230}},
		QueueDepth: &CalendarQueueDepth{Derived: true, Anchor: 64925},
		BucketedOn: &CalendarBucketing{Submitted: "QDate", Completed: "EnteredHistoryTime", Removed: "EnteredHistoryTime"},
		Source:     "htcondordb mirror",
		ComputedAt: 1700000000,
	}
	blob, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"enabled", "days", "window_days", "step", "queue_depth", "bucketed_on",
		"source", "computed_at", "partial", "note",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("the response has no %q: %s", key, blob)
		}
	}
	// partial and note carry no omitempty, so an answer with nothing
	// wrong still says so rather than leaving the panel to infer it from
	// an absent field.
	if got["partial"] != false || got["note"] != "" {
		t.Errorf("a complete answer should still state partial=false and note=\"\": %s", blob)
	}
	day := got["days"].([]any)[0].(map[string]any)
	for _, key := range []string{"day", "submitted", "completed", "removed", "in_queue"} {
		if _, ok := day[key]; !ok {
			t.Errorf("a day row has no %q: %s", key, blob)
		}
	}
	depth := got["queue_depth"].(map[string]any)
	for _, key := range []string{"derived", "anchor"} {
		if _, ok := depth[key]; !ok {
			t.Errorf("queue_depth has no %q: %s", key, blob)
		}
	}
	buckets := got["bucketed_on"].(map[string]any)
	for _, key := range []string{"submitted", "completed", "removed"} {
		if _, ok := buckets[key]; !ok {
			t.Errorf("bucketed_on has no %q: %s", key, blob)
		}
	}
}
