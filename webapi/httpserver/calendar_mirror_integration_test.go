//go:build integration

package httpserver

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/db"
	"github.com/PelicanPlatform/classad/dbrpc"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// The calendar asks a real database three things the unit tests cannot
// check by construction:
//
//   - whether a bucketed GROUP BY on EnteredHistoryTime actually counts
//     a REMOVED job. That is the whole premise: a removed record has no
//     CompletionDate attribute at all, and the question of what the
//     aggregate does with a record missing the attribute next to the one
//     it groups on is a property of the aggregate, not of the Go code.
//   - whether windowing on EnteredHistoryTime while bucketing on QDate
//     works at all. Window and bucket on different attributes of the
//     same record is an unusual shape, and nothing in Go settles whether
//     the engine honours it.
//   - whether the live table and the archive sum to a coherent
//     submitted series across the two APIs.
//
// The archive here is built as an ARCHIVE table zone-mapped the way
// htcondordb's schedd-sync builds it. A plain table of the same name is
// not interchangeable: the archive aggregate reaches one only through
// the archive API, and a suite built on a plain table passed while the
// feature errored on every call in production.

const calendarTestOwner = "caluser"
const calendarTestOther = "otheruser"

// calDay is the start of the bucket n days before today, UTC.
func calDay(now time.Time, n int) int64 {
	return (now.Unix()/86400)*86400 - int64(n)*86400
}

// seedCalendarHistory writes a known population into the history
// archive. The shape is the point: completions and removals on the same
// day, a day with nothing at all, a job whose submit day differs from
// its history day, a record outside the window, and another owner's.
func seedCalendarHistory(ctx context.Context, t *testing.T, dbc *dbrpc.Client, now time.Time) {
	t.Helper()
	d := func(n int) int64 { return calDay(now, n) }

	type rec struct {
		owner  string
		status int
		eht    int64
		qdate  int64
		// completion is 0 for a removed job, which carries no
		// CompletionDate at all -- the reason the window and the bucket
		// are on EnteredHistoryTime.
		completion int64
	}
	recs := []rec{
		// Three finished on day 3. The third was submitted on day 4, so
		// it counts as submitted then and completed on day 3.
		{calendarTestOwner, 4, d(3) + 3600, d(3) + 100, d(3) + 3000},
		{calendarTestOwner, 4, d(3) + 3700, d(3) + 100, d(3) + 3000},
		{calendarTestOwner, 4, d(3) + 3800, d(4) + 100, d(3) + 3000},
		// Two removed on day 3, with no CompletionDate. These are the
		// rows the whole design turns on.
		{calendarTestOwner, 3, d(3) + 4000, d(3) + 200, 0},
		{calendarTestOwner, 3, d(3) + 4100, d(3) + 200, 0},
		// Day 2 gets no history record of its own, so the response has
		// to carry its completions and removals as zeros.
		// One of each on day 1.
		{calendarTestOwner, 4, d(1) + 100, d(1) + 50, d(1) + 90},
		{calendarTestOwner, 3, d(1) + 200, d(1) + 50, 0},
		// The midnight straddler: CompletionDate says 23:53 on day 2,
		// EnteredHistoryTime says five minutes later, on day 1. The two
		// normally agree to the second; they come apart when the
		// terminal transition and the completion fall either side of
		// midnight, or when the stamp came from the ingest clock after a
		// backlog drain. It belongs to day 1 here, because that is the
		// day this buckets on -- and a drill-down that asked day 1 for a
		// CompletionDate would not find it, which is the disagreement
		// bucketed_on exists to prevent. Submitted on day 2, so it also
		// pins that the submit day and the history day are read
		// independently.
		{calendarTestOwner, 4, d(1) + 300, d(2) + 100, d(2) + 86000},
		// One finished today.
		{calendarTestOwner, 4, d(0) + 60, d(0) + 10, d(0) + 50},
		// Outside the window. Without it, dropping the window entirely
		// would still pass -- and it is also what the archive-reach
		// probe finds, which is how the response knows the window is
		// covered rather than merely empty at its start.
		{calendarTestOwner, 4, d(10) + 100, d(10) + 50, d(10) + 90},
		// Another owner, inside the window. The owner scope is the only
		// thing keeping this out of caluser's chart.
		{calendarTestOther, 4, d(3) + 3600, d(3) + 100, d(3) + 3000},
	}

	// Appended, not transacted: an archive is append-only.
	for i, r := range recs {
		ad := fmt.Sprintf("ClusterId = %d\nProcId = 0\nOwner = %q\nJobStatus = %d\nQDate = %d\nEnteredHistoryTime = %d\nRemoteWallClockTime = 60",
			1000+i, r.owner, r.status, r.qdate, r.eht)
		if r.completion > 0 {
			ad += fmt.Sprintf("\nCompletionDate = %d\nExitCode = 0\nExitBySignal = false", r.completion)
		}
		if err := dbc.ArchiveAppend(ctx, "history", ad); err != nil {
			t.Fatalf("append history %d: %v", 1000+i, err)
		}
	}
}

// seedCalendarQueue writes the live queue: work submitted inside the
// window that has not finished, plus a job older than the window (which
// counts towards the anchor but towards no day) and another owner's.
func seedCalendarQueue(ctx context.Context, t *testing.T, dbc *dbrpc.Client, now time.Time) {
	t.Helper()
	d := func(n int) int64 { return calDay(now, n) }

	type live struct {
		owner  string
		status int
		qdate  int64
	}
	jobs := []live{
		{calendarTestOwner, 1, d(1) + 500},
		{calendarTestOwner, 1, d(1) + 600},
		{calendarTestOwner, 2, d(0) + 700},
		// Submitted before the window: in the queue, so in the anchor,
		// but on no day of the chart.
		{calendarTestOwner, 1, d(20) + 100},
		// Another owner's, which must reach neither the days nor the
		// anchor.
		{calendarTestOther, 1, d(1) + 800},
	}

	tx, err := dbc.BeginTable(ctx, "jobs")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	for i, j := range jobs {
		ad := fmt.Sprintf("ClusterId = %d\nProcId = 0\nOwner = %q\nJobStatus = %d\nQDate = %d\nCmd = \"/bin/sleep\"",
			2000+i, j.owner, j.status, j.qdate)
		if err := tx.NewClassAd(ctx, fmt.Sprintf("%d.0", 2000+i), ad); err != nil {
			t.Fatalf("insert %d.0: %v", 2000+i, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// mirrorForCalendar brings up a collector, a mirror, a seeded history
// archive and a seeded jobs table, and returns a Handler wired to them.
func mirrorForCalendar(ctx context.Context, t *testing.T, now time.Time) *Handler {
	t.Helper()
	bin := htcondordbBinary(t)
	harness := htcondor.SetupCondorHarnessWithConfig(t, "DAEMON_LIST = MASTER, COLLECTOR\n")
	startMirror(t, harness, bin, t.TempDir())

	cfg := config.NewEmpty()
	cfg.Set("SEC_DEFAULT_AUTHENTICATION_METHODS", "FS")
	cfg.Set("SEC_CLIENT_AUTHENTICATION_METHODS", "FS")
	cfg.Set("UID_DOMAIN", harness.GetTrustDomain())
	cfg.Set("TRUST_DOMAIN", harness.GetTrustDomain())

	h := &Handler{
		dbMirror: dbmirror.NewLocator(htcondor.NewCollector(harness.GetCollectorAddr()), cfg),
		logger:   testLogger(t),
	}

	waitFor(t, "the mirror to accept a connection", 45*time.Second, func() bool {
		dbc, closer, _, err := h.dbMirror.Client(ctx)
		if err != nil {
			return false
		}
		defer closer()
		cerr := dbc.CreateTable(ctx, "jobs")
		return cerr == nil || strings.Contains(cerr.Error(), "exists")
	})

	dbc, closer, _, err := h.dbMirror.Client(ctx)
	if err != nil {
		t.Fatalf("connecting to seed: %v", err)
	}
	defer closer()

	// Zone-mapped exactly as htcondordb's schedd-sync makes it: both the
	// completion time and the ingest time, so a window on either prunes.
	if err := dbc.CreateArchiveTable(ctx, "history", db.ArchiveConfig{
		ZoneAttrs: []string{"CompletionDate", "EnteredHistoryTime"},
	}); err != nil && !strings.Contains(err.Error(), "exists") {
		t.Fatalf("creating the history archive: %v", err)
	}
	seedCalendarHistory(ctx, t, dbc, now)
	seedCalendarQueue(ctx, t, dbc, now)
	return h
}

// TestCalendarFromMirrorCountsRealDays runs the calendar's own query
// path against a real database holding a known population.
func TestCalendarFromMirrorCountsRealDays(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	now := time.Now()
	h := mirrorForCalendar(ctx, t, now)

	resp, err := h.calendarFromMirror(ctx, calendarTestOwner, true, 5)
	if err != nil {
		t.Fatalf("calendarFromMirror: %v", err)
	}
	if !resp.Enabled || resp.WindowDays != 5 {
		t.Fatalf("enabled=%v window_days=%d, want true/5", resp.Enabled, resp.WindowDays)
	}
	if len(resp.Days) != 5 {
		t.Fatalf("got %d days, want 5: %+v", len(resp.Days), resp.Days)
	}

	// Ascending, day-aligned, contiguous. A panel plots these in order
	// and in place, so a gap or a repeat is a wrong chart.
	for i, d := range resp.Days {
		if want := calDay(now, 4-i); d.Day != want {
			t.Errorf("days[%d].Day = %d, want %d", i, d.Day, want)
		}
	}

	// Index by days-ago so the expectations read like the fixture.
	byAgo := map[int]CalendarDay{}
	for i, d := range resp.Days {
		byAgo[4-i] = d
	}
	want := map[int]CalendarDay{
		// One job was submitted on day 4 and finished on day 3, which is
		// the case that proves window and bucket are on different
		// attributes: it is counted as submitted here, with nothing else.
		4: {Submitted: 1},
		// Three finished and two removed; four of the five were also
		// submitted that day (the third completion was submitted on day 4).
		3: {Submitted: 4, Completed: 3, Removed: 2},
		// Nothing finished or was removed, and the row still has to
		// exist: a gap and a zero are different facts and the panel must
		// be able to tell them apart. The one submission is the midnight
		// straddler, whose completion lands on day 1.
		2: {Submitted: 1},
		// One finished, one removed, two still in the queue -- plus the
		// straddler, ingested at 00:05 and so counted here rather than on
		// the day it completed.
		1: {Submitted: 4, Completed: 2, Removed: 1},
		// One finished, and one still running, submitted today.
		0: {Submitted: 2, Completed: 1},
	}
	for ago, w := range want {
		got := byAgo[ago]
		if got.Submitted != w.Submitted || got.Completed != w.Completed || got.Removed != w.Removed {
			t.Errorf("%d days ago: submitted=%d completed=%d removed=%d, want %d/%d/%d",
				ago, got.Submitted, got.Completed, got.Removed, w.Submitted, w.Completed, w.Removed)
		}
	}

	// The claim the whole design rests on, stated as its own failure:
	// three of the five records on day 3 carry a CompletionDate and two
	// do not. Bucketing on CompletionDate would have counted the three
	// and silently dropped the two.
	if byAgo[3].Removed != 2 {
		t.Errorf("day 3 shows %d removals, want 2 -- a removed job has no CompletionDate, "+
			"so this is what a window or bucket on CompletionDate drops", byAgo[3].Removed)
	}

	// The straddler, stated as its own failure. A job that completed at
	// 23:53 on day 2 and entered history at 00:05 on day 1 is counted on
	// day 1, because EnteredHistoryTime is what the series buckets on --
	// and bucketed_on says so, so a drill-down selects the same set
	// rather than asking day 1 for a CompletionDate it does not have.
	if byAgo[1].Completed != 2 || byAgo[2].Completed != 0 {
		t.Errorf("the midnight straddler landed on the wrong day: completions day 1 = %d (want 2), day 2 = %d (want 0)",
			byAgo[1].Completed, byAgo[2].Completed)
	}
	if resp.BucketedOn == nil || resp.BucketedOn.Completed != "EnteredHistoryTime" {
		t.Errorf("bucketed_on.completed = %+v, want EnteredHistoryTime -- "+
			"a drill-down built on anything else selects a different set", resp.BucketedOn)
	}
	if resp.BucketedOn != nil && resp.BucketedOn.Submitted != "QDate" {
		t.Errorf("bucketed_on.submitted = %q, want QDate", resp.BucketedOn.Submitted)
	}

	// step is what a panel spaces its axis by, and the days have to be
	// that far apart or every figure is mislaid.
	if resp.Step != 86400 {
		t.Errorf("step = %d, want 86400", resp.Step)
	}
	for i := 1; i < len(resp.Days); i++ {
		if got := resp.Days[i].Day - resp.Days[i-1].Day; got != resp.Step {
			t.Errorf("days[%d] is %d seconds after days[%d], but step says %d", i, got, i-1, resp.Step)
		}
	}
	// UTC-midnight aligned, which is what lets a panel label them in UTC
	// and get whole days. The engine floors a bucket to
	// floor(v/width)*width, so this is epoch alignment, not a convention
	// this code applies.
	for i, d := range resp.Days {
		if d.Day%86400 != 0 {
			t.Errorf("days[%d].Day = %d is not a UTC midnight", i, d.Day)
		}
	}

	// Another owner's finished job is in the same bucket as caluser's
	// three, and must not be in them.
	if byAgo[3].Completed != 3 {
		t.Errorf("day 3 shows %d completions, want 3 -- %q's job leaked into %q's chart",
			byAgo[3].Completed, calendarTestOther, calendarTestOwner)
	}

	// The window is covered: the fixture holds a record from ten days
	// ago, which the reach probe finds.
	if resp.Partial {
		t.Errorf("reported partial over a covered window: %q", resp.Note)
	}
}

// TestCalendarFromMirrorDerivesQueueDepth checks the in_queue series
// against the real live count rather than a fake anchor.
func TestCalendarFromMirrorDerivesQueueDepth(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	now := time.Now()
	h := mirrorForCalendar(ctx, t, now)

	resp, err := h.calendarFromMirror(ctx, calendarTestOwner, true, 5)
	if err != nil {
		t.Fatalf("calendarFromMirror: %v", err)
	}
	if resp.QueueDepth == nil {
		t.Fatalf("no queue_depth block: %q", resp.Note)
	}
	if !resp.QueueDepth.Derived {
		t.Error("queue_depth does not say it is derived, which is the one thing a reader needs to know about it")
	}
	// Four of caluser's jobs are in the queue; the fifth live job is
	// another owner's and must not be counted.
	if resp.QueueDepth.Anchor != 4 {
		t.Errorf("anchor = %d, want 4 (caluser's live jobs, not %q's)", resp.QueueDepth.Anchor, calendarTestOther)
	}
	// Today's row IS the anchor -- the only measured value in the series.
	if last := resp.Days[len(resp.Days)-1]; last.InQueue != resp.QueueDepth.Anchor {
		t.Errorf("today's in_queue = %d, want the anchor %d", last.InQueue, resp.QueueDepth.Anchor)
	}
	// Walked back through the flows this fixture produces:
	//   d0 = 4 (anchor)
	//   d1 = 4 - 2 + 1 + 0 = 3
	//   d2 = 3 - 4 + 2 + 1 = 2
	//   d3 = 2 - 1 + 0 + 0 = 1
	//   d4 = 1 - 4 + 3 + 2 = 2
	wantDepth := []int{2, 1, 2, 3, 4}
	for i, w := range wantDepth {
		if resp.Days[i].InQueue != w {
			t.Errorf("days[%d] (%d days ago) in_queue = %d, want %d (series: %+v)",
				i, 4-i, resp.Days[i].InQueue, w, resp.Days)
		}
	}
}

// TestCalendarFromMirrorReportsAShortArchive covers the other branch of
// the archive-reach probe, on an owner whose history starts inside the
// window. Days before their first record are unknown rather than empty,
// and saying so is the difference between "you ran nothing" and "we
// cannot tell".
func TestCalendarFromMirrorReportsAShortArchive(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	now := time.Now()
	h := mirrorForCalendar(ctx, t, now)

	// otheruser has exactly one history record, three days ago, and
	// nothing before it.
	resp, err := h.calendarFromMirror(ctx, calendarTestOther, true, 5)
	if err != nil {
		t.Fatalf("calendarFromMirror: %v", err)
	}
	if !resp.Partial {
		t.Error("an archive that starts inside the window was not reported partial")
	}
	if !strings.Contains(resp.Note, "no record from before") {
		t.Errorf("the note does not say how far the archive reaches: %q", resp.Note)
	}
	if len(resp.Days) != 5 {
		t.Errorf("a partial answer dropped days: %d, want 5", len(resp.Days))
	}
	// Partial is not empty: the one record is still counted.
	total := 0
	for _, d := range resp.Days {
		total += d.Completed
	}
	if total != 1 {
		t.Errorf("otheruser's completions = %d, want 1", total)
	}
}
