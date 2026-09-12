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

// The mirror-backed dashboard asks the database three kinds of question
// the unit tests fake: a two-key GROUP BY, a GROUP BY on an attribute
// most rows do not have, and a windowed range read. Faking them proves
// the bucketing arithmetic and nothing about whether the database
// answers the way the arithmetic assumes.
//
// The assumption worth checking is the second one. Only held jobs carry
// HoldReasonCode; an idle job has no such attribute at all. Grouping by
// it therefore asks the database what group a row with no value belongs
// to, and the answer decides whether two thousand idle jobs land under
// "idle" or somewhere else entirely. Nothing in the Go code can settle
// that -- it is a property of the aggregate implementation.

// seedJobs writes a known population into the mirror's jobs table.
// The shape matters more than the size: statuses with and without a
// hold code, two different hold codes, and timestamps inside the
// activity window.
func seedJobs(ctx context.Context, t *testing.T, dbc *dbrpc.Client, owner string) {
	t.Helper()
	now := time.Now().Unix()

	type job struct {
		cluster int
		status  int
		attrs   string
	}
	jobs := []job{
		// Idle and running jobs have no HoldReasonCode attribute at
		// all. This is the case the GROUP BY has to handle.
		{1, 1, ""},
		{2, 1, ""},
		{3, 2, fmt.Sprintf("JobCurrentStartDate = %d\nRemoteHost = \"slot1@ep.example\"", now-120)},
		// Three held for one reason, so the breakdown has a dominant
		// cause to rank first, each with a distinct message.
		{4, 5, fmt.Sprintf("HoldReasonCode = 13\nHoldReason = \"transfer output: /no/such/a\"\nEnteredCurrentStatus = %d", now-60)},
		{5, 5, fmt.Sprintf("HoldReasonCode = 13\nHoldReason = \"transfer output: /no/such/b\"\nEnteredCurrentStatus = %d", now-50)},
		{6, 5, fmt.Sprintf("HoldReasonCode = 13\nHoldReason = \"transfer output: /no/such/c\"\nEnteredCurrentStatus = %d", now-40)},
		// Held only because input is still spooling: a submit in
		// progress, which the tiles must not count as HELD.
		{7, 5, fmt.Sprintf("HoldReasonCode = 16\nHoldReason = \"spooling input data\"\nEnteredCurrentStatus = %d", now-30)},
		{8, 4, fmt.Sprintf("CompletionDate = %d\nExitCode = 0", now-20)},
		// Outside the activity window, and the reason these tests can
		// tell a bounded query from an unbounded one. Without a row the
		// window excludes, dropping the window entirely still passes:
		// every seeded job is recent, so "all of them" and "the recent
		// ones" are the same answer.
		{9, 1, fmt.Sprintf("QDate = %d", now-3*3600)},
		{10, 5, fmt.Sprintf("QDate = %d\nHoldReasonCode = 13\nHoldReason = \"transfer output: /old\"\nEnteredCurrentStatus = %d", now-3*3600, now-3*3600)},
	}

	tx, err := dbc.BeginTable(ctx, "jobs")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	for _, j := range jobs {
		ad := fmt.Sprintf("ClusterId = %d\nProcId = 0\nOwner = %q\nJobStatus = %d\nCmd = \"/bin/sleep\"",
			j.cluster, owner, j.status)
		if !strings.Contains(j.attrs, "QDate") {
			ad += fmt.Sprintf("\nQDate = %d", now-300)
		}
		if j.attrs != "" {
			ad += "\n" + j.attrs
		}
		if err := tx.NewClassAd(ctx, fmt.Sprintf("%d.0", j.cluster), ad); err != nil {
			t.Fatalf("insert %d.0: %v", j.cluster, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// mirrorForDashboard brings up a collector, a mirror and a seeded jobs
// table, and returns a Handler wired to them.
func mirrorForDashboard(ctx context.Context, t *testing.T, owner string, withHistory bool) *Handler {
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
	seedJobs(ctx, t, dbc, owner)
	if withHistory {
		// An ARCHIVE table, zone-mapped on CompletionDate: that is what
		// htcondordb's schedd-sync creates, and it is not
		// interchangeable with a plain table of the same name. Built as
		// a plain table this suite passed while the feature under test
		// errored on every call in production -- the aggregate reaches
		// an archive only through the archive API.
		if err := dbc.CreateArchiveTable(ctx, "history", db.ArchiveConfig{
			ZoneAttrs: []string{"CompletionDate"},
		}); err != nil && !strings.Contains(err.Error(), "exists") {
			t.Fatalf("creating the history archive: %v", err)
		}
		seedHistory(ctx, t, dbc, owner)
	}
	return h
}

// seedHistory writes finished jobs, covering every way the summary has
// to classify one: a clean exit, a bad exit, a fatal signal, and a job
// that left without an outcome at all.
func seedHistory(ctx context.Context, t *testing.T, dbc *dbrpc.Client, owner string) {
	t.Helper()
	now := time.Now().Unix()

	type done struct {
		cluster int
		attrs   string
	}
	rows := []done{
		// Two clean successes, cheap.
		{101, "ExitCode = 0\nExitBySignal = false\nRemoteWallClockTime = 100"},
		{102, "ExitCode = 0\nExitBySignal = false\nRemoteWallClockTime = 200"},
		// A cheap, frequent failure and an expensive, rare one. The
		// ranking must prefer the second.
		{103, "ExitCode = 1\nExitBySignal = false\nRemoteWallClockTime = 5"},
		{104, "ExitCode = 1\nExitBySignal = false\nRemoteWallClockTime = 5"},
		{105, "ExitCode = 127\nExitBySignal = false\nRemoteWallClockTime = 40000"},
		// Killed by a signal. The exit code recorded beside it means
		// nothing.
		{106, "ExitCode = 0\nExitBySignal = true\nExitSignal = 9\nRemoteWallClockTime = 60"},
		// Removed before it finished: no exit code at all. This is the
		// row that must not be counted as a success.
		{107, "RemoteWallClockTime = 30"},
		// Outside the window, so it must not be counted at all.
		{108, "ExitCode = 0\nExitBySignal = false\nRemoteWallClockTime = 999999"},
	}

	// Appended, not transacted: an archive is append-only and has no
	// BeginTable.
	for _, r := range rows {
		completed := now - 60
		if r.cluster == 108 {
			completed = now - 48*3600
		}
		ad := fmt.Sprintf("ClusterId = %d\nProcId = 0\nOwner = %q\nJobStatus = 4\nCompletionDate = %d\n%s",
			r.cluster, owner, completed, r.attrs)
		if err := dbc.ArchiveAppend(ctx, "history", ad); err != nil {
			t.Fatalf("append history %d: %v", r.cluster, err)
		}
	}
}

// TestDashboardFromMirrorCountsRealRows runs the dashboard's own query
// path against a real database holding a known population.
func TestDashboardFromMirrorCountsRealRows(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	const owner = "dashuser"
	h := mirrorForDashboard(ctx, t, owner, false)

	snap, err := h.dashboardFromMirror(ctx, owner, false)
	if err != nil {
		t.Fatalf("dashboardFromMirror: %v", err)
	}

	// The whole point: a job with no HoldReasonCode is still counted,
	// and counted as its status. If the database groups a missing
	// attribute somewhere unexpected, these two are the first to go
	// wrong -- and they would go wrong silently, as a dashboard that
	// says zero idle jobs on an access point full of them.
	want := map[string]int{
		"idle":      3, // two recent, one submitted three hours ago
		"running":   1,
		"held":      4, // three recent, one held three hours ago
		"uploading": 1, // held code 16 is a submit in progress
		"completed": 1,
	}
	for name, n := range want {
		if snap.Counts[name] != n {
			t.Errorf("counts[%q] = %d, want %d (all counts: %v)", name, snap.Counts[name], n, snap.Counts)
		}
	}
	if snap.Total != 10 {
		t.Errorf("total = %d, want 10", snap.Total)
	}
	// Nothing may appear under a bucket the population has none of; a
	// stray key here is the missing-attribute case landing in its own
	// group.
	for name, n := range snap.Counts {
		if _, ok := want[name]; !ok && n != 0 {
			t.Errorf("unexpected bucket %q with %d jobs -- a row grouped somewhere it should not", name, n)
		}
	}
}

// TestDashboardFromMirrorBreaksDownHolds checks the hold panel, which
// needs both the GROUP BY and a follow-up row read for the message.
func TestDashboardFromMirrorBreaksDownHolds(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	const owner = "dashuser"
	h := mirrorForDashboard(ctx, t, owner, false)

	snap, err := h.dashboardFromMirror(ctx, owner, false)
	if err != nil {
		t.Fatalf("dashboardFromMirror: %v", err)
	}

	rows := snap.Activity.HoldReasons
	if len(rows) == 0 {
		t.Fatal("no hold breakdown for a population with four held jobs")
	}
	// Ordered by weight: the dominant cause is the one to act on.
	if rows[0].Code != 13 || rows[0].Count != 4 {
		t.Errorf("first hold row = code %d x%d, want code 13 x4 (all: %+v)", rows[0].Code, rows[0].Count, rows)
	}
	if rows[0].Label == "13" {
		t.Error("hold code 13 rendered as its number, so the label table did not resolve it")
	}
	// The example message is a second query per row. It is what makes
	// the row actionable -- the code says "transfer failed", the
	// message says which file.
	if !strings.Contains(rows[0].Example, "/no/such/") {
		t.Errorf("hold row carries no example message: %q", rows[0].Example)
	}

	total := 0
	for _, r := range rows {
		total += r.Count
	}
	// The breakdown sits beside the HELD tile and has to add up to the
	// held population, spooling included.
	if total != 5 {
		t.Errorf("hold rows sum to %d, want 5: %+v", total, rows)
	}
}

// TestDashboardFromMirrorReadsRecentActivity covers the windowed range
// reads, including the one that must come back newest-first.
func TestDashboardFromMirrorReadsRecentActivity(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	const owner = "dashuser"
	h := mirrorForDashboard(ctx, t, owner, false)

	snap, err := h.dashboardFromMirror(ctx, owner, false)
	if err != nil {
		t.Fatalf("dashboardFromMirror: %v", err)
	}
	act := snap.Activity

	// Eight of the ten were submitted inside the window. The other two
	// are three hours old, and this is the assertion that makes the
	// window load-bearing: it fails if the query drops the lower bound.
	if len(act.RecentlySubmitted) != 8 {
		t.Errorf("recently submitted = %d, want 8 of the 10 seeded (two are outside the hour)", len(act.RecentlySubmitted))
	}
	if len(act.RecentlyStarted) != 1 {
		t.Errorf("recently started = %d, want 1 (only the running job has a start date)", len(act.RecentlyStarted))
	}
	// Five jobs are held; one entered that state three hours ago.
	if len(act.RecentlyHeld) != 4 {
		t.Errorf("recently held = %d, want 4 of the 5 held (one is outside the hour)", len(act.RecentlyHeld))
	}

	// Newest first, which is the ordering the panel promises and which
	// the mutable table cannot push down into the query.
	for i := 1; i < len(act.RecentlyHeld); i++ {
		if act.RecentlyHeld[i-1].At < act.RecentlyHeld[i].At {
			t.Errorf("recently held is not newest-first at %d: %d then %d",
				i, act.RecentlyHeld[i-1].At, act.RecentlyHeld[i].At)
			break
		}
	}
	// The detail is the one fact shown beside the job.
	if len(act.RecentlyStarted) == 1 && !strings.Contains(act.RecentlyStarted[0].Detail, "ep.example") {
		t.Errorf("recently started shows no execute host: %q", act.RecentlyStarted[0].Detail)
	}

	// The queue still holds the completed job, so the list is populated
	// but partial: there is no history table in this database, and
	// saying "available" without one would promise an hour of
	// completions when the queue holds seconds of them.
	if !act.CompletedAvailable {
		t.Error("completed marked unavailable even though the queue holds a completed job")
	}
	if !act.CompletedPartial {
		t.Error("completed not marked partial with no history table present")
	}
}

// TestDashboardFromMirrorScopesToOwner checks the owner filter really
// filters at the database rather than being dropped into a constraint
// the database ignores.
func TestDashboardFromMirrorScopesToOwner(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	const owner = "dashuser"
	h := mirrorForDashboard(ctx, t, owner, false)

	// Scoped to somebody with nothing in the table.
	snap, err := h.dashboardFromMirror(ctx, "nobody-else", true)
	if err != nil {
		t.Fatalf("dashboardFromMirror: %v", err)
	}
	if snap.Total != 0 {
		t.Errorf("a user with no jobs sees %d: the owner scope is not reaching the database (%v)",
			snap.Total, snap.Counts)
	}
	if len(snap.Activity.RecentlySubmitted) != 0 {
		t.Errorf("a user with no jobs sees %d recent submissions", len(snap.Activity.RecentlySubmitted))
	}

	// And the owner who does own them still sees them, so the filter is
	// discriminating rather than simply breaking every query.
	mine, err := h.dashboardFromMirror(ctx, owner, true)
	if err != nil {
		t.Fatalf("dashboardFromMirror(owner): %v", err)
	}
	if mine.Total != 10 {
		t.Errorf("the owner sees %d of their own 10 jobs", mine.Total)
	}
}

// TestDashboardGoodputFromRealHistory is the counterpart to the counts
// test: it asks a real database to group and sum over attributes that
// most rows have and some do not, and checks the classification that
// rides on the answer.
func TestDashboardGoodputFromRealHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	const owner = "dashuser"
	h := mirrorForDashboard(ctx, t, owner, true)

	snap, err := h.dashboardFromMirror(ctx, owner, false)
	if err != nil {
		t.Fatalf("dashboardFromMirror: %v", err)
	}
	gp := snap.Goodput
	if gp == nil {
		t.Fatal("no goodput summary with a history table present")
	}

	if gp.Succeeded != 2 {
		t.Errorf("succeeded = %d, want 2 (the two clean exits inside the window)", gp.Succeeded)
	}
	// Two exit-1, one exit-127, one signalled.
	if gp.Failed != 4 {
		t.Errorf("failed = %d, want 4", gp.Failed)
	}
	// The row with no exit code at all. Counting it as a success is the
	// wrong answer this assertion exists to catch: it has no ExitCode
	// attribute, and a parse that treats absent as zero would call it
	// one.
	if gp.Unfinished != 1 {
		t.Errorf("unfinished = %d, want 1 (the job that left without an outcome)", gp.Unfinished)
	}

	// Wall clock, which is the half that makes the panel worth having.
	if gp.GoodSeconds != 300 {
		t.Errorf("good seconds = %d, want 300", gp.GoodSeconds)
	}
	if gp.BadSeconds != 5+5+40000+60+30 {
		t.Errorf("bad seconds = %d, want %d", gp.BadSeconds, 5+5+40000+60+30)
	}

	// The window. The 999999-second success sits two days back; if it
	// were counted the good total above would be wrong, so this is
	// really asserted twice over.
	if gp.GoodSeconds > 999999 {
		t.Error("a completion outside the window was counted")
	}

	if len(gp.TopFailures) == 0 {
		t.Fatal("failures were counted but none ranked")
	}
	// Ranked by wasted time: one job that burned eleven hours outranks
	// two that failed in five seconds.
	if gp.TopFailures[0].Code != 127 || gp.TopFailures[0].Seconds != 40000 {
		t.Errorf("top failure is %+v, want exit 127 at 40000s", gp.TopFailures[0])
	}
	// And the signalled job is reported as killed rather than as exit 0,
	// which is what its ExitCode attribute literally says.
	sawSignal := false
	for _, f := range gp.TopFailures {
		if f.Signal {
			sawSignal = true
			if f.Count != 1 {
				t.Errorf("signalled row counts %d jobs, want 1", f.Count)
			}
		}
	}
	if !sawSignal {
		t.Error("the job killed by a signal is not in the failure breakdown")
	}
}
