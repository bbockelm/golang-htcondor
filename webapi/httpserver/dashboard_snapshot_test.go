package httpserver

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

func heldAd(cluster, proc, code, at int64, reason string) *classad.ClassAd {
	ad := classad.New()
	ad.InsertAttr("ClusterId", cluster)
	ad.InsertAttr("ProcId", proc)
	ad.InsertAttr("JobStatus", int64(5))
	ad.InsertAttr("HoldReasonCode", code)
	ad.InsertAttr("EnteredCurrentStatus", at)
	ad.InsertAttrString("HoldReason", reason)
	ad.InsertAttrString("Owner", "alice")
	return ad
}

// TestHoldReasonsTurnACountIntoADiagnosis is the point of the panel. An
// access point with ten thousand held jobs looks identical whether that
// is one broken submission or ten thousand unrelated problems; the
// breakdown is what tells them apart.
func TestHoldReasonsTurnACountIntoADiagnosis(t *testing.T) {
	a := newActivityCollector()
	for i := int64(0); i < 900; i++ {
		a.observe(heldAd(42, i, 13, 1000+i, "Transfer input files failure: reading /home/alice/missing.dat"))
	}
	for i := int64(0); i < 12; i++ {
		a.observe(heldAd(43, i, 16, 2000+i, "Spooling input data files"))
	}
	a.observe(heldAd(44, 0, 1, 3000, "via condor_hold (by user alice)"))

	got := a.result(time.Now())
	if len(got.HoldReasons) != 3 {
		t.Fatalf("expected three distinct reasons, got %+v", got.HoldReasons)
	}
	// Ordered by weight: the dominant cause is the one to act on.
	if got.HoldReasons[0].Code != 13 || got.HoldReasons[0].Count != 900 {
		t.Errorf("the dominant cause should lead: %+v", got.HoldReasons[0])
	}
	if got.HoldReasons[0].Label == "" || got.HoldReasons[0].Label == "13" {
		t.Errorf("a bare code makes the operator go and look it up: %q", got.HoldReasons[0].Label)
	}
	// The message says WHICH file; the code only says the category.
	if got.HoldReasons[0].Example == "" {
		t.Error("no example hold message; the code alone does not say which file or host")
	}
}

// TestSpoolingIsNotAFailure: a large submit still uploading is held on
// code 16. Counting that with real failures makes every big submission
// look like an outage while it is working correctly.
func TestSpoolingIsNotAFailure(t *testing.T) {
	if !holdReasonIsRoutine(16) {
		t.Error("spooling input should be classified as routine")
	}
	for _, code := range []int64{13, 1, 3, 34} {
		if holdReasonIsRoutine(code) {
			t.Errorf("code %d is a real hold, not routine", code)
		}
	}
	if label := holdReasonLabel(16); label == "" {
		t.Error("spooling needs a label that says it is not a failure")
	}
}

// TestHoldReasonTailIsSummedNotDropped: the rows sit beside the HELD
// tile, so they have to add up to it. Dropping the tail would make the
// panel quietly disagree with the number next to it.
func TestHoldReasonTailIsSummedNotDropped(t *testing.T) {
	a := newActivityCollector()
	total := 0
	for code := int64(1); code <= 20; code++ {
		for i := int64(0); i < code; i++ {
			a.observe(heldAd(code, i, code, 1000, "reason"))
			total++
		}
	}
	got := a.result(time.Now())
	if len(got.HoldReasons) != topHoldReasons+1 {
		t.Fatalf("expected %d rows plus an 'other', got %d", topHoldReasons, len(got.HoldReasons))
	}
	sum := 0
	for _, r := range got.HoldReasons {
		sum += r.Count
	}
	if sum != total {
		t.Errorf("rows sum to %d but %d jobs are held; the panel would disagree with the tile", sum, total)
	}
}

// TestUnknownHoldCodeSaysTheNumber: an unlabelled code must still be
// searchable. "unknown" is useless; the number is what gets looked up.
func TestUnknownHoldCodeSaysTheNumber(t *testing.T) {
	if got := holdReasonLabel(37); got == "" || got == "unknown" {
		t.Errorf("unlabelled code rendered as %q", got)
	}
	if got := holdReasonLabel(1013); got == "" {
		t.Error("the 1000+ family needs a label too")
	}
	// The eviction family is a different kind of problem from a
	// submission error, and the label should say so even unlabelled.
	if got := holdReasonLabel(1013); got == holdReasonLabel(37) {
		t.Error("an eviction and a submission hold should not read identically")
	}
}

// TestRecentListsKeepTheNewest: the lists exist to show a burst, so they
// have to hold the newest entries regardless of the order jobs arrive in
// during the walk -- the queue is unordered.
func TestRecentListsKeepTheNewest(t *testing.T) {
	a := newActivityCollector()
	// Oldest first, then newest, then middle: the walk has no order.
	for _, at := range []int64{100, 900, 500, 800, 200, 700, 300, 600, 400, 1000, 50} {
		a.observe(heldAd(42, at, 13, at, fmt.Sprintf("held at %d", at)))
	}
	got := a.result(time.Now())
	if len(got.RecentlyHeld) != recentPerList {
		t.Fatalf("kept %d entries, want %d", len(got.RecentlyHeld), recentPerList)
	}
	if got.RecentlyHeld[0].At != 1000 {
		t.Errorf("newest first: got %d", got.RecentlyHeld[0].At)
	}
	for i := 1; i < len(got.RecentlyHeld); i++ {
		if got.RecentlyHeld[i].At > got.RecentlyHeld[i-1].At {
			t.Fatalf("not sorted newest-first at %d: %+v", i, got.RecentlyHeld)
		}
	}
	// 50 is older than the ten kept, so it must have been evicted.
	for _, e := range got.RecentlyHeld {
		if e.At == 50 {
			t.Error("an older entry displaced a newer one")
		}
	}
}

// TestCompletedComesFromTheQueueAndTheArchive. A finished job is
// destroyed from the queue by the reaper, but there is a window before
// that where it sits in JobStatus == 4 -- so the walk catches the last
// few. That is a real answer and the freshest one available, just
// short-sighted, and the archive supplies the rest.
func TestCompletedComesFromTheQueueAndTheArchive(t *testing.T) {
	a := newActivityCollector()
	done := classad.New()
	done.InsertAttr("ClusterId", int64(42))
	done.InsertAttr("ProcId", int64(0))
	done.InsertAttr("JobStatus", int64(4))
	done.InsertAttr("CompletionDate", int64(5000))
	done.InsertAttr("ExitCode", int64(0))
	done.InsertAttrString("Owner", "alice")
	a.observe(done)

	got := a.result(time.Now())
	if !got.CompletedAvailable || len(got.RecentlyCompleted) != 1 {
		t.Fatalf("a job caught before the reaper should be reported: %+v", got.RecentlyCompleted)
	}
	if !got.CompletedPartial {
		t.Error("queue-only covers the last seconds, not the last hour; it must say so")
	}

	// The archive fills in what the reaper already took, and wins the
	// deduplication because it carries the outcome.
	got.mergeArchivedCompletions([]RecentJob{
		{ClusterID: 42, ProcID: 0, At: 5000, Detail: "exit 0"},
		{ClusterID: 41, ProcID: 7, At: 4000, Detail: "exit 1"},
		{ClusterID: 40, ProcID: 0, At: 6000, Detail: "killed by a signal"},
	})
	if got.CompletedPartial {
		t.Error("with the archive merged it is no longer just what the queue held")
	}
	if len(got.RecentlyCompleted) != 3 {
		t.Fatalf("the overlapping job should appear once, not twice: %+v", got.RecentlyCompleted)
	}
	if got.RecentlyCompleted[0].At != 6000 {
		t.Errorf("merged list is not newest-first: %+v", got.RecentlyCompleted)
	}
}

// TestNoCompletionsAnywhereIsReportedHonestly: with nothing in the queue
// and no archive, the list is unavailable rather than empty. An empty
// list reads as "nothing finished", which on a busy access point is the
// opposite of the truth.
func TestNoCompletionsAnywhereIsReportedHonestly(t *testing.T) {
	got := newActivityCollector().result(time.Now())
	if got.CompletedAvailable {
		t.Error("nothing could answer; the panel must not claim it did")
	}
	if len(got.RecentlyCompleted) != 0 {
		t.Error("no completions should be invented")
	}
	// An archive that returns nothing is still an answer: it means
	// nothing finished, which is different from not knowing.
	got.mergeArchivedCompletions(nil)
	if got.CompletedAvailable {
		t.Error("an empty archive result should not flip availability on its own")
	}
}

// TestSnapshotsAreNeverSharedAcrossOwners is the property that matters
// most here, and the one the cost test below does NOT cover.
//
// Most viewers are scoped to their own jobs, so each owner has their own
// cache key and their own walk -- sharing is the exception, not the
// rule. The danger in a shared cache is not a wasted query, it is
// serving alice's snapshot to bob: the counts, the hold messages and the
// recent job ids are all hers, and nothing downstream would notice.
func TestSnapshotsAreNeverSharedAcrossOwners(t *testing.T) {
	c := newDashboardCache()
	now := time.Now()
	c.now = func() time.Time { return now }

	snapshotFor := func(owner string) *dashboardSnapshot {
		t.Helper()
		got, err := c.get("mine:"+owner, func() (*dashboardSnapshot, error) {
			return &dashboardSnapshot{
				Counts: map[string]int{"idle": 1},
				Total:  len(owner), // a value only this owner's walk produces
				Activity: DashboardActivity{
					RecentlyHeld: []RecentJob{{ClusterID: 1, Owner: owner, At: 1}},
				},
			}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	alice := snapshotFor("alice")
	bob := snapshotFor("bob")

	if bob.Total == alice.Total {
		t.Fatalf("bob was served alice's snapshot (total=%d)", bob.Total)
	}
	if got := bob.Activity.RecentlyHeld[0].Owner; got != "bob" {
		t.Errorf("bob's recent activity names %q; one user's jobs leaked into another's dashboard", got)
	}
	// And alice keeps hers -- bob's walk must not have overwritten it.
	if again := snapshotFor("alice"); again.Activity.RecentlyHeld[0].Owner != "alice" {
		t.Error("alice's snapshot was replaced by bob's")
	}
}

// TestHandlerKeysTheCacheByOwner checks the key the HANDLER builds, not
// just the cache's behaviour given distinct keys. The leak, if it
// happened, would be an owner missing from the key here -- the cache
// itself is only as isolated as what it is asked for.
func TestHandlerKeysTheCacheByOwner(t *testing.T) {
	alice := dashboardCacheKey("alice", true)
	bob := dashboardCacheKey("bob", true)
	if alice == bob {
		t.Fatalf("alice and bob share the cache key %q; one would be served the other's jobs", alice)
	}
	if pool := dashboardCacheKey("alice", false); pool == alice {
		t.Error("the pool-wide view must not share a key with an owner-scoped one")
	}
	// Two admins on the pool-wide view genuinely do share.
	if dashboardCacheKey("alice", false) != dashboardCacheKey("bob", false) {
		t.Error("the pool-wide view is the same answer for everyone; it should share one walk")
	}
}

// TestRepeatedLoadsShareOneWalk is the cost property, and it applies
// PER SCOPE rather than per deployment: an owner-scoped viewer shares a
// snapshot only with themselves reloading, while everyone on the admin
// pool-wide view shares one. That still removes the old behaviour --
// a full walk on every open of the page -- which is what it is for.
func TestRepeatedLoadsShareOneWalk(t *testing.T) {
	c := newDashboardCache()
	now := time.Now()
	c.now = func() time.Time { return now }

	walks := 0
	compute := func() (*dashboardSnapshot, error) {
		walks++
		return &dashboardSnapshot{Total: walks}, nil
	}
	for i := 0; i < 25; i++ {
		if _, err := c.get("mine:alice", compute); err != nil {
			t.Fatal(err)
		}
	}
	if walks != 1 {
		t.Errorf("25 reloads by one viewer caused %d walks, want 1", walks)
	}

	// A second owner is a second walk, by design -- see
	// TestSnapshotsAreNeverSharedAcrossOwners. That walk is bounded by
	// that owner's own jobs, because the query carries FetchMyJobs.
	if _, err := c.get("mine:bob", compute); err != nil {
		t.Fatal(err)
	}
	if walks != 2 {
		t.Errorf("a second owner should get their own walk (walks=%d)", walks)
	}

	// The admin pool-wide scope is the one many viewers genuinely share.
	for i := 0; i < 10; i++ {
		if _, err := c.get("all", compute); err != nil {
			t.Fatal(err)
		}
	}
	if walks != 3 {
		t.Errorf("ten admins on the pool-wide view should share one walk (walks=%d)", walks)
	}

	now = now.Add(dashboardRefresh + time.Second)
	if _, err := c.get("mine:alice", compute); err != nil {
		t.Fatal(err)
	}
	if walks != 4 {
		t.Errorf("the snapshot never refreshed (walks=%d)", walks)
	}
}

// TestFailedRefreshKeepsTheLastGoodAnswer: a dashboard that blanks when
// the schedd hiccups is worse than one saying it is three minutes old.
func TestFailedRefreshKeepsTheLastGoodAnswer(t *testing.T) {
	c := newDashboardCache()
	now := time.Now()
	c.now = func() time.Time { return now }

	if _, err := c.get("k", func() (*dashboardSnapshot, error) {
		return &dashboardSnapshot{Total: 7}, nil
	}); err != nil {
		t.Fatal(err)
	}

	now = now.Add(dashboardRefresh + time.Second)
	got, err := c.get("k", func() (*dashboardSnapshot, error) {
		return nil, errors.New("schedd unreachable")
	})
	if err != nil {
		t.Fatalf("a failed refresh should fall back, not fail: %v", err)
	}
	if got.Total != 7 {
		t.Errorf("lost the last good snapshot: %+v", got)
	}

	// With nothing cached at all, the error is the honest answer.
	if _, err := c.get("fresh", func() (*dashboardSnapshot, error) {
		return nil, errors.New("schedd unreachable")
	}); err == nil {
		t.Error("with no prior snapshot the failure must surface")
	}
}

// TestBothSourcesFoldTheHoldTailTheSameWay. The breakdown sits beside
// the HELD tile and has to add up to it whichever source answered. A
// rule that drifted between the mirror and the schedd would make the
// panel disagree with itself depending on which was reachable -- and
// that disagreement would look like a data problem, not a code one.
func TestBothSourcesFoldTheHoldTailTheSameWay(t *testing.T) {
	// Built the way the mirror path builds them: counts from a GROUP BY,
	// no example messages yet.
	var fromMirror []HoldReasonCount
	// And the same population through the collector, the way a queue
	// walk builds it.
	fromWalk := newActivityCollector()

	total := 0
	for code := int64(1); code <= 20; code++ {
		fromMirror = append(fromMirror, HoldReasonCount{
			Code: code, Label: holdReasonLabel(code), Count: int(code),
		})
		for i := int64(0); i < code; i++ {
			fromWalk.observe(heldAd(code, i, code, 1000, "reason"))
			total++
		}
	}

	mirrorRows := topHoldReasonRows(fromMirror)
	walkRows := fromWalk.result(time.Now()).HoldReasons

	if len(mirrorRows) != len(walkRows) {
		t.Fatalf("row counts differ by source: mirror %d, walk %d", len(mirrorRows), len(walkRows))
	}
	sum := 0
	for i := range mirrorRows {
		if mirrorRows[i].Code != walkRows[i].Code || mirrorRows[i].Count != walkRows[i].Count {
			t.Errorf("row %d differs by source: mirror %+v, walk %+v", i, mirrorRows[i], walkRows[i])
		}
		sum += mirrorRows[i].Count
	}
	if sum != total {
		t.Errorf("rows sum to %d but %d jobs are held", sum, total)
	}
}

// TestNewestFirstTrims is the shared ordering both sources rely on: the
// mirror over-fetches a window because a mutable table has no ordering
// to push a limit into, and the walk collects in queue order, which is
// no order at all.
func TestNewestFirstTrims(t *testing.T) {
	var jobs []RecentJob
	for at := int64(1); at <= 30; at++ {
		jobs = append(jobs, RecentJob{ClusterID: at, At: at})
	}
	got := newestFirst(jobs, recentPerList)
	if len(got) != recentPerList {
		t.Fatalf("kept %d, want %d", len(got), recentPerList)
	}
	if got[0].At != 30 {
		t.Errorf("newest first: got %d", got[0].At)
	}
	if got[len(got)-1].At != 30-int64(recentPerList)+1 {
		t.Errorf("trimmed the wrong end: %+v", got)
	}
}
