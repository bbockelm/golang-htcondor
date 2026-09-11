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

	got := a.result("schedd", time.Now())
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
	got := a.result("schedd", time.Now())
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
	got := a.result("schedd", time.Now())
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

// TestCompletedIsAbsentNotEmpty. A finished job is destroyed from the
// queue, so a queue walk cannot see one however recent. An empty list
// would read as "nothing finished", which on a busy access point is the
// opposite of the truth.
func TestCompletedIsAbsentNotEmpty(t *testing.T) {
	got := newActivityCollector().result("schedd", time.Now())
	if got.CompletedAvailable {
		t.Error("the schedd path cannot answer 'recently completed'; it must not claim to")
	}
	if len(got.RecentlyCompleted) != 0 {
		t.Error("no completed entries should be invented from a queue walk")
	}
}

// TestOneWalkServesEveryViewer is the cost property. The dashboard's
// queue walk is the most expensive thing the access point is asked for,
// and it used to happen on every page load.
func TestOneWalkServesEveryViewer(t *testing.T) {
	c := newDashboardCache()
	now := time.Now()
	c.now = func() time.Time { return now }

	walks := 0
	compute := func() (*dashboardSnapshot, error) {
		walks++
		return &dashboardSnapshot{Total: walks}, nil
	}
	for i := 0; i < 25; i++ {
		if _, err := c.get("mine:alice", dashboardRefresh, compute); err != nil {
			t.Fatal(err)
		}
	}
	if walks != 1 {
		t.Errorf("25 page loads caused %d queue walks, want 1", walks)
	}

	// A different scope is a different answer, so it gets its own walk.
	if _, err := c.get("all", dashboardRefresh, compute); err != nil {
		t.Fatal(err)
	}
	if walks != 2 {
		t.Errorf("the pool-wide scope should not be served the owner-scoped snapshot (walks=%d)", walks)
	}

	// And it does refresh, once the interval has passed.
	now = now.Add(dashboardRefresh + time.Second)
	if _, err := c.get("mine:alice", dashboardRefresh, compute); err != nil {
		t.Fatal(err)
	}
	if walks != 3 {
		t.Errorf("the snapshot never refreshed (walks=%d)", walks)
	}
}

// TestFailedRefreshKeepsTheLastGoodAnswer: a dashboard that blanks when
// the schedd hiccups is worse than one saying it is three minutes old.
func TestFailedRefreshKeepsTheLastGoodAnswer(t *testing.T) {
	c := newDashboardCache()
	now := time.Now()
	c.now = func() time.Time { return now }

	if _, err := c.get("k", dashboardRefresh, func() (*dashboardSnapshot, error) {
		return &dashboardSnapshot{Total: 7}, nil
	}); err != nil {
		t.Fatal(err)
	}

	now = now.Add(dashboardRefresh + time.Second)
	got, err := c.get("k", dashboardRefresh, func() (*dashboardSnapshot, error) {
		return nil, errors.New("schedd unreachable")
	})
	if err != nil {
		t.Fatalf("a failed refresh should fall back, not fail: %v", err)
	}
	if got.Total != 7 {
		t.Errorf("lost the last good snapshot: %+v", got)
	}

	// With nothing cached at all, the error is the honest answer.
	if _, err := c.get("fresh", dashboardRefresh, func() (*dashboardSnapshot, error) {
		return nil, errors.New("schedd unreachable")
	}); err == nil {
		t.Error("with no prior snapshot the failure must surface")
	}
}
