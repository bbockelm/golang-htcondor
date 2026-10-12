package interactive

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// Review gaps in manager_multiap_test.go: each test here passes on the
// branch and fails on one named mutant of multiap.go / manager*.go.

// lagging makes the catalog know nothing -- a hub that has not yet seen
// any of the caller's sessions.
func (f *fakeAPs) lagging() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.catalog = func() []LocatedAd { return nil }
}

func (f *fakeAPs) setUnreachable(ap string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unreachable[ap] = true
}

// Create asks the AP it is about to submit to even when the catalog has
// not caught up: a session of that name already there is refused.
// Kills: listAll without `also` (the assigned AP).
func TestMultiAPCreateAsksTheAssignedAPDespiteALaggingCatalog(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	aps.injectSession(testAP1, 7, "work")
	aps.lagging()
	mgr, _ := multiManager(t, aps, Options{})

	_, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"})
	var exists *SessionExistsError
	if !errors.As(err, &exists) || exists.Info.Schedd != testAP1 {
		t.Fatalf("Create = %v, want SessionExistsError for the session on %s", err, testAP1)
	}
	if n := len(aps.schedds[testAP1].submittedFiles()); n != 0 {
		t.Errorf("%s got %d submissions, want none", testAP1, n)
	}
}

// Create asks the AP this process's own record names even when the
// catalog has not caught up. Kills: listAll without knownAPs.
func TestMultiAPCreateAsksTheRecordedAPDespiteALaggingCatalog(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	aps.lagging()
	aps.assign(testAP2)
	mgr, _ := multiManager(t, aps, Options{})
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	aps.assign(testAP1)
	_, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"})
	var exists *SessionExistsError
	if !errors.As(err, &exists) || exists.Info.Schedd != testAP2 {
		t.Fatalf("second Create = %v, want SessionExistsError for the session on %s", err, testAP2)
	}
	if n := len(aps.schedds[testAP1].submittedFiles()); n != 0 {
		t.Errorf("%s got %d submissions, want none", testAP1, n)
	}
}

// Stop of a session whose AP cannot be reached fails naming that AP; it
// does not report "stopping" for a job nobody removed. Kills: lookupMulti
// returning a single unreachable match as if reachable.
func TestMultiAPStopOnAnUnreachableAPFails(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	aps.assign(testAP2)
	mgr, _ := multiManager(t, aps, Options{})
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	aps.running(testAP2)
	aps.setUnreachable(testAP2)
	mgr.Close()
	mgr, _ = multiManager(t, aps, Options{})

	info, err := mgr.Stop(context.Background(), alice, "work")
	if err == nil || !strings.Contains(err.Error(), testAP2) {
		t.Fatalf("Stop = %+v, %v; want a failure naming %s", info, err, testAP2)
	}
	for ap, s := range aps.schedds {
		if got := s.removedJobs(); len(got) != 0 {
			t.Errorf("removed on %s: %v", ap, got)
		}
	}
}

// The per-owner limit counts a session on an AP that cannot be reached
// now. Kills: the limit counting only verified sessions.
func TestMultiAPLimitCountsSessionsOnAnUnreachableAP(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	aps.assign(testAP2)
	mgr, _ := multiManager(t, aps, Options{MaxPerOwner: 1})
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "a"}); err != nil {
		t.Fatalf("Create a: %v", err)
	}
	aps.setUnreachable(testAP2)
	aps.assign(testAP1)
	_, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "b"})
	if err == nil || !strings.Contains(err.Error(), "per-user limit") {
		t.Fatalf("Create b = %v, want the per-user limit", err)
	}
	if n := len(aps.schedds[testAP1].submittedFiles()); n != 0 {
		t.Errorf("%s got %d submissions, want none", testAP1, n)
	}
}

// BeforeSubmit (the credential bootstrap) runs against the assigned AP.
// Kills: BeforeSubmit(ctx) instead of BeforeSubmit(submitCtx).
func TestMultiAPBeforeSubmitRunsAgainstTheAssignedAP(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	aps.assign(testAP2)
	var mu sync.Mutex
	var saw []string
	mgr, _ := multiManager(t, aps, Options{BeforeSubmit: func(ctx context.Context) {
		ap, _ := ctx.Value(apKey{}).(string)
		mu.Lock()
		saw = append(saw, ap)
		mu.Unlock()
	}})
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(saw, ",") != testAP2 {
		t.Errorf("BeforeSubmit ran routed to %q, want %s once", saw, testAP2)
	}
}

// A job whose watchdog could not be spooled is removed on the AP it was
// submitted to. Kills: the spool-failure removal sent with no AP.
func TestMultiAPSpoolFailureRemovesOnTheAssignedAP(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	aps.assign(testAP2)
	aps.schedds[testAP2].spoolErr = errors.New("spool refused")
	mgr, _ := multiManager(t, aps, Options{})
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"}); err == nil {
		t.Fatal("Create succeeded with the spool failing")
	}
	if got := aps.schedds[testAP2].removedJobs(); len(got) != 1 || !strings.Contains(got[0], "ClusterId == 200") {
		t.Errorf("removals on %s = %v, want the half-submitted job", testAP2, got)
	}
}

// Another owner's row in the catalog for an AP that cannot be asked is
// not reported as the caller's, and does not take the caller's name.
// (TestMultiAPCatalogRowsAreFilteredAgain cannot fail on this: its AP is
// reachable, so the catalog row is never what is returned.)
// Kills: located() skipping the owner re-filter.
func TestMultiAPOtherOwnersCatalogRowOnAnUnreachableAP(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	ad := classad.New()
	ad.InsertAttr("ClusterId", int64(5))
	ad.InsertAttr("ProcId", int64(0))
	ad.InsertAttr("JobStatus", int64(jobStatusRunning))
	ad.InsertAttrString("Owner", "mallory")
	ad.InsertAttrString("JobBatchName", BatchNameForSession("work"))
	aps.catalog = func() []LocatedAd { return []LocatedAd{{AP: testAP2, Ad: ad}} }
	aps.setUnreachable(testAP2)
	mgr, _ := multiManager(t, aps, Options{})

	infos, err := mgr.List(context.Background(), alice)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(infos) != 0 {
		t.Errorf("List = %+v, want none of mallory's", infos)
	}
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"}); err != nil {
		t.Errorf("Create of a name only mallory uses = %v", err)
	}
}

// A session adopted by a restarted process still expires on its own AP.
// Kills: adopt not recording the session's AP.
func TestMultiAPLeaseExpiryAfterRestartRemovesOnTheSessionsAP(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	aps.assign(testAP2)
	opts := Options{HeartbeatInterval: 10 * time.Millisecond, DefaultLease: 60 * time.Millisecond}
	mgr, _ := multiManager(t, aps, opts)
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	aps.running(testAP2)
	mgr.Close()
	aps.assign(testAP1)
	mgr, _ = multiManager(t, aps, opts)
	if _, err := mgr.Exec(context.Background(), alice, "work", ExecRequest{Command: "true"}); err != nil {
		t.Fatalf("Exec after restart: %v", err)
	}
	waitFor(t, "the adopted session's job to be removed on "+testAP2, 3*time.Second, func() bool {
		return len(aps.schedds[testAP2].removedJobs()) > 0
	})
	if got := aps.schedds[testAP1].removedJobs(); len(got) != 0 {
		t.Errorf("lease expiry removed on %s: %v", testAP1, got)
	}
}
