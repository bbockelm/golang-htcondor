package jobwatch

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// recorder counts per-owner checks and signals each one, so a test can
// wait for the nudge instead of sleeping for it.
type recorder struct {
	mu     sync.Mutex
	counts map[string]int
	calls  chan string
	err    error
}

func newRecorder() *recorder {
	return &recorder{counts: map[string]int{}, calls: make(chan string, 64)}
}

func (r *recorder) check(_ context.Context, owner string) (int, error) {
	r.mu.Lock()
	r.counts[owner]++
	err := r.err
	r.mu.Unlock()
	r.calls <- owner
	return 0, err
}

func (r *recorder) count(owner string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts[owner]
}

// waitCall waits for one check to happen, failing rather than hanging.
func (r *recorder) waitCall(t *testing.T) string {
	t.Helper()
	select {
	case owner := <-r.calls:
		return owner
	case <-time.After(5 * time.Second):
		t.Fatal("no evaluation was nudged")
		return ""
	}
}

// nudgerFixture runs a nudger against a live feed with a short delay, so
// the test exercises the real subscription rather than a stub of it.
func nudgerFixture(t *testing.T) (*Feed, *recorder, *Nudger) {
	t.Helper()
	f := NewFeed(nil)
	rec := newRecorder()
	n := NewNudger(f, rec.check, nil)
	n.Delay = 10 * time.Millisecond
	n.MinGap = 0

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); n.Run(ctx) }()
	// Run subscribes inside the goroutine, and an event published before
	// that happens is simply not seen -- harmless in production, where
	// the sweep covers it, but it would make these tests flaky. Wait for
	// the subscription to exist rather than racing it.
	waitSubscribed(t, f)
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the nudger did not stop when its context was cancelled")
		}
	})
	return f, rec, n
}

// waitSubscribed blocks until the nudger's subscription is registered.
func waitSubscribed(t *testing.T, f *Feed) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := len(f.activitySubs)
		f.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the nudger never subscribed to the activity stream")
}

// The point of the whole thing: a job starting on the change stream must
// re-evaluate that owner's watches, rather than leaving them until the
// 30-second sweep -- by which time a short job has already finished and
// the running state can no longer be sampled.
func TestAJobStartingNudgesItsOwner(t *testing.T) {
	f, rec, _ := nudgerFixture(t)

	// Known idle first, so the next upsert is a transition rather than a
	// first sighting.
	applyUpsert(f, "1.0", jobAd(1, "alice", 1, fmt.Sprintf("QDate = %d", time.Now().Add(-time.Hour).Unix())))
	applyUpsert(f, "1.0", jobAd(1, "alice", 2, `RemoteHost = "slot1@ep.example"`))

	if owner := rec.waitCall(t); owner != "alice" {
		t.Errorf("nudged %q, want alice", owner)
	}
}

// Ten thousand jobs starting is one submission, not ten thousand reasons
// to read the queue. Each sweep reads the owner's whole queue, so an
// un-coalesced nudge would turn a busy submission into a self-inflicted
// load test.
func TestABurstCollapsesToOneSweep(t *testing.T) {
	f, rec, n := nudgerFixture(t)

	const jobs = 200
	start := time.Now()
	qdate := fmt.Sprintf("QDate = %d", time.Now().Add(-time.Hour).Unix())
	for i := 0; i < jobs; i++ {
		key := fmt.Sprintf("1.%d", i)
		applyUpsert(f, key, jobAd(1, "alice", 1, qdate))
		applyUpsert(f, key, jobAd(1, "alice", 2, `RemoteHost = "slot1@ep.example"`))
	}
	rec.waitCall(t)
	// Let several more ticks pass; a coalescing nudger has nothing left
	// to do with them.
	time.Sleep(5 * n.Delay)

	// The guarantee is one sweep per Delay window, not a fixed number:
	// how many windows the burst spans depends on the machine, and
	// asserting a count instead of the rate is what makes a test like
	// this fail on a busy CI runner for no reason.
	got := rec.count("alice")
	limit := int(time.Since(start)/n.Delay) + 2
	if got > limit {
		t.Errorf("%d job starts caused %d sweeps in %s, more than the %d that %s windows allow",
			jobs, got, time.Since(start), limit, n.Delay)
	}
	if got >= jobs {
		t.Errorf("%d sweeps for %d jobs: the burst did not coalesce at all", got, jobs)
	}
}

// Coalescing must not merge owners together: alice's jobs starting is no
// reason to leave bob's watches unevaluated.
func TestOwnersAreNudgedSeparately(t *testing.T) {
	f, rec, _ := nudgerFixture(t)

	qdate := fmt.Sprintf("QDate = %d", time.Now().Add(-time.Hour).Unix())
	for _, owner := range []string{"alice", "bob"} {
		key := owner + ".0"
		applyUpsert(f, key, jobAd(1, owner, 1, qdate))
		applyUpsert(f, key, jobAd(1, owner, 2, `RemoteHost = "slot1@ep.example"`))
	}

	deadline := time.After(5 * time.Second)
	for rec.count("alice") == 0 || rec.count("bob") == 0 {
		select {
		case <-rec.calls:
		case <-deadline:
			t.Fatalf("alice=%d bob=%d, want both nudged", rec.count("alice"), rec.count("bob"))
		}
	}
}

// MinGap holds a second sweep back when activity is continuous rather
// than bursty -- but holding it back must not drop it, or the last
// change before things go quiet is never acted on.
func TestMinGapDefersRatherThanDropping(t *testing.T) {
	f := NewFeed(nil)
	rec := newRecorder()
	n := NewNudger(f, rec.check, nil)

	now := time.Unix(1_700_000_000, 0)
	n.now = func() time.Time { return now }

	pending := map[string]struct{}{"alice": {}}
	last := map[string]time.Time{"alice": now.Add(-time.Second)}
	n.MinGap = 5 * time.Second

	n.drain(context.Background(), pending, last)
	if rec.count("alice") != 0 {
		t.Fatal("swept inside the minimum gap")
	}
	if _, still := pending["alice"]; !still {
		t.Fatal("the deferred owner was dropped instead of being left pending")
	}

	now = now.Add(10 * time.Second)
	n.drain(context.Background(), pending, last)
	if rec.count("alice") != 1 {
		t.Errorf("alice swept %d times once the gap had passed, want 1", rec.count("alice"))
	}
}

// A failing evaluation is a slower answer, not a dead nudger: the next
// change still has to be acted on.
func TestAFailedCheckDoesNotStopTheNudger(t *testing.T) {
	f, rec, _ := nudgerFixture(t)
	rec.mu.Lock()
	rec.err = errors.New("mirror unreachable")
	rec.mu.Unlock()

	qdate := fmt.Sprintf("QDate = %d", time.Now().Add(-time.Hour).Unix())
	applyUpsert(f, "1.0", jobAd(1, "alice", 1, qdate))
	applyUpsert(f, "1.0", jobAd(1, "alice", 2, `RemoteHost = "slot1@ep.example"`))
	rec.waitCall(t)

	rec.mu.Lock()
	rec.err = nil
	rec.mu.Unlock()
	applyUpsert(f, "2.0", jobAd(2, "alice", 1, qdate))
	applyUpsert(f, "2.0", jobAd(2, "alice", 2, `RemoteHost = "slot2@ep.example"`))
	rec.waitCall(t)
}

// An event carrying no owner cannot be routed to anyone's watches, and
// must not be turned into a sweep of the empty-string owner.
func TestUnownedActivityIsIgnored(t *testing.T) {
	f, rec, _ := nudgerFixture(t)

	f.mu.Lock()
	f.publishActivityLocked(ActivityEvent{Kind: ActivityStarted, Cluster: 1})
	f.mu.Unlock()

	time.Sleep(60 * time.Millisecond)
	if got := rec.count(""); got != 0 {
		t.Errorf("an ownerless event caused %d sweeps", got)
	}
}
