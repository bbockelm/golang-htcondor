package multiap

// Gap tests for multi-ap-hub-ha: each passes on the branch and kills a
// mutant the branch's own tests let survive (named per test).

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/bbockelm/golang-htcondor/jobid"
)

// moveTo makes the pair's active hub `to` by taking the other down for
// two refreshes, then bringing it back.
func (p *hubPair) moveTo(t *testing.T, to string) {
	t.Helper()
	other := p.a
	if to == hubA {
		other = p.b
	}
	other.down.Store(true)
	p.refresh()
	p.refresh()
	other.down.Store(false)
	if p.active() != to {
		t.Fatalf("active %q, want %s", p.active(), to)
	}
}

func pairService(p *hubPair) *Service {
	return &Service{Registry: newFakeRegistry(ap1, ap2), Hub: p.hub, Codec: jobid.Default(), Stale: StaleInclude, UIDDomain: "d"}
}

// TestGapQueueCoveredReadsThePinnedHubsSources: a pass pinned to one
// hub reads BOTH federation_sources reads around its queue read from
// that hub, while another is active. Kills M22 (after-read from the
// active hub) and M23 (before-read from the active hub).
func TestGapQueueCoveredReadsThePinnedHubsSources(t *testing.T) {
	a, b := hubDB(t), hubDB(t)
	synced := []string{"JobsSynced = true", "JobsSyncedAt = 100"}
	for _, db := range []*testDB{a, b} {
		db.PutJob(ap1, "alice@d", 1, 0, "")
		db.PutSourceAd(ap1, sourceAd(ap1, StateFresh, synced...))
	}
	a.PutSourceAd(ap2, sourceAd(ap2, StateFresh, synced...))
	b.PutSourceAd(ap2, sourceAd(ap2, StateStale, "JobsSynced = false", "JobsSyncedAt = 100"))
	p := newHubPair(t, a, b, HubPolicy{})
	p.refresh()
	s := pairService(p)
	src := WatchSource{Service: s}
	cover := func(ctx context.Context) bool {
		_, cov, err := src.QueueCovered(ctx, "alice", []string{"ClusterId", "ProcId"}, 100, func(*classad.ClassAd) {})
		if err != nil {
			t.Fatal(err)
		}
		_, ok := cov.AsOf(ap2)
		return ok
	}

	// Pinned to A, B active: A vouches for ap2 before and after.
	pinA := s.PinHub(context.Background())
	p.moveTo(t, hubB)
	if !cover(pinA) {
		t.Fatal("a pass pinned to hub A did not vouch for ap2, which A vouches for: a read went to hub B")
	}

	// Pinned to B, A active: B's ap2 is stale (its jobs stream caught up,
	// with the same JobsSyncedAt as A's). Nothing may be vouched on A's word.
	b.PutSourceAd(ap2, sourceAd(ap2, StateStale, synced...))
	p.refresh()
	pinB := s.PinHub(context.Background())
	p.moveTo(t, hubA)
	if cover(pinB) {
		t.Fatal("a pass pinned to hub B vouched for ap2, which B reports stale: hub A's federation_sources was consulted")
	}
}

// TestGapBulkSkipUsesThePinnedHubsFreshness: a bulk action pinned to a
// hub that is 300s behind on ap1 never skips ap1, even though the
// active hub is fresh there and neither holds a matching job. Kills M27.
func TestGapBulkSkipUsesThePinnedHubsFreshness(t *testing.T) {
	a, b := hubDB(t), hubDB(t)
	a.PutSource(ap1, StateFresh, 2)
	b.PutSource(ap1, StateFresh, 300)
	p := newHubPair(t, a, b, HubPolicy{})
	p.refresh()
	p.moveTo(t, hubB)
	s := pairService(p)
	s.Registry = newFakeRegistry(ap1).WithSchedds(func(n string) string { return "<10.0.0.1:9618?name=" + n + ">" })
	pinB := s.PinHub(context.Background())
	p.moveTo(t, hubA)
	rec := &bulkRecorder{}
	rep, err := s.FanOut(pinB, BulkRequest{User: "alice@d", Owner: "alice", Constraint: "true", FreshWithin: 60 * time.Second}, rec.act)
	if err != nil {
		t.Fatal(err)
	}
	if got := statusOf(rep, ap1); got.Status == BulkSkipped {
		t.Fatalf("ap1 skipped on the word of a hub 300s behind (the active hub's freshness was used): %+v", got)
	}
}

// TestGapTableSourcesUsesThePinnedHub: a request pinned to hub A judges
// each AP's jobs stream by A, not by the hub active now. Kills M26.
func TestGapTableSourcesUsesThePinnedHub(t *testing.T) {
	a, b := hubDB(t), hubDB(t)
	freshSources(a)
	b.PutSourceAd(ap1, sourceAd(ap1, StateFresh))
	b.PutSourceAd(ap2, `ScheddName = "`+ap2+`"`+"\nState = \"fresh\"\nStalenessSeconds = 2\nJobsConnected = false")
	p := newHubPair(t, a, b, HubPolicy{})
	p.refresh()
	s := pairService(p)
	pinA := s.PinHub(context.Background())
	p.moveTo(t, hubB)
	src := s.TableSources(pinA, s.Sources(pinA), TableJobs)
	if src.Hub != hubA || src.Fresh != 2 || len(src.Degraded) != 0 {
		t.Fatalf("pinned to %s: %+v; hub B's disconnected ap2 jobs stream leaked into hub A's sources", hubA, src)
	}
}

// discoverable is a hub list the test changes between discoveries.
type discoverable struct {
	mu    sync.Mutex
	specs []HubSpec
}

func (d *discoverable) set(specs ...HubSpec) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.specs = specs
}

func (d *discoverable) discover(context.Context) ([]HubSpec, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]HubSpec(nil), d.specs...), nil
}

// TestGapDiscoveryKeepsALapsedActiveHub: the active hub's ad lapses
// while it still answers; it stays known, active and reported. Kills M10.
func TestGapDiscoveryKeepsALapsedActiveHub(t *testing.T) {
	a, b := memoryHub(t), memoryHub(t)
	freshSources(a)
	freshSources(b)
	d := &discoverable{}
	d.set(HubSpec{Name: hubA, Dial: a.Dial}, HubSpec{Name: hubB, Dial: b.Dial})
	h := NewHubSet(HubOptions{Interval: time.Hour, Discover: d.discover})
	ctx := context.Background()
	if err := h.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	_ = h.Refresh(ctx)
	if h.Active().Name() != hubA {
		t.Fatalf("active %q", h.Active().Name())
	}
	d.set(HubSpec{Name: hubB, Dial: b.Dial})
	_ = h.Discover(ctx)
	_ = h.Refresh(ctx)
	found := false
	for _, st := range h.Statuses() {
		if st.Name == hubA && st.Active && st.Reachable {
			found = true
		}
	}
	if !found || h.Active().Name() != hubA {
		t.Fatalf("after %s's ad lapsed: statuses %+v, active %q; want it kept, active and reported", hubA, h.Statuses(), h.Active().Name())
	}
}

// TestGapNeverAnsweredHubIsNoFailoverTarget: the active hub stops
// answering; the only other hub was discovered meanwhile and has never
// answered (one failed read, under FailAfter). It is not a target: reads
// stay where they are. Kills M05.
func TestGapNeverAnsweredHubIsNoFailoverTarget(t *testing.T) {
	a := &switchableHub{db: memoryHub(t)}
	b := &switchableHub{db: memoryHub(t)}
	freshSources(a.db)
	b.down.Store(true)
	d := &discoverable{}
	d.set(HubSpec{Name: hubA, Dial: a.dial})
	clock := &testClock{t: time.Now()}
	h := NewHubSet(HubOptions{Interval: time.Hour, Discover: d.discover, Policy: HubPolicy{FailAfter: 2}})
	h.now = clock.now
	ctx := context.Background()
	_ = h.Discover(ctx)
	_ = h.Refresh(ctx)
	a.down.Store(true)
	clock.advance(5 * time.Second)
	_ = h.Refresh(ctx) // A: 1 failure
	d.set(HubSpec{Name: hubA, Dial: a.dial}, HubSpec{Name: hubB, Dial: b.dial})
	_ = h.Discover(ctx)
	clock.advance(5 * time.Second)
	_ = h.Refresh(ctx) // A: 2 failures, B: 1 failure, never a success
	if got := h.Active().Name(); got != hubA || h.Generation() != 0 {
		t.Fatalf("active %q (generation %d): reads moved to a hub that has never answered", got, h.Generation())
	}
}

// TestGapIntermittentFailuresDoNotAccumulate: single failed reads with
// successes between them never add up to FailAfter. Kills M14.
func TestGapIntermittentFailuresDoNotAccumulate(t *testing.T) {
	a, b := memoryHub(t), memoryHub(t)
	freshSources(a)
	freshSources(b)
	p := newHubPair(t, a, b, HubPolicy{FailAfter: 2})
	p.refresh()
	for i := 0; i < 5; i++ {
		p.a.down.Store(true)
		p.clock.advance(5 * time.Second)
		p.refresh()
		p.a.down.Store(false)
		p.clock.advance(5 * time.Second)
		p.refresh()
	}
	if p.active() != hubA || len(p.sw) != 0 {
		t.Fatalf("active %q, switches %+v: isolated failed reads counted as consecutive", p.active(), p.sw)
	}
}

// TestGapAfterReadFailureVouchesNothing: the federation_sources read
// after the queue read fails; nothing confirms the catch-up held, so the
// pass vouches for no AP. Kills M40.
func TestGapAfterReadFailureVouchesNothing(t *testing.T) {
	db := hubDB(t)
	db.PutJob(ap1, "alice@d", 1, 0, "")
	freshSources(db)
	var dials atomic.Int32
	h := NewHub(func(ctx context.Context) (*dbrpc.Client, func(), error) {
		if dials.Add(1) == 3 { // sources, queue, then sources again
			return nil, nil, errors.New("connection reset")
		}
		return db.Dial(ctx)
	}, time.Hour)
	s := &Service{Registry: newFakeRegistry(ap1, ap2), Hub: h, Codec: jobid.Default(), Stale: StaleInclude, UIDDomain: "d"}
	_, cov, err := WatchSource{Service: s}.QueueCovered(context.Background(), "alice", []string{"ClusterId"}, 100, func(*classad.ClassAd) {})
	if err != nil {
		t.Fatal(err)
	}
	if dials.Load() != 3 {
		t.Fatalf("%d dials, want 3 (the test's model of QueueCovered is out of date)", dials.Load())
	}
	for _, ap := range []string{ap1, ap2} {
		if _, ok := cov.AsOf(ap); ok {
			t.Fatalf("vouched for %s with the after-read failed", ap)
		}
	}
}
