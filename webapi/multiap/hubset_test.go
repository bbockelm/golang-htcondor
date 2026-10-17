package multiap

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// Two federation hubs: selection (sticky, failover, hysteresis), reads
// pinned to one hub, and every consumer's behaviour across a switch.

const (
	hubA = "hub-a@example.org"
	hubB = "hub-b@example.org"
)

// switchableHub is an in-process hub that can be made to refuse
// connections.
type switchableHub struct {
	db   *testDB
	down atomic.Bool
}

func (s *switchableHub) dial(ctx context.Context) (*dbrpc.Client, func(), error) {
	if s.down.Load() {
		return nil, nil, errors.New("connection refused")
	}
	return s.db.Dial(ctx)
}

// testClock is a settable clock.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// hubPair is two hubs behind one Hub set on a test clock.
type hubPair struct {
	t     *testing.T
	a, b  *switchableHub
	hub   *Hub
	clock *testClock
	sw    []HubSwitch
}

func newHubPair(t *testing.T, a, b *testDB, policy HubPolicy) *hubPair {
	t.Helper()
	p := &hubPair{t: t, a: &switchableHub{db: a}, b: &switchableHub{db: b}, clock: &testClock{t: time.Now()}}
	p.hub = NewHubSet(HubOptions{
		Interval: time.Hour,
		Policy:   policy,
		Static: []HubSpec{
			{Name: hubB, Dial: p.b.dial}, // out of order: the set sorts by name
			{Name: hubA, Dial: p.a.dial},
		},
		OnSwitch: func(sw HubSwitch) { p.sw = append(p.sw, sw) },
	})
	p.hub.now = p.clock.now
	return p
}

// refresh re-reads both hubs and selects.
func (p *hubPair) refresh() {
	p.t.Helper()
	_ = p.hub.Refresh(context.Background())
}

// over refreshes every step for d.
func (p *hubPair) over(d, step time.Duration) {
	p.t.Helper()
	for elapsed := time.Duration(0); elapsed < d; elapsed += step {
		p.clock.advance(step)
		p.refresh()
	}
}

func (p *hubPair) active() string { return p.hub.Active().Name() }

// freshSources writes both APs fresh on db.
func freshSources(db *testDB) {
	db.PutSourceAd(ap1, sourceAd(ap1, StateFresh))
	db.PutSourceAd(ap2, sourceAd(ap2, StateFresh))
}

func memoryHub(t *testing.T) *testDB { return multiaptest.NewMemoryHub(t) }

// TestHubSelectionIsSticky: two equally fresh hubs; the first by name is
// chosen and kept, refresh after refresh, with no switch.
func TestHubSelectionIsSticky(t *testing.T) {
	a, b := memoryHub(t), memoryHub(t)
	freshSources(a)
	freshSources(b)
	p := newHubPair(t, a, b, HubPolicy{SwitchAfter: time.Minute})
	if got := p.active(); got != hubA {
		t.Fatalf("before any refresh reads go to %q, want the first by name, %q", got, hubA)
	}
	p.refresh()
	p.over(30*time.Minute, 30*time.Second)
	if got := p.active(); got != hubA || p.hub.Generation() != 0 || len(p.sw) != 0 {
		t.Fatalf("active %q, generation %d, switches %+v: want %s kept with no switch", got, p.hub.Generation(), p.sw, hubA)
	}
	sts := p.hub.Statuses()
	if len(sts) != 2 || !sts[0].Active || sts[0].Name != hubA || sts[1].Active || sts[0].FreshAPs != 2 || sts[1].FreshAPs != 2 {
		t.Fatalf("statuses %+v, want %s active and %s its peer, both with 2 fresh APs", sts, hubA, hubB)
	}
}

// TestHubFailoverOnUnreachable: the active hub stops answering; after
// FailAfter failed reads the other takes over, and stays when the first
// returns -- no failback to a hub that is merely back.
func TestHubFailoverOnUnreachable(t *testing.T) {
	a, b := memoryHub(t), memoryHub(t)
	freshSources(a)
	freshSources(b)
	p := newHubPair(t, a, b, HubPolicy{FailAfter: 2})
	p.refresh()
	p.a.down.Store(true)
	p.clock.advance(5 * time.Second)
	p.refresh()
	if got := p.active(); got != hubA {
		t.Fatalf("after one failed read the active hub is %q, want %s kept (FailAfter 2)", got, hubA)
	}
	p.clock.advance(5 * time.Second)
	p.refresh()
	if got := p.active(); got != hubB {
		t.Fatalf("after two failed reads the active hub is %q, want %s", got, hubB)
	}
	if len(p.sw) != 1 || p.sw[0].Reason != "unreachable" || p.sw[0].From != hubA || p.sw[0].To != hubB || p.hub.Generation() != 1 {
		t.Fatalf("switches %+v (generation %d), want one from %s to %s for unreachability", p.sw, p.hub.Generation(), hubA, hubB)
	}
	if !p.hub.AnyReachable() {
		t.Fatal("no hub reachable with one answering")
	}
	p.a.down.Store(false)
	p.over(time.Hour, 30*time.Second)
	if got := p.active(); got != hubB || len(p.sw) != 1 {
		t.Fatalf("after %s came back the active hub is %q (switches %+v), want %s kept", hubA, got, p.sw, hubB)
	}
}

// TestHubFailoverNeedsSomewhereToGo: with both hubs down the active one
// is kept -- there is nothing better -- and nothing is reachable.
func TestHubFailoverNeedsSomewhereToGo(t *testing.T) {
	a, b := memoryHub(t), memoryHub(t)
	freshSources(a)
	freshSources(b)
	p := newHubPair(t, a, b, HubPolicy{})
	p.refresh()
	p.a.down.Store(true)
	p.b.down.Store(true)
	p.over(5*time.Hour, 30*time.Minute)
	if got := p.active(); got != hubA || len(p.sw) != 0 {
		t.Fatalf("active %q, switches %+v: want %s kept with nowhere to go", got, p.sw, hubA)
	}
	if p.hub.AnyReachable() {
		t.Fatal("a hub reads as reachable with both down")
	}
}

// TestHubNoFlapOnBriefFreshness: the other hub is fresher, but never for
// SwitchAfter at a stretch -- each hub's state pass lands at its own
// moment -- so nothing switches.
func TestHubNoFlapOnBriefFreshness(t *testing.T) {
	a, b := memoryHub(t), memoryHub(t)
	freshSources(a)
	freshSources(b)
	p := newHubPair(t, a, b, HubPolicy{SwitchAfter: 2 * time.Minute})
	p.refresh()
	for round := 0; round < 10; round++ {
		// ap2 stale on the active hub for 90 s, then fresh again.
		a.PutSourceAd(ap2, sourceAd(ap2, StateStale))
		p.over(90*time.Second, 30*time.Second)
		freshSources(a)
		p.over(30*time.Second, 30*time.Second)
		// And the other way round, which must not pull it back either.
		b.PutSourceAd(ap1, sourceAd(ap1, StateStale))
		p.over(90*time.Second, 30*time.Second)
		freshSources(b)
	}
	if got := p.active(); got != hubA || len(p.sw) != 0 {
		t.Fatalf("active %q after brief differences, switches %+v: want %s kept", got, p.sw, hubA)
	}
}

// TestHubSwitchOnSustainedFreshness: the other hub reports more fresh
// APs at every refresh for SwitchAfter; reads move to it. When the first
// recovers to equal, nothing moves back; when it is fresher again,
// it must be so for SwitchAfter again.
func TestHubSwitchOnSustainedFreshness(t *testing.T) {
	a, b := memoryHub(t), memoryHub(t)
	freshSources(a)
	freshSources(b)
	p := newHubPair(t, a, b, HubPolicy{SwitchAfter: 2 * time.Minute})
	p.refresh()
	a.PutSourceAd(ap2, sourceAd(ap2, StateStale))
	p.over(90*time.Second, 30*time.Second)
	if got := p.active(); got != hubA {
		t.Fatalf("switched to %q after 90 s of a 2-minute window", got)
	}
	p.over(60*time.Second, 30*time.Second)
	if got := p.active(); got != hubB {
		t.Fatalf("active %q after 150 s of %s being fresher, want %s", got, hubB, hubB)
	}
	if len(p.sw) != 1 || p.sw[0].Reason != "fresher" {
		t.Fatalf("switches %+v, want one for freshness", p.sw)
	}
	freshSources(a)
	p.over(30*time.Minute, 30*time.Second)
	if got := p.active(); got != hubB || len(p.sw) != 1 {
		t.Fatalf("active %q (switches %+v) with both equal, want %s kept", got, p.sw, hubB)
	}
	b.PutSourceAd(ap1, sourceAd(ap1, StateStale))
	p.over(150*time.Second, 30*time.Second)
	if got := p.active(); got != hubA || len(p.sw) != 2 {
		t.Fatalf("active %q (switches %+v) with %s fresher for 150 s, want %s", got, p.sw, hubA, hubA)
	}
}

// TestHubSwitchMargin: a hub fresher by fewer APs than SwitchMargin is
// not fresher.
func TestHubSwitchMargin(t *testing.T) {
	a, b := memoryHub(t), memoryHub(t)
	freshSources(a)
	freshSources(b)
	p := newHubPair(t, a, b, HubPolicy{SwitchAfter: time.Minute, SwitchMargin: 2})
	p.refresh()
	a.PutSourceAd(ap2, sourceAd(ap2, StateStale))
	p.over(time.Hour, 30*time.Second)
	if got := p.active(); got != hubA {
		t.Fatalf("switched to %q on a one-AP difference with margin 2", got)
	}
	a.PutSourceAd(ap1, sourceAd(ap1, StateStale))
	p.over(90*time.Second, 30*time.Second)
	if got := p.active(); got != hubB {
		t.Fatalf("active %q on a two-AP difference with margin 2, want %s", got, hubB)
	}
}

// TestHubFreshnessCountsMembersOnly: fresh rows for schedds outside the
// AP set do not make a hub fresher.
func TestHubFreshnessCountsMembersOnly(t *testing.T) {
	a, b := memoryHub(t), memoryHub(t)
	freshSources(a)
	freshSources(b)
	for _, n := range []string{"x1.example.org", "x2.example.org", "x3.example.org"} {
		b.PutSourceAd(n, sourceAd(n, StateFresh))
	}
	p := newHubPair(t, a, b, HubPolicy{SwitchAfter: time.Minute})
	reg := newFakeRegistry(ap1, ap2)
	p.hub.SetMembership(func(n string) bool { _, ok := reg.Get(n); return ok })
	p.refresh()
	p.over(time.Hour, 30*time.Second)
	if got := p.active(); got != hubA {
		t.Fatalf("switched to %q for non-member sources", got)
	}
}

// TestHubOneHubUnchanged: with one hub -- given as a dialer, or as the
// only one named -- nothing is ever switched, whatever it does, and the
// origin a read is pinned to never changes.
func TestHubOneHubUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(d Dialer) *Hub
	}{
		{"dialer", func(d Dialer) *Hub { return NewHub(d, time.Hour) }},
		{"one named", func(d Dialer) *Hub {
			return NewHubSet(HubOptions{Interval: time.Hour, Static: []HubSpec{{Name: hubA, Dial: d}}})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := memoryHub(t)
			freshSources(db)
			sh := &switchableHub{db: db}
			h := tc.make(sh.dial)
			clock := &testClock{t: time.Now()}
			h.now = clock.now
			origin := h.Origin(context.Background())
			ep := h.Active()
			if err := h.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			sh.down.Store(true)
			for i := 0; i < 10; i++ {
				clock.advance(time.Hour)
				_ = h.Refresh(context.Background())
			}
			sh.down.Store(false)
			_ = h.Refresh(context.Background())
			if h.Active() != ep || h.Generation() != 0 || h.LastSwitch() != nil || h.Origin(context.Background()) != origin {
				t.Fatalf("one hub: active %p (was %p), generation %d, switch %+v, origin %q (was %q)",
					h.Active(), ep, h.Generation(), h.LastSwitch(), h.Origin(context.Background()), origin)
			}
			if st := h.Status(); !st.Reachable || st.Sources != 2 || !st.Active {
				t.Fatalf("status %+v, want reachable with 2 sources", st)
			}
		})
	}
}

// TestHubPinnedReadStaysOnItsHub: a read pinned before a switch is served
// from, and reports the freshness of, the hub it was pinned to; an
// unpinned one goes to the new hub. Neither mixes them.
func TestHubPinnedReadStaysOnItsHub(t *testing.T) {
	a, b := memoryHub(t), memoryHub(t)
	a.PutJob(ap1, "alice@d", 1, 0, "")
	b.PutJob(ap1, "alice@d", 2, 0, "")
	freshSources(a)
	b.PutSourceAd(ap1, sourceAd(ap1, StateFresh))
	b.PutSourceAd(ap2, sourceAd(ap2, StateStale))
	p := newHubPair(t, a, b, HubPolicy{})
	p.refresh()
	s := &Service{Registry: newFakeRegistry(ap1, ap2), Hub: p.hub, Codec: jobid.Default(), Stale: StaleInclude, UIDDomain: "d"}

	pinned := s.PinHub(context.Background())
	p.a.down.Store(true)
	p.refresh()
	p.refresh()
	if p.active() != hubB {
		t.Fatalf("active %q, want %s", p.active(), hubB)
	}
	// The hub the read was pinned to is back up, but not active.
	p.a.down.Store(false)

	list := func(ctx context.Context) ([]Row, *ListResult) {
		var rows []Row
		res, err := s.ListJobs(ctx, ListRequest{User: "alice@d"}, func(r Row) bool { rows = append(rows, r); return true })
		if err != nil {
			t.Fatal(err)
		}
		return rows, res
	}
	rows, res := list(pinned)
	if got := ids(s, rows); len(got) != 1 || rows[0].ID.Cluster != 1 || res.Sources.Hub != hubA || res.Sources.Fresh != 2 {
		t.Fatalf("pinned read: rows %v, sources %+v; want %s's 1.0 with %s's 2 fresh APs", got, res.Sources, hubA, hubA)
	}
	rows, res = list(context.Background())
	if got := ids(s, rows); len(got) != 1 || rows[0].ID.Cluster != 2 || res.Sources.Hub != hubB || res.Sources.Fresh != 1 {
		t.Fatalf("unpinned read: rows %v, sources %+v; want %s's 2.0 with %s's 1 fresh AP", got, res.Sources, hubB, hubB)
	}
	if o1, o2 := s.HubOrigin(pinned), s.HubOrigin(context.Background()); o1 == o2 {
		t.Fatalf("origins %q and %q are equal across a switch", o1, o2)
	}
}

// --- watches across a switch ----------------------------------------------

// twoHubWatchRig is watchRig over two hubs: alice's "done" watch over
// ClusterId == 1, which is a job on each AP.
type twoHubWatchRig struct {
	*watchRig
	pair *hubPair
	b    *testDB
}

func newTwoHubWatchRig(t *testing.T, policy HubPolicy, setupB func(b *testDB)) *twoHubWatchRig {
	t.Helper()
	r := newWatchRig(t, jobwatch.ModeAny, "ClusterId == 1")
	b := hubDB(t)
	setupB(b)
	pair := newHubPair(t, r.hub, b, policy)
	pair.refresh()
	r.svc.Hub = pair.hub
	r.eval = jobwatch.NewEvaluator(r.store, WatchSource{Service: r.svc}, nil)
	return &twoHubWatchRig{watchRig: r, pair: pair, b: b}
}

// TestWatchFailoverToLaggingHubDoesNotFire is the rule a second hub must
// not break: ap2's 1.0 is on hub A, and the watch has seen it there.
// Reads move to hub B, which is still catching up on ap2 -- its ap2 jobs
// stream has not finished its replay (JobsSynced false) and does not
// hold the job yet. B vouches for nothing on ap2, so the job's absence
// from B is not evidence, and the watch must not fire, however much time
// passes, until B has caught up -- and then only once the absence has
// been earned on B.
//
// Hub A is still answering throughout (it fell behind on ap1, which is
// why reads moved), so anything that consulted A's federation_sources
// -- which vouches for ap2 -- would see the job "gone" and fire.
func TestWatchFailoverToLaggingHubDoesNotFire(t *testing.T) {
	r := newTwoHubWatchRig(t, HubPolicy{SwitchAfter: time.Minute}, func(b *testDB) {
		b.PutJob(ap1, "alice@d", 1, 0, "")
		b.PutSourceAd(ap1, sourceAd(ap1, StateFresh, "JobsSynced = true", "JobsSyncedAt = 100"))
		b.PutSourceAd(ap2, sourceAd(ap2, StateFresh, "JobsSynced = false", "JobsSyncedAt = 100"))
	})
	if r.pair.active() != hubA {
		t.Fatalf("active %q, want %s", r.pair.active(), hubA)
	}
	r.pass()
	if got := r.watch().Tracked; len(got) != 2 {
		t.Fatalf("tracked %+v on %s, want 1.0 on both APs", got, hubA)
	}
	// A falls behind on ap1 for longer than SwitchAfter; reads move to B.
	r.hub.PutSourceAd(ap1, sourceAd(ap1, StateStale, "JobsSynced = true", "JobsSyncedAt = 100"))
	r.hub.PutSourceAd(ap2, sourceAd(ap2, StateFresh, "JobsSynced = true", "JobsSyncedAt = 100"))
	r.pair.over(3*time.Minute, 30*time.Second)
	if r.pair.active() != hubB {
		t.Fatalf("active %q, want %s after A fell behind", r.pair.active(), hubB)
	}
	for i := 0; i < 3; i++ {
		r.pair.clock.advance(3 * time.Hour)
		r.pair.refresh()
		if st := r.pass(); st.Fired != 0 {
			t.Fatalf("pass %d on %s fired while it is still catching up on ap2: %+v", i, hubB, r.watch().Matched)
		}
	}
	if r.pair.active() != hubB {
		t.Fatalf("active %q, want %s", r.pair.active(), hubB)
	}
	// B catches up on ap2, and the job is not there: now absence is
	// evidence -- earned on B, over two of B's reads.
	r.b.PutSourceAd(ap2, sourceAd(ap2, StateFresh, "JobsSynced = true", "JobsSyncedAt = 200"))
	fired := 0
	for i := 0; i < 3 && fired == 0; i++ {
		r.pair.clock.advance(3 * time.Hour)
		r.pair.refresh()
		fired = r.pass().Fired
	}
	if fired != 1 {
		t.Fatal("the watch never fired once B had caught up and the job was gone")
	}
	if w := r.watch(); len(w.Matched) != 1 || w.Matched[0].Schedd != ap2 {
		t.Fatalf("matched %+v, want 1.0@%s", w.Matched, ap2)
	}
}

// TestWatchCoverageNamesItsHub: an evaluation pass is pinned to one hub
// and its coverage names that hub and the selection generation, so the
// evaluator can tell a read of the new hub from one of the old and start
// its absence memory over (jobwatch TestAbsenceOriginChangeReearns).
func TestWatchCoverageNamesItsHub(t *testing.T) {
	r := newTwoHubWatchRig(t, HubPolicy{}, func(b *testDB) {
		b.PutJob(ap1, "alice@d", 1, 0, "")
		b.PutSourceAd(ap1, sourceAd(ap1, StateFresh))
		b.PutSourceAd(ap2, sourceAd(ap2, StateFresh))
	})
	src := WatchSource{Service: r.svc}
	read := func(ctx context.Context) (string, int) {
		n := 0
		_, cov, err := src.QueueCovered(ctx, "alice", []string{"ClusterId", "ProcId"}, 100, func(*classad.ClassAd) { n++ })
		if err != nil {
			t.Fatal(err)
		}
		return cov.Origin(), n
	}
	pass := src.PinPass(context.Background())
	originA, rowsA := read(pass)
	if originA != hubA+"/0" || rowsA != 2 {
		t.Fatalf("coverage origin %q with %d rows, want %s/0 with alice's 2", originA, rowsA, hubA)
	}
	r.pair.a.down.Store(true)
	r.pair.refresh()
	r.pair.refresh()
	if r.pair.active() != hubB {
		t.Fatalf("active %q, want %s", r.pair.active(), hubB)
	}
	// A pass pinned before the switch reads on from its own hub...
	r.pair.a.down.Store(false)
	if origin, rows := read(pass); origin != originA || rows != 2 {
		t.Fatalf("a pass pinned to %s read origin %q with %d rows after the switch", hubA, origin, rows)
	}
	// ...and the next one reads the new hub, under a new origin.
	if origin, rows := read(src.PinPass(context.Background())); origin != hubB+"/1" || rows != 1 {
		t.Fatalf("coverage origin %q with %d rows after the switch, want %s/1 with 1", origin, rows, hubB)
	}
}

// --- the jobs feed across a switch ------------------------------------------

// TestFeedFailoverStartsOver: the feed follows hub A, holding a
// departure and the last ad of a job that completed (still in A's
// queue). Reads move to B. The feed starts over on B, from B's head: A's
// departure is gone, the ad it held is gone -- so B deleting that job's
// row reports no departure from A's ad -- and it follows B's changes.
// A cursor from A is never sent to B.
func TestFeedFailoverStartsOver(t *testing.T) {
	a, b := memoryHub(t), memoryHub(t)
	freshSources(a)
	freshSources(b)
	p := newHubPair(t, a, b, HubPolicy{})
	p.refresh()
	s := &Service{Registry: newFakeRegistry(ap1, ap2), Hub: p.hub, Codec: jobid.Default(), Stale: StaleInclude, UIDDomain: "d"}

	feed := jobwatch.NewFeed(nil)
	feed.OwnerOf = s.OwnerOfRow
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = feed.RunResumableFrom(ctx, s.OpenJobsWatch) }()
	waitUntil(t, "the feed to follow hub A", func() bool { return feed.Warm() })
	originA := feed.Origin()

	// On A: 1.0 completed and still queued; 2.0 completed and gone.
	a.PutJob(ap1, "alice@d", 1, 0, "JobStatus = 4") // key opaque-1, as on B below
	a.PutJob(ap1, "alice@d", 2, 0, "JobStatus = 4")
	a.DeleteJob(ap1, 2, 0)
	since := time.Now().Add(-time.Hour)
	waitUntil(t, "A's departure of 2.0", func() bool { return len(feed.Departures("alice", since)) == 1 })
	// B holds 1.0 too, under the same storage key, written before the
	// feed reaches B.
	b.PutJob(ap1, "alice@d", 1, 0, "JobStatus = 2")

	p.a.down.Store(true)
	p.refresh()
	p.refresh()
	if p.active() != hubB {
		t.Fatalf("active %q, want %s", p.active(), hubB)
	}
	waitUntil(t, "the feed to follow hub B", func() bool { return feed.Warm() && feed.Origin() != originA })
	if d := feed.Departures("alice", since); len(d) != 0 {
		t.Fatalf("departures after the switch %+v, want none: they were A's", d)
	}
	if rec := feed.Terminal("alice", since); len(rec) != 0 {
		t.Fatalf("%d terminal records after the switch, want none: they were A's", len(rec))
	}

	// B deletes 1.0's row: the feed never saw B upsert it, and must not
	// report A's "completed" ad as its departure. B's 3.0 then completes
	// and leaves, which the feed does report.
	b.DeleteJob(ap1, 1, 0)
	b.PutJob(ap1, "alice@d", 3, 0, "JobStatus = 4")
	b.DeleteJob(ap1, 3, 0)
	waitUntil(t, "B's departure of 3.0", func() bool { return len(feed.Departures("alice", since)) > 0 })
	if d := feed.Departures("alice", since); len(d) != 1 || d[0].Cluster != 3 {
		t.Fatalf("departures on B %+v, want 3.0 alone", d)
	}

	// A cursor issued by another hub is not sent to this one: the stream
	// opens at B's head, so its first event is the next change, not a
	// Reset and a replay -- or a failure -- over a position B never had.
	ch, stop, origin, err := s.OpenJobsWatch(ctx, jobwatch.Resume{Cursor: []byte("not-B's-cursor"), Origin: originA})
	if err != nil {
		t.Fatalf("opening B's jobs watch with A's cursor: %v", err)
	}
	defer stop()
	if origin != feed.Origin() {
		t.Fatalf("OpenJobsWatch origin %q, want the feed's %q", origin, feed.Origin())
	}
	b.PutJob(ap1, "alice@d", 4, 0, "")
	const watchSynced = 3 // db.WatchSynced: the end of catch-up, with nothing to catch up on
	for {
		select {
		case ev := <-ch:
			if ev.Kind == watchSynced {
				continue
			}
			if ev.Kind != jobwatch.WatchUpsert || !strings.Contains(ev.AdText, "ClusterId = 4") {
				t.Fatalf("first change %+v, want the upsert of 4.0", ev)
			}
			return
		case <-time.After(10 * time.Second):
			t.Fatal("no event from B's head")
		}
	}
}

// TestFeedRecordsFollowTheirHub: the watch source uses the feed's
// terminal records only while the feed follows the hub the pass reads.
func TestFeedRecordsFollowTheirHub(t *testing.T) {
	r := newWatchRig(t, jobwatch.ModeAny, "ClusterId > 5")
	feed := followHub(t, r)
	r.hub.PutJob(ap2, "alice@d", 6, 0, "JobStatus = 4")
	r.hub.DeleteJob(ap2, 6, 0)
	waitUntil(t, "the delete to reach the feed", func() bool { return len(feed.Terminal("alice", time.Now().Add(-time.Hour))) == 1 })
	read := func(ctx context.Context) int {
		n := 0
		err := WatchSource{Service: r.svc, Feed: feed}.History(ctx, "alice", []string{"ClusterId", "ProcId", "JobStatus"},
			time.Now().Add(-time.Hour), 100, func(*classad.ClassAd) { n++ })
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := read(context.Background()); n != 1 {
		t.Fatalf("%d terminal records on the feed's own hub, want 1", n)
	}
	// A pass pinned to another origin: same hub pointer, but a pin taken
	// in a later generation names a different origin.
	r.svc.Hub.mu.Lock()
	r.svc.Hub.gen++
	r.svc.Hub.mu.Unlock()
	if n := read(context.Background()); n != 0 {
		t.Fatalf("%d terminal records from a feed following another origin, want 0", n)
	}
}

func waitUntil(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
