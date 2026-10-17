package jobwatch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// Absence across access points: the evaluator's side of the rule. The
// source (webapi/multiap) decides which APs a read vouches for; these
// tests drive the evaluator with that decision fixed and check what it
// does with it.

// apAd is proc 0 of a cluster on an access point, as a federation hub row carries it.
func apAd(schedd string, cluster, status int64) *classad.ClassAd {
	ad := classad.New()
	ad.InsertAttrString("ScheddName", schedd)
	ad.InsertAttr("ClusterId", cluster)
	ad.InsertAttr("ProcId", int64(0))
	ad.InsertAttr("JobStatus", status)
	ad.InsertAttrString("Owner", "alice")
	return ad
}

// coveredSource is a multi-AP source: a queue, a history, and the
// coverage the read returns, all fixed by the test between passes.
type coveredSource struct {
	mu      sync.Mutex
	queue   []*classad.ClassAd
	history []*classad.ClassAd
	// vouch is the APs the read vouches for; asOf computes each one's
	// time from the read's time.
	vouch    map[string]bool
	lag      time.Duration
	now      func() time.Time
	queueErr error
	// origin is the coverage's origin: which of several backends the
	// read came from.
	origin string
	// single, when set, is what Queue (the single-AP entry point) was
	// asked: a multi-AP source must never be read through it.
	single int
}

func (c *coveredSource) Queue(context.Context, string, []string, int, func(*classad.ClassAd)) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.single++
	return false, errors.New("a multi-AP source was read without its coverage")
}

func (c *coveredSource) QueueCovered(_ context.Context, _ string, _ []string, _ int,
	yield func(*classad.ClassAd)) (bool, *Coverage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.queueErr != nil {
		return false, nil, c.queueErr
	}
	cov := NewCoverageFrom(c.origin)
	for ap, ok := range c.vouch {
		if ok {
			cov.Vouch(ap, c.now().Add(-c.lag))
		}
	}
	for _, ad := range c.queue {
		yield(ad)
	}
	return false, cov, nil
}

func (c *coveredSource) History(_ context.Context, _ string, _ []string, _ time.Time, _ int,
	yield func(*classad.ClassAd)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ad := range c.history {
		yield(ad)
	}
	return nil
}

func (c *coveredSource) set(fn func(c *coveredSource)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fn(c)
}

// absenceRig is one owner's watch over 1.0 on two APs, with a clock.
type absenceRig struct {
	t     *testing.T
	store *Store
	eval  *Evaluator
	src   *coveredSource
	clock time.Time
}

const (
	apOne = "ap1.example.org"
	apTwo = "ap2.example.org"
)

func newAbsenceRig(t *testing.T, event Event, mode Mode) *absenceRig {
	t.Helper()
	return newAbsenceRigWith(t, event, mode, "ClusterId == 1")
}

func newAbsenceRigWith(t *testing.T, event Event, mode Mode, constraint string) *absenceRig {
	t.Helper()
	r := &absenceRig{t: t, store: testStore(t), clock: time.Now()}
	r.src = &coveredSource{
		queue: []*classad.ClassAd{apAd(apOne, 1, 2), apAd(apTwo, 1, 2)},
		vouch: map[string]bool{apOne: true, apTwo: true},
		lag:   5 * time.Second,
		now:   func() time.Time { return r.clock },
	}
	r.eval = NewEvaluator(r.store, r.src, nil)
	r.eval.now = func() time.Time { return r.clock }
	w, err := New("alice", "both", constraint, event, "", mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.store.Register(context.Background(), w, 0); err != nil {
		t.Fatal(err)
	}
	return r
}

// pass advances the clock and evaluates.
func (r *absenceRig) pass(advance time.Duration) Stats {
	r.t.Helper()
	r.clock = r.clock.Add(advance)
	st, err := r.eval.Pass(context.Background())
	if err != nil {
		r.t.Fatalf("Pass: %v", err)
	}
	return st
}

func (r *absenceRig) live() *Watch {
	r.t.Helper()
	all, err := r.store.ForOwner(context.Background(), "alice", nil)
	if err != nil || len(all) != 1 {
		r.t.Fatalf("ForOwner: %d watches, %v", len(all), err)
	}
	return all[0]
}

// dropAP2 takes ap2's 1.0 out of the queue.
func (r *absenceRig) dropAP2() {
	r.src.set(func(c *coveredSource) { c.queue = []*classad.ClassAd{apAd(apOne, 1, 2)} })
}

// TestAbsenceFiresOnlyForAVouchedAP is the central rule from the
// evaluator's side: the same 1.0 on two access points is two tracked
// jobs; ap2's leaving fires the watch -- for ap2 alone -- only once the
// read vouches for ap2 and is newer than when 1.0@ap2 was last seen.
func TestAbsenceFiresOnlyForAVouchedAP(t *testing.T) {
	r := newAbsenceRig(t, EventDone, ModeAny)
	r.pass(0)
	w := r.live()
	if len(w.Tracked) != 2 {
		t.Fatalf("tracked %+v, want 1.0 on each AP as two entries", w.Tracked)
	}
	for _, id := range w.Tracked {
		if id.Schedd == "" {
			t.Fatalf("tracked entry %+v has no access point", id)
		}
	}

	// ap2's job leaves, but the read does not vouch for ap2.
	r.dropAP2()
	r.src.set(func(c *coveredSource) { c.vouch[apTwo] = false })
	for i := 0; i < 5; i++ {
		if st := r.pass(time.Minute); st.Fired != 0 {
			t.Fatalf("pass %d fired with ap2 unvouched: its job's absence proves nothing", i)
		}
	}

	// Vouched, but no newer than the job's last sighting: wait.
	r.src.set(func(c *coveredSource) { c.vouch[apTwo] = true; c.lag = 10 * time.Minute })
	if st := r.pass(time.Second); st.Fired != 0 {
		t.Fatal("fired on a read that reflects ap2 only up to before the job was last seen")
	}

	// Vouched and newer: fires, for ap2's 1.0 only.
	r.src.set(func(c *coveredSource) { c.lag = 5 * time.Second })
	if st := r.pass(time.Second); st.Fired != 1 {
		t.Fatalf("fired %d, want 1 once ap2 is vouched for and newer", st.Fired)
	}
	got := r.live()
	if len(got.Matched) != 1 || got.Matched[0].Schedd != apTwo || got.Matched[0].Cluster != 1 {
		t.Fatalf("matched %+v, want only 1.0@%s", got.Matched, apTwo)
	}
	if r.src.single != 0 {
		t.Errorf("the source was read %d times without coverage", r.src.single)
	}
}

// TestAbsenceNeedsANewerReadThanTheLastSighting: the read that finds a
// job gone must reflect the AP from after the job was last seen. A job
// seen a moment ago, missing from a read that only reflects the AP up to
// a minute ago, has not been shown to have left -- the read may simply be
// older data (another hub, one rebuilt from its spokes).
func TestAbsenceNeedsANewerReadThanTheLastSighting(t *testing.T) {
	r := newAbsenceRig(t, EventDone, ModeAny)
	r.src.set(func(c *coveredSource) { c.lag = time.Minute })
	r.pass(0) // both seen at t0
	r.dropAP2()
	// 30 s later the read reflects ap2 only up to t0-30s: older than the
	// sighting.
	if st := r.pass(30 * time.Second); st.Fired != 0 {
		t.Fatal("fired on a read older than the job's last sighting")
	}
	// The sighting is remembered from the read that made it, not
	// re-dated by the passes that missed it: 61 s after it, a read
	// reflecting up to 1 s past it is newer.
	if st := r.pass(31 * time.Second); st.Fired != 1 {
		t.Fatalf("fired %d once a read newer than the last sighting showed the job gone, want 1", st.Fired)
	}
}

// TestRestartedEvaluatorTreatsTheFirstReadAsTheLastSighting: memory of
// when a job was last seen does not survive a restart, and the
// replacement assumes the worst -- the job was there at its first read.
func TestRestartedEvaluatorTreatsTheFirstReadAsTheLastSighting(t *testing.T) {
	r := newAbsenceRig(t, EventDone, ModeAny)
	r.pass(0)
	r.dropAP2()
	// A new evaluator over the same store: no memory.
	r.eval = NewEvaluator(r.store, r.src, nil)
	r.eval.now = func() time.Time { return r.clock }
	r.src.set(func(c *coveredSource) { c.lag = 20 * time.Second })
	if st := r.pass(time.Hour); st.Fired != 0 {
		t.Fatal("a restarted evaluator counted an absence on its first read")
	}
	if st := r.pass(30 * time.Second); st.Fired != 1 {
		t.Fatalf("fired %d once a read newer than the restart's first one showed the job gone, want 1", st.Fired)
	}
}

// TestHistoryFiresWhateverTheCoverage: a history record is terminal
// evidence of its own, so a job whose AP is stale still resolves from it.
func TestHistoryFiresWhateverTheCoverage(t *testing.T) {
	r := newAbsenceRig(t, EventDone, ModeAny)
	r.pass(0)
	r.dropAP2()
	r.src.set(func(c *coveredSource) {
		c.vouch = map[string]bool{}
		c.history = []*classad.ClassAd{apAd(apTwo, 1, 4)}
	})
	if st := r.pass(time.Second); st.Fired != 1 {
		t.Fatalf("fired %d, want the history record for 1.0@%s to fire with no AP vouched for", st.Fired, apTwo)
	}
	got := r.live()
	if len(got.Matched) != 1 || got.Matched[0].Schedd != apTwo || got.Matched[0].Attrs["JobStatus"] != "4" {
		t.Fatalf("matched %+v, want 1.0@%s from its history record", got.Matched, apTwo)
	}
}

// TestHistoryOnOneAPDoesNotFinishTheOther: a history record names its
// AP, so ap2's finished 1.0 says nothing about ap1's.
func TestHistoryOnOneAPDoesNotFinishTheOther(t *testing.T) {
	r := newAbsenceRig(t, EventDone, ModeAll)
	r.pass(0)
	r.dropAP2()
	r.src.set(func(c *coveredSource) { c.history = []*classad.ClassAd{apAd(apTwo, 1, 4)} })
	if st := r.pass(time.Minute); st.Fired != 0 {
		t.Fatal(`an "all" watch fired with ap1's 1.0 still queued`)
	}
	w := r.live()
	if len(w.Tracked) != 2 {
		t.Fatalf("tracked %+v, want two entries", w.Tracked)
	}
}

// TestUnvouchedAbsenceNeverGivesUp: "succeeded" gives up waiting for an
// outcome after a grace period once every job has left -- but a job on an
// AP the read cannot vouch for has not been shown to have left, so the
// grace period never starts and no "undetermined" fires.
func TestUnvouchedAbsenceNeverGivesUp(t *testing.T) {
	r := newAbsenceRig(t, EventSucceeded, ModeAll)
	r.pass(0)
	r.src.set(func(c *coveredSource) { c.queue = nil; c.vouch = map[string]bool{} })
	for i := 0; i < 4; i++ {
		if st := r.pass(UnresolvedOutcomeGrace); st.Fired != 0 {
			t.Fatalf("pass %d: fired on jobs whose APs nothing vouches for", i)
		}
	}
	// With both vouched the absences count, and the grace period runs.
	r.src.set(func(c *coveredSource) { c.vouch = map[string]bool{apOne: true, apTwo: true} })
	r.pass(time.Second)
	if st := r.pass(UnresolvedOutcomeGrace + time.Second); st.Fired != 1 {
		t.Fatalf("fired %d, want the undetermined verdict once both absences are evidence", st.Fired)
	}
	if w := r.live(); !w.Undetermined {
		t.Errorf("fired without the undetermined mark: %+v", w)
	}
}

// TestLegacyEntryWithoutAnAPNeverCountsAsGone: a tracked entry stored
// before access points were recorded cannot be matched to a hub row, so
// it is absent from every read -- and must never count as finished.
func TestLegacyEntryWithoutAnAPNeverCountsAsGone(t *testing.T) {
	r := newAbsenceRig(t, EventDone, ModeAll)
	w := r.live()
	if err := r.store.SaveProgress(context.Background(), w, Outcome{Tracked: []JobID{{Cluster: 7, Proc: 0}}}); err != nil {
		t.Fatal(err)
	}
	r.src.set(func(c *coveredSource) { c.queue = nil })
	for i := 0; i < 3; i++ {
		if st := r.pass(time.Hour); st.Fired != 0 {
			t.Fatalf("pass %d fired on a tracked entry with no access point", i)
		}
	}
}

// TestQueueErrorIsNotAnEmptyQueue: a failed read is a failed pass, not
// "everything left".
func TestQueueErrorIsNotAnEmptyQueue(t *testing.T) {
	r := newAbsenceRig(t, EventDone, ModeAny)
	r.pass(0)
	r.src.set(func(c *coveredSource) { c.queue = nil; c.queueErr = errors.New("the federation hub is unavailable") })
	if st := r.pass(time.Hour); st.Fired != 0 || st.Errors != 1 {
		t.Fatalf("stats %+v: want one error and nothing fired", st)
	}
}

// TestTrackedEntriesCarryTheirAP: the stored form keeps each entry's
// access point, coalesces only within one, and reads back a range stored
// without one as single-AP.
func TestTrackedEntriesCarryTheirAP(t *testing.T) {
	ids := []JobID{
		{Cluster: 1, Proc: 0, Schedd: apTwo}, {Cluster: 1, Proc: 1, Schedd: apTwo},
		{Cluster: 1, Proc: 0, Schedd: apOne}, {Cluster: 1, Proc: 1, Schedd: apOne},
	}
	blob, err := encodeTracked(ids)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(blob, `"s":`) != 2 {
		t.Errorf("stored %s: want one range per AP", blob)
	}
	back, err := decodeTracked(blob)
	if err != nil {
		t.Fatal(err)
	}
	want := map[JobID]bool{}
	for _, id := range ids {
		want[id] = true
	}
	if len(back) != len(ids) {
		t.Fatalf("decoded %+v, want %+v", back, ids)
	}
	for _, id := range back {
		if !want[id] {
			t.Errorf("decoded %+v, which was not stored", id)
		}
	}
	old, err := decodeTracked(`[{"c":5,"f":0,"t":1}]`)
	if err != nil || len(old) != 2 || old[0].Schedd != "" {
		t.Errorf("a range stored without an AP decoded as %+v, %v", old, err)
	}
}

// TestSingleAPFoldIgnoresARecordedAP: a server with one schedd reading a
// watch a multi-AP server stored matches its entries to the queue on
// cluster.proc; an entry it cannot match would otherwise be absent from
// every read, which with one schedd means finished.
func TestSingleAPFoldIgnoresARecordedAP(t *testing.T) {
	w, err := New("alice", "", "ClusterId == 1", EventDone, "", ModeAll)
	if err != nil {
		t.Fatal(err)
	}
	w.Tracked = []JobID{{Cluster: 1, Proc: 0, Schedd: apOne}}
	q := classad.New()
	q.InsertAttr("ClusterId", int64(1))
	q.InsertAttr("ProcId", int64(0))
	q.InsertAttr("JobStatus", int64(2))
	out := w.Evaluate(Snapshot{Queue: []*classad.ClassAd{q}})
	if out.Fires || out.Selected != 1 {
		t.Fatalf("outcome %+v: the queued job should be recognised as the tracked one", out)
	}
}

// TestFeedDeparturesNeedEvidence: a delete on a federation hub is also
// an AP being retired or reconciled, and a job that leaves while running
// or held has not been shown to have finished: only a last ad that says
// completed or removed makes a departure.
func TestFeedDeparturesNeedEvidence(t *testing.T) {
	f := warmFeed(t)
	f.Apply(upsert("k1", apAd(apOne, 1, 2)))
	f.Apply(upsert("k2", apAd(apTwo, 1, 5)))
	f.Apply(upsert("k3", apAd(apTwo, 2, 4)))
	f.Apply(upsert("k4", apAd(apOne, 3, 3)))
	for _, k := range []string{"k1", "k2", "k3", "k4"} {
		f.Apply(del(k))
	}
	got := map[string]bool{}
	for _, d := range f.Departures("alice", time.Now().Add(-time.Minute)) {
		got[fmt.Sprintf("%d.%d@%s", d.Cluster, d.Proc, d.Schedd)] = true
	}
	if len(got) != 2 || !got["2.0@"+apTwo] || !got["3.0@"+apOne] {
		t.Fatalf("departures %v: want the completed 2.0 and the removed 3.0 only", got)
	}
}

// TestFeedResetIsNotDepartures: a Reset is the source starting over, not
// every job it held leaving.
func TestFeedResetIsNotDepartures(t *testing.T) {
	f := warmFeed(t)
	f.Apply(upsert("k1", apAd(apOne, 1, 4)))
	f.Apply(WatchEvent{Kind: WatchReset})
	if d := f.Departures("alice", time.Now().Add(-time.Minute)); len(d) != 0 {
		t.Fatalf("departures after a Reset: %+v", d)
	}
}

// TestFeedResumeThatCannotOpenStartsOver: a resume the source cannot
// even open drops what the feed held and its cursor, and starts again
// from the head.
func TestFeedResumeThatCannotOpenStartsOver(t *testing.T) {
	f := NewFeed(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var asked [][]byte
	dials := make(chan chan WatchEvent, 4)
	go func() {
		_ = f.RunResumable(ctx, func(_ context.Context, cursor []byte) (<-chan WatchEvent, func(), error) {
			mu.Lock()
			asked = append(asked, append([]byte(nil), cursor...))
			n := len(asked)
			mu.Unlock()
			if n == 2 {
				return nil, nil, errors.New("cursor from another epoch")
			}
			ch := make(chan WatchEvent, 8)
			dials <- ch
			return ch, func() {}, nil
		})
	}()
	first := <-dials
	first <- WatchEvent{Kind: WatchUpsert, Key: "k", AdText: exitAd(1, 0, 4, 0).MarshalOld(), Cursor: []byte("c1")}
	close(first)
	third := <-dials
	// The job's last ad went with the reset: its delete records nothing.
	third <- WatchEvent{Kind: WatchDelete, Key: "k", Cursor: []byte("c2")}
	third <- WatchEvent{Kind: WatchUpsert, Key: "sentinel", AdText: exitAd(2, 0, 2, 0).MarshalOld(), Cursor: []byte("c3")}
	waitUntil(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.live["sentinel"] != nil
	})
	if n := len(f.Terminal("alice", time.Now().Add(-time.Hour))); n != 0 {
		t.Errorf("%d terminal records survived a resume that could not open", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) < 3 || string(asked[1]) != "c1" || len(asked[2]) != 0 {
		t.Errorf("dialed with cursors %q, want none, c1, then none", asked)
	}
}

// TestFeedKeepsOnlyWhatItReads: the feed's copy of a job holds FeedAttrs
// and the live watches' attributes; a subscriber still gets the whole ad.
func TestFeedKeepsOnlyWhatItReads(t *testing.T) {
	f := warmFeed(t)
	f.Keep = func() []string { return []string{"JobBatchName", "RequestMemory"} }
	ad := apAd(apOne, 1, 2)
	ad.InsertAttrString("JobBatchName", "b")
	if err := ad.Set("RequestMemory", mustExpr(t, "ifThenElse(MemoryUsage =!= undefined, MemoryUsage, 2048)")); err != nil {
		t.Fatal(err)
	}
	if err := ad.Set("MemoryUsage", mustExpr(t, "ResidentSetSize / 1024")); err != nil {
		t.Fatal(err)
	}
	ad.InsertAttr("ResidentSetSize", 1024*489)
	ad.InsertAttrString("Environment", "A=1 B=2")
	ch, cancel := f.Subscribe(1, 0)
	defer cancel()
	f.Apply(upsert("k", ad))
	if c := <-ch; c.View == nil {
		t.Fatal("no update delivered")
	} else if _, ok := c.View.Get("Environment"); !ok {
		t.Error("the subscriber's ad was projected")
	}
	f.mu.Lock()
	kept := f.live["k"]
	f.mu.Unlock()
	if _, ok := kept.Lookup("Environment"); ok {
		t.Error("the feed kept an attribute nothing reads")
	}
	for _, a := range []string{"JobBatchName", "ScheddName", "JobStatus", "ClusterId"} {
		if _, ok := kept.Lookup(a); !ok {
			t.Errorf("the feed dropped %s", a)
		}
	}
	// What a kept expression refers to is kept with it.
	if v, ok := kept.EvaluateAttrInt("RequestMemory"); !ok || v != 489 {
		t.Errorf("RequestMemory = %d, %v on the feed's copy, want 489", v, ok)
	}
}

func mustExpr(t *testing.T, text string) *classad.Expr {
	t.Helper()
	e, err := classad.ParseExpr(text)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// TestFeedRecordResolvesOnlyTrackedJobs: a terminal record from the feed
// is a projection, so it resolves a job the watch already tracks and is
// never re-matched against the constraint to select a new one.
func TestFeedRecordResolvesOnlyTrackedJobs(t *testing.T) {
	w, err := New("alice", "", `JobBatchName =!= "skip"`, EventDone, "", ModeAny)
	if err != nil {
		t.Fatal(err)
	}
	record := func(cluster int64) *classad.ClassAd {
		ad := exitAd(cluster, 0, 4, 0)
		ad.InsertAttrBool(FeedRecordAttr, true)
		return ad
	}
	if out := w.Evaluate(Snapshot{History: []*classad.ClassAd{record(9)}}); out.Fires || out.Selected != 0 {
		t.Fatalf("an untracked job's feed record was matched: %+v", out)
	}
	w.Tracked = []JobID{{Cluster: 9}}
	if out := w.Evaluate(Snapshot{History: []*classad.ClassAd{record(9)}}); !out.Fires {
		t.Fatalf("a tracked job's feed record did not resolve it: %+v", out)
	}
}

// TestLegacyEntryResolvesFromAnUnambiguousHistoryRecord: a tracked entry
// stored without an access point completes from a history record when
// exactly one access point has that cluster.proc; with two it waits.
func TestLegacyEntryResolvesFromAnUnambiguousHistoryRecord(t *testing.T) {
	for _, tc := range []struct {
		name    string
		history []*classad.ClassAd
		queue   []*classad.ClassAd
		fires   bool
	}{
		{"one AP's record", []*classad.ClassAd{apAd(apTwo, 7, 4)}, nil, true},
		{"two APs' records", []*classad.ClassAd{apAd(apOne, 7, 4), apAd(apTwo, 7, 4)}, nil, false},
		{"one record, the id queued on another AP", []*classad.ClassAd{apAd(apTwo, 7, 4)}, []*classad.ClassAd{apAd(apOne, 7, 2)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newAbsenceRigWith(t, EventDone, ModeAll, "ClusterId == 7")
			w := r.live()
			if err := r.store.SaveProgress(context.Background(), w, Outcome{Tracked: []JobID{{Cluster: 7, Proc: 0}}}); err != nil {
				t.Fatal(err)
			}
			r.src.set(func(c *coveredSource) { c.queue, c.history = tc.queue, tc.history })
			st := r.pass(time.Minute)
			if fired := st.Fired == 1; fired != tc.fires {
				t.Fatalf("fired=%v, want %v (tracked %+v)", fired, tc.fires, r.live().Tracked)
			}
		})
	}
}

// TestFeedResumesFromItsCursor: after a dropped stream the feed asks for
// the changes since the last event it applied, keeping what it held, so
// a delete that happened in the gap still finds the job's last ad. A
// resume the source cannot honour is a Reset, which clears.
func TestFeedResumesFromItsCursor(t *testing.T) {
	f := NewFeed(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var asked [][]byte
	dials := make(chan chan WatchEvent, 4)
	go func() {
		_ = f.RunResumable(ctx, func(_ context.Context, cursor []byte) (<-chan WatchEvent, func(), error) {
			mu.Lock()
			asked = append(asked, append([]byte(nil), cursor...))
			mu.Unlock()
			ch := make(chan WatchEvent, 8)
			dials <- ch
			return ch, func() {}, nil
		})
	}()

	first := <-dials
	ad := exitAd(1, 0, 4, 0)
	first <- WatchEvent{Kind: WatchUpsert, Key: "k", AdText: ad.MarshalOld(), Cursor: []byte("c1")}
	close(first) // the stream drops

	second := <-dials
	second <- WatchEvent{Kind: WatchDelete, Key: "k", Cursor: []byte("c2")}
	waitUntil(t, func() bool { return len(f.Terminal("alice", time.Now().Add(-time.Minute))) == 1 })

	mu.Lock()
	if len(asked) != 2 || len(asked[0]) != 0 || string(asked[1]) != "c1" {
		t.Errorf("dialed with cursors %q, want none and then c1", asked)
	}
	mu.Unlock()

	// The source cannot resume: a Reset, then its table again.
	second <- WatchEvent{Kind: WatchReset}
	waitUntil(t, func() bool { return len(f.Terminal("alice", time.Now().Add(-time.Minute))) == 0 })
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestAbsenceOriginChangeReearns: the source's reads move to another
// backend (a second federation hub) and ap2's 1.0 is missing there. The
// read vouches for ap2 and is newer than the job's last sighting -- but
// that sighting was on the other backend, so it is forgotten: the first
// read of the new origin counts as the last sighting, and only a later
// read of that origin, newer than it, fires.
func TestAbsenceOriginChangeReearns(t *testing.T) {
	r := newAbsenceRig(t, EventDone, ModeAny)
	r.src.set(func(c *coveredSource) { c.origin = "hub-a/0" })
	r.pass(0)
	if w := r.live(); len(w.Tracked) != 2 {
		t.Fatalf("tracked %+v, want 1.0 on each AP", w.Tracked)
	}
	r.dropAP2()
	r.src.set(func(c *coveredSource) { c.origin = "hub-b/1" })
	if st := r.pass(time.Minute); st.Fired != 0 {
		t.Fatal("fired on the first read of a new origin, from a sighting on the old one")
	}
	if st := r.pass(time.Minute); st.Fired != 1 {
		t.Fatalf("fired %d on the second read of the new origin, want 1", st.Fired)
	}
}

// TestAbsenceSameOriginKeepsMemory: reads of one origin keep the memory,
// so a job that leaves fires on the first read newer than its sighting,
// exactly as with a source that names no origin.
func TestAbsenceSameOriginKeepsMemory(t *testing.T) {
	r := newAbsenceRig(t, EventDone, ModeAny)
	r.src.set(func(c *coveredSource) { c.origin = "hub-a/0" })
	r.pass(0)
	r.dropAP2()
	if st := r.pass(time.Minute); st.Fired != 1 {
		t.Fatalf("fired %d on a newer read of the same origin, want 1", st.Fired)
	}
}

// pinningSource is a coveredSource that pins each pass (PassPinner) and
// records whether every read of a pass carried the pass's pin.
type pinningSource struct {
	*coveredSource
	pins     int
	unpinned int
}

type passPinKey struct{}

func (p *pinningSource) PinPass(ctx context.Context) context.Context {
	p.mu.Lock()
	p.pins++
	n := p.pins
	p.mu.Unlock()
	return context.WithValue(ctx, passPinKey{}, n)
}

func (p *pinningSource) check(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n, _ := ctx.Value(passPinKey{}).(int); n == 0 || n != p.pins {
		p.unpinned++
	}
}

func (p *pinningSource) QueueCovered(ctx context.Context, owner string, attrs []string, limit int,
	yield func(*classad.ClassAd)) (bool, *Coverage, error) {
	p.check(ctx)
	return p.coveredSource.QueueCovered(ctx, owner, attrs, limit, yield)
}

func (p *pinningSource) History(ctx context.Context, owner string, attrs []string, since time.Time, limit int,
	yield func(*classad.ClassAd)) error {
	p.check(ctx)
	return p.coveredSource.History(ctx, owner, attrs, since, limit, yield)
}

// TestPassPinnerPinsEveryRead: a PassPinner is pinned once per owner
// pass, and the pass's queue and history reads both carry that pin.
func TestPassPinnerPinsEveryRead(t *testing.T) {
	r := newAbsenceRig(t, EventDone, ModeAny)
	src := &pinningSource{coveredSource: r.src}
	r.eval = NewEvaluator(r.store, src, nil)
	r.eval.now = func() time.Time { return r.clock }
	for i := 0; i < 3; i++ {
		r.pass(time.Minute)
	}
	if src.pins != 3 || src.unpinned != 0 {
		t.Fatalf("pins %d, unpinned reads %d: want 3 passes each read under its own pin", src.pins, src.unpinned)
	}
}

// TestFeedOriginChangeStartsOver: the stream reopens on another origin
// (a second federation hub). Everything the feed held came from the
// first -- a departure, the last ad of a completed job still queued
// there -- and is dropped, as on a Reset: no departures, and the new
// origin deleting a key the old one held reports nothing. The dialer is
// told the old origin with its cursor, so it can tell the cursor is not
// the new one's.
func TestFeedOriginChangeStartsOver(t *testing.T) {
	f := NewFeed(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var asked []Resume
	origins := []string{"hub-a/0", "hub-b/1"}
	dials := make(chan chan WatchEvent, 4)
	go func() {
		_ = f.RunResumableFrom(ctx, func(_ context.Context, from Resume) (<-chan WatchEvent, func(), string, error) {
			mu.Lock()
			asked = append(asked, Resume{Cursor: append([]byte(nil), from.Cursor...), Origin: from.Origin})
			origin := origins[min(len(asked)-1, len(origins)-1)]
			mu.Unlock()
			ch := make(chan WatchEvent, 8)
			dials <- ch
			return ch, func() {}, origin, nil
		})
	}()
	since := time.Now().Add(-time.Hour)
	a := <-dials
	a <- WatchEvent{Kind: WatchUpsert, Key: "k1", AdText: exitAd(1, 0, 4, 0).MarshalOld(), Cursor: []byte("a1")}
	a <- WatchEvent{Kind: WatchUpsert, Key: "k2", AdText: exitAd(2, 0, 4, 0).MarshalOld(), Cursor: []byte("a2")}
	a <- WatchEvent{Kind: WatchDelete, Key: "k2", Cursor: []byte("a3")}
	waitUntil(t, func() bool { return len(f.Departures("alice", since)) == 1 })
	if f.Origin() != "hub-a/0" {
		t.Fatalf("origin %q, want hub-a/0", f.Origin())
	}
	close(a)
	b := <-dials
	b <- WatchEvent{Kind: WatchDelete, Key: "k1", Cursor: []byte("b1")}
	b <- WatchEvent{Kind: WatchUpsert, Key: "sentinel", AdText: exitAd(3, 0, 2, 0).MarshalOld(), Cursor: []byte("b2")}
	waitUntil(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.live["sentinel"] != nil
	})
	if d := f.Departures("alice", since); len(d) != 0 {
		t.Fatalf("departures after moving to another origin: %+v", d)
	}
	if n := len(f.Terminal("alice", since)); n != 0 {
		t.Fatalf("%d terminal records survived moving to another origin", n)
	}
	if f.Origin() != "hub-b/1" {
		t.Fatalf("origin %q, want hub-b/1", f.Origin())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 2 || asked[0].Cursor != nil || asked[0].Origin != "" || string(asked[1].Cursor) != "a3" || asked[1].Origin != "hub-a/0" {
		t.Fatalf("dialed with %+v, want nothing, then a3 from hub-a/0", asked)
	}
}
