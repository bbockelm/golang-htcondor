package jobwatch

import (
	"context"
	"errors"
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

// apAd is a job on an access point, as a federation hub row carries it.
func apAd(schedd string, cluster, proc, status int64) *classad.ClassAd {
	ad := classad.New()
	ad.InsertAttrString("ScheddName", schedd)
	ad.InsertAttr("ClusterId", cluster)
	ad.InsertAttr("ProcId", proc)
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
	cov := NewCoverage()
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
	r := &absenceRig{t: t, store: testStore(t), clock: time.Now()}
	r.src = &coveredSource{
		queue: []*classad.ClassAd{apAd(apOne, 1, 0, 2), apAd(apTwo, 1, 0, 2)},
		vouch: map[string]bool{apOne: true, apTwo: true},
		lag:   5 * time.Second,
		now:   func() time.Time { return r.clock },
	}
	r.eval = NewEvaluator(r.store, r.src, nil)
	r.eval.now = func() time.Time { return r.clock }
	w, err := New("alice", "both", "ClusterId == 1", event, "", mode)
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
	r.src.set(func(c *coveredSource) { c.queue = []*classad.ClassAd{apAd(apOne, 1, 0, 2)} })
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
		c.history = []*classad.ClassAd{apAd(apTwo, 1, 0, 4)}
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
	r.src.set(func(c *coveredSource) { c.history = []*classad.ClassAd{apAd(apTwo, 1, 0, 4)} })
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
// an AP being retired or reconciled, so a departure counts only if the
// job's last ad says it finished or the hook vouched for the delete.
func TestFeedDeparturesNeedEvidence(t *testing.T) {
	f := warmFeed(t)
	vouch := map[string]bool{apOne: true}
	f.VouchDeparture = func(ad *classad.ClassAd) bool {
		s, _ := ad.EvaluateAttrString("ScheddName")
		return vouch[s]
	}
	f.Apply(upsert("k1", apAd(apOne, 1, 0, 2)))
	f.Apply(upsert("k2", apAd(apTwo, 1, 0, 2)))
	f.Apply(upsert("k3", apAd(apTwo, 2, 0, 4)))
	for _, k := range []string{"k1", "k2", "k3"} {
		f.Apply(del(k))
	}
	got := f.Departures("alice", time.Now().Add(-time.Minute))
	if got[apOne] != 1 || got[apTwo] != 1 {
		t.Fatalf("departures %v: want ap1's vouched delete and ap2's completed job, not ap2's unvouched delete", got)
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
	if len(asked) != 2 || asked[0] != nil && len(asked[0]) != 0 || string(asked[1]) != "c1" {
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
