package jobwatch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// fakeSource records what it was asked for, which is how the tests
// assert the thing that matters most: the backend query is per-owner and
// never carries a caller-supplied expression.
type fakeSource struct {
	queue     map[string][]*classad.ClassAd
	truncated bool
	history   map[string][]*classad.ClassAd
	askedFor  []string
	// attrsSeen records the projection each read was given, so a test
	// can assert whole ads are never fetched.
	attrsSeen []string
	queueErr  error
	histErr   error
	sinceSeen time.Time
}

func (f *fakeSource) Queue(_ context.Context, owner string, attrs []string, _ int,
	yield func(*classad.ClassAd)) (bool, error) {
	f.askedFor = append(f.askedFor, owner)
	f.attrsSeen = attrs
	if f.queueErr != nil {
		return false, f.queueErr
	}
	for _, ad := range f.queue[owner] {
		yield(ad)
	}
	return f.truncated, nil
}

func (f *fakeSource) History(_ context.Context, owner string, _ []string, since time.Time, _ int,
	yield func(*classad.ClassAd)) error {
	f.sinceSeen = since
	if f.histErr != nil {
		return f.histErr
	}
	for _, ad := range f.history[owner] {
		yield(ad)
	}
	return nil
}

func fired(t *testing.T, s *Store, owner string) []*Watch {
	t.Helper()
	yes := true
	got, err := s.ForOwner(context.Background(), owner, &yes)
	if err != nil {
		t.Fatalf("ForOwner: %v", err)
	}
	return got
}

// TestPassFiresAndRecords is the happy path end to end: a watch whose
// jobs have finished fires once, with what finished.
func TestPassFiresAndRecords(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	register(t, s, "alice", EventDone, ModeAll)

	src := &fakeSource{history: map[string][]*classad.ClassAd{
		"alice": {historyAd(0, completed, 0), historyAd(1, completed, 0)},
	}}
	st, err := NewEvaluator(s, src, nil).Pass(ctx)
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if st.Fired != 1 {
		t.Errorf("Fired = %d, want 1", st.Fired)
	}
	got := fired(t, s, "alice")
	if len(got) != 1 || got[0].MatchedTotal != 2 {
		t.Fatalf("expected one fired watch over two jobs: %+v", got)
	}
	// And it leaves the evaluator's working set.
	if st2, _ := NewEvaluator(s, src, nil).Pass(ctx); st2.Watches != 0 {
		t.Errorf("a fired watch is still being evaluated: %d", st2.Watches)
	}
}

// TestSourceIsAskedPerOwnerNotPerConstraint pins the structural defence.
// A caller-supplied constraint that reached the backend query could
// escape the owner scope; here the query is only ever "this owner's
// jobs", and one query serves every watch that owner has.
func TestSourceIsAskedPerOwnerNotPerConstraint(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for _, ev := range []Event{EventDone, EventHeld, EventRunning} {
		register(t, s, "alice", ev, ModeAny)
	}
	register(t, s, "bob", EventDone, ModeAny)

	src := &fakeSource{}
	if _, err := NewEvaluator(s, src, nil).Pass(ctx); err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if len(src.askedFor) != 2 {
		t.Errorf("the source was queried %d times for 4 watches across 2 owners; want one read per owner: %v",
			len(src.askedFor), src.askedFor)
	}
	seen := map[string]bool{}
	for _, o := range src.askedFor {
		seen[o] = true
	}
	if !seen["alice"] || !seen["bob"] {
		t.Errorf("both owners should have been read: %v", src.askedFor)
	}
}

// TestOneOwnersFailureDoesNotAbandonTheRest. Watches are independent,
// and the likeliest cause of a per-owner failure is that owner's
// authorization -- no reason to stop answering everyone else.
func TestOneOwnersFailureDoesNotAbandonTheRest(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	register(t, s, "alice", EventDone, ModeAny)
	register(t, s, "bob", EventDone, ModeAny)

	src := &failOne{
		fail: "alice",
		inner: &fakeSource{history: map[string][]*classad.ClassAd{
			"bob": {historyAd(0, completed, 0)},
		}},
	}
	st, err := NewEvaluator(s, src, nil).Pass(ctx)
	if err != nil {
		t.Fatalf("the pass itself should not fail: %v", err)
	}
	if st.Errors != 1 {
		t.Errorf("Errors = %d, want alice's failure counted", st.Errors)
	}
	if st.Fired != 1 {
		t.Errorf("Fired = %d; bob's watch should still have been answered", st.Fired)
	}
	if len(fired(t, s, "bob")) != 1 {
		t.Error("bob's watch did not fire despite his data being available")
	}
}

type failOne struct {
	fail  string
	inner *fakeSource
}

func (f *failOne) Queue(ctx context.Context, owner string, attrs []string, limit int,
	yield func(*classad.ClassAd)) (bool, error) {
	if owner == f.fail {
		return false, errors.New("permission denied")
	}
	return f.inner.Queue(ctx, owner, attrs, limit, yield)
}

func (f *failOne) History(ctx context.Context, owner string, attrs []string, since time.Time, limit int,
	yield func(*classad.ClassAd)) error {
	return f.inner.History(ctx, owner, attrs, since, limit, yield)
}

// TestHistoryOutageDegradesRatherThanFreezes: losing history should cost
// the terminal outcomes, not stop the pass. The alternative is that a
// history problem silently freezes every watch, including the ones that
// never needed it.
func TestHistoryOutageDegradesRatherThanFreezes(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	register(t, s, "alice", EventHeld, ModeAny)

	src := &fakeSource{
		queue:   map[string][]*classad.ClassAd{"alice": {job(42, 0, held)}},
		histErr: errors.New("archive unavailable"),
	}
	st, err := NewEvaluator(s, src, nil).Pass(ctx)
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if st.Fired != 1 {
		t.Error("a held watch needs no history and should still fire during a history outage")
	}
}

// TestTruncatedQueueDoesNotReportRunningJobsAsDone is the safety
// property behind QueueTruncated. "Done" partly rests on a tracked job
// no longer being in the queue, and in a truncated read "not here" only
// means "not in the part we got" -- so a paginated backend would report
// a running cluster as finished.
func TestTruncatedQueueDoesNotReportRunningJobsAsDone(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	// ModeAny, so the only thing that can make this fire is the tracked
	// job's absence being treated as evidence. With ModeAll a second
	// still-running job would block the fire for an unrelated reason and
	// the test would pass whether or not truncation was honoured.
	w := register(t, s, "alice", EventDone, ModeAny)
	if err := s.SaveProgress(ctx, w, Outcome{Tracked: []JobID{{42, 0}}}); err != nil {
		t.Fatal(err)
	}

	src := &fakeSource{
		truncated: true,
		queue: map[string][]*classad.ClassAd{
			// 42.0 is absent from this page, and there are more pages.
			"alice": []*classad.ClassAd{job(42, 9, running)},
		},
	}
	st, err := NewEvaluator(s, src, nil).Pass(ctx)
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if st.Fired != 0 {
		t.Error("absence in a truncated queue is not evidence that a job finished; " +
			"a paginated backend would report a running cluster as done")
	}

	// The same absence in a COMPLETE read is evidence.
	src.truncated = false
	src.queue["alice"] = []*classad.ClassAd{job(42, 9, running)}
	if st, _ = NewEvaluator(s, src, nil).Pass(ctx); st.Fired != 1 {
		t.Error("a complete queue read should let the tracked-but-absent job count as done")
	}
}

// TestProgressIsPersistedBetweenPasses: the tracked set is how a watch
// remembers jobs it has seen, and it is what makes the next pass able to
// notice they are gone.
func TestProgressIsPersistedBetweenPasses(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	register(t, s, "alice", EventDone, ModeAll)

	src := &fakeSource{queue: map[string][]*classad.ClassAd{
		"alice": []*classad.ClassAd{job(42, 0, running), job(42, 1, running)},
	}}
	ev := NewEvaluator(s, src, nil)
	if st, err := ev.Pass(ctx); err != nil || st.Fired != 0 {
		t.Fatalf("running jobs should not fire: %+v %v", st, err)
	}

	live, err := s.Live(ctx)
	if err != nil || len(live) != 1 {
		t.Fatalf("Live: %v", err)
	}
	if len(live[0].Tracked) != 2 {
		t.Fatalf("the pass did not remember the jobs it saw: %+v", live[0].Tracked)
	}

	// Now they are gone from a complete queue: done.
	src.queue["alice"] = nil
	if st, _ := ev.Pass(ctx); st.Fired != 1 {
		t.Error("the remembered jobs disappearing should fire the watch")
	}
}

// TestHistoryLookbackCoversJobsThatFinishedFirst: an agent submits, does
// something else, and only then thinks to wait. The watch must see what
// already happened rather than wait forever for it to happen again.
func TestHistoryLookbackCoversJobsThatFinishedFirst(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	register(t, s, "alice", EventDone, ModeAll)

	src := &fakeSource{history: map[string][]*classad.ClassAd{
		"alice": {historyAd(0, completed, 0)},
	}}
	before := time.Now()
	if _, err := NewEvaluator(s, src, nil).Pass(ctx); err != nil {
		t.Fatal(err)
	}
	if !src.sinceSeen.Before(before.Add(-HistoryLookback + time.Minute)) {
		t.Errorf("history was read from %v, which does not look back far enough to find jobs "+
			"that finished before the watch was registered", src.sinceSeen)
	}
	if len(fired(t, s, "alice")) != 1 {
		t.Error("a watch registered after its jobs finished must fire from history")
	}
}

// TestReadsAreProjected is a memory property, and a big one. A whole job
// ad parses to about 12 KB of heap; fetching 20,000 of them costs 231 MB
// held and 677 MB allocated, every pass, per owner -- to evaluate
// expressions that touch about ten attributes. Projected, the same read
// is about 26 MB.
//
// It is also a correctness property: an attribute left out of the
// projection does not error, it evaluates to UNDEFINED, so the watch
// quietly never fires. The projection must cover what the evaluator
// itself reads AND what each watch's expressions reference.
func TestReadsAreProjected(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// A constraint over an attribute outside the base set.
	w, err := New("alice", "l", `ProjectName == "IceCube"`, EventHeld, "", ModeAny)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Register(ctx, w, 0); err != nil {
		t.Fatal(err)
	}
	// And a custom condition over another one.
	w2, err := New("alice", "l2", "ClusterId == 42", EventCustom, "RemoteWallClockTime > 3600", ModeAny)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Register(ctx, w2, 0); err != nil {
		t.Fatal(err)
	}

	src := &fakeSource{}
	if _, err := NewEvaluator(s, src, nil).Pass(ctx); err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if len(src.attrsSeen) == 0 {
		t.Fatal("the read was not projected; whole ads cost roughly nine times the heap")
	}
	got := map[string]bool{}
	for _, a := range src.attrsSeen {
		got[a] = true
	}
	// Everything the evaluator reads for itself.
	for _, want := range BaseAttrs {
		if !got[want] {
			t.Errorf("projection omits %q, which the evaluator reads; the watch would never fire", want)
		}
	}
	// And everything the watches reference.
	for _, want := range []string{"ProjectName", "RemoteWallClockTime"} {
		if !got[want] {
			t.Errorf("projection omits %q, referenced by a watch; its constraint would evaluate to UNDEFINED", want)
		}
	}
}
