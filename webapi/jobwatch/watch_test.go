package jobwatch

import (
	"errors"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

const (
	idle      = 1
	running   = 2
	removed   = 3
	completed = 4
	held      = 5
)

func job(cluster, proc, status int64) *classad.ClassAd {
	ad := classad.New()
	ad.InsertAttr("ClusterId", cluster)
	ad.InsertAttr("ProcId", proc)
	ad.InsertAttr("JobStatus", status)
	ad.InsertAttrString("Owner", "alice")
	return ad
}

// historyAd builds a history row for cluster 42, which is what every
// test here constrains on.
func historyAd(proc, status, exitCode int64) *classad.ClassAd {
	ad := job(42, proc, status)
	ad.InsertAttr("ExitCode", exitCode)
	ad.InsertAttrBool("ExitBySignal", false)
	return ad
}

func mustWatch(t *testing.T, event Event, mode Mode) *Watch {
	t.Helper()
	w, err := New("alice", "test", "ClusterId == 42", event, "", mode)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return w
}

// TestDoneSurvivesTheJobLeavingTheQueue is the bug the vocabulary
// exists for. The schedd DESTROYS a finished job from the queue
// (schedd.cpp, the COMPLETED/REMOVED branch calling DestroyProc), so it
// never sits in JobStatus == 4 to be observed. A watch written the
// obvious way -- and "JobStatus == 4" is exactly what a language model
// writes when asked to wait for completion -- would watch the ad vanish
// and never fire.
func TestDoneSurvivesTheJobLeavingTheQueue(t *testing.T) {
	w := mustWatch(t, EventDone, ModeAll)

	// Tick 1: running. Not done, and now tracked.
	got := w.Evaluate(Snapshot{Queue: []*classad.ClassAd{job(42, 0, running)}})
	if got.Fires {
		t.Fatal("a running job is not done")
	}
	if len(got.Tracked) != 1 {
		t.Fatalf("the job should be tracked after being seen: %+v", got.Tracked)
	}
	w.Tracked = got.Tracked

	// Tick 2: the job is gone from the queue and its history row has not
	// landed yet. The ad has disappeared, which is the event.
	got = w.Evaluate(Snapshot{})
	if !got.Fires {
		t.Error("a tracked job absent from the queue has finished; \"done\" must fire " +
			"without waiting for history, or it never fires at all")
	}
	if got.Selected != 1 {
		t.Errorf("Selected = %d, want the remembered job (a drained cluster is not an empty watch)", got.Selected)
	}
}

// TestDoneFiresFromHistoryAlone: an agent that registers a watch after
// the jobs have already finished has nothing tracked, so the history row
// is the only evidence. It has to be enough.
func TestDoneFiresFromHistoryAlone(t *testing.T) {
	w := mustWatch(t, EventDone, ModeAll)
	got := w.Evaluate(Snapshot{History: []*classad.ClassAd{historyAd(0, completed, 0)}})
	if !got.Fires {
		t.Error("a watch registered after the fact must fire from history")
	}
}

// TestModeAllNeedsANonEmptySet is the vacuous-truth trap: "all finished"
// is trivially true of no jobs, so a watch registered before submission
// -- or with a typo'd constraint -- would fire instantly and report
// success for work that never ran.
func TestModeAllNeedsANonEmptySet(t *testing.T) {
	w := mustWatch(t, EventDone, ModeAll)

	if w.Evaluate(Snapshot{}).Fires {
		t.Error("an empty queue and empty history must not satisfy \"all done\"")
	}
	if w.Evaluate(Snapshot{Queue: []*classad.ClassAd{job(7, 0, completed)}}).Fires {
		t.Error("only other clusters matched; must not fire")
	}
}

// TestModeAllWaitsForTheLastJob: a cluster is done when the last one is.
// The half that has already drained out of the queue must stay counted.
func TestModeAllWaitsForTheLastJob(t *testing.T) {
	w := mustWatch(t, EventDone, ModeAll)
	w.Tracked = []JobID{{42, 0}, {42, 1}, {42, 2}}

	got := w.Evaluate(Snapshot{
		Queue:   []*classad.ClassAd{job(42, 1, running)},
		History: []*classad.ClassAd{historyAd(0, completed, 0), historyAd(2, completed, 0)},
	})
	if got.Fires {
		t.Error("one job still running; \"all done\" must not fire")
	}
	if got.Selected != 3 || got.Satisfied != 2 {
		t.Errorf("progress = %d/%d, want 2/3 -- the counts are what make a not-yet answer useful",
			got.Satisfied, got.Selected)
	}

	got = w.Evaluate(Snapshot{History: []*classad.ClassAd{
		historyAd(0, completed, 0), historyAd(1, completed, 0), historyAd(2, completed, 0),
	}})
	if !got.Fires {
		t.Error("every job finished; should fire")
	}
}

// TestSucceededAndFailedPartitionTerminal. Absence from the queue says a
// job ended, not how it ended, so these two need the history row -- and
// anything that is not a clean exit 0 has to count as failure, or a job
// killed by a signal is quietly reported as success.
func TestSucceededAndFailedPartitionTerminal(t *testing.T) {
	signalled := historyAd(1, completed, 0)
	signalled.InsertAttrBool("ExitBySignal", true)
	noCode := job(42, 3, completed)

	cases := []struct {
		name      string
		ad        *classad.ClassAd
		succeeded bool
	}{
		{"exit 0", historyAd(0, completed, 0), true},
		{"killed by a signal", signalled, false},
		{"nonzero exit", historyAd(2, completed, 1), false},
		{"no exit code at all", noCode, false},
		{"removed before finishing", historyAd(4, removed, 0), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, event := range []Event{EventSucceeded, EventFailed} {
				w := mustWatch(t, event, ModeAny)
				got := w.Evaluate(Snapshot{History: []*classad.ClassAd{c.ad}})
				want := c.succeeded == (event == EventSucceeded)
				if got.Fires != want {
					t.Errorf("%s: fires = %v, want %v", event, got.Fires, want)
				}
			}
		})
	}

	// Gone from the queue with no history row is "done" but is neither
	// succeeded nor failed -- we do not know yet, and guessing would
	// report an outcome that was never observed.
	for _, event := range []Event{EventSucceeded, EventFailed} {
		w := mustWatch(t, event, ModeAny)
		w.Tracked = []JobID{{42, 0}}
		if w.Evaluate(Snapshot{}).Fires {
			t.Errorf("%s fired on absence alone; the outcome is not known without history", event)
		}
	}
}

// TestHeldCarriesTheReason: being told a job is held without the reason
// costs another round trip for the only fact that makes it actionable.
func TestHeldCarriesTheReason(t *testing.T) {
	ad := job(42, 0, held)
	ad.InsertAttrString("HoldReason", "Failed to open input file")
	ad.InsertAttr("HoldReasonCode", 13)

	w := mustWatch(t, EventHeld, ModeAny)
	got := w.Evaluate(Snapshot{Queue: []*classad.ClassAd{ad, job(42, 1, running)}})
	if !got.Fires || len(got.Matched) != 1 {
		t.Fatalf("expected one held match: %+v", got)
	}
	m := got.Matched[0]
	if m.Cluster != 42 || m.Proc != 0 {
		t.Errorf("job identity wrong: %+v", m)
	}
	if m.Attrs["HoldReason"] != "Failed to open input file" || m.Attrs["HoldReasonCode"] != "13" {
		t.Errorf("hold reason not carried: %+v", m.Attrs)
	}
}

// TestAnyFiresOnceForTheWholeSet: an agent watching a 10k cluster wants
// one answer naming what failed, not one wakeup per job.
func TestAnyFiresOnceForTheWholeSet(t *testing.T) {
	w := mustWatch(t, EventFailed, ModeAny)
	got := w.Evaluate(Snapshot{History: []*classad.ClassAd{
		historyAd(0, completed, 0), historyAd(1, completed, 1), historyAd(2, completed, 2),
	}})
	if !got.Fires {
		t.Fatal("two failures should fire")
	}
	if got.Satisfied != 2 || len(got.Matched) != 2 {
		t.Errorf("both failures should be in one outcome: satisfied=%d matched=%d", got.Satisfied, len(got.Matched))
	}
}

// TestMatchedIsCappedButCounted: a fired watch is a notification, not a
// query result -- but the count has to survive the cap or "everything
// failed" loses the "everything".
func TestMatchedIsCappedButCounted(t *testing.T) {
	w := mustWatch(t, EventDone, ModeAny)
	var hist []*classad.ClassAd
	for i := int64(0); i < MaxMatched*3; i++ {
		hist = append(hist, historyAd(i, completed, 0))
	}
	got := w.Evaluate(Snapshot{History: hist})
	if len(got.Matched) != MaxMatched {
		t.Errorf("Matched = %d, want capped at %d", len(got.Matched), MaxMatched)
	}
	if got.Satisfied != MaxMatched*3 {
		t.Errorf("Satisfied = %d, want the true total %d beside the capped list", got.Satisfied, MaxMatched*3)
	}
}

// TestNewRejectsWhatWouldNeverFire. A watch that cannot fire is
// indistinguishable from one still waiting, so the caller waits forever
// on a typo. Reject at registration instead.
func TestNewRejectsWhatWouldNeverFire(t *testing.T) {
	cases := []struct {
		name       string
		owner      string
		constraint string
		event      Event
		condition  string
		mode       Mode
		want       error
	}{
		{"no owner", "", "ClusterId == 1", EventDone, "", ModeAny, ErrNoOwner},
		{"no constraint", "alice", "", EventDone, "", ModeAny, ErrNoConstraint},
		{"unknown event", "alice", "ClusterId == 1", Event("finished"), "", ModeAny, ErrUnknownEvent},
		{"custom without a condition", "alice", "ClusterId == 1", EventCustom, "", ModeAny, ErrNoCondition},
		{"condition without custom", "alice", "ClusterId == 1", EventDone, "JobStatus == 5", ModeAny, ErrHasCondition},
		{"bad mode", "alice", "ClusterId == 1", EventDone, "", Mode("eventually"), ErrUnknownMode},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(c.owner, "l", c.constraint, c.event, c.condition, c.mode)
			if !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}
		})
	}

	if _, err := New("alice", "l", "ClusterId ==== 1", EventDone, "", ModeAny); err == nil {
		t.Error("an unparseable constraint must be refused, not silently match nothing")
	}
	if _, err := New("alice", "l", "ClusterId == 1", EventCustom, "JobStatus ==== 5", ModeAny); err == nil {
		t.Error("an unparseable custom condition must be refused")
	}

	// The defaults are the common case: wait for everything to finish.
	w, err := New("alice", "l", "ClusterId == 1", "", "", "")
	if err != nil || w.Event != EventDone || w.Mode != ModeAny {
		t.Errorf("defaults should be done/any: %v %q %q", err, w.Event, w.Mode)
	}
}

// TestUnknownEventNamesTheAlternatives: the caller is usually a language
// model, and an error that lists the vocabulary is one it can act on.
func TestUnknownEventNamesTheAlternatives(t *testing.T) {
	_, err := New("alice", "l", "ClusterId == 1", Event("JobStatus == 4"), "", ModeAny)
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"done", "failed", "held", "custom"} {
		if !contains(err.Error(), want) {
			t.Errorf("the error should list %q so the caller can correct itself: %v", want, err)
		}
	}
}

// TestCompileRestoresAStoredWatch: a stored watch is just strings, and
// an uncompiled one must select nothing rather than everything.
func TestCompileRestoresAStoredWatch(t *testing.T) {
	stored := &Watch{Owner: "alice", Constraint: "ClusterId == 42", Event: EventHeld, Mode: ModeAny}
	if stored.Evaluate(Snapshot{Queue: []*classad.ClassAd{job(42, 0, held)}}).Fires {
		t.Error("an uncompiled watch must not select anything")
	}
	if err := stored.Compile(); err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !stored.Evaluate(Snapshot{Queue: []*classad.ClassAd{job(42, 0, held)}}).Fires {
		t.Error("after Compile the watch should evaluate normally")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
