package jobwatch

import (
	"context"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestAllCannotFireOnAPartialView is the bug hiding behind the queue
// limit. A truncated read discovers only the first QueueLimit jobs, and
// only those enter the tracked set -- so "all done" would fire as soon
// as the visible ones finished, reporting that everything was done while
// thousands of jobs nobody looked at were still running.
//
// "All" is a claim about a set. It cannot be made about a set that was
// never fully seen, however many of the jobs in hand are finished.
func TestAllCannotFireOnAPartialView(t *testing.T) {
	w := mustWatch(t, EventDone, ModeAll)
	w.Tracked = []JobID{{42, 0}, {42, 1}}

	// Every job we know about has finished...
	complete := Snapshot{History: []*classad.ClassAd{historyAd(0, completed, 0), historyAd(1, completed, 0)}}
	if got := w.Evaluate(complete); !got.Fires {
		t.Fatal("with a complete read, all-finished should fire")
	}

	// ...but the read was cut short, so there may be more.
	partial := complete
	partial.QueueTruncated = true
	got := w.Evaluate(partial)
	if got.Fires {
		t.Error("\"all done\" fired on a truncated read; the jobs beyond the limit were never looked at")
	}
	if !got.Incomplete {
		t.Error("the caller is not told its watch covers only a sample, so it cannot narrow the constraint")
	}
}

// TestAnyStillFiresOnAPartialView: "any" is a claim about one job, and
// seeing that job is enough however much else was cut off. Refusing it
// would make a large queue undetectable rather than merely unbounded.
func TestAnyStillFiresOnAPartialView(t *testing.T) {
	w := mustWatch(t, EventHeld, ModeAny)
	got := w.Evaluate(Snapshot{
		Queue:          []*classad.ClassAd{job(42, 0, held)},
		QueueTruncated: true,
	})
	if !got.Fires {
		t.Error("a held job was seen; \"any held\" should fire whatever else was truncated")
	}
}

// TestTruncationIsReportedThroughThePass: the evaluator has to carry the
// flag onto the watch, or check_watches cannot mention it and the agent
// waits on something that will never fire.
func TestTruncationIsReportedThroughThePass(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	register(t, s, "alice", EventDone, ModeAll)

	src := &fakeSource{
		truncated: true,
		queue:     map[string][]*classad.ClassAd{"alice": {job(42, 0, running)}},
	}
	if _, err := NewEvaluator(s, src, nil).Pass(ctx); err != nil {
		t.Fatal(err)
	}
	live, err := s.Live(ctx)
	if err != nil || len(live) != 1 {
		t.Fatalf("Live: %v", err)
	}
	if !live[0].Incomplete {
		t.Error("the pass did not record that the watch covers only a sample")
	}
}
