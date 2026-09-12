package jobwatch

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestDoneFiresForCompletedJobStillInQueue is the AP40 bug: an OSPool access
// point leaves a completed job in job_queue.log as JobStatus 4 rather than
// destroying it, so it shows in the queue (and the mirror's jobs table) as
// done but never reaches a history row. "done" must resolve from that terminal
// queue ad, not only from Finished(). (Confirmed against the live mirror: the
// job was JobStatus 4 in `jobs`, absent from `history`.)
func TestDoneFiresForCompletedJobStillInQueue(t *testing.T) {
	w := mustWatch(t, EventDone, ModeAll)
	got := w.Evaluate(Snapshot{Queue: []*classad.ClassAd{job(42, 0, completed)}})
	if !got.Fires {
		t.Error("a Completed job still in the queue must fire done")
	}
	if got.Satisfied != 1 || got.Selected != 1 {
		t.Errorf("Satisfied=%d Selected=%d, want 1/1", got.Satisfied, got.Selected)
	}

	// A Removed job in the queue is terminal too.
	w2 := mustWatch(t, EventDone, ModeAll)
	if !w2.Evaluate(Snapshot{Queue: []*classad.ClassAd{job(42, 0, removed)}}).Fires {
		t.Error("a Removed job still in the queue must fire done")
	}
}

// A running job in the queue is NOT terminal and must not fire done.
func TestDoneDoesNotFireForRunningJobInQueue(t *testing.T) {
	w := mustWatch(t, EventDone, ModeAll)
	if w.Evaluate(Snapshot{Queue: []*classad.ClassAd{job(42, 0, running)}}).Fires {
		t.Error("a running job in the queue must not fire done")
	}
}

// succeeded/failed resolve from a terminal queue ad by exit code, same as they
// would from a history row.
func TestSucceededFailedResolveFromQueueTerminal(t *testing.T) {
	queued := func(exit int64) *classad.ClassAd {
		ad := job(42, 0, completed)
		ad.InsertAttr("ExitCode", exit)
		ad.InsertAttrBool("ExitBySignal", false)
		return ad
	}
	if !mustWatch(t, EventSucceeded, ModeAll).Evaluate(Snapshot{Queue: []*classad.ClassAd{queued(0)}}).Fires {
		t.Error("exit-0 completed-in-queue must fire succeeded")
	}
	if mustWatch(t, EventFailed, ModeAll).Evaluate(Snapshot{Queue: []*classad.ClassAd{queued(0)}}).Fires {
		t.Error("exit-0 completed-in-queue must NOT fire failed")
	}
	if !mustWatch(t, EventFailed, ModeAll).Evaluate(Snapshot{Queue: []*classad.ClassAd{queued(1)}}).Fires {
		t.Error("exit-1 completed-in-queue must fire failed")
	}
}

// A job observed terminal in BOTH the queue and history within one pass counts
// once, not twice.
func TestTerminalCountedOnceAcrossQueueAndHistory(t *testing.T) {
	w := mustWatch(t, EventDone, ModeAll)
	got := w.Evaluate(Snapshot{
		Queue:   []*classad.ClassAd{job(42, 0, completed)},
		History: []*classad.ClassAd{historyAd(0, completed, 0)},
	})
	if got.Satisfied != 1 {
		t.Errorf("Satisfied=%d, want 1 (same job in queue and history counts once)", got.Satisfied)
	}
	if got.Selected != 1 {
		t.Errorf("Selected=%d, want 1", got.Selected)
	}
}
