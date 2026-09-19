package jobwatch

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// ranAd is a completed job carrying the evidence the schedd writes when it
// spawns a shadow. add_shadow_birthdate() puts JobStartDate and
// JobCurrentStartDate straight into the job queue at that moment, so they
// survive into the terminal ad and into history.
func ranAd(proc int64) *classad.ClassAd {
	ad := job(42, proc, completed)
	ad.InsertAttr("JobStartDate", 1750000000)
	ad.InsertAttr("JobCurrentStartDate", 1750000000)
	ad.InsertAttr("NumJobStarts", 1)
	return ad
}

// removedBeforeStarting is a job that left the queue without ever executing.
// NumJobStarts is present and zero, which is what condor_submit writes at
// submission time, and the start dates are absent entirely.
func removedBeforeStarting() *classad.ClassAd {
	ad := job(42, 0, removed)
	ad.InsertAttr("NumJobStarts", 0)
	return ad
}

// TestRunningFiresForAJobThatAlreadyFinished is the reported bug. The
// evaluator samples the queue every couple of seconds, so a job that starts
// and finishes between two passes is never seen in JobStatus 2 -- and a
// "running" watch decided purely on the live sample would then wait out its
// entire timeout for a job that ran to completion long ago.
//
// Observed against a real deployment: the job went to "complete" quickly and
// the running watch never fired.
func TestRunningFiresForAJobThatAlreadyFinished(t *testing.T) {
	for _, tc := range []struct {
		name string
		snap Snapshot
	}{
		// Completed but still sitting in the queue, the OSPool shape.
		{"terminal in queue", Snapshot{Queue: []*classad.ClassAd{ranAd(0)}}},
		// Destroyed from the queue and archived, the ordinary shape.
		{"history row", Snapshot{History: []*classad.ClassAd{ranAd(0)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mustWatch(t, EventRunning, ModeAny).Evaluate(tc.snap)
			if !got.Fires {
				t.Fatal("a job that ran and finished must fire a running watch; the run happened, it was just never sampled")
			}
			if got.Unsatisfiable {
				t.Error("Unsatisfiable set for a job that did run")
			}
			if got.Satisfied != 1 {
				t.Errorf("Satisfied=%d, want 1", got.Satisfied)
			}
		})
	}
}

// Completion alone is enough, with no start attributes at all: a job cannot
// complete without having run. This is the fallback for the universes that
// never spawn a shadow, and for NumJobStarts being written lazily.
func TestRunningFiresOnCompletionWithoutStartAttributes(t *testing.T) {
	got := mustWatch(t, EventRunning, ModeAny).Evaluate(
		Snapshot{History: []*classad.ClassAd{job(42, 0, completed)}})
	// Fires alone is not the assertion: the unsatisfiable path fires too,
	// and "it ran" versus "it never ran" is the entire difference. Both
	// firings look identical if only Fires is checked.
	if !got.Fires || got.Unsatisfiable || got.Satisfied != 1 {
		t.Errorf("a completed job must count as having run even with no start attributes; Fires=%v Unsatisfiable=%v Satisfied=%d",
			got.Fires, got.Unsatisfiable, got.Satisfied)
	}
}

// The other half: a job removed without ever starting did NOT run, and saying
// it did would be a lie an agent acts on. It must resolve as unsatisfiable
// instead -- which still releases the caller, but with the opposite answer.
func TestRunningDoesNotClaimAJobRanWhenItNeverDid(t *testing.T) {
	got := mustWatch(t, EventRunning, ModeAny).Evaluate(
		Snapshot{History: []*classad.ClassAd{removedBeforeStarting()}})
	if got.Satisfied != 0 {
		t.Errorf("Satisfied=%d, want 0: the job never ran", got.Satisfied)
	}
	if !got.Unsatisfiable {
		t.Error("a running watch whose only job was removed before starting must be unsatisfiable")
	}
	if !got.Fires {
		t.Error("an unsatisfiable watch must still fire; leaving the caller blocked on a settled question is the bug")
	}
}

// A watch left waiting for a state that can no longer occur is the failure the
// report is really about: the caller blocks for the full timeout and then gets
// silence, which reads exactly like "still pending".
func TestHeldBecomesUnsatisfiableOnceTheJobsAreGone(t *testing.T) {
	got := mustWatch(t, EventHeld, ModeAny).Evaluate(
		Snapshot{History: []*classad.ClassAd{ranAd(0)}})
	if !got.Unsatisfiable || !got.Fires {
		t.Errorf("a held watch over a finished job must resolve, got Fires=%v Unsatisfiable=%v", got.Fires, got.Unsatisfiable)
	}
}

// "Any" must stay open while a job could still enter the state. Only the
// whole set being gone settles it.
func TestAnyStaysOpenWhileAJobCouldStillRun(t *testing.T) {
	got := mustWatch(t, EventRunning, ModeAny).Evaluate(Snapshot{
		Queue:   []*classad.ClassAd{job(42, 1, idle)},
		History: []*classad.ClassAd{removedBeforeStarting()},
	})
	if got.Fires || got.Unsatisfiable {
		t.Errorf("one job removed does not settle an \"any\" watch while another is idle; Fires=%v Unsatisfiable=%v", got.Fires, got.Unsatisfiable)
	}
}

// "All" is settled by a single job ending without the state: whatever the rest
// of the set does, "all of them" can no longer become true.
func TestAllIsSettledByOneJobThatNeverRan(t *testing.T) {
	got := mustWatch(t, EventRunning, ModeAll).Evaluate(Snapshot{
		Queue:   []*classad.ClassAd{job(42, 1, running)},
		History: []*classad.ClassAd{removedBeforeStarting()},
	})
	if !got.Unsatisfiable || !got.Fires {
		t.Errorf("an \"all\" watch cannot still be pending once one job has ended without running; Fires=%v Unsatisfiable=%v", got.Fires, got.Unsatisfiable)
	}
}

// "All running" over a set of short jobs is the shape that could never work
// before: every job had to be caught in JobStatus 2 within a single pass.
// Reading durable evidence off the terminal ads makes the jobs' runs
// independent of when they were sampled.
func TestAllRunningAcrossJobsThatRanAtDifferentTimes(t *testing.T) {
	got := mustWatch(t, EventRunning, ModeAll).Evaluate(Snapshot{
		Queue:   []*classad.ClassAd{job(42, 2, running)},
		History: []*classad.ClassAd{ranAd(0), ranAd(1)},
	})
	if !got.Fires || got.Unsatisfiable {
		t.Errorf("all three ran; Fires=%v Unsatisfiable=%v Satisfied=%d", got.Fires, got.Unsatisfiable, got.Satisfied)
	}
}

// A truncated read saw only part of the set, so absence is not evidence and no
// verdict can be drawn from it -- the same rule the "all" firing already obeys.
func TestTruncatedReadCannotDeclareAWatchUnsatisfiable(t *testing.T) {
	w := mustWatch(t, EventRunning, ModeAny)
	got := w.Evaluate(Snapshot{History: []*classad.ClassAd{removedBeforeStarting()}, QueueTruncated: true})
	if got.Unsatisfiable {
		t.Error("a partial read must not settle a watch")
	}
}

// The terminal events are answered by the job ending, so ending is not a
// failure mode for them and they must never be marked unsatisfiable.
func TestTerminalEventsAreNeverUnsatisfiable(t *testing.T) {
	for _, ev := range []Event{EventDone, EventSucceeded, EventFailed} {
		got := mustWatch(t, ev, ModeAny).Evaluate(
			Snapshot{History: []*classad.ClassAd{historyAd(0, completed, 0)}})
		if got.Unsatisfiable {
			t.Errorf("%s must not be unsatisfiable", ev)
		}
	}
}

// The evidence attributes have to be in the projection or none of this works:
// a projected read that omits them yields UNDEFINED, everRan says no, and the
// watch waits out its timeout exactly as it did before. The failure is silent,
// which is why it is asserted rather than left to the reader.
func TestProjectionCarriesTheRunEvidence(t *testing.T) {
	attrs := mustWatch(t, EventRunning, ModeAny).ReadAttrs()
	for _, want := range []string{"JobStartDate", "JobCurrentStartDate", "NumJobStarts"} {
		found := false
		for _, a := range attrs {
			if a == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s missing from the projection; everRan cannot see it", want)
		}
	}
}
