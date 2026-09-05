package jobwatch

import "fmt"

// Event is what a watch waits for. It is a closed vocabulary rather than
// a raw expression, for two reasons that point the same way.
//
// The first is correctness. A job that finishes is DESTROYED from the
// queue by the schedd's reaper (schedd.cpp, the COMPLETED/REMOVED branch
// that calls DestroyProc), so it does not sit in JobStatus == 4 waiting
// to be observed. A watch written as "JobStatus == 4" against the queue
// therefore never fires -- the ad disappears instead of changing -- and
// the failure is invisible, indistinguishable from work still running.
// Terminal events have to be resolved across the queue/history boundary,
// and that is not something a caller can express in a constraint.
//
// The second is that the caller is usually a language model, and this
// vocabulary is its instructions. "JobStatus == 4" is exactly what a
// model writes when asked to wait for completion, because it is what the
// documentation says completion means. Offering "done" makes the correct
// thing the obvious thing, and leaves the wrong thing unsayable.
type Event string

const (
	// EventDone means the job left the queue, whatever the outcome. This is
	// what "wait for my jobs to finish" means.
	EventDone Event = "done"
	// EventSucceeded means terminal, exit code 0, not killed by a signal.
	EventSucceeded Event = "succeeded"
	// EventFailed means terminal and not successful -- a nonzero exit, a
	// signal, or removed before finishing.
	EventFailed Event = "failed"
	// EventHeld means in the queue and held, which is the state that needs a
	// human or an agent to do something.
	EventHeld Event = "held"
	// EventRunning means in the queue and executing.
	EventRunning Event = "running"
	// EventCustom is the escape hatch: Condition is a ClassAd expression
	// evaluated against the job ad. Only useful for states where the ad
	// is still in the queue; a terminal condition written this way has
	// the disappearing-ad problem above.
	EventCustom Event = "custom"
)

// EventSpec documents one event for the caller. The MCP tool schema is
// built from this list so the vocabulary an agent is shown and the
// vocabulary the evaluator implements cannot drift apart -- a tool
// description that promises something the code does not do is worse than
// no description, because it is believed.
type EventSpec struct {
	Event   Event
	Summary string
	// NeedsHistory marks events that cannot be decided from the queue
	// alone, because the ad they describe is gone by then.
	NeedsHistory bool
}

// Events is the full vocabulary, in the order worth showing a caller.
var Events = []EventSpec{
	{EventDone, "the job left the queue, whatever the outcome -- this is what \"finished\" means", true},
	{EventSucceeded, "the job finished with exit code 0 and was not killed by a signal", true},
	{EventFailed, "the job finished unsuccessfully: a nonzero exit code, a signal, or removed before it finished", true},
	{EventHeld, "the job is held and needs attention; the hold reason comes back with it", false},
	{EventRunning, "the job started executing", false},
	{EventCustom, "a ClassAd expression you supply as `condition`, evaluated against the job ad while it is in the queue", false},
}

// Terminal reports whether an event can only be decided once the job has
// left the queue.
func (e Event) Terminal() bool {
	switch e {
	case EventDone, EventSucceeded, EventFailed:
		return true
	}
	return false
}

// Valid reports whether e is part of the vocabulary.
func (e Event) Valid() bool {
	for _, spec := range Events {
		if spec.Event == e {
			return true
		}
	}
	return false
}

// DescribeEvents renders the vocabulary for a tool description.
func DescribeEvents() string {
	out := ""
	for _, spec := range Events {
		out += fmt.Sprintf("- %q: %s\n", spec.Event, spec.Summary)
	}
	return out
}

// DefaultMode is the mode an event means when the caller does not say.
//
// It varies by event because the plain-English reading does. "Tell me
// when my jobs are done" means all of them; "tell me if anything fails"
// means any. Defaulting everything to "any" would make the single most
// common call -- waiting for a cluster -- fire on the first job of a
// thousand, which is a wrong answer that looks like a right one.
//
// The chosen mode is echoed back in the tool's response, so a caller
// never has to infer which one it got.
func DefaultMode(e Event) Mode {
	switch e {
	case EventDone, EventSucceeded:
		return ModeAll
	default:
		return ModeAny
	}
}
