package jobwatch

import (
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// A live stream of what is happening on the access point, built from the
// same mirror watch the per-job subscriptions use.
//
// The dashboard's activity lists answer "what happened in the last hour"
// with a query. This answers "what is happening right now" without one:
// the feed already sees every write to the jobs table, so a transition
// is a comparison between the ad it is about to store and the one it
// already had. Nothing is polled and nothing is queried.
//
// Only transitions are emitted, never every write. On a busy access
// point the jobs table is written many times a second -- an attribute
// update, a resource usage report -- and almost none of those are events
// a person would want to watch. Filtering to status changes is what
// makes this cheap enough to leave open, and it is a property of the
// data rather than a rate limit imposed on top of it.

// ActivityKind is the closed set of transitions the stream reports.
type ActivityKind string

const (
	// ActivitySubmitted is a job entering the queue.
	ActivitySubmitted ActivityKind = "submitted"
	// ActivityStarted is a job beginning to run.
	ActivityStarted ActivityKind = "started"
	// ActivityHeld is a job going on hold, for any reason.
	ActivityHeld ActivityKind = "held"
	// ActivityReleased is a held job returning to the queue, which is
	// almost always somebody fixing something.
	ActivityReleased ActivityKind = "released"
	// ActivityCompleted is a job finishing.
	ActivityCompleted ActivityKind = "completed"
	// ActivityRemoved is a job deleted by its owner or by policy.
	ActivityRemoved ActivityKind = "removed"
)

// ActivityEvent is one transition.
type ActivityEvent struct {
	Kind    ActivityKind
	Cluster int64
	Proc    int64
	Owner   string
	// At is when the transition was observed, not when the job says it
	// happened. The two differ by the mirror's lag, and the observed
	// time is the honest one for a live ticker.
	At int64
	// Detail is the one fact worth showing beside it: the hold reason,
	// the execute host, the exit code.
	Detail string
	// Skipped is how many events this subscriber missed immediately
	// before this one, because it was not reading fast enough. Zero
	// almost always; non-zero says the ticker has a gap rather than
	// letting it look continuous.
	Skipped int
}

// firstSightingWindow decides whether the first upsert seen for a job
// describes something that just happened or a job that has been sitting
// in the queue since before this process connected.
//
// The watch starts from the head of the change log, so the first event
// for a given job is the first time it was WRITTEN since we connected --
// which for a week-old idle job might be a routine attribute update.
// Treating every first sighting as a submission would report a burst of
// thousands of submissions moments after every restart. Instead the ad
// has to say for itself that the thing happened recently.
const firstSightingWindow = 2 * time.Minute

type activitySub struct {
	// owner is the identity this subscriber may see, or "" for all of
	// them. Filtering here rather than in the caller keeps an
	// unprivileged browser from ever receiving another user's job.
	owner string
	ch    chan ActivityEvent
	mu    sync.Mutex
	// skipped counts events dropped because ch was full, to be reported
	// on the next one that fits.
	skipped int
	once    sync.Once
}

// SubscribeActivity follows every transition, optionally filtered to one
// owner. Pass "" for all owners, which is for an administrator only.
//
// The returned cancel must be called or the subscription leaks for the
// life of the process. buf is how many events may queue for a slow
// reader; beyond that the oldest are dropped and counted, because a
// browser tab must never be able to stall the feed the MCP watch
// evaluator reads from.
func (f *Feed) SubscribeActivity(owner string, buf int) (<-chan ActivityEvent, func()) {
	if buf <= 0 {
		buf = 64
	}
	s := &activitySub{owner: owner, ch: make(chan ActivityEvent, buf)}

	f.mu.Lock()
	if f.activitySubs == nil {
		f.activitySubs = make(map[*activitySub]struct{})
	}
	f.activitySubs[s] = struct{}{}
	f.mu.Unlock()

	return s.ch, func() {
		s.once.Do(func() {
			f.mu.Lock()
			delete(f.activitySubs, s)
			f.mu.Unlock()
			close(s.ch)
		})
	}
}

// publishActivityLocked fans one transition out. The caller holds f.mu;
// sends never block, so no subscriber can hold up the feed.
func (f *Feed) publishActivityLocked(ev ActivityEvent) {
	for s := range f.activitySubs {
		if s.owner != "" && s.owner != ev.Owner {
			continue
		}
		s.deliver(ev)
	}
}

func (s *activitySub) deliver(ev ActivityEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ev.Skipped = s.skipped
	select {
	case s.ch <- ev:
		s.skipped = 0
	default:
		// Drop the newest rather than evicting the oldest: the buffer
		// already holds a run of events this reader has not caught up
		// on, and reordering it to make room would hand them a ticker
		// that jumps backwards.
		s.skipped++
	}
}

// activityFor works out what transition, if any, an upsert represents.
// prev is the ad the feed held for this key, nil if it held none.
func (f *Feed) activityFor(prev, next *classad.ClassAd) (ActivityEvent, bool) {
	if next == nil {
		return ActivityEvent{}, false
	}
	id, ok := identOf(next)
	if !ok {
		return ActivityEvent{}, false
	}
	status, ok := next.EvaluateAttrInt("JobStatus")
	if !ok {
		return ActivityEvent{}, false
	}
	now := f.now()
	ev := ActivityEvent{Cluster: id.cluster, Proc: id.proc, At: now.Unix()}
	ev.Owner, _ = next.EvaluateAttrString("Owner")

	recent := func(attr string) bool {
		at, ok := next.EvaluateAttrInt(attr)
		return ok && now.Sub(time.Unix(at, 0)) < firstSightingWindow && at <= now.Unix()+60
	}

	if prev == nil {
		// No previous ad to compare against, so the ad has to say for
		// itself that this just happened. See firstSightingWindow.
		switch {
		case recent("QDate"):
			ev.Kind, ev.Detail = ActivitySubmitted, commandName(next)
		case status == 2 && recent("JobCurrentStartDate"):
			ev.Kind, ev.Detail = ActivityStarted, attrString(next, "RemoteHost")
		case status == 5 && recent("EnteredCurrentStatus"):
			ev.Kind, ev.Detail = ActivityHeld, attrString(next, "HoldReason")
		default:
			return ActivityEvent{}, false
		}
		return ev, true
	}

	was, ok := prev.EvaluateAttrInt("JobStatus")
	if !ok || was == status {
		// The overwhelming majority of writes: an attribute changed and
		// the job is doing exactly what it was doing before.
		return ActivityEvent{}, false
	}
	switch status {
	case 1:
		if was != 5 {
			// Idle after anything but a hold is not a transition worth
			// a line -- a job moving back to idle from transferring,
			// say, is bookkeeping.
			return ActivityEvent{}, false
		}
		ev.Kind = ActivityReleased
	case 2:
		ev.Kind, ev.Detail = ActivityStarted, attrString(next, "RemoteHost")
	case 4:
		ev.Kind, ev.Detail = ActivityCompleted, outcome(next)
	case 5:
		ev.Kind, ev.Detail = ActivityHeld, attrString(next, "HoldReason")
	case 3:
		ev.Kind = ActivityRemoved
	default:
		return ActivityEvent{}, false
	}
	return ev, true
}

// activityForDelete reads the outcome off the last ad the feed kept.
//
// A job leaves the queue moments after the schedd records how it went,
// and the delete event itself carries nothing. Where the last ad does
// not say, this stays quiet: a job that vanished for an unknown reason
// is not evidence that it completed, and inventing that would put a
// success on the ticker for something that may have failed.
func (f *Feed) activityForDelete(last *classad.ClassAd) (ActivityEvent, bool) {
	if last == nil {
		return ActivityEvent{}, false
	}
	id, ok := identOf(last)
	if !ok {
		return ActivityEvent{}, false
	}
	status, ok := last.EvaluateAttrInt("JobStatus")
	if !ok {
		return ActivityEvent{}, false
	}
	ev := ActivityEvent{Cluster: id.cluster, Proc: id.proc, At: f.now().Unix()}
	ev.Owner, _ = last.EvaluateAttrString("Owner")
	switch status {
	case 4:
		ev.Kind, ev.Detail = ActivityCompleted, outcome(last)
	case 3:
		ev.Kind = ActivityRemoved
	default:
		return ActivityEvent{}, false
	}
	return ev, true
}

func attrString(ad *classad.ClassAd, name string) string {
	v, _ := ad.EvaluateAttrString(name)
	return v
}

// commandName is the executable's base name, which is what identifies a
// submission at a glance; the full path is mostly the submitter's home
// directory repeated on every line.
func commandName(ad *classad.ClassAd) string {
	cmd, _ := ad.EvaluateAttrString("Cmd")
	if cmd == "" {
		return ""
	}
	return path.Base(cmd)
}

// outcome renders how a finished job went.
func outcome(ad *classad.ClassAd) string {
	if sig, ok := ad.EvaluateAttrBool("ExitBySignal"); ok && sig {
		return "killed by a signal"
	}
	if code, ok := ad.EvaluateAttrInt("ExitCode"); ok {
		if code == 0 {
			return "exit 0"
		}
		return "exit " + strconv.FormatInt(code, 10)
	}
	return ""
}
