package jobwatch

import (
	"context"
	"time"
)

// Nudger evaluates an owner's watches when something actually happens to
// their jobs, instead of only when the next sweep comes round.
//
// The sweep is every 30 seconds (DefaultInterval), which sets both the
// latency of every answer and the width of the window a transient state
// can hide in. "Running" is the state that suffers: a job that starts and
// finishes between two sweeps is never sampled in it. The terminal ad
// still says the job ran, so the answer is recoverable after the fact --
// but recovering it after the fact is no use to a caller waiting to be
// told that a long job has started.
//
// The change stream already knows. The Feed follows the mirror's jobs
// table, which scheddsync fills by tailing job_queue.log, so it sees
// every write -- including the ones that exist for 200ms -- and
// activityFor already recognises the start. Until now that went only to
// the dashboard's ticker. This subscribes the evaluator to the same
// signal, so a watch is re-evaluated within the mirror's propagation
// time of the thing it is watching for.
//
// It is a trigger, never evidence. All it does is ask the evaluator to
// look now; the answer still comes from reading the queue and the
// archive, so nothing here can satisfy a watch by itself, and a missed
// or dropped event costs latency rather than correctness. That matters
// because the stream can miss a transition outright: it carries
// committed row versions, and a commit holds one value per key, so a job
// that starts and finishes inside a single mirror commit never has a
// running version to emit. The periodic sweep and the terminal-ad
// evidence remain the answer for those.
type Nudger struct {
	feed  *Feed
	check func(context.Context, string) (int, error)
	logf  func(string, ...any)

	// Delay is how long to let a burst settle before sweeping. A cluster
	// of ten thousand jobs starting produces ten thousand events and has
	// to cost one sweep, not ten thousand: each sweep reads the owner's
	// whole queue, so an un-coalesced nudge would turn a busy submission
	// into a self-inflicted load test.
	Delay time.Duration
	// MinGap bounds how often any one owner can be swept, whatever the
	// stream does. Delay coalesces a burst; this is what holds when the
	// activity is continuous rather than bursty.
	MinGap time.Duration

	now func() time.Time
}

const (
	// DefaultNudgeDelay is short enough to be imperceptible next to the
	// mirror's own lag and long enough to collapse a submission burst.
	DefaultNudgeDelay = 500 * time.Millisecond
	// DefaultNudgeMinGap keeps a continuously busy owner from being swept
	// more than a few times a minute, well inside the periodic sweep.
	DefaultNudgeMinGap = 5 * time.Second
	// nudgeBuffer is the subscription depth. Overflow drops events and
	// costs only latency, so this is sized to absorb a burst rather than
	// to never drop.
	nudgeBuffer = 256
	// ownerForgetAfter prunes the last-swept memory so an access point
	// that has seen many owners does not hold them all forever.
	ownerForgetAfter = 10 * time.Minute
)

// NewNudger wires a feed to an evaluator's per-owner check.
func NewNudger(feed *Feed, check func(context.Context, string) (int, error), logf func(string, ...any)) *Nudger {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Nudger{
		feed:   feed,
		check:  check,
		logf:   logf,
		Delay:  DefaultNudgeDelay,
		MinGap: DefaultNudgeMinGap,
		now:    time.Now,
	}
}

// Run follows the feed until ctx is done.
func (n *Nudger) Run(ctx context.Context) {
	if n.feed == nil || n.check == nil {
		return
	}
	events, cancel := n.feed.SubscribeActivity("", nudgeBuffer)
	defer cancel()

	tick := time.NewTicker(n.Delay)
	defer tick.Stop()

	pending := make(map[string]struct{})
	last := make(map[string]time.Time)

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			// An event with no owner cannot be routed to anyone's
			// watches. The periodic sweep still covers the job.
			if ev.Owner != "" {
				pending[ev.Owner] = struct{}{}
			}
		case <-tick.C:
			n.drain(ctx, pending, last)
		}
	}
}

// drain sweeps every owner whose turn has come, leaving the rest pending
// for a later tick rather than dropping them.
func (n *Nudger) drain(ctx context.Context, pending map[string]struct{}, last map[string]time.Time) {
	now := n.now()
	for owner := range pending {
		if seen, ok := last[owner]; ok && now.Sub(seen) < n.MinGap {
			continue
		}
		delete(pending, owner)
		last[owner] = now
		if _, err := n.check(ctx, owner); err != nil {
			// The periodic sweep will try again; a failed nudge is a
			// slower answer, not a wrong one.
			n.logf("job watches: nudged evaluation failed: %v", err)
		}
		if ctx.Err() != nil {
			return
		}
	}
	for owner, seen := range last {
		if now.Sub(seen) > ownerForgetAfter {
			delete(last, owner)
		}
	}
}
