package jobwatch

import (
	"context"
	"fmt"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// Source supplies the job ads an evaluation needs.
//
// It is asked for ONE OWNER's jobs and never for a watch's constraint.
// That is deliberate. Splicing a caller-supplied expression into a
// backend query is how owner scoping gets defeated -- an expression with
// unbalanced parentheses escapes the enclosing AND and matches every
// job -- and the defence is a re-serialization step that is easy to
// forget in a new call site. Here the constraint never reaches the
// backend at all: the query is "this owner's jobs", and the watch's own
// compiled matcher narrows the result in process. Forgetting to scope is
// not a mistake this interface can express.
//
// It also means one query serves every watch an owner has registered,
// which is the coalescing that makes a single evaluator cheap.
type Source interface {
	// Queue returns the owner's current jobs, up to limit, projected to
	// attrs. Truncated must be set when there were more, because an
	// incomplete queue makes absence meaningless.
	//
	// attrs is never empty and always covers what the evaluator reads;
	// an implementation may ignore it and return whole ads, at a cost
	// measured in hundreds of megabytes on a large queue.
	Queue(ctx context.Context, owner string, attrs []string, limit int) (QueueResult, error)
	// History returns the owner's finished jobs since a point in time,
	// projected the same way.
	History(ctx context.Context, owner string, attrs []string, since time.Time, limit int) ([]*classad.ClassAd, error)
}

// QueueResult is a queue read and whether it was complete.
type QueueResult struct {
	Ads       []*classad.ClassAd
	Truncated bool
}

const (
	// QueueLimit bounds one owner's queue read.
	//
	// It is a memory bound and a correctness one at the same time. A
	// projected job ad costs about 1.4 KB on the heap (a whole one costs
	// 12 KB, measured), so this caps a pass at roughly 26 MB per owner.
	// Past the cap the read is truncated, which disables the
	// absence-implies-finished evidence -- so raising it buys correctness
	// for very large clusters and costs memory linearly, and lowering it
	// does the reverse. Truncation is not a wrong answer, only a slower
	// one: those watches wait for the history archive instead.
	QueueLimit = 20000
	// HistoryLimit bounds one owner's history read.
	HistoryLimit = 5000
	// HistoryLookback is how far back a watch looks for jobs that
	// finished before it was registered.
	//
	// Registering a watch for a cluster that has already finished should
	// fire immediately rather than wait forever -- that is the
	// lost-wakeup case, and it is easy to hit because an agent submits,
	// does something else, and only then thinks to wait. Looking back
	// covers it without reading all of history.
	HistoryLookback = 24 * time.Hour
	// DefaultInterval is how often the evaluator sweeps.
	DefaultInterval = 30 * time.Second
)

// Evaluator runs the watches. One instance serves every registered
// watch: the polling does not disappear, it moves off the agents and off
// the schedd, and stops scaling with the number of callers.
type Evaluator struct {
	store  *Store
	src    Source
	logf   func(msg string, args ...any)
	now    func() time.Time
	Period time.Duration
}

// NewEvaluator wires an evaluator. logf may be nil.
func NewEvaluator(store *Store, src Source, logf func(string, ...any)) *Evaluator {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Evaluator{store: store, src: src, logf: logf, now: time.Now, Period: DefaultInterval}
}

// Stats is what one pass did, for logging and tests.
type Stats struct {
	Watches int
	Owners  int
	Fired   int
	Pruned  int64
	Errors  int
}

// Run sweeps until ctx is done.
func (e *Evaluator) Run(ctx context.Context) {
	ticker := time.NewTicker(e.Period)
	defer ticker.Stop()
	for {
		// Sweep first: a daemon that just started may already be holding
		// watches whose answer arrived during the restart.
		if st, err := e.Pass(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			e.logf("job watch pass failed", "error", err)
		} else if st.Fired > 0 || st.Errors > 0 {
			e.logf("job watches evaluated", "watches", st.Watches, "fired", st.Fired, "errors", st.Errors)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Pass runs one sweep: read every live watch, group by owner, fetch each
// owner's jobs once, and record what happened.
//
// A failure for one owner does not abandon the pass. Watches are
// independent, and one owner's unreachable data is no reason to stop
// answering everybody else's questions -- especially since the most
// likely cause is a per-owner authorization problem rather than a
// systemic one.
func (e *Evaluator) Pass(ctx context.Context) (Stats, error) {
	var st Stats
	if n, err := e.store.Prune(ctx); err != nil {
		e.logf("pruning expired job watches failed", "error", err)
	} else {
		st.Pruned = n
	}

	live, err := e.store.Live(ctx)
	if err != nil {
		return st, fmt.Errorf("listing live watches: %w", err)
	}
	st.Watches = len(live)
	if len(live) == 0 {
		return st, nil
	}

	byOwner := make(map[string][]*Watch, 4)
	for _, w := range live {
		byOwner[w.Owner] = append(byOwner[w.Owner], w)
	}
	st.Owners = len(byOwner)

	for owner, watches := range byOwner {
		if ctx.Err() != nil {
			return st, ctx.Err()
		}
		fired, err := e.passOwner(ctx, owner, watches)
		st.Fired += fired
		if err != nil {
			st.Errors++
			e.logf("evaluating job watches failed for one owner", "owner", owner, "error", err)
		}
	}
	return st, nil
}

func (e *Evaluator) passOwner(ctx context.Context, owner string, watches []*Watch) (int, error) {
	// The oldest watch decides how far back to look, so a watch
	// registered after its jobs finished still sees them.
	since := e.now().Add(-HistoryLookback)
	for _, w := range watches {
		if t := w.CreatedAt.Add(-HistoryLookback); t.Before(since) {
			since = t
		}
	}

	attrs := projectionFor(watches)
	queue, err := e.src.Queue(ctx, owner, attrs, QueueLimit)
	if err != nil {
		return 0, fmt.Errorf("reading the queue: %w", err)
	}
	history, err := e.src.History(ctx, owner, attrs, since, HistoryLimit)
	if err != nil {
		// A queue read without history still decides "done" by absence,
		// "held" and "running". Losing history should degrade what can
		// be answered, not stop the pass -- the alternative is that a
		// history outage silently freezes every watch.
		e.logf("reading history for job watches failed; terminal outcomes are unavailable this pass",
			"owner", owner, "error", err)
		history = nil
	}
	snap := Snapshot{Now: e.now(), Queue: queue.Ads, History: history, QueueTruncated: queue.Truncated}

	var fired int
	var firstErr error
	for _, w := range watches {
		out := w.Evaluate(snap)
		if !out.Fires {
			if err := e.store.SaveProgress(ctx, w.ID, out); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("saving progress for %s: %w", w.ID, err)
			}
			continue
		}
		if err := e.store.Fire(ctx, w.ID, out, e.now().UTC()); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("recording that %s fired: %w", w.ID, err)
			}
			continue
		}
		fired++
		e.logf("job watch fired", "watch", w.ID, "owner", owner, "label", w.Label,
			"event", string(w.Event), "mode", string(w.Mode), "jobs", out.Satisfied,
			"outcome_undetermined", out.Undetermined)
	}
	return fired, firstErr
}

// CheckOwner evaluates one owner's live watches right now and reports
// how many fired.
//
// Registration calls this before returning, which is what turns the
// lost-wakeup fix into a one-shot: a caller that asks to be told when a
// cluster finishes, for a cluster that finished an hour ago, gets the
// answer in the same call instead of waiting for a condition that has
// already happened and will not happen again.
func (e *Evaluator) CheckOwner(ctx context.Context, owner string) (int, error) {
	live, err := e.store.Live(ctx)
	if err != nil {
		return 0, fmt.Errorf("listing live watches: %w", err)
	}
	var mine []*Watch
	for _, w := range live {
		if w.Owner == owner {
			mine = append(mine, w)
		}
	}
	if len(mine) == 0 {
		return 0, nil
	}
	return e.passOwner(ctx, owner, mine)
}

// projectionFor is the union of what an owner's watches read.
//
// Fetching whole job ads was costing about 12 KB each on the heap --
// 231 MB held and 677 MB allocated for a 20,000-job queue, every pass,
// per owner -- to evaluate expressions that touch about ten attributes.
// Projecting to those cuts it roughly ninefold.
func projectionFor(watches []*Watch) []string {
	seen := make(map[string]bool, 16)
	out := make([]string, 0, 16)
	for _, w := range watches {
		for _, attr := range w.ReadAttrs() {
			if attr == "" || seen[attr] {
				continue
			}
			seen[attr] = true
			out = append(out, attr)
		}
	}
	return out
}
