package jobwatch

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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
	// Queue streams the owner's current jobs, projected to attrs, calling
	// yield for each. It reports whether the read was truncated at limit,
	// because an incomplete queue makes absence meaningless.
	//
	// Streaming rather than returning a slice is what keeps a pass from
	// holding the queue: the evaluator folds each ad into counters and
	// job identities and lets it go. attrs is never empty and always
	// covers what the evaluator reads.
	Queue(ctx context.Context, owner string, attrs []string, limit int, yield func(*classad.ClassAd)) (truncated bool, err error)
	// History streams the owner's finished jobs since a point in time,
	// projected the same way.
	History(ctx context.Context, owner string, attrs []string, since time.Time, limit int, yield func(*classad.ClassAd)) error
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

	mu sync.Mutex
	// owners serializes passes per owner: the sweep, a nudge and a
	// caller's wait may all evaluate one owner's watches, and the
	// absence memory below is only meaningful in pass order.
	owners map[string]*sync.Mutex
	// memory is per watch id; see absenceMemory. Used only with a
	// CoveredSource.
	memory map[string]*absenceMemory
	// liveAttrs is what the live watches read, for the feed's projection
	// (LiveAttrs).
	liveAttrs atomic.Pointer[[]string]
}

// LiveAttrs is every attribute the live watches read, as of the last
// sweep and any registration since: what a feed must keep of each job
// (Feed.Keep) for its terminal records to resolve them.
func (e *Evaluator) LiveAttrs() []string {
	if p := e.liveAttrs.Load(); p != nil {
		return *p
	}
	return BaseAttrs
}

// noteAttrs records watches' read sets; replace starts over from them.
func (e *Evaluator) noteAttrs(watches []*Watch, replace bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var have []string
	if p := e.liveAttrs.Load(); p != nil && !replace {
		have = *p
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(have)+16)
	for _, a := range append(append([]string(nil), have...), projectionFor(watches)...) {
		if k := strings.ToLower(a); !seen[k] {
			seen[k] = true
			out = append(out, a)
		}
	}
	e.liveAttrs.Store(&out)
}

// NewEvaluator wires an evaluator. logf may be nil.
func NewEvaluator(store *Store, src Source, logf func(string, ...any)) *Evaluator {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Evaluator{store: store, src: src, logf: logf, now: time.Now, Period: DefaultInterval,
		owners: map[string]*sync.Mutex{}, memory: map[string]*absenceMemory{}}
}

// ownerLock returns the mutex serializing owner's passes.
func (e *Evaluator) ownerLock(owner string) *sync.Mutex {
	e.mu.Lock()
	defer e.mu.Unlock()
	m := e.owners[owner]
	if m == nil {
		m = &sync.Mutex{}
		e.owners[owner] = m
	}
	return m
}

// memoryFor returns a watch's absence memory for a read with coverage
// cov, creating it -- or starting it over when it was gathered from
// another origin. What one backend showed says nothing about another's
// absence, so a started-over memory is strict: a job counts as gone by
// absence only after it has been seen in the new origin's queue (see
// Coverage). A memory started fresh on a source with several origins is
// strict too, since the watch's jobs may have been tracked on another.
func (e *Evaluator) memoryFor(id string, cov *Coverage) *absenceMemory {
	e.mu.Lock()
	defer e.mu.Unlock()
	m := e.memory[id]
	switch {
	case m == nil:
		m = &absenceMemory{origin: cov.Origin(), strict: cov != nil && cov.several, since: map[JobID]time.Time{},
			seenHere: map[JobID]bool{}}
		e.memory[id] = m
	case m.origin != cov.Origin():
		m = &absenceMemory{origin: cov.Origin(), strict: true, since: map[JobID]time.Time{}, seenHere: map[JobID]bool{}}
		e.memory[id] = m
	}
	return m
}

// forget drops the absence memory of watches not in live, which have
// fired, expired or been cancelled.
func (e *Evaluator) forget(live []*Watch) {
	keep := make(map[string]bool, len(live))
	for _, w := range live {
		keep[w.ID] = true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for id := range e.memory {
		if !keep[id] {
			delete(e.memory, id)
		}
	}
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
	e.forget(live)
	e.noteAttrs(live, true)
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
	lock := e.ownerLock(owner)
	lock.Lock()
	defer lock.Unlock()
	if p, ok := e.src.(PassPinner); ok {
		// Every read below is one backend's.
		ctx = p.PinPass(ctx)
	}

	// The oldest watch decides how far back to look, so a watch
	// registered after its jobs finished still sees them.
	since := e.now().Add(-HistoryLookback)
	for _, w := range watches {
		if t := w.CreatedAt.Add(-HistoryLookback); t.Before(since) {
			since = t
		}
	}

	attrs := projectionFor(watches)

	// One fold per watch, all fed from a single pass over the owner's
	// jobs. This is why the queue is read once per owner rather than
	// once per watch, and why none of it is kept.
	covered, perAP := e.src.(CoveredSource)
	folds := make([]*Fold, len(watches))
	for i, w := range watches {
		folds[i] = w.fold(e.now(), false, perAP)
	}

	queued := func(ad *classad.ClassAd) {
		for _, f := range folds {
			f.Queued(ad)
		}
	}
	var truncated bool
	var cov *Coverage
	var err error
	if perAP {
		truncated, cov, err = covered.QueueCovered(ctx, owner, attrs, QueueLimit, queued)
		if cov == nil {
			cov = NewCoverage()
		}
	} else {
		truncated, err = e.src.Queue(ctx, owner, attrs, QueueLimit, queued)
	}
	if err != nil {
		return 0, fmt.Errorf("reading the queue: %w", err)
	}
	readAt := e.now()
	for i, f := range folds {
		if truncated {
			// Discovered only at the end of the read, so it is applied
			// to the folds now rather than at construction.
			f.Truncated()
		}
		if perAP {
			f.cov, f.mem, f.readAt = cov, e.memoryFor(watches[i].ID, cov), readAt
		}
	}

	if err := e.src.History(ctx, owner, attrs, since, HistoryLimit, func(ad *classad.ClassAd) {
		for _, f := range folds {
			f.Finished(ad)
		}
	}); err != nil {
		// A queue read without history still decides "done" by absence,
		// "held" and "running". Losing history should degrade what can
		// be answered, not stop the pass -- the alternative is that a
		// history outage silently freezes every watch.
		e.logf("reading history for job watches failed; terminal outcomes are unavailable this pass",
			"owner", owner, "error", err)
	}

	var fired int
	var firstErr error
	for i, w := range watches {
		out := folds[i].Done()
		w.Incomplete = out.Incomplete
		if !out.Fires {
			if err := e.store.SaveProgress(ctx, w, out); err != nil && firstErr == nil {
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
	e.noteAttrs(mine, false)
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

// Await runs the evaluator for one owner and asks answered whether there
// is something to report, repeating until there is, until deadline, or
// until ctx ends.
//
// Evaluating before reporting is what makes a watch answerable at all: a
// caller asking "what happened" should not be told "nothing yet" only
// because the background sweep is a few seconds out of phase with the
// question. Waiting is that same sweep held open -- there is no second
// mechanism -- so an answer that already exists comes back on the first
// pass without blocking.
//
// An evaluation error does not end the wait. The sweep is best-effort
// here: the watch may already have fired and be sitting in storage, and
// refusing to look because a refresh failed would withhold an answer
// that is already known. onError, when set, sees each such error.
func Await(
	ctx context.Context,
	eval *Evaluator,
	owner string,
	deadline time.Time,
	poll time.Duration,
	onError func(error),
	answered func() (bool, error),
) error {
	if poll <= 0 {
		poll = time.Second
	}
	for {
		if eval != nil {
			if _, err := eval.CheckOwner(ctx, owner); err != nil && onError != nil {
				onError(err)
			}
		}
		done, err := answered()
		if err != nil {
			return err
		}
		remaining := time.Until(deadline)
		if done || remaining <= 0 {
			return nil
		}
		if remaining > poll {
			remaining = poll
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(remaining):
		}
	}
}
