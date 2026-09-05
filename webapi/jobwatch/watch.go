// Package jobwatch lets a caller register interest in something
// happening to a set of jobs, and find out later that it happened,
// instead of asking repeatedly whether it has.
//
// The caller this exists for is an LLM agent, and that shapes the design
// more than the HTCondor side does. An agent is not a process: between
// turns nothing of it is running and there is no socket to push to, and
// it may come back in seconds, in hours, or as a different session
// entirely. So a watch is not a subscription and not a callback -- it is
// a durable question, asked once, whose answer accumulates until
// somebody comes back for it. "What fired while I was gone" has to be
// answerable in one cheap call, because that is the only shape of
// question an agent reliably asks.
//
// Polling does not disappear, it moves. One evaluator serves every
// registered watch and reads through the htcondordb mirror rather than
// the schedd, so the cost stops scaling with the number of agents. What
// the agent stops doing is spending a turn per check.
package jobwatch

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections/vm"
)

// Mode says how a watch over several jobs resolves to one answer.
type Mode string

const (
	// ModeAny fires as soon as one selected job has the event.
	// "Tell me if anything fails."
	ModeAny Mode = "any"
	// ModeAll fires when every selected job has it, and at least one job
	// was selected. "Tell me when they have all finished."
	ModeAll Mode = "all"
)

// JobID identifies a job within a schedd.
type JobID struct {
	Cluster int64 `json:"cluster_id"`
	Proc    int64 `json:"proc_id"`
}

// Watch is a registered interest: Constraint selects which jobs, Event
// says what to wait for, Mode says how several jobs resolve to one
// answer.
type Watch struct {
	ID    string
	Owner string
	Label string

	// Constraint is a ClassAd expression selecting the jobs in scope,
	// evaluated against both queue and history ads.
	Constraint string
	Event      Event
	// Condition is the ClassAd expression for EventCustom, ignored
	// otherwise.
	Condition string
	Mode      Mode

	CreatedAt time.Time

	// AllEndedAt is when every tracked job was first seen to have left
	// the queue with its outcome still unresolved. It starts the grace
	// period after which the watch gives up waiting for history and
	// reports what it does know; zero while any job is still running or
	// while the outcomes are resolving normally.
	AllEndedAt time.Time

	// Tracked is every job this watch has ever selected. It is the
	// watch's memory, and without it the terminal events cannot work: a
	// cluster that has fully drained is absent from the queue, so
	// "selected" computed from the current queue alone would be empty
	// and ModeAll would be back to deciding a vacuous truth.
	Tracked []JobID

	// FiredAt, Matched and MatchedTotal record the first time the watch
	// was satisfied and what satisfied it.
	FiredAt      time.Time
	Matched      []JobRef
	MatchedTotal int

	// Undetermined is set on a watch that fired without establishing the
	// outcome; see giveUpWaiting.
	Undetermined bool

	// DeliveredAt is when a caller last read the outcome. Recorded
	// rather than acted on: a fired watch stays readable so a later
	// session, or the same one after losing its context, can still find
	// out what happened.
	DeliveredAt time.Time

	matchConstraint *vm.Query
	matchCondition  *vm.Query
	// truncated carries QueueTruncated from the snapshot being evaluated
	// down to the per-job decision.
	truncated bool
	// trackedBlob is the stored form of Tracked as it was loaded, so a
	// pass that changed nothing can skip the write.
	trackedBlob string
}

// JobRef is a job in a fired watch, with enough of the ad to act on
// without a second lookup.
type JobRef struct {
	JobID
	Attrs map[string]string `json:"attrs,omitempty"`
}

// MaxMatched bounds what a fired watch carries. A watch over a 100k-job
// cluster has to summarize rather than hand back the cluster; the count
// beside the list is what keeps the scale visible.
const MaxMatched = 25

// CarryAttrs are copied into a JobRef. Deliberately short -- this is a
// notification, not a query result -- but HoldReason and ExitCode earn
// their place: being told a job is held without the reason costs the
// agent another round trip for the only fact that makes the answer
// actionable.
var CarryAttrs = []string{"JobStatus", "Owner", "HoldReason", "HoldReasonCode", "ExitCode", "ExitBySignal", "ExitSignal", "RemoveReason"}

// Registration errors, kept apart because each has a different fix and
// the caller is often a language model correcting its own call.
var (
	ErrNoOwner      = errors.New("a watch needs an owner to scope it to")
	ErrNoConstraint = errors.New("a watch needs a constraint selecting which jobs it is about")
	ErrUnknownEvent = errors.New("unknown event")
	ErrUnknownMode  = errors.New("mode must be \"any\" or \"all\"")
	ErrNoCondition  = errors.New("event \"custom\" needs a condition expression")
	ErrHasCondition = errors.New("a condition is only meaningful with event \"custom\"")
)

// New validates and compiles a watch. It does not register it.
//
// Everything that could make a watch silently never fire is rejected
// here, because a watch that cannot fire is worse than an error: from
// the outside it looks exactly like a condition that has not happened
// yet, so the caller waits forever on a typo.
func New(owner, label, constraint string, event Event, condition string, mode Mode) (*Watch, error) {
	if strings.TrimSpace(owner) == "" {
		return nil, ErrNoOwner
	}
	if strings.TrimSpace(constraint) == "" {
		return nil, ErrNoConstraint
	}
	if event == "" {
		event = EventDone
	}
	if !event.Valid() {
		return nil, fmt.Errorf("%w %q; expected one of:\n%s", ErrUnknownEvent, event, DescribeEvents())
	}
	condition = strings.TrimSpace(condition)
	switch {
	case event == EventCustom && condition == "":
		return nil, ErrNoCondition
	case event != EventCustom && condition != "":
		// Silently ignoring it would leave the caller believing a filter
		// is applied that is not.
		return nil, fmt.Errorf("%w (got event %q)", ErrHasCondition, event)
	}
	if mode == "" {
		mode = ModeAny
	}
	if mode != ModeAny && mode != ModeAll {
		return nil, fmt.Errorf("%w: got %q", ErrUnknownMode, mode)
	}

	w := &Watch{
		Owner:      strings.TrimSpace(owner),
		Label:      label,
		Constraint: constraint,
		Event:      event,
		Condition:  condition,
		Mode:       mode,
	}
	if err := w.Compile(); err != nil {
		return nil, err
	}
	return w, nil
}

// Compile parses the expressions on a watch that came back from storage.
// A stored watch is just strings; nothing evaluates until this has run,
// and an uncompiled watch deliberately selects nothing rather than
// matching everything.
func (w *Watch) Compile() error {
	if w.matchConstraint == nil {
		sel, err := vm.Parse(w.Constraint)
		if err != nil {
			return fmt.Errorf("constraint %q: %w", w.Constraint, err)
		}
		w.matchConstraint = sel
	}
	if w.Event == EventCustom && w.matchCondition == nil {
		cond, err := vm.Parse(w.Condition)
		if err != nil {
			return fmt.Errorf("condition %q: %w", w.Condition, err)
		}
		w.matchCondition = cond
	}
	return nil
}

// Snapshot is what the evaluator hands a watch: the jobs currently in
// the queue and the history rows for jobs that have left it, both
// already narrowed by the watch's constraint where the backend can do
// it.
//
// History is a separate list rather than more ads because the two answer
// different questions. A job in History has finished, whatever its
// attributes say; a job in Queue has not. Merging them would lose
// exactly the distinction the terminal events turn on.
type Snapshot struct {
	// Now is the evaluation time, for the unresolved-outcome grace
	// period. Zero means time.Now.
	Now     time.Time
	Queue   []*classad.ClassAd
	History []*classad.ClassAd
	// QueueTruncated says the backend could not return every job, so
	// this queue is a sample rather than the queue.
	//
	// It disables the absence evidence for terminal events, and that is
	// the whole reason it exists: "done" partly rests on a job this
	// watch was tracking no longer being here, and in a truncated
	// snapshot "not here" means "not in the part we got". Without this
	// flag a paginated read would report a running cluster as finished.
	QueueTruncated bool
}

// Outcome is one evaluation of a watch.
type Outcome struct {
	// Fires is whether the watch is satisfied.
	Fires bool
	// Selected and Satisfied are the counts behind that answer, reported
	// even when it does not fire: "0 selected" and "3 of 10" are the
	// difference between a watch that has not started and one partway
	// there, which is what "how is it going" actually asks.
	Selected  int
	Satisfied int
	Matched   []JobRef
	// Tracked is the updated memory of every job this watch has seen,
	// for the caller to persist.
	Tracked []JobID

	// Undetermined marks a firing where the jobs are known to have ended
	// but their outcome could not be established -- see
	// UnresolvedOutcomeGrace. The watch fires anyway; what it reports is
	// "these finished and I cannot tell you how", which an agent can act
	// on. Silence is the one answer it cannot.
	Undetermined bool
	// AllEndedAt is the updated grace-period stamp, for the caller to
	// persist. Zero clears it.
	AllEndedAt time.Time
}

// UnresolvedOutcomeGrace is how long a succeeded/failed watch waits for
// history to explain jobs it has already seen leave the queue.
//
// Not zero, because in a healthy pool the history row lands seconds
// later and firing immediately would report "outcome unknown" for
// everything, destroying the distinction the event exists for. Not
// unbounded, because when history never arrives -- an unreachable
// mirror, a stalled syncer -- the alternative is that the watch stays
// silent forever, and an agent reads silence as "nothing failed".
const UnresolvedOutcomeGrace = 5 * time.Minute

// Evaluate decides whether the watch is satisfied by this snapshot,
// without mutating the watch. It is a thin wrapper over Fold, kept
// because a whole-snapshot answer is much easier to reason about in
// tests than a stream of calls.
func (w *Watch) Evaluate(s Snapshot) Outcome {
	f := w.Fold(s.Now, s.QueueTruncated)
	for _, ad := range s.Queue {
		f.Queued(ad)
	}
	for _, ad := range s.History {
		f.Finished(ad)
	}
	return f.Done()
}

// Fold accumulates an evaluation over a stream of ads, so a pass never
// has to hold the queue in memory.
//
// Even projected, materializing a 20,000-job queue costs about 26 MB per
// owner per pass. Folding as the rows arrive costs the job IDENTITIES
// instead -- tens of bytes each rather than 1.4 KB -- because that is
// genuinely all the decision needs: which jobs are in scope, which of
// them satisfy the event, and a capped handful of ads to put in the
// notification.
//
// Queued must be called for every job in the queue and Finished for
// every history row, in that order or interleaved; Done then answers.
// Order does not matter because each job's verdict depends on where it
// was seen, not on when.
type Fold struct {
	w         *Watch
	now       time.Time
	truncated bool

	// seen is every job in scope: the tracked set plus anything matching
	// that turns up now. The value records where it was seen, which is
	// what the terminal events turn on.
	seen map[JobID]placement

	satisfied int
	matched   []JobRef
}

// placement is where a job was observed this pass.
type placement struct {
	inQueue   bool
	inHistory bool
}

// Fold starts an evaluation. now may be zero for time.Now.
func (w *Watch) Fold(now time.Time, queueTruncated bool) *Fold {
	f := &Fold{w: w, now: now, truncated: queueTruncated, seen: make(map[JobID]placement, len(w.Tracked)+16)}
	// The tracked set is in scope before anything arrives. Without it a
	// cluster that has fully drained would look like an empty selection,
	// and "all done" would be back to deciding a vacuous truth.
	for _, id := range w.Tracked {
		f.seen[id] = placement{}
	}
	return f
}

// Truncated marks the queue read as incomplete. It is called after the
// read rather than at construction because a backend only discovers it
// hit the limit at the end -- and it must be applied before Done, since
// absence in a partial read is not evidence of anything.
func (f *Fold) Truncated() { f.truncated = true }

// Queued folds in one job currently in the queue.
func (f *Fold) Queued(ad *classad.ClassAd) {
	if !f.w.selects(ad) {
		return
	}
	id := jobIDOf(ad)
	p := f.seen[id]
	p.inQueue = true
	f.seen[id] = p

	// Decide the live events here, while the ad is in hand: keeping it
	// until Done would be keeping the queue.
	switch f.w.Event {
	case EventHeld:
		if statusOf(ad) == statusHeld {
			f.hit(id, ad)
		}
	case EventRunning:
		if statusOf(ad) == statusRunning {
			f.hit(id, ad)
		}
	case EventCustom:
		if f.w.matchCondition != nil && f.w.matchCondition.Matches(ad) {
			f.hit(id, ad)
		}
	}
}

// Finished folds in one history row.
func (f *Fold) Finished(ad *classad.ClassAd) {
	if !f.w.selects(ad) {
		return
	}
	id := jobIDOf(ad)
	p := f.seen[id]
	p.inHistory = true
	f.seen[id] = p

	switch f.w.Event {
	case EventDone:
		f.hit(id, ad)
	case EventSucceeded, EventFailed:
		if succeeded(ad) == (f.w.Event == EventSucceeded) {
			f.hit(id, ad)
		}
	}
}

func (f *Fold) hit(id JobID, ad *classad.ClassAd) {
	f.satisfied++
	if len(f.matched) < MaxMatched {
		f.matched = append(f.matched, jobRef(id, ad))
	}
}

// Done resolves the fold, including the verdicts that can only be
// reached once everything has been seen: a tracked job absent from a
// complete queue and from history has finished, which is what lets
// "done" work without an archive.
func (f *Fold) Done() Outcome {
	out := Outcome{Tracked: make([]JobID, 0, len(f.seen)), Satisfied: f.satisfied, Matched: f.matched}
	var unresolved []JobID
	var stillHere int
	for id, p := range f.seen {
		out.Tracked = append(out.Tracked, id)
		switch {
		case p.inQueue:
			stillHere++
		case p.inHistory:
			// Accounted for by Finished.
		case f.truncated:
			// Absent from a partial read means absent from the part we
			// got, which is not evidence of anything.
		default:
			// Gone from a complete queue with nothing to explain it.
			if f.w.Event == EventDone && f.w.tracks(id) {
				f.satisfied++
				out.Satisfied = f.satisfied
				if len(out.Matched) < MaxMatched {
					out.Matched = append(out.Matched, JobRef{JobID: id})
				}
			} else if f.w.Event == EventSucceeded || f.w.Event == EventFailed {
				unresolved = append(unresolved, id)
			}
		}
	}
	out.Selected = len(out.Tracked)
	sortJobIDs(out.Tracked)
	sortJobIDs(unresolved)

	switch f.w.Mode {
	case ModeAll:
		// The non-empty requirement is the vacuous-truth guard: "all
		// finished" is trivially true of no jobs, so without it a watch
		// registered before its jobs exist -- or with a typo in the
		// constraint -- fires at once and reports success for work that
		// never ran.
		out.Fires = out.Selected > 0 && out.Satisfied == out.Selected
	default:
		out.Fires = out.Satisfied > 0
	}
	if out.Fires {
		return out
	}
	return f.w.giveUpWaiting(out, unresolved, stillHere, f.now)
}

// BaseAttrs are the attributes every evaluation needs regardless of what
// a watch asks: identity, the owner the snapshot is scoped to, the state
// the live events test, the outcome the terminal events test, and the
// attributes carried into a notification.
//
// A projected read that omitted one of these would not error -- the
// attribute would evaluate to UNDEFINED, the comparison would be false,
// and the watch would quietly never fire. So the list is deliberately
// generous: one extra attribute costs bytes, a missing one costs a watch
// that waits forever.
var BaseAttrs = append([]string{"ClusterId", "ProcId", "Owner", "JobStatus"}, CarryAttrs...)

// ReadAttrs is every attribute this watch's expressions touch, so a
// caller can fetch a projected ad instead of a whole one.
//
// It comes from the compiled program's own read set (the vm walks the
// expression tree for attribute references), the same information the
// store's query planner uses. If that ever under-reports, the symptom
// here is a watch that silently never fires -- which is why BaseAttrs
// covers everything the evaluator itself reads.
func (w *Watch) ReadAttrs() []string {
	out := append([]string(nil), BaseAttrs...)
	if w.matchConstraint != nil {
		out = append(out, w.matchConstraint.ReadAttrs()...)
	}
	if w.matchCondition != nil {
		out = append(out, w.matchCondition.ReadAttrs()...)
	}
	return out
}

// giveUpWaiting decides whether a watch that cannot resolve its outcomes
// should fire anyway.
//
// It applies only to the events that need history. "Done" already fires
// on absence, and the live-state events describe jobs that are still in
// the queue, so neither can be left waiting on an outcome nobody can
// supply.
//
// The condition is deliberately narrow: every selected job has left the
// queue, at least one of them has no history row to explain it, and that
// has been true for longer than the grace period. A healthy pool never
// reaches it -- the row lands seconds after the job goes. A pool whose
// mirror is unreachable or whose syncer has stalled reaches it in five
// minutes, and the watch says "these finished, I cannot tell you how"
// instead of saying nothing at all. Nothing is the one answer an agent
// misreads, because it looks exactly like "still running".
func (w *Watch) giveUpWaiting(out Outcome, unresolved []JobID, stillHere int, now time.Time) Outcome {
	if w.Event != EventSucceeded && w.Event != EventFailed {
		return out
	}
	if stillHere > 0 || len(unresolved) == 0 {
		// Either work is still running, or everything that ended was
		// explained. Nothing to give up on.
		return out
	}
	if now.IsZero() {
		now = time.Now()
	}
	out.AllEndedAt = w.AllEndedAt
	if out.AllEndedAt.IsZero() {
		out.AllEndedAt = now
	}
	if now.Sub(out.AllEndedAt) < UnresolvedOutcomeGrace {
		return out
	}

	out.Fires, out.Undetermined = true, true
	out.Satisfied = len(unresolved)
	out.Matched = out.Matched[:0]
	for _, id := range unresolved {
		if len(out.Matched) >= MaxMatched {
			break
		}
		// No ad to carry: the whole point is that nothing describes
		// these. The identity is what lets the agent go and look.
		out.Matched = append(out.Matched, JobRef{JobID: id})
	}
	return out
}

func (w *Watch) selects(ad *classad.ClassAd) bool {
	return w.matchConstraint != nil && w.matchConstraint.Matches(ad)
}

func (w *Watch) tracks(id JobID) bool {
	for _, t := range w.Tracked {
		if t == id {
			return true
		}
	}
	return false
}

// HTCondor JobStatus values used here.
const (
	statusRunning = 2
	statusRemoved = 3
	statusHeld    = 5
)

// succeeded reads a history ad's outcome. Anything that is not a clean
// exit 0 counts as failure, so a job killed by a signal or removed
// before it finished is not quietly reported as success.
func succeeded(ad *classad.ClassAd) bool {
	if ad == nil {
		return false
	}
	if statusOf(ad) == statusRemoved {
		return false
	}
	if bySignal, ok := ad.EvaluateAttrBool("ExitBySignal"); ok && bySignal {
		return false
	}
	code, ok := ad.EvaluateAttrInt("ExitCode")
	if !ok {
		// A terminal ad with no exit code cannot be called a success.
		return false
	}
	return code == 0
}

func statusOf(ad *classad.ClassAd) int64 {
	if ad == nil {
		return 0
	}
	v, _ := ad.EvaluateAttrInt("JobStatus")
	return v
}

func jobIDOf(ad *classad.ClassAd) JobID {
	id := JobID{}
	id.Cluster, _ = ad.EvaluateAttrInt("ClusterId")
	id.Proc, _ = ad.EvaluateAttrInt("ProcId")
	return id
}

func jobRef(id JobID, ad *classad.ClassAd) JobRef {
	ref := JobRef{JobID: id}
	if ad == nil {
		return ref
	}
	for _, attr := range CarryAttrs {
		if v, ok := ad.EvaluateAttrString(attr); ok && v != "" {
			ref.set(attr, v)
			continue
		}
		if b, ok := ad.EvaluateAttrBool(attr); ok {
			ref.set(attr, fmt.Sprintf("%t", b))
			continue
		}
		if n, ok := ad.EvaluateAttrInt(attr); ok {
			ref.set(attr, fmt.Sprintf("%d", n))
		}
	}
	return ref
}

func (r *JobRef) set(k, v string) {
	if r.Attrs == nil {
		r.Attrs = make(map[string]string, len(CarryAttrs))
	}
	r.Attrs[k] = v
}

// sortJobIDs keeps the tracked set stable, so storing it does not churn
// and a diff between evaluations is readable.
func sortJobIDs(ids []JobID) {
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && (ids[j].Cluster < ids[j-1].Cluster ||
			(ids[j].Cluster == ids[j-1].Cluster && ids[j].Proc < ids[j-1].Proc)); j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
}
