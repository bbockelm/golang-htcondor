package jobwatch

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/ast"
	"github.com/PelicanPlatform/classad/classad"
)

// Feed remembers the one thing a snapshot of the queue cannot show: the
// state a job was in immediately before it left.
//
// A finished job carries its outcome -- ExitCode, ExitBySignal -- only
// for the moment between the schedd writing those attributes and
// DestroyProc removing the ad, well under a second. Sampling the queue
// every thirty seconds essentially never lands in that window, so by the
// time an evaluator sees the job is gone, the fact that says HOW it went
// is gone too. That is why absence alone answers "done" and cannot
// answer "succeeded" or "failed".
//
// The mirror does not sample: it tails job_queue.log, so that write is
// recorded even though it existed for 200ms. Following the change log
// rather than polling its result gets the outcome back. A delete event
// carries no ad, but the upsert just before it carries the full one --
// so keeping the last upsert per key and freezing it when the delete
// arrives yields the outcome, with no history table involved at all.
//
// This rides the same authenticated CEDAR session as every other mirror
// read (dbrpc opWatch). htcondordb also serves an HTTP/SSE feed, but
// that exists for consumers who cannot speak CEDAR; using it here would
// have meant a second listener to configure, a second credential to
// manage, and an endpoint the collector ad does not advertise -- to
// reach a database this daemon is already connected to.
//
// The Feed is an augmentation, never the source of truth. Everything it
// misses -- before it connects, across a reconnect, after an eviction --
// degrades to the snapshot and history path that already worked. That
// asymmetry is deliberate: a missed terminal record costs a later
// answer, a wrongly invented one costs a wrong answer.
type Feed struct {
	mu sync.Mutex
	// Keyed by the source's own storage key, never by a parsed
	// ClusterId/ProcId: a delete event carries only that key, and
	// inventing a parse for it would couple this to a format the mirror
	// is free to change. The ad itself carries the job identity for
	// everything downstream.
	//
	// live is the last upsert seen per job, which becomes the terminal
	// record when the delete arrives. It is not a queue mirror and is
	// never used as one -- the evaluator's queue still comes from a
	// complete read.
	live map[string]*classad.ClassAd
	// ended is the final observed ad for jobs that have left the queue,
	// frozen: see endedJob.
	ended map[string]endedJob
	// warm says a stream is connected and nothing has been missed since.
	warm bool
	// activitySubs are followers of the whole stream rather than of one
	// job: the dashboard's live ticker. See activity.go.
	activitySubs map[*activitySub]struct{}
	// announced remembers the terminal transition already published for
	// a key, so the delete that follows does not report it a second
	// time. A finishing job produces both: the schedd writes JobStatus
	// 4, then DestroyProc removes the ad, usually within the same
	// second. Both say "completed", and publishing both puts the same
	// line on the ticker twice.
	announced map[string]ActivityKind
	// subs are per-job followers of this same stream. See subscribe.go.
	// Keyed by job identity rather than storage key so the feed's refusal
	// to parse that key does not leak out to callers.
	subs map[jobIdent]map[*keySub]struct{}

	now  func() time.Time
	logf func(string, ...any)

	// cursor is the position of the last event applied, for a resumable
	// stream (RunResumable); nil before the first.
	cursor []byte
	// origin names the source the stream, its cursor and everything held
	// came from (RunResumableFrom); originSet once a stream has opened.
	origin    string
	originSet bool

	// OwnerOf names the owner a job ad belongs to, for owner-scoped
	// reads and the activity stream. Nil reads the Owner attribute. A
	// server fronting several access points keys on User instead (see
	// webapi/multiap), and must set this before Run.
	OwnerOf func(*classad.ClassAd) string
	// Keep, when set, makes the feed hold only FeedAttrs and the
	// attributes it names (the evaluator's live watches' read set, see
	// Evaluator.LiveAttrs) of each job, and what those refer to. Nil
	// holds whole ads. See project.
	Keep func() []string

	// MaxEnded bounds memory; oldest out first.
	MaxEnded int
	// EndedTTL is how long a terminal record stays useful. It only has
	// to outlive the lookback a watch uses.
	EndedTTL time.Duration
}

// endedJob is a job's final ad, kept as a frozen attribute list rather
// than as a ClassAd.
//
// The feed hands these to evaluations it does not control: the sweep, a
// nudged check, an MCP caller waiting on a watch and a watch share can
// all read one owner's terminal records at once. A *classad.ClassAd
// cannot be shared that way, because its reads write to it --
// evaluating a reference to an expression-valued attribute records it in
// a per-ad map, and serializing sorts its attribute slice in place. A
// watch constraint naming RequestMemory, which is usually an expression,
// was enough for two evaluations to write that map at once, which is a
// fatal error rather than a failed request.
//
// So nothing reads this list but the code that builds ads from it (see
// ad), nothing writes it after freezeEnded, and each caller gets a
// ClassAd of its own.
type endedJob struct {
	attrs []ast.AttributeAssignment
	// owner is read once, when the job ends, so selecting one owner's
	// records needs no evaluation at all.
	owner string
	at    time.Time
	// schedd, cluster, proc and status are the job's ScheddName
	// (lower-cased), id and last JobStatus, for Departures.
	schedd        string
	cluster, proc int64
	status        int64
}

// freezeEnded records ad as a job's final state. The caller holds f.mu
// and owns ad: AST sorts the ad's attribute slice in place.
func (f *Feed) freezeEnded(ad *classad.ClassAd, at time.Time) endedJob {
	owner := f.ownerOf(ad)
	schedd, _ := ad.EvaluateAttrString("ScheddName")
	id, _ := identOf(ad)
	src := ad.AST().Attributes
	attrs := make([]ast.AttributeAssignment, 0, len(src))
	for _, a := range src {
		if a != nil {
			attrs = append(attrs, *a)
		}
	}
	return endedJob{attrs: attrs, owner: owner, at: at, schedd: strings.ToLower(schedd),
		cluster: id.cluster, proc: id.proc, status: statusOf(ad)}
}

// ad builds a ClassAd over the frozen attributes for one caller. It is
// safe to call concurrently, and without f.mu, because it only reads
// e.attrs.
//
// The copy is shallow at the expression level: the caller's ad has its
// own attribute list, index and cyclic-reference state -- everything a
// read writes -- and shares the expression trees, which evaluation and
// serialization never modify. Insert, Set and Delete on the returned ad
// replace its own entries and leave the frozen list alone.
// InsertListElement appends to a shared list expression in place, so a
// caller must not use it on these ads.
//
// Re-parsing from the ad text would give a deep copy, at about fifteen
// times the cost (200us against 13us for a 160-attribute job ad), paid
// for every terminal record on every evaluation.
func (e endedJob) ad() *classad.ClassAd {
	vals := slices.Clone(e.attrs)
	ptrs := make([]*ast.AttributeAssignment, len(vals))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	ad := classad.FromAST(&ast.ClassAd{Attributes: ptrs})
	ad.InsertAttrBool(FeedRecordAttr, true)
	return ad
}

// FeedRecordAttr marks a terminal record built from the feed's last ad
// of a job, which holds only some of its attributes (see FeedAttrs).
const FeedRecordAttr = "JobwatchFeedRecord"

// isFeedRecord reports whether ad is one of the feed's terminal records.
func isFeedRecord(ad *classad.ClassAd) bool {
	v, ok := ad.EvaluateAttrBool(FeedRecordAttr)
	return ok && v
}

const (
	// DefaultMaxEnded bounds the remembered terminal records.
	DefaultMaxEnded = 50000
	// DefaultEndedTTL outlives HistoryLookback with room to spare.
	DefaultEndedTTL = 26 * time.Hour
)

// WatchEvent is one change from the mirror, mirroring dbrpc.WatchEvent
// so this package does not depend on the transport.
type WatchEvent struct {
	Kind   uint8 // 0 upsert, 1 delete, 2 reset (db.WatchKind)
	Key    string
	AdText string
	// Cursor is the stream position after this event, for resuming a
	// stream (RunResumable). Empty where the transport gives none.
	Cursor []byte
}

// Event kinds, matching db.WatchKind.
const (
	WatchUpsert uint8 = 0
	WatchDelete uint8 = 1
	WatchReset  uint8 = 2
)

// Dialer opens a watch on the mirror's jobs table. It is a function
// rather than a client so each reconnect goes through the same discovery
// and authentication path as every other mirror read, picking up a moved
// or restarted database with no special handling here.
type Dialer func(ctx context.Context) (events <-chan WatchEvent, stop func(), err error)

// NewFeed returns an empty, cold Feed. logf may be nil.
func NewFeed(logf func(string, ...any)) *Feed {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Feed{
		live:     make(map[string]*classad.ClassAd),
		ended:    make(map[string]endedJob),
		now:      time.Now,
		logf:     logf,
		MaxEnded: DefaultMaxEnded,
		EndedTTL: DefaultEndedTTL,
	}
}

// Run follows the mirror's jobs table until ctx is done, reconnecting
// with backoff.
//
// Each attempt starts from the head of the log rather than a saved
// cursor. Resuming would deliver deletes for jobs whose upserts this
// process never saw -- terminal records with no outcome in them, which
// is worse than not having them -- and the history archive already
// covers whatever the feed missed while it was away.
func (f *Feed) Run(ctx context.Context, dial Dialer) error {
	backoff := time.Second
	for ctx.Err() == nil {
		err := f.follow(ctx, dial)
		if ctx.Err() != nil {
			return nil
		}
		// A dropped stream means deletes went by unseen, so nothing held
		// here can be trusted any more.
		f.Reset()
		if err != nil {
			f.logf("htcondordb job watch stream ended; falling back to the history archive", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > time.Minute {
			backoff = time.Minute
		}
	}
	return nil
}

// ResumeDialer opens a watch on a jobs table from a cursor: nil for the
// head of the change log (changes from now on), else the position after
// the last event this feed applied.
type ResumeDialer func(ctx context.Context, cursor []byte) (events <-chan WatchEvent, stop func(), err error)

// RunResumable follows a jobs table until ctx is done, like Run, but
// resumes from where it left off after a dropped stream instead of
// starting over: what it holds survives the gap, and the deletes that
// happened during it arrive on resume carrying the outcomes it kept.
//
// The source decides whether it can resume. When it cannot -- its change
// log no longer reaches back that far, or it restarted -- it says so with
// a Reset, which clears this feed, followed by its whole table. A resume
// that cannot even be opened starts over from the head, cleared: the
// cursor may be the reason.
//
// A federation hub's jobs table is what this follows in multi-AP mode:
// one stream for every access point.
func (f *Feed) RunResumable(ctx context.Context, dial ResumeDialer) error {
	return f.RunResumableFrom(ctx, func(ctx context.Context, from Resume) (<-chan WatchEvent, func(), string, error) {
		events, stop, err := dial(ctx, from.Cursor)
		return events, stop, "", err
	})
}

// Resume is where a resumable stream continues: the cursor after the
// last event applied, and the origin of the stream that issued it.
type Resume struct {
	Cursor []byte
	Origin string
}

// OriginDialer opens a watch on a jobs table that may come from one of
// several sources (two federation hubs), and names the one it opened:
// origin. A cursor is a position in one source's change log, meaningless
// to another, so a dialer that opens a different origin than from.Origin
// must not pass from.Cursor to it: it opens that source's head instead.
type OriginDialer func(ctx context.Context, from Resume) (events <-chan WatchEvent, stop func(), origin string, err error)

// RunResumableFrom is RunResumable over a dialer that names its origin.
// When a stream opens on a different origin than the one the feed holds
// state from, the feed starts over (as on a Reset: everything held is
// dropped, followers are told, and no departure is reported) and follows
// the new origin from its head. A stream from one source ends when its
// dialer ends it, which is how a dialer moves the feed to another.
func (f *Feed) RunResumableFrom(ctx context.Context, dial OriginDialer) error {
	backoff := time.Second
	for ctx.Err() == nil {
		f.mu.Lock()
		from := Resume{Cursor: append([]byte(nil), f.cursor...), Origin: f.origin}
		f.mu.Unlock()
		if len(from.Cursor) == 0 {
			from.Cursor = nil
		}
		cursor := from.Cursor
		err := f.follow(ctx, func(ctx context.Context) (<-chan WatchEvent, func(), error) {
			events, stop, origin, err := dial(ctx, from)
			if err != nil {
				return nil, nil, err
			}
			f.adoptOrigin(origin)
			return events, stop, nil
		})
		if ctx.Err() != nil {
			return nil
		}
		var openErr *followOpenError
		if errors.As(err, &openErr) && cursor != nil {
			// Nothing was resumed, and the cursor may be why.
			f.Reset()
			f.mu.Lock()
			f.cursor = nil
			f.mu.Unlock()
		} else {
			// Cold while away, but what is held stays: the resume
			// brings the gap's changes, or a Reset if it cannot.
			f.setWarm(false)
		}
		if err != nil {
			f.logf("htcondordb job watch stream ended; resuming", "error", err)
		} else {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > time.Minute {
			backoff = time.Minute
		}
	}
	return nil
}

// followOpenError is a stream that could not be opened at all.
type followOpenError struct{ err error }

func (e *followOpenError) Error() string { return "opening the change stream: " + e.err.Error() }
func (e *followOpenError) Unwrap() error { return e.err }

func (f *Feed) follow(ctx context.Context, dial Dialer) error {
	events, stop, err := dial(ctx)
	if err != nil {
		return &followOpenError{err: err}
	}
	defer stop()

	// The stream starts at the head, so from here on the picture is
	// complete for everything that happens next -- which is all the
	// terminal records are ever claimed to cover.
	f.setWarm(true)
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-events:
			if !ok {
				return nil
			}
			f.Apply(ev)
		}
	}
}

// Apply folds one change into the remembered state. Exported so the
// semantics can be tested without a transport.
func (f *Feed) Apply(ev WatchEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(ev.Cursor) > 0 {
		f.cursor = append(f.cursor[:0], ev.Cursor...)
	}

	switch ev.Kind {
	case WatchUpsert:
		ad, err := parseWatchAd(ev.AdText)
		if err != nil || ad == nil {
			// An unreadable upsert leaves no record, so the delete that
			// follows finds nothing and the job falls through to the
			// history archive: later, not wrong.
			return
		}
		// The transition is the difference between what is arriving and
		// what is already held, so it has to be read before the
		// overwrite.
		if act, ok := f.activityFor(f.live[ev.Key], ad); ok {
			f.publishActivityLocked(act)
			if act.Kind == ActivityCompleted || act.Kind == ActivityRemoved {
				if f.announced == nil {
					f.announced = make(map[string]ActivityKind)
				}
				f.announced[ev.Key] = act.Kind
			} else {
				// Housekeeping, not correctness: a job that comes back
				// would otherwise keep an entry until it is deleted, and
				// the next terminal transition overwrites it anyway.
				delete(f.announced, ev.Key)
			}
		}
		// Subscribers get the whole ad; the feed keeps only what it reads.
		f.live[ev.Key] = f.project(ad)
		// A job can come back -- a held job released, or a key reused
		// after a compaction reload. Clear any terminal record so it is
		// not reported as finished while it is running again.
		delete(f.ended, ev.Key)
		if id, ok := identOf(ad); ok {
			f.notifyAdLocked(id, ad)
		}
	case WatchDelete:
		// The delete says only that the key is gone. What it was doing
		// when it went is in the upsert we kept.
		if ad, ok := f.live[ev.Key]; ok {
			f.ended[ev.Key] = f.freezeEnded(ad, f.now())
			delete(f.live, ev.Key)
			if act, aok := f.activityForDelete(ad); aok && f.announced[ev.Key] != act.Kind {
				f.publishActivityLocked(act)
			}
			delete(f.announced, ev.Key)
			if id, idok := identOf(ad); idok {
				f.notifyLocked(id, KeyChange{Gone: true})
			}
		}
		// A delete for a job never seen upserted carries nothing to act
		// on; the snapshot path will notice its absence.
	case WatchReset:
		// A full replay is about to follow, so what is held describes a
		// world that no longer applies.
		f.clearLocked()
		f.notifyAllLocked()
		return
	}
	f.evictLocked()
}

// adoptOrigin records the origin of a stream that just opened, starting
// over when it is not the one the feed's state came from.
func (f *Feed) adoptOrigin(origin string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.originSet && f.origin == origin {
		return
	}
	if f.originSet {
		f.clearLocked()
		f.cursor = nil
		f.notifyAllLocked()
		f.logf("job watch stream moved to another source; starting over", "from", f.origin, "to", origin)
	}
	f.origin, f.originSet = origin, true
}

// Origin names the source the feed's state came from (see
// RunResumableFrom); empty before a stream has opened, and for a feed
// whose dialer names none.
func (f *Feed) Origin() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.origin
}

// Reset drops everything and goes cold, for a caller that knows the
// stream's continuity is broken.
func (f *Feed) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clearLocked()
	f.warm = false
	f.notifyAllLocked()
}

func (f *Feed) clearLocked() {
	f.live = make(map[string]*classad.ClassAd)
	f.ended = make(map[string]endedJob)
	f.announced = nil
}

func (f *Feed) setWarm(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	was := f.warm
	f.warm = v
	// Tell followers when the stream drops. Without this a subscriber
	// cannot distinguish a disconnected feed from a quiet one, and would
	// sit indefinitely believing no news is good news.
	if was && !v {
		f.notifyAllLocked()
	}
}

// Warm reports whether the feed has a usable picture. A cold feed
// contributes nothing rather than contributing partially.
func (f *Feed) Warm() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.warm
}

// Terminal returns the final observed ads for one owner's jobs that
// ended at or after since. These stand in for history rows: the same
// outcome attributes, observed on the wire rather than read back from
// the archive.
//
// Each ad is the caller's own; see EachTerminal.
func (f *Feed) Terminal(owner string, since time.Time) []*classad.ClassAd {
	var out []*classad.ClassAd
	f.EachTerminal(owner, since, func(ad *classad.ClassAd) {
		out = append(out, ad)
	})
	return out
}

// EachTerminal calls yield with the final observed ad of each of one
// owner's jobs that ended at or after since, one at a time, so a caller
// folding them never holds them all.
//
// Every ad yielded is a new one belonging to the caller: it may be
// evaluated or serialized freely, concurrently with any other caller's
// (see endedJob.ad for the one thing it must not be used for). The feed
// keeps nothing that a yielded ad can reach and write.
//
// yield runs without the feed's lock held, so an evaluation, however
// slow, never holds up the change stream.
//
// The stream carries every job on the access point, so the owner filter
// here is what keeps one user's outcomes out of another's watch. An
// empty owner selects nothing: it is what an unidentified caller has,
// and it must not match jobs whose Owner is missing.
func (f *Feed) EachTerminal(owner string, since time.Time, yield func(*classad.ClassAd)) {
	if owner == "" {
		return
	}
	f.mu.Lock()
	if !f.warm {
		f.mu.Unlock()
		return
	}
	// Collect under the lock, build outside it. The frozen attribute
	// lists stay valid after the lock is released: eviction and reset
	// drop map entries, never modify the lists they held.
	var mine []endedJob
	for _, e := range f.ended {
		if e.owner == owner && !e.at.Before(since) {
			mine = append(mine, e)
		}
	}
	f.mu.Unlock()
	for _, e := range mine {
		yield(e.ad())
	}
}

// ownerOf is OwnerOf, defaulting to the Owner attribute.
func (f *Feed) ownerOf(ad *classad.ClassAd) string {
	if f.OwnerOf != nil {
		return f.OwnerOf(ad)
	}
	v, _ := ad.EvaluateAttrString("Owner")
	return v
}

// Departure is a job the feed saw leave the queue.
type Departure struct {
	// Schedd is the job's ScheddName, lower-cased; empty for a row
	// without one.
	Schedd  string
	Cluster int64
	Proc    int64
	At      time.Time
}

// Departures lists one owner's jobs that left the queue at or after
// since whose last ad said they had completed or been removed. A delete
// alone is not evidence: on a federation hub it is also an access point
// being retired, or reconciled after a replay, and a job that leaves
// while held or idle has not been shown to have finished. Nil from a
// cold feed, which has no picture to count from.
func (f *Feed) Departures(owner string, since time.Time) []Departure {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.warm {
		return nil
	}
	out := []Departure{}
	for _, e := range f.ended {
		if e.at.Before(since) || e.owner != owner {
			continue
		}
		if !isTerminalStatus(e.status) {
			continue
		}
		out = append(out, Departure{Schedd: e.schedd, Cluster: e.cluster, Proc: e.proc, At: e.at})
	}
	return out
}

// evictLocked bounds memory: age first, then oldest-out if still over.
func (f *Feed) evictLocked() {
	cutoff := f.now().Add(-f.EndedTTL)
	for key, e := range f.ended {
		if e.at.Before(cutoff) {
			delete(f.ended, key)
		}
	}
	if f.MaxEnded <= 0 || len(f.ended) <= f.MaxEnded {
		return
	}
	// Cheap approximate LRU. Exact ordering is not worth a heap: an
	// evicted record degrades to the history archive, it does not
	// produce a wrong answer.
	for len(f.ended) > f.MaxEnded {
		var oldestKey string
		oldest := time.Time{}
		for key, e := range f.ended {
			if oldest.IsZero() || e.at.Before(oldest) {
				oldestKey, oldest = key, e.at
			}
		}
		delete(f.ended, oldestKey)
	}
}

// parseWatchAd reads the ad text a watch event carries.
//
// The transport sends whatever ClassAd.String() produces, which is the
// new format ([a = b; c = d]); dbrpc's own comment calls it old-ClassAd
// text, and that is what this used to parse it as. ParseOld fails on the
// new format, so every upsert from a real database took the unreadable
// branch: the feed's live map stayed empty, no terminal record was ever
// built, and the change stream contributed nothing. Nothing reported it,
// because an empty feed degrades to the history archive by design --
// answers arrive later rather than wrong, which is invisible unless you
// are looking for it.
//
// Both formats are accepted rather than one: the wire format is a
// property of whatever wrote the row, this reads from two transports
// already, and being wrong about it silently costs the whole feature.
func parseWatchAd(text string) (*classad.ClassAd, error) {
	if text == "" {
		return nil, errEmptyAd
	}
	if ad, err := classad.Parse(text); err == nil && ad != nil {
		return ad, nil
	}
	return classad.ParseOld(text)
}

var errEmptyAd = errors.New("jobwatch: empty ad text")

// FeedAttrs are the attributes the feed keeps for every job: identity
// and owner, the state and outcome the evaluator and the activity
// stream read, the evidence a job ran, and what a notification carries.
//
// The feed holds the last ad of every job written since it connected --
// on a federation hub, every AP's -- so whole ads cost several kilobytes
// each for attributes nothing here reads. Subscribers to one job are
// handed the whole ad as it arrives; only what the feed keeps is
// projected. A watch constraint may name anything, so the evaluator's
// live watches' read set is kept too (Keep), and a terminal record only
// ever resolves a job a watch already tracks (see Fold.Finished): one
// projected before a watch naming another attribute existed cannot be
// mistaken for a match.
var FeedAttrs = append([]string{
	"ScheddName", "User", "GlobalJobId",
	"QDate", "EnteredCurrentStatus", "CompletionDate", "Cmd", "RemoteHost",
}, BaseAttrs...)

// project returns a copy of ad holding FeedAttrs, Keep's attributes and
// every attribute of the ad those refer to (RequestMemory is usually an
// expression over MemoryUsage, which is one over ResidentSetSize), or ad
// itself when Keep is nil. It shares the kept expressions, which nothing
// here modifies.
func (f *Feed) project(ad *classad.ClassAd) *classad.ClassAd {
	if f.Keep == nil {
		return ad
	}
	want := append(append([]string(nil), FeedAttrs...), f.Keep()...)
	keep := make(map[string]bool, len(want)+16)
	out := classad.New()
	for len(want) > 0 {
		name := want[len(want)-1]
		want = want[:len(want)-1]
		if keep[strings.ToLower(name)] {
			continue
		}
		keep[strings.ToLower(name)] = true
		e, ok := ad.Lookup(name)
		if !ok {
			continue
		}
		out.InsertExpr(name, e)
		want = append(want, ad.InternalRefs(e)...)
	}
	return out
}
