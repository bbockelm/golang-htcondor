package jobwatch

import (
	"context"
	"fmt"
	"sync"
	"time"

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
	// ended is the final observed ad for jobs that have left the queue.
	ended map[string]endedJob
	// warm says a stream is connected and nothing has been missed since.
	warm bool
	// subs are per-job followers of this same stream. See subscribe.go.
	// Keyed by job identity rather than storage key so the feed's refusal
	// to parse that key does not leak out to callers.
	subs map[jobIdent]map[*keySub]struct{}

	now  func() time.Time
	logf func(string, ...any)

	// MaxEnded bounds memory; oldest out first.
	MaxEnded int
	// EndedTTL is how long a terminal record stays useful. It only has
	// to outlive the lookback a watch uses.
	EndedTTL time.Duration
}

type endedJob struct {
	ad *classad.ClassAd
	at time.Time
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

func (f *Feed) follow(ctx context.Context, dial Dialer) error {
	events, stop, err := dial(ctx)
	if err != nil {
		return fmt.Errorf("opening the change stream: %w", err)
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

	switch ev.Kind {
	case WatchUpsert:
		ad, err := classad.ParseOld(ev.AdText)
		if err != nil || ad == nil {
			// An unreadable upsert leaves no record, so the delete that
			// follows finds nothing and the job falls through to the
			// history archive: later, not wrong.
			return
		}
		f.live[ev.Key] = ad
		// A job can come back -- a held job released, or a key reused
		// after a compaction reload. Clear any terminal record so it is
		// not reported as finished while it is running again.
		delete(f.ended, ev.Key)
		if id, ok := identOf(ad); ok {
			f.notifyLocked(id, KeyChange{Ad: ad})
		}
	case WatchDelete:
		// The delete says only that the key is gone. What it was doing
		// when it went is in the upsert we kept.
		if ad, ok := f.live[ev.Key]; ok {
			f.ended[ev.Key] = endedJob{ad: ad, at: f.now()}
			delete(f.live, ev.Key)
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
// The stream carries every job on the access point, so the owner filter
// here is what keeps one user's outcomes out of another's watch.
func (f *Feed) Terminal(owner string, since time.Time) []*classad.ClassAd {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.warm {
		return nil
	}
	out := make([]*classad.ClassAd, 0, 16)
	for _, e := range f.ended {
		if e.at.Before(since) {
			continue
		}
		if v, ok := e.ad.EvaluateAttrString("Owner"); ok && v == owner {
			out = append(out, e.ad)
		}
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
