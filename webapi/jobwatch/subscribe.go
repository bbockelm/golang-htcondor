package jobwatch

import (
	"sync"

	"github.com/PelicanPlatform/classad/classad"
)

// Per-job subscriptions on top of the feed.
//
// The feed already sees every change to the jobs table for the MCP watch
// evaluator. A caller that wants to follow one job -- a browser sitting on
// a session page -- can read from that same stream instead of opening a
// second watch on the same table, which would double the wire traffic to
// learn nothing new.
//
// Subscription is by job identity, not by storage key. The feed keys its
// maps by the source's own key and deliberately does not parse it; making
// callers supply that key would push the coupling the feed avoids out into
// every caller. A delete carries only the key, but the feed still holds the
// last upsert for it, so identity is recoverable from the ad it already
// kept.

// KeyChange is one change to a subscribed job.
//
// Exactly one of the three states holds: Ad is set for an update, Gone is
// true when the job left the queue, and Stale is true when the feed lost
// continuity and the subscriber must re-read the job for itself.
type KeyChange struct {
	Ad    *classad.ClassAd
	Gone  bool
	Stale bool
}

type jobIdent struct{ cluster, proc int64 }

type keySub struct {
	id   jobIdent
	ch   chan KeyChange
	once sync.Once
	feed *Feed
}

// identOf reads a job's identity from its ad. ok is false for an ad
// without one, which is not a job row this can address.
func identOf(ad *classad.ClassAd) (jobIdent, bool) {
	if ad == nil {
		return jobIdent{}, false
	}
	c, okc := ad.EvaluateAttrInt("ClusterId")
	p, okp := ad.EvaluateAttrInt("ProcId")
	if !okc || !okp {
		return jobIdent{}, false
	}
	return jobIdent{cluster: c, proc: p}, true
}

// Subscribe follows one job. The returned channel delivers changes until
// cancel is called; cancel is safe to call more than once and must be
// called, or the subscription leaks for the life of the process.
//
// The channel holds one change. A subscriber that is slow to read sees the
// most recent state rather than a queue of stale ones, and never stalls the
// feed: this is the same stream the MCP evaluator reads, and one idle
// browser tab must not be able to hold it up.
func (f *Feed) Subscribe(cluster, proc int64) (<-chan KeyChange, func()) {
	s := &keySub{
		id:   jobIdent{cluster: cluster, proc: proc},
		ch:   make(chan KeyChange, 1),
		feed: f,
	}
	f.mu.Lock()
	if f.subs == nil {
		f.subs = make(map[jobIdent]map[*keySub]struct{})
	}
	m := f.subs[s.id]
	if m == nil {
		m = make(map[*keySub]struct{})
		f.subs[s.id] = m
	}
	m[s] = struct{}{}
	f.mu.Unlock()

	return s.ch, func() {
		s.once.Do(func() {
			f.mu.Lock()
			if m := f.subs[s.id]; m != nil {
				delete(m, s)
				if len(m) == 0 {
					delete(f.subs, s.id)
				}
			}
			f.mu.Unlock()
			close(s.ch)
		})
	}
}

// notifyLocked delivers one change to the subscribers of id. The caller
// holds f.mu; sends are non-blocking so the feed's apply path cannot be
// stalled by a reader.
func (f *Feed) notifyLocked(id jobIdent, ch KeyChange) {
	for s := range f.subs[id] {
		s.deliver(ch)
	}
}

// notifyAllLocked tells every subscriber their view may be stale. Used
// when the stream's continuity breaks, where the feed cannot say which
// jobs changed while it was away -- only that it no longer knows.
func (f *Feed) notifyAllLocked() {
	for _, m := range f.subs {
		for s := range m {
			s.deliver(KeyChange{Stale: true})
		}
	}
}

func (s *keySub) deliver(ch KeyChange) {
	select {
	case s.ch <- ch:
	default:
		// Replace the pending change: only the latest matters, and a
		// dropped intermediate state is invisible to a UI that renders
		// current state. A Stale must not be lost this way, though --
		// it is the one change that is not superseded by a later ad,
		// because it says "you must go and look".
		select {
		case old := <-s.ch:
			if old.Stale {
				ch.Stale = true
			}
		default:
		}
		select {
		case s.ch <- ch:
		default:
		}
	}
}
