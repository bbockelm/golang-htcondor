package httpserver

import (
	"context"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// Watching one job for changes.
//
// Two sources, one contract. Where an htcondordb mirror is reachable the
// handler subscribes to jobwatch.Feed, which already follows the mirror's
// jobs table for the MCP watch evaluator -- one stream for the daemon, not
// one per viewer. Where there is no mirror -- a plain pool, or one whose
// mirror is down -- we fall back to polling the schedd, which is what this
// file provides.
//
// The fallback shares one poll across every watcher of the same job rather
// than giving each connection its own ticker: the schedd is the scarce
// resource, and N browsers on one job should cost what one costs. Watches
// are not persisted in either case; a client that reconnects gets a fresh
// snapshot and carries on.

// jobWatchUpdate is one delivery. A nil Ad means the job is no longer in
// the queue -- removed, and on its way to the archive. Note that a job
// which merely *finished* is still in the queue (submissions carry a
// LeaveJobInQueue expression that keeps completed jobs listed for days),
// so "gone" and "completed" are different events and only the latter
// arrives as an ad with JobStatus 4.
type jobWatchUpdate struct {
	Ad *classad.ClassAd
}

// jobWatchSource yields updates for one job until its context ends.
type jobWatchSource interface {
	// Updates returns the channel to read. It is closed when the source
	// is finished, which the caller must treat as end-of-stream rather
	// than as "the job is gone".
	Updates() <-chan jobWatchUpdate
	// Close releases the source. Safe to call more than once.
	Close()
}

// --- schedd polling fallback ---

// jobPollHub runs one poll loop per distinct constraint, however many
// watchers that constraint has.
//
// Keyed on the constraint rather than the job id on purpose: the
// constraint carries the caller's owner scope (see jobOwnerScope), so two
// callers entitled to see different things never share a subscription,
// while the common case -- several viewers of the same job with the same
// scope -- collapses to a single query per interval.
type jobPollHub struct {
	interval time.Duration
	query    func(ctx context.Context, constraint string) (*classad.ClassAd, error)
	logger   *logging.Logger

	mu     sync.Mutex
	groups map[string]*jobPollGroup
}

type jobPollGroup struct {
	hub        *jobPollHub
	constraint string
	cancel     context.CancelFunc

	mu   sync.Mutex
	subs map[*jobPollSub]struct{}
}

type jobPollSub struct {
	group *jobPollGroup
	ch    chan jobWatchUpdate
	once  sync.Once
}

func newJobPollHub(interval time.Duration, logger *logging.Logger,
	query func(ctx context.Context, constraint string) (*classad.ClassAd, error)) *jobPollHub {
	return &jobPollHub{
		interval: interval,
		query:    query,
		logger:   logger,
		groups:   map[string]*jobPollGroup{},
	}
}

// Subscribe joins (or starts) the poll for constraint. The returned source
// must be closed; the underlying poll stops when its last subscriber goes.
func (h *jobPollHub) Subscribe(constraint string) jobWatchSource {
	h.mu.Lock()
	defer h.mu.Unlock()

	g := h.groups[constraint]
	if g == nil {
		ctx, cancel := context.WithCancel(context.Background())
		g = &jobPollGroup{
			hub:        h,
			constraint: constraint,
			cancel:     cancel,
			subs:       map[*jobPollSub]struct{}{},
		}
		h.groups[constraint] = g
		go g.run(ctx)
	}

	// Buffered: a subscriber that is slow to read must not stall the poll
	// loop, which is shared. One slot is enough because only the latest
	// ad matters -- see the drop in broadcast.
	s := &jobPollSub{group: g, ch: make(chan jobWatchUpdate, 1)}
	g.mu.Lock()
	g.subs[s] = struct{}{}
	g.mu.Unlock()
	return s
}

func (g *jobPollGroup) run(ctx context.Context) {
	ticker := time.NewTicker(g.hub.interval)
	defer ticker.Stop()

	// Poll once immediately so a subscriber does not wait a full interval
	// for its first look at the job.
	g.pollOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.pollOnce(ctx)
		}
	}
}

func (g *jobPollGroup) pollOnce(ctx context.Context) {
	ad, err := g.hub.query(ctx, g.constraint)
	if err != nil {
		// A failed poll is not evidence the job is gone -- saying so would
		// tell every watcher their job vanished because the schedd was
		// briefly busy. Skip the tick; the next one re-reads.
		if g.hub.logger != nil {
			g.hub.logger.Debug(logging.DestinationHTTP, "job watch poll failed",
				"constraint", g.constraint, "error", err)
		}
		return
	}
	g.broadcast(jobWatchUpdate{Ad: ad})
}

func (g *jobPollGroup) broadcast(u jobWatchUpdate) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for s := range g.subs {
		select {
		case s.ch <- u:
		default:
			// The subscriber has an unread update. Replace it: only the
			// most recent state matters, and blocking here would let one
			// stalled reader stop everyone else's.
			select {
			case <-s.ch:
			default:
			}
			select {
			case s.ch <- u:
			default:
			}
		}
	}
}

func (s *jobPollSub) Updates() <-chan jobWatchUpdate { return s.ch }

func (s *jobPollSub) Close() {
	s.once.Do(func() {
		g := s.group
		g.mu.Lock()
		delete(g.subs, s)
		last := len(g.subs) == 0
		g.mu.Unlock()
		if !last {
			return
		}
		// Last one out stops the poll and drops the group, so an idle
		// server runs no job queries at all.
		h := g.hub
		h.mu.Lock()
		if h.groups[g.constraint] == g {
			delete(h.groups, g.constraint)
		}
		h.mu.Unlock()
		g.cancel()
	})
}

// scheddJobQuery is the hub's query function against a live schedd. It
// returns (nil, nil) when nothing matches, which the caller reads as "the
// job has left the queue".
func (s *Handler) scheddJobQuery(ctx context.Context, constraint string) (*classad.ClassAd, error) {
	ads, _, err := s.getSchedd().QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{Limit: 1})
	if err != nil {
		return nil, err
	}
	if len(ads) == 0 {
		return nil, nil
	}
	return ads[0], nil
}
