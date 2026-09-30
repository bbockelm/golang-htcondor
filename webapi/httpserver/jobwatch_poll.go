package httpserver

import (
	"context"
	"fmt"
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

// jobPollHub runs one poll loop per distinct caller and constraint,
// however many watchers that pair has.
//
// Keyed on the CALLER's credential as well as the constraint. An earlier
// version keyed on the constraint alone, reasoning that the constraint
// carries the caller's owner scope so two callers entitled to see
// different things never share. That is not true: bulkOwnerScope returns
// the constraint UNSCOPED both for a web UI admin and for any caller with
// no session, so two such callers watching the same job produce byte-
// identical constraints and shared one subscription -- and with it one
// credential.
//
// The key is the credential's SecurityTag, which is what cedar already
// partitions its own client sessions by, so this draws the boundary in
// the same place the layer underneath does. A caller with no tag gets a
// group of its own rather than joining one, because "no tag" is not an
// identity and must not be treated as one shared between strangers.
//
// The sharing that remains is the case it was built for: several viewers
// of the same job, as the same person, collapsing to one query per
// interval.
type jobPollHub struct {
	interval time.Duration
	query    func(ctx context.Context, constraint string) (*classad.ClassAd, error)
	logger   *logging.Logger

	mu     sync.Mutex
	groups map[pollKey]*jobPollGroup
	// untagged numbers the groups that cannot be keyed by a credential,
	// so each gets its own rather than colliding on the empty tag.
	untagged uint64
}

// pollKey identifies a poll group: whose credential it runs on, and what
// it asks for.
type pollKey struct {
	cred       string
	constraint string
}

type jobPollGroup struct {
	hub        *jobPollHub
	key        pollKey
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
		groups:   map[pollKey]*jobPollGroup{},
	}
}

// Subscribe joins (or starts) the poll for constraint, as the caller that
// ctx carries. The returned source must be closed; the underlying poll
// stops when its last subscriber goes.
//
// ctx is read for the caller's credential and is NOT retained: it belongs
// to one HTTP request and the poll outlives it. The credential is copied
// onto a fresh background context instead, which means the poll keeps
// running on the authority the subscriber had when it joined, and does
// not re-check it. That is deliberate -- a watch is a stream the caller
// already opened, not a fresh act of authorization each tick.
func (h *jobPollHub) Subscribe(ctx context.Context, constraint string) jobWatchSource {
	h.mu.Lock()
	defer h.mu.Unlock()

	key, pollCtx := h.keyFor(ctx, constraint)

	g := h.groups[key]
	if g == nil {
		gctx, cancel := context.WithCancel(pollCtx)
		g = &jobPollGroup{
			hub:        h,
			key:        key,
			constraint: constraint,
			cancel:     cancel,
			subs:       map[*jobPollSub]struct{}{},
		}
		h.groups[key] = g
		go g.run(gctx)
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

// keyFor derives a group key from the caller's credential and returns the
// background context the group's polls run on.
//
// The poll context is built from Background rather than from the request,
// because the group outlives the request that created it and a cancelled
// parent would stop it for every other subscriber. It carries the
// caller's security config so the query reaches the schedd as them, and
// is marked as a caller's request so that a missing credential is refused
// rather than falling through to this daemon's own.
func (h *jobPollHub) keyFor(ctx context.Context, constraint string) (pollKey, context.Context) {
	pollCtx := htcondor.WithUserRequest(context.Background(), "job watch poll")

	// GetSecurityConfigFromContext hands back a copy, so the group holds
	// its own and cannot be disturbed by whatever the request does next.
	secCfg, ok := htcondor.GetSecurityConfigFromContext(ctx)
	if ok {
		cfg := secCfg
		pollCtx = htcondor.WithSecurityConfig(pollCtx, &cfg)
	}
	if user := htcondor.GetAuthenticatedUserFromContext(ctx); user != "" {
		pollCtx = htcondor.WithAuthenticatedUser(pollCtx, user)
	}

	if ok && secCfg.SecurityTag != "" {
		return pollKey{cred: secCfg.SecurityTag, constraint: constraint}, pollCtx
	}

	// No credential to key on. Give this subscriber a group of its own:
	// an empty tag is the absence of an identity, and treating it as one
	// would put every such caller on a single shared poll.
	h.untagged++
	return pollKey{cred: fmt.Sprintf("\x00untagged-%d", h.untagged), constraint: constraint}, pollCtx
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
		if h.groups[g.key] == g {
			delete(h.groups, g.key)
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
