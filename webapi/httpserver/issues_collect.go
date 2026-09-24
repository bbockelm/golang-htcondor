package httpserver

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/issues"
)

// The HTTP server's side of the issues view: where the records are read
// from, and how long they are kept. What counts as a problem, and how
// problems are grouped, lives in webapi/issues -- the MCP server asks the
// same questions through the same package, and a second copy of "which
// vacate codes mean the job could not be kept running" would drift.

// issueScanLimit bounds the schedd's backwards walk of epoch history when
// no mirror can answer. The walk is over a file.
const issueScanLimit = 200000

// issueRefresh is how long a collected set is reused. The granularity
// slider and the section toggles re-cluster this set rather than
// re-reading it, which is what makes them feel immediate.
const issueRefresh = 60 * time.Second

// issueRefreshIncomplete is how long a set that is missing a section is
// reused. Short, because it is a failure: at the full lifetime, one
// read that did not finish put a banner on the page for a minute, for
// everyone in that scope, with no way to ask again.
const issueRefreshIncomplete = 5 * time.Second

// issueCollectTimeout bounds a collection that no longer has a requester
// waiting on it. Generous, because it is a bound on runaway work rather
// than a service level -- the reads are big and the answer is worth
// having in the cache even if the person who triggered it has gone.
const issueCollectTimeout = 2 * time.Minute

// handlerIssueSource reads through the mirror when it can and the schedd
// otherwise, which is the same preference every other listing has.
type handlerIssueSource struct{ s *Handler }

func (h handlerIssueSource) JobAds(ctx context.Context, constraint string, projection []string, limit int) ([]*classad.ClassAd, string, error) {
	if ads, err := h.s.mirrorRows(ctx, "jobs", constraint, projection, limit); err == nil {
		return ads, "htcondordb mirror", nil
	} else if h.s.dbMirror.Enabled() {
		h.s.logger.Debug(logging.DestinationHTTP, "issues: mirror declined the queue read", "error", err)
	}
	ads, _, err := h.s.getSchedd().QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Projection: projection,
		Limit:      limit,
	})
	if err != nil {
		return nil, "", err
	}
	return ads, "schedd", nil
}

func (h handlerIssueSource) EpochAds(ctx context.Context, constraint string, projection []string, limit int) ([]*classad.ClassAd, string, error) {
	if ads, err := h.s.mirrorRows(ctx, "epoch_history", constraint, projection, limit); err == nil {
		return ads, "htcondordb mirror", nil
	} else if h.s.dbMirror.Enabled() {
		h.s.logger.Debug(logging.DestinationHTTP, "issues: mirror declined the epoch read", "error", err)
	}
	ads, err := h.s.getSchedd().QueryHistoryWithOptions(ctx, constraint, &htcondor.HistoryQueryOptions{
		Source:     htcondor.HistorySourceJobEpoch,
		Projection: projection,
		Limit:      limit,
		ScanLimit:  issueScanLimit,
		Backwards:  true,
	})
	if err != nil {
		return nil, "", err
	}
	return ads, "schedd", nil
}

// mirrorRows is one bounded projected read of a mirror table.
func (s *Handler) mirrorRows(ctx context.Context, table, constraint string, projection []string, limit int) ([]*classad.ClassAd, error) {
	if !s.dbMirror.Enabled() {
		return nil, fmt.Errorf("no htcondordb mirror is configured")
	}
	dbc, closer, _, err := s.dbMirror.Client(ctx)
	if err != nil {
		return nil, err
	}
	defer closer()

	rows, err := dbc.QueryRawProject(ctx, table, constraint, projection, limit)
	if err != nil {
		return nil, err
	}
	out := make([]*classad.ClassAd, 0, len(rows))
	for _, raw := range rows {
		ad, perr := classad.ParseOld(raw)
		if perr != nil {
			continue
		}
		out = append(out, ad)
	}
	return out, nil
}

// issueCache serializes collection per scope, so a room full of
// facilitators with the page open costs one read rather than one each --
// and so that moving the granularity slider re-clusters a set that is
// already in memory.
type issueCache struct {
	mu    sync.Mutex
	byKey map[string]*cachedIssues
	now   func() time.Time
}

type cachedIssues struct {
	// A channel rather than a sync.Mutex, so a waiter can give up when
	// its own caller goes away instead of blocking on a collection it
	// no longer needs.
	lock chan struct{}
	set  *issues.Set
	at   time.Time
}

func newIssueCache() *issueCache {
	return &issueCache{byKey: make(map[string]*cachedIssues), now: time.Now}
}

// ttl is how long a set may be reused, which depends on whether it is a
// whole answer.
func (c *issueCache) ttl(set *issues.Set) time.Duration {
	if set.Incomplete {
		return issueRefreshIncomplete
	}
	return issueRefresh
}

// get returns a set and whether it came from the cache.
//
// ctx bounds the WAIT, not the collection. The two are deliberately
// different lifetimes: the set is shared -- cached, and served to every
// other viewer in this scope -- so tying its production to whichever
// request happened to trigger it means one person navigating away kills
// a read that everybody else is waiting for. The collection gets its own
// context (see the caller); a waiter that loses its own caller stops
// waiting, and the collection carries on into the cache for whoever asks
// next.
func (c *issueCache) get(ctx context.Context, key string, compute func(context.Context) (*issues.Set, error)) (*issues.Set, bool, error) {
	c.mu.Lock()
	entry := c.byKey[key]
	if entry == nil {
		entry = &cachedIssues{lock: make(chan struct{}, 1)}
		c.byKey[key] = entry
	}
	c.mu.Unlock()

	select {
	case entry.lock <- struct{}{}:
		defer func() { <-entry.lock }()
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}

	if entry.set != nil && c.now().Sub(entry.at) < c.ttl(entry.set) {
		return entry.set, true, nil
	}
	// Detached here rather than by the caller: see sharedComputeContext.
	computeCtx, cancel := sharedComputeContext(ctx, issueCollectTimeout)
	defer cancel()
	set, err := compute(computeCtx)
	if err != nil {
		// Serving the last good answer beats blanking the page when the
		// schedd hiccups, the same trade the dashboard makes.
		if entry.set != nil {
			return entry.set, true, nil
		}
		return nil, false, err
	}
	entry.set, entry.at = set, c.now()
	return set, false, nil
}

func (s *Handler) issueSets() *issueCache {
	s.issueCacheOnce.Do(func() { s.issueCacheVal = newIssueCache() })
	return s.issueCacheVal
}
