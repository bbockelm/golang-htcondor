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
	mu  sync.Mutex // held across a read, so viewers queue rather than pile on
	set *issues.Set
	at  time.Time
}

func newIssueCache() *issueCache {
	return &issueCache{byKey: make(map[string]*cachedIssues), now: time.Now}
}

// get returns a set and whether it came from the cache.
func (c *issueCache) get(key string, compute func() (*issues.Set, error)) (*issues.Set, bool, error) {
	c.mu.Lock()
	entry := c.byKey[key]
	if entry == nil {
		entry = &cachedIssues{}
		c.byKey[key] = entry
	}
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.set != nil && c.now().Sub(entry.at) < issueRefresh {
		return entry.set, true, nil
	}
	set, err := compute()
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
