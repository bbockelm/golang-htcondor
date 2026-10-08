// Package multiap serves read-only job queries for a multi-AP
// htcondor-api: one API server in front of every access point whose
// schedd ad matches HTTP_API_SCHEDD_CONSTRAINT.
//
// Unscoped reads come from a federation hub -- an htcondordb that fans
// every AP's per-AP mirror (spoke) into one catalog -- and every response
// carries a sources block saying which APs' rows are fresh. A read
// scoped to one job falls back, when that AP's hub copy is not fresh, to
// the AP's own spoke and then to its schedd.
//
// The hub's data contract (htcondordb federate/): tables jobs (mutable),
// history (archive) and federation_sources (one row per schedd). Every
// replicated row carries ScheddName, set by the hub from the source's
// validated identity. Hub storage keys are opaque and never parsed here;
// rows are selected on ScheddName, ClusterId and ProcId.
package multiap

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"
)

// Hub table and attribute names, from the hub's contract.
const (
	TableJobs    = "jobs"
	TableHistory = "history"
	TableSources = "federation_sources"

	AttrScheddName = "ScheddName"
)

// Source states the hub reports in federation_sources.State.
const (
	StateFresh     = "fresh"
	StateStale     = "stale"
	StateAbsent    = "absent"
	StateUntrusted = "untrusted"
	StateRetiring  = "retiring"
)

// DefaultSourcesInterval is how often the hub's federation_sources table
// is re-read. A source's state changes on the hub's own 5 s cadence.
const DefaultSourcesInterval = 5 * time.Second

// Source is one federation_sources row.
type Source struct {
	Schedd string
	State  string
	Reason string
	// Staleness is the hub's bound on how far its copy of this AP is
	// behind the AP's schedd. StalenessKnown is false when the hub could
	// not measure it (no heartbeat yet), which it reports as stale.
	Staleness      int64
	StalenessKnown bool
	LastSeen       time.Time
	LastReset      time.Time
	SpokeAddress   string
}

// ParseSource reads a federation_sources row. ok is false for a row
// with no ScheddName.
func ParseSource(ad *classad.ClassAd) (Source, bool) {
	var s Source
	s.Schedd, _ = ad.EvaluateAttrString(AttrScheddName)
	if s.Schedd == "" {
		return s, false
	}
	s.State, _ = ad.EvaluateAttrString("State")
	s.Reason, _ = ad.EvaluateAttrString("Reason")
	s.Staleness, s.StalenessKnown = ad.EvaluateAttrInt("StalenessSeconds")
	if v, ok := ad.EvaluateAttrInt("LastSeen"); ok && v > 0 {
		s.LastSeen = time.Unix(v, 0).UTC()
	}
	if v, ok := ad.EvaluateAttrInt("LastReset"); ok && v > 0 {
		s.LastReset = time.Unix(v, 0).UTC()
	}
	s.SpokeAddress, _ = ad.EvaluateAttrString("SpokeAddress")
	if s.State == "" {
		// A row the hub wrote without a state says nothing about
		// freshness, so it is not fresh.
		s.State = StateStale
	}
	return s, true
}

// Dialer opens a dbrpc session to a database. The caller invokes the
// returned closer.
type Dialer func(ctx context.Context) (*dbrpc.Client, func(), error)

// Hub reads the federation hub: it dials it for queries and keeps the
// latest federation_sources snapshot.
type Hub struct {
	dial     Dialer
	interval time.Duration
	now      func() time.Time

	mu          sync.RWMutex
	sources     map[string]Source // keyed by lower-cased schedd name
	sourcesAt   time.Time
	lastAttempt time.Time
	lastErr     string
}

// NewHub returns a Hub that dials with dial.
func NewHub(dial Dialer, interval time.Duration) *Hub {
	if interval <= 0 {
		interval = DefaultSourcesInterval
	}
	return &Hub{dial: dial, interval: interval, now: time.Now}
}

// Client dials the hub.
func (h *Hub) Client(ctx context.Context) (*dbrpc.Client, func(), error) {
	if h == nil || h.dial == nil {
		return nil, nil, fmt.Errorf("no federation hub is configured")
	}
	return h.dial(ctx)
}

// Refresh re-reads federation_sources. On error the previous snapshot is
// kept, and its age says how old it is.
func (h *Hub) Refresh(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	sources, err := h.readSources(ctx)
	now := h.now()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastAttempt = now
	if err != nil {
		h.lastErr = err.Error()
		return err
	}
	h.sources, h.sourcesAt, h.lastErr = sources, now, ""
	return nil
}

func (h *Hub) readSources(ctx context.Context) (map[string]Source, error) {
	dbc, closer, err := h.Client(ctx)
	if err != nil {
		return nil, err
	}
	defer closer()
	out := map[string]Source{}
	var perr error
	err = dbc.QueryRawTableStream(ctx, TableSources, "true", 0, func(row string) bool {
		ad, e := classad.ParseOld(row)
		if e != nil {
			perr = fmt.Errorf("unparseable %s row: %w", TableSources, e)
			return false
		}
		if s, ok := ParseSource(ad); ok {
			out[strings.ToLower(s.Schedd)] = s
		}
		return true
	})
	if err == nil {
		err = perr
	}
	if err != nil {
		return nil, fmt.Errorf("reading the hub's %s: %w", TableSources, err)
	}
	return out, nil
}

// Run refreshes until ctx is done, starting immediately.
func (h *Hub) Run(ctx context.Context, onResult func(error)) {
	poll := func() {
		err := h.Refresh(ctx)
		if onResult != nil {
			onResult(err)
		}
	}
	poll()
	t := time.NewTicker(h.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			poll()
		}
	}
}

// HubStatus is the hub's reachability, for /readyz and /api/v1/aps.
type HubStatus struct {
	// Reachable is whether the last federation_sources read succeeded
	// within three refresh intervals.
	Reachable   bool
	LastSuccess time.Time
	LastAttempt time.Time
	LastError   string
	Sources     int
}

// Status reports the hub's reachability.
func (h *Hub) Status() HubStatus {
	if h == nil {
		return HubStatus{LastError: "no federation hub is configured"}
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	st := HubStatus{LastSuccess: h.sourcesAt, LastAttempt: h.lastAttempt, LastError: h.lastErr, Sources: len(h.sources)}
	st.Reachable = !h.sourcesAt.IsZero() && h.now().Sub(h.sourcesAt) <= 3*h.interval+10*time.Second
	return st
}

// Source returns the hub's row for schedd. ok is false when the hub has
// none -- or when the snapshot is too old to vouch for anything, in which
// case nothing the hub holds counts as fresh.
func (h *Hub) Source(schedd string) (Source, bool) {
	if h == nil {
		return Source{}, false
	}
	if !h.Status().Reachable {
		return Source{}, false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	s, ok := h.sources[strings.ToLower(schedd)]
	return s, ok
}

// Sources returns the snapshot, sorted by schedd.
func (h *Hub) Sources() []Source {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Source, 0, len(h.sources))
	for _, s := range h.sources {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Schedd < out[j].Schedd })
	return out
}
