package matchanalyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// SlotQuerier is the small slice of *htcondor.Collector the analyzer needs.
// We don't depend on htcondor.Collector directly so tests can stand in a
// stub without spinning up a collector connection. Production wires the
// real collector in via NewCollectorSlotProvider.
type SlotQuerier interface {
	QueryAdsWithProjection(ctx context.Context, adType string, constraint string, projection []string) ([]*classad.ClassAd, error)
}

// CollectorSlotProvider fetches StartdAds from a collector with attribute-
// aware caching.
//
// # Caching policy
//
// The cache is single-bucket (one collector → one cached slot snapshot).
// Each entry remembers:
//   - the projection it was fetched with (a sorted set of attribute names)
//   - the time it was fetched
//   - the slot ads themselves
//
// A new request with attrs A is served from cache iff:
//   - the cached projection ⊇ A, AND
//   - the cached entry is younger than ttl
//
// Otherwise we re-fetch with the union of (cached projection ∪ A) and
// replace the cache. The union strategy keeps the cache useful for a
// caller asking for a subset of what a previous caller asked for, without
// "cache thrash" between callers requesting disjoint attribute sets.
//
// Projection "*"
//
// If a caller passes the special projection ["*"] we skip the cache key
// arithmetic and treat it as "all attributes". Subsequent requests for
// any subset are served from the same entry.
type CollectorSlotProvider struct {
	q SlotQuerier

	// Constraint passed to the collector. Defaults to empty (no
	// constraint), meaning all StartdAds. Tests and callers wanting to
	// scope analysis (e.g., per-pool subset) can override.
	constraint string

	// adType is the collector ad type to query for. Always "StartdAd"
	// in production; configurable for tests.
	adType string

	ttl time.Duration

	mu    sync.Mutex
	entry *slotCacheEntry
}

// slotCacheEntry is one snapshot of slot ads with the projection used.
type slotCacheEntry struct {
	fetchedAt time.Time

	// allAttrs is true iff this entry was fetched with the "*" projection.
	// In that case projection is empty and any attribute request hits.
	allAttrs bool

	// projection is the sorted, distinct set of attributes the cached ads
	// are guaranteed to contain. The collector may have included more
	// (it does include identity attrs like Name regardless), but we only
	// commit to what we asked for.
	projection map[string]struct{}

	ads []*classad.ClassAd
}

// CollectorSlotProviderOption configures a CollectorSlotProvider.
type CollectorSlotProviderOption func(*CollectorSlotProvider)

// WithSlotConstraint scopes the slot pool query with a ClassAd constraint
// expression (passed verbatim to the collector). Default is no constraint.
func WithSlotConstraint(constraint string) CollectorSlotProviderOption {
	return func(p *CollectorSlotProvider) { p.constraint = constraint }
}

// WithSlotAdType overrides the ad type queried for. Defaults to "StartdAd".
// Tests use this to swap in a small ad type when standing up a fixture.
func WithSlotAdType(adType string) CollectorSlotProviderOption {
	return func(p *CollectorSlotProvider) { p.adType = adType }
}

// WithSlotCacheTTL sets the cache TTL. Default 30s — short enough to pick
// up a slot's drain/cordon transitions in roughly one analysis cycle, long
// enough to amortize the cost of a multi-thousand-ad query across rapid
// page reloads.
func WithSlotCacheTTL(ttl time.Duration) CollectorSlotProviderOption {
	return func(p *CollectorSlotProvider) { p.ttl = ttl }
}

// NewCollectorSlotProvider constructs a SlotProvider backed by the given
// SlotQuerier (typically *htcondor.Collector).
func NewCollectorSlotProvider(q SlotQuerier, opts ...CollectorSlotProviderOption) *CollectorSlotProvider {
	if q == nil {
		panic("matchanalyzer.NewCollectorSlotProvider: nil SlotQuerier")
	}
	p := &CollectorSlotProvider{
		q:      q,
		adType: "StartdAd",
		ttl:    30 * time.Second,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Slots implements SlotProvider. requiredAttrs is the union of attributes
// the caller will read from the returned ads. The provider may return ads
// containing additional attributes, but never fewer.
func (p *CollectorSlotProvider) Slots(ctx context.Context, requiredAttrs []string) ([]*classad.ClassAd, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	wantAll, requested := normalizeAttrs(requiredAttrs)

	// Cache hit?
	if p.entry != nil && !p.entry.expired(p.ttl) {
		if p.entry.allAttrs {
			return p.entry.ads, nil
		}
		if !wantAll && hasAll(p.entry.projection, requested) {
			return p.entry.ads, nil
		}
	}

	// Cache miss (or stale). Build the projection we'll actually
	// request. If the caller asked for "*", honor that. Otherwise
	// fetch the union of the cached projection (if any, even if
	// stale, to keep future hits warm) and the new requirements.
	var projection []string
	if wantAll {
		projection = []string{"*"}
	} else {
		merged := map[string]struct{}{}
		for k := range requested {
			merged[k] = struct{}{}
		}
		if p.entry != nil {
			for k := range p.entry.projection {
				merged[k] = struct{}{}
			}
		}
		projection = sortedKeys(merged)
	}

	ads, err := p.q.QueryAdsWithProjection(ctx, p.adType, p.constraint, projection)
	if err != nil {
		return nil, fmt.Errorf("matchanalyzer: slot query: %w", err)
	}

	entry := &slotCacheEntry{
		fetchedAt: time.Now(),
		ads:       ads,
		allAttrs:  wantAll,
	}
	if !wantAll {
		entry.projection = make(map[string]struct{}, len(projection))
		for _, a := range projection {
			entry.projection[a] = struct{}{}
		}
	}
	p.entry = entry

	return ads, nil
}

// CacheStatus returns a description of the current cache entry, mostly
// useful for debug endpoints and tests. Returns zero-valued struct when
// the cache is empty.
func (p *CollectorSlotProvider) CacheStatus() CacheStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.entry == nil {
		return CacheStatus{}
	}
	return CacheStatus{
		FetchedAt:  p.entry.fetchedAt,
		AdCount:    len(p.entry.ads),
		AllAttrs:   p.entry.allAttrs,
		Projection: sortedKeys(p.entry.projection),
		AgeSeconds: int(time.Since(p.entry.fetchedAt).Seconds()),
	}
}

// CacheStatus is the public view of the slot cache. JSON-serializable for
// the eventual debug UI.
type CacheStatus struct {
	FetchedAt  time.Time `json:"fetched_at,omitempty"`
	AgeSeconds int       `json:"age_seconds,omitempty"`
	AdCount    int       `json:"ad_count,omitempty"`
	AllAttrs   bool      `json:"all_attrs,omitempty"`
	Projection []string  `json:"projection,omitempty"`
}

func (e *slotCacheEntry) expired(ttl time.Duration) bool {
	if ttl <= 0 {
		return true
	}
	return time.Since(e.fetchedAt) >= ttl
}

// normalizeAttrs returns (wantAll, set). wantAll is true if "*" is in the
// list (treat as "all attributes"). Otherwise set is the deduplicated
// non-empty set. Empty / nil input → wantAll=false, set=empty.
func normalizeAttrs(attrs []string) (bool, map[string]struct{}) {
	set := make(map[string]struct{}, len(attrs))
	wantAll := false
	for _, a := range attrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if a == "*" {
			wantAll = true
			continue
		}
		set[a] = struct{}{}
	}
	return wantAll, set
}

func hasAll(haystack, needles map[string]struct{}) bool {
	for n := range needles {
		if _, ok := haystack[n]; !ok {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// StaticSlotProvider is a trivial in-memory SlotProvider for tests. It
// returns the same set of ads on every call, regardless of the requested
// attributes — so tests can reason about slot match outcomes without
// worrying about projection truncation.
type StaticSlotProvider struct {
	Ads []*classad.ClassAd

	// LastRequestedAttrs records the attrs argument from the most recent
	// Slots call. Tests assert on this to verify the analyzer asked for
	// the right projection.
	LastRequestedAttrs []string
}

// Slots implements SlotProvider.
func (p *StaticSlotProvider) Slots(_ context.Context, requiredAttrs []string) ([]*classad.ClassAd, error) {
	// Deep-copy the slice so a test's mutation of LastRequestedAttrs
	// doesn't echo back into the analyzer's state on a subsequent call.
	p.LastRequestedAttrs = append([]string(nil), requiredAttrs...)
	return p.Ads, nil
}
