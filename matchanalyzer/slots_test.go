package matchanalyzer

import (
	"context"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// fakeQuerier records every query it receives so cache-behavior tests can
// assert on what was actually fetched. The Ads field is the canned
// response; tests vary it across calls to mimic a changing pool.
type fakeQuerier struct {
	mu    sync.Mutex
	calls []fakeQuery
	ads   []*classad.ClassAd
	err   error
}

type fakeQuery struct {
	adType     string
	constraint string
	projection []string
}

func (f *fakeQuerier) QueryAdsWithProjection(_ context.Context, adType, constraint string, projection []string) ([]*classad.ClassAd, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Copy the projection so the test can inspect what was actually
	// requested without aliasing the analyzer's slice.
	pcopy := append([]string(nil), projection...)
	sort.Strings(pcopy)
	f.calls = append(f.calls, fakeQuery{adType: adType, constraint: constraint, projection: pcopy})
	return f.ads, f.err
}

func (f *fakeQuerier) lastCall(t *testing.T) fakeQuery {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		t.Fatal("no calls made")
	}
	return f.calls[len(f.calls)-1]
}

func (f *fakeQuerier) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func TestCollectorSlotProviderCachesSubsetRequests(t *testing.T) {
	// First request asks for {Arch, Memory}. Second asks for {Arch}.
	// The second is a subset of what's cached, so it must NOT trigger
	// another collector call. This is the central caching property —
	// the analyzer can be invoked many times back-to-back during a
	// debug session without hammering the collector.
	q := &fakeQuerier{}
	p := NewCollectorSlotProvider(q, WithSlotCacheTTL(time.Hour))

	if _, err := p.Slots(context.Background(), []string{"Arch", "Memory"}); err != nil {
		t.Fatalf("first Slots: %v", err)
	}
	if got := q.callCount(); got != 1 {
		t.Fatalf("after first request, calls = %d, want 1", got)
	}

	if _, err := p.Slots(context.Background(), []string{"Arch"}); err != nil {
		t.Fatalf("second Slots: %v", err)
	}
	if got := q.callCount(); got != 1 {
		t.Errorf("subset request must hit cache (calls = %d, want 1)", got)
	}
}

func TestCollectorSlotProviderRefetchesForSupersetAndUnionsProjection(t *testing.T) {
	// First request: {Arch}. Second adds {Memory}. The cache only knows
	// about {Arch}, so it has to re-fetch — and when it does, it should
	// ask for {Arch, Memory} (the union), not just {Memory}, so that
	// future {Arch}-only requests still hit cache.
	q := &fakeQuerier{}
	p := NewCollectorSlotProvider(q, WithSlotCacheTTL(time.Hour))

	if _, err := p.Slots(context.Background(), []string{"Arch"}); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := p.Slots(context.Background(), []string{"Memory"}); err != nil {
		t.Fatalf("second: %v", err)
	}
	if got := q.callCount(); got != 2 {
		t.Errorf("expected 2 calls (subset miss → refetch), got %d", got)
	}
	wantProjection := []string{"Arch", "Memory"}
	if got := q.lastCall(t).projection; !reflect.DeepEqual(got, wantProjection) {
		t.Errorf("refetch projection = %v, want %v (must union with cached attrs)", got, wantProjection)
	}

	// Now a third request for just {Arch} should hit the cache (because
	// the second fetch unioned attrs).
	before := q.callCount()
	if _, err := p.Slots(context.Background(), []string{"Arch"}); err != nil {
		t.Fatalf("third: %v", err)
	}
	if q.callCount() != before {
		t.Errorf("after union refetch, {Arch}-only request should hit cache (calls before=%d, after=%d)", before, q.callCount())
	}
}

func TestCollectorSlotProviderRefetchesAfterTTL(t *testing.T) {
	q := &fakeQuerier{}
	// Tiny TTL so we don't have to wait. A negative TTL would force
	// every call to miss; we want zero misses initially and then a miss
	// after expiry, so use a small positive value and sleep past it.
	p := NewCollectorSlotProvider(q, WithSlotCacheTTL(10*time.Millisecond))

	if _, err := p.Slots(context.Background(), []string{"Arch"}); err != nil {
		t.Fatalf("first: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := p.Slots(context.Background(), []string{"Arch"}); err != nil {
		t.Fatalf("second: %v", err)
	}
	if got := q.callCount(); got != 2 {
		t.Errorf("expected refetch after TTL, calls=%d", got)
	}
}

func TestCollectorSlotProviderStarProjectionShortCircuits(t *testing.T) {
	// If a caller asks for "*" (all attributes), subsequent requests
	// for any subset should hit cache regardless of projection — there
	// is no superset.
	q := &fakeQuerier{}
	p := NewCollectorSlotProvider(q, WithSlotCacheTTL(time.Hour))

	if _, err := p.Slots(context.Background(), []string{"*"}); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := p.Slots(context.Background(), []string{"Arch", "Memory", "Disk"}); err != nil {
		t.Fatalf("second: %v", err)
	}
	if got := q.callCount(); got != 1 {
		t.Errorf("after '*' fetch, subsequent requests must hit cache; calls=%d", got)
	}

	if !p.CacheStatus().AllAttrs {
		t.Error("CacheStatus should report AllAttrs=true after '*' fetch")
	}
}

func TestCollectorSlotProviderCacheStatus(t *testing.T) {
	q := &fakeQuerier{ads: []*classad.ClassAd{
		mustParse(t, `[ Name = "h1"; Arch = "Linux" ]`),
		mustParse(t, `[ Name = "h2"; Arch = "Linux" ]`),
	}}
	p := NewCollectorSlotProvider(q, WithSlotCacheTTL(time.Hour))

	// Empty before any call.
	if status := p.CacheStatus(); status.AdCount != 0 {
		t.Errorf("empty cache: AdCount = %d, want 0", status.AdCount)
	}

	if _, err := p.Slots(context.Background(), []string{"Arch", "Memory"}); err != nil {
		t.Fatalf("Slots: %v", err)
	}
	status := p.CacheStatus()
	if status.AdCount != 2 {
		t.Errorf("AdCount = %d, want 2", status.AdCount)
	}
	if status.FetchedAt.IsZero() {
		t.Error("FetchedAt should be set")
	}
	if !reflect.DeepEqual(status.Projection, []string{"Arch", "Memory"}) {
		t.Errorf("Projection = %v, want [Arch Memory]", status.Projection)
	}
	if status.AllAttrs {
		t.Error("AllAttrs should be false for a non-* projection")
	}
}

func TestNormalizeAttrs(t *testing.T) {
	cases := []struct {
		name        string
		in          []string
		wantAll     bool
		wantNonStar []string
	}{
		{"empty", nil, false, []string{}},
		{"single attr", []string{"Arch"}, false, []string{"Arch"}},
		{"star", []string{"*"}, true, []string{}},
		{"star with attrs", []string{"Arch", "*"}, true, []string{"Arch"}},
		{"duplicates dropped", []string{"Arch", "Arch"}, false, []string{"Arch"}},
		{"empty strings filtered", []string{"", "Arch", " "}, false, []string{"Arch"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotAll, set := normalizeAttrs(tc.in)
			if gotAll != tc.wantAll {
				t.Errorf("wantAll = %v, want %v", gotAll, tc.wantAll)
			}
			gotKeys := sortedKeys(set)
			if gotKeys == nil {
				gotKeys = []string{}
			}
			if !reflect.DeepEqual(gotKeys, tc.wantNonStar) {
				t.Errorf("set = %v, want %v", gotKeys, tc.wantNonStar)
			}
		})
	}
}

func mustParse(t *testing.T, s string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return ad
}
