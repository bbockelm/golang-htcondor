package matchanalyzer

import (
	"context"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// makeSlotAd is a tiny helper for building slot ads from a key=value-like
// map. Real slot ads have many more attributes; the analyzer only ever
// reads what the predicates reference, so this minimal shape is enough
// for testing the analysis logic.
func makeSlotAd(t *testing.T, attrs string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.Parse(attrs)
	if err != nil {
		t.Fatalf("Parse(%q): %v", attrs, err)
	}
	return ad
}

func makeJobAd(t *testing.T, requirements string) *classad.ClassAd {
	t.Helper()
	src := "[ Requirements = " + requirements + " ]"
	ad, err := classad.Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	return ad
}

// TestAnalyzeBasicMatchCounts exercises the core: each predicate evaluated
// against each slot, full-match count = AND of predicate outcomes.
func TestAnalyzeBasicMatchCounts(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "slot1@host-a"; Machine = "host-a"; Arch = "Linux"; Cpus = 8 ]`),
		makeSlotAd(t, `[ Name = "slot1@host-b"; Machine = "host-b"; Arch = "Linux"; Cpus = 16 ]`),
		makeSlotAd(t, `[ Name = "slot1@host-c"; Machine = "host-c"; Arch = "OSX"; Cpus = 4 ]`),
	}
	provider := &StaticSlotProvider{Ads: slots}
	job := makeJobAd(t, `Arch == "Linux" && Cpus >= 8`)

	a := New(provider)
	res, err := a.Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if res.TotalSlots != 3 {
		t.Errorf("TotalSlots = %d, want 3", res.TotalSlots)
	}
	if res.FullMatches != 2 {
		t.Errorf("FullMatches = %d, want 2 (host-a and host-b)", res.FullMatches)
	}
	if len(res.Predicates) != 2 {
		t.Fatalf("expected 2 predicates, got %d", len(res.Predicates))
	}

	// Predicate 0: Arch == "Linux" → matches slot1@host-a, slot1@host-b
	if got := res.Predicates[0].Matched; got != 2 {
		t.Errorf("Arch predicate: matched=%d, want 2", got)
	}
	if got := res.Predicates[0].NotMatched; got != 1 {
		t.Errorf("Arch predicate: not_matched=%d, want 1", got)
	}

	// Predicate 1: Cpus >= 8 → matches slot1@host-a, slot1@host-b
	if got := res.Predicates[1].Matched; got != 2 {
		t.Errorf("Cpus predicate: matched=%d, want 2", got)
	}
}

// TestAnalyzeNarrowingPredicate verifies the "which predicate is reducing
// matches the most?" heuristic. Slot pool is set up so one predicate is
// clearly the bottleneck and the others would otherwise pass.
func TestAnalyzeNarrowingPredicate(t *testing.T) {
	// 5 slots, all with Cpus>=8 and Memory>=1024; one has Arch=Linux,
	// the other 4 are OSX. Without the Arch predicate, all 5 would
	// match. With it, only 1 matches. So Arch is the narrower.
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "linux-1"; Machine = "h1"; Arch = "Linux"; Cpus = 8;  Memory = 4096 ]`),
		makeSlotAd(t, `[ Name = "osx-1";   Machine = "h2"; Arch = "OSX";   Cpus = 16; Memory = 8192 ]`),
		makeSlotAd(t, `[ Name = "osx-2";   Machine = "h3"; Arch = "OSX";   Cpus = 16; Memory = 8192 ]`),
		makeSlotAd(t, `[ Name = "osx-3";   Machine = "h4"; Arch = "OSX";   Cpus = 16; Memory = 8192 ]`),
		makeSlotAd(t, `[ Name = "osx-4";   Machine = "h5"; Arch = "OSX";   Cpus = 16; Memory = 8192 ]`),
	}
	job := makeJobAd(t, `Arch == "Linux" && Cpus >= 8 && Memory >= 1024`)

	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if res.FullMatches != 1 {
		t.Errorf("FullMatches = %d, want 1", res.FullMatches)
	}
	if res.NarrowingPredicateIndex != 0 {
		t.Errorf("NarrowingPredicateIndex = %d, want 0 (Arch); predicates: %+v",
			res.NarrowingPredicateIndex, res.Predicates)
	}
}

// TestAnalyzeNoNarrowingWhenAllMatch verifies that NarrowingPredicateIndex
// is -1 when nothing is narrowing — i.e., every slot matches every
// predicate. Without this guard /readyz / debug UIs would point at "the
// first predicate" arbitrarily.
func TestAnalyzeNoNarrowingWhenAllMatch(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "h1"; Arch = "Linux" ]`),
		makeSlotAd(t, `[ Name = "h2"; Arch = "Linux" ]`),
	}
	job := makeJobAd(t, `Arch == "Linux"`)
	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.NarrowingPredicateIndex != -1 {
		t.Errorf("NarrowingPredicateIndex = %d, want -1 (no narrowing)", res.NarrowingPredicateIndex)
	}
}

// TestAnalyzeUndefinedDistinctFromError verifies that missing-attribute
// references show up as Undefined (not as NotMatched and not as Error).
// This distinction is the whole reason we surface four counts instead of
// just matched/not-matched: an operator who sees Undefined=N for a
// predicate referencing FooBarBaz immediately knows "no slot publishes
// FooBarBaz" rather than "every slot fails the comparison".
func TestAnalyzeUndefinedDistinctFromError(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "h1"; Arch = "Linux" ]`),
		makeSlotAd(t, `[ Name = "h2"; Arch = "Linux" ]`),
	}
	// "MissingAttr" exists on no slot. Reference returns undefined;
	// `undefined == 1` is undefined, not false.
	job := makeJobAd(t, `MissingAttr == 1`)
	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if got := res.Predicates[0].Undefined; got != 2 {
		t.Errorf("Undefined = %d, want 2", got)
	}
	if got := res.Predicates[0].NotMatched; got != 0 {
		t.Errorf("NotMatched = %d, want 0 (must not double-count undefined as not-matched)", got)
	}
}

// TestAnalyzeAttributeDistribution verifies the per-attribute histogram
// that drives the canonical -better-analyze "Arch was Linux for X and OSX
// for Y" output.
func TestAnalyzeAttributeDistribution(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "h1"; Arch = "Linux" ]`),
		makeSlotAd(t, `[ Name = "h2"; Arch = "Linux" ]`),
		makeSlotAd(t, `[ Name = "h3"; Arch = "Linux" ]`),
		makeSlotAd(t, `[ Name = "h4"; Arch = "OSX" ]`),
	}
	job := makeJobAd(t, `Arch == "Linux"`)
	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(res.Predicates) != 1 {
		t.Fatalf("preds: got %d", len(res.Predicates))
	}
	dists := res.Predicates[0].AttributeDistributions
	if len(dists) != 1 {
		t.Fatalf("expected 1 distribution, got %d", len(dists))
	}
	if dists[0].Attribute != "Arch" {
		t.Errorf("attr = %q, want Arch", dists[0].Attribute)
	}
	// Sorted by descending count: Linux=3, OSX=1
	if len(dists[0].Values) != 2 {
		t.Fatalf("values: got %d, want 2", len(dists[0].Values))
	}
	if dists[0].Values[0].Value != "Linux" || dists[0].Values[0].Count != 3 {
		t.Errorf("first value = %+v, want Linux=3", dists[0].Values[0])
	}
	if dists[0].Values[1].Value != "OSX" || dists[0].Values[1].Count != 1 {
		t.Errorf("second value = %+v, want OSX=1", dists[0].Values[1])
	}
}

// TestAnalyzeRequestsConservativeProjection verifies that the analyzer
// asks the SlotProvider for the union of (job's slot refs ∪ IdentityAttrs).
// This is the contract that lets the SlotProvider request a minimal
// projection from the collector.
func TestAnalyzeRequestsConservativeProjection(t *testing.T) {
	provider := &StaticSlotProvider{Ads: nil}
	job := makeJobAd(t, `Arch == "Linux" && Memory >= 1024`)
	if _, err := New(provider).Analyze(context.Background(), job); err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	// Expect at minimum: Arch, Memory, plus IdentityAttrs (Name, Machine, SlotID).
	have := map[string]bool{}
	for _, a := range provider.LastRequestedAttrs {
		have[a] = true
	}
	for _, expected := range []string{"Arch", "Memory", "Name", "Machine", "SlotID"} {
		if !have[expected] {
			t.Errorf("projection missing %q (got %v)", expected, provider.LastRequestedAttrs)
		}
	}
}

// TestAnalyzeMissingRequirements verifies that an ad with no Requirements
// attribute analyzes as a vacuous match — every slot in the pool counts
// as a full match. Useful when a caller wants to use the same code path
// for "what fraction of the pool could conceivably run this?" queries
// before Requirements has been written.
func TestAnalyzeMissingRequirements(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "h1" ]`),
		makeSlotAd(t, `[ Name = "h2" ]`),
	}
	job, err := classad.Parse(`[ Cmd = "/bin/true" ]`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.FullMatches != 2 {
		t.Errorf("FullMatches = %d, want 2 (no requirements ⇒ vacuous match)", res.FullMatches)
	}
}

// TestRenderTextHumanReadable spot-checks that the text renderer produces
// output containing the headline numbers and per-predicate breakdowns.
// We don't pin the exact format (it's intended for humans, not parsing),
// but we do guard against regressions that drop key fields.
func TestRenderTextHumanReadable(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "h1"; Arch = "Linux"; Cpus = 8 ]`),
		makeSlotAd(t, `[ Name = "h2"; Arch = "OSX";   Cpus = 4 ]`),
	}
	job := makeJobAd(t, `Arch == "Linux" && Cpus >= 8`)
	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	out := RenderText(res)
	for _, want := range []string{
		"Slots fully matching:    1 / 2",
		"Per-predicate breakdown",
		"Arch",
		"Cpus",
		"matched=",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("RenderText output missing %q. Full output:\n%s", want, out)
		}
	}
}

// TestNewPanicsOnNilSlotProvider locks the documented contract: passing
// nil to New is a programming error and we want it to fail fast at
// construction.
func TestNewPanicsOnNilSlotProvider(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when slots is nil")
		}
	}()
	_ = New(nil)
}
