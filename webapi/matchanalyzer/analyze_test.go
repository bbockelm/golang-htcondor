package matchanalyzer

import (
	"context"
	"fmt"
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

// TestAnalyzeBareReferenceFallsBackToJob is the regression test for the
// "TARGET.Memory >= RequestMemory" bug. The Pelican classad library does
// NOT fall back from self to target when resolving a bare attribute
// reference, so the analyzer has to rewrite the predicate up front so
// every reference is explicitly scoped (MY. or TARGET.) based on which
// ad actually defines it. Without that pass, RequestMemory (a job-side
// attribute) evaluated against the slot ad returns undefined and the
// predicate gets bucketed as "undefined" — masking the real outcome.
//
// Pinning the user's exact case: slot Memory=2048, job RequestMemory=4096,
// predicate `TARGET.Memory >= RequestMemory`. Correct outcome is
// not_matched (2048 < 4096), not undefined.
func TestAnalyzeBareReferenceFallsBackToJob(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "small";  Machine = "h1"; Memory = 2048 ]`),
		makeSlotAd(t, `[ Name = "medium"; Machine = "h2"; Memory = 4096 ]`),
		makeSlotAd(t, `[ Name = "big";    Machine = "h3"; Memory = 16384 ]`),
	}
	job := makeJobAd(t, `TARGET.Memory >= RequestMemory`)
	// makeJobAd builds [ Requirements = ... ] — we have to add
	// RequestMemory ourselves so the bare reference resolves.
	if err := job.Set("RequestMemory", int64(4096)); err != nil {
		t.Fatalf("Set RequestMemory: %v", err)
	}

	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if len(res.Predicates) != 1 {
		t.Fatalf("expected 1 predicate, got %d", len(res.Predicates))
	}
	pr := res.Predicates[0]

	// The headline assertion: zero "undefined" outcomes. Before the fix
	// every slot bucketed as undefined because RequestMemory was
	// undefined in the slot.
	if pr.Undefined != 0 {
		t.Errorf("predicate.Undefined = %d, want 0 (the bug bucketed every slot as undefined because the bare RequestMemory ref didn't fall back to the job ad)", pr.Undefined)
	}

	// Slot "small" (2048) fails the comparison; "medium" (4096) and
	// "big" (16384) pass. Correctness on both directions catches a
	// fix that accidentally inverts sense.
	if pr.Matched != 2 {
		t.Errorf("predicate.Matched = %d, want 2 (medium=4096, big=16384)", pr.Matched)
	}
	if pr.NotMatched != 1 {
		t.Errorf("predicate.NotMatched = %d, want 1 (small=2048 < 4096)", pr.NotMatched)
	}
	if res.FullMatches != 2 {
		t.Errorf("FullMatches = %d, want 2", res.FullMatches)
	}
}

// TestAnalyzeBareReferenceWithoutTargetPrefix is the same bug shape but
// using the more typical Requirements form `RequestMemory <= Memory`
// where both sides are bare. The job's RequestMemory must resolve to
// the job; the slot's Memory must resolve to the slot.
func TestAnalyzeBareReferenceWithoutTargetPrefix(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "small";  Memory = 2048 ]`),
		makeSlotAd(t, `[ Name = "big";    Memory = 16384 ]`),
	}
	job := makeJobAd(t, `RequestMemory <= Memory`)
	if err := job.Set("RequestMemory", int64(4096)); err != nil {
		t.Fatalf("Set RequestMemory: %v", err)
	}

	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	pr := res.Predicates[0]
	if pr.Undefined != 0 {
		t.Errorf("Undefined = %d, want 0", pr.Undefined)
	}
	if pr.Matched != 1 || pr.NotMatched != 1 {
		t.Errorf("Matched=%d NotMatched=%d, want Matched=1 NotMatched=1", pr.Matched, pr.NotMatched)
	}
}

// TestAnalyzeMissingAttributeStillUndefined guards the inverse: if a
// predicate references an attribute that's in *neither* the job nor any
// slot, the result really is undefined. The bare-reference rewrite
// should default to TARGET. for unknown attrs, and TARGET.NoSuchThing on
// a slot that doesn't publish it evaluates to undefined — preserving the
// pre-existing "no slot publishes this" diagnostic that operators rely
// on for catching typos in Requirements.
func TestAnalyzeMissingAttributeStillUndefined(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "h1"; Arch = "Linux" ]`),
		makeSlotAd(t, `[ Name = "h2"; Arch = "Linux" ]`),
	}
	job := makeJobAd(t, `NoSuchAttr == 1`) // attribute is on neither ad
	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if got := res.Predicates[0].Undefined; got != 2 {
		t.Errorf("Undefined = %d, want 2 (NoSuchAttr is on neither side)", got)
	}
}

// TestAnalyzeMyScopeStillResolvesToJob guards the explicit-MY case:
// `MY.RequestCpus <= TARGET.Cpus` should behave the same as the bare
// form. The fix changed the evaluation scope from slot → job, and a
// regression there would manifest as MY.RequestCpus resolving to the
// slot.
func TestAnalyzeMyScopeStillResolvesToJob(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "tiny"; Cpus = 2 ]`),
		makeSlotAd(t, `[ Name = "big";  Cpus = 16 ]`),
	}
	job := makeJobAd(t, `MY.RequestCpus <= TARGET.Cpus`)
	if err := job.Set("RequestCpus", int64(8)); err != nil {
		t.Fatalf("Set RequestCpus: %v", err)
	}

	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	pr := res.Predicates[0]
	if pr.Undefined != 0 {
		t.Errorf("Undefined = %d, want 0", pr.Undefined)
	}
	if pr.Matched != 1 || pr.NotMatched != 1 {
		t.Errorf("Matched=%d NotMatched=%d, want Matched=1 NotMatched=1", pr.Matched, pr.NotMatched)
	}
}

// TestAnalyzeIsntUndefinedAcrossSlotShapes is the regression test for a
// reported bug where `(TARGET.Arch isnt undefined)` was claimed to evaluate
// to "not matched" for most slots even though the slots had Arch defined.
//
// The test pins the exact behavior across the four realistic slot shapes
// the analyzer should distinguish:
//
//  1. Slot publishes Arch as a string literal → matched (true)
//  2. Slot publishes Arch as an expression that evaluates to a string →
//     matched (the indirection happens at lookup time, returning the
//     resolved string)
//  3. Slot publishes Arch as an expression that evaluates to undefined
//     (e.g., `Arch = SomethingNotPublished`) → not matched. This LOOKS
//     like "Arch is defined" if you only inspect attribute names, which
//     is a legitimate operator-confusion case worth pinning.
//  4. Slot does not publish Arch at all → not matched.
//
// Together these cover the realistic ways an operator can see this
// predicate report "not matched": case (3) is the surprising one and
// the most common cause of "but I see Arch in the ad!" confusion. The
// per-slot expectations below are what HTCondor's matching semantics
// require, and the test guards against any change to the analyzer that
// would break them.
func TestAnalyzeIsntUndefinedAcrossSlotShapes(t *testing.T) {
	cases := []struct {
		name         string
		slot         string
		wantMatched  int // predicate-level: matched count for THIS slot (0 or 1)
		wantNotMatch int
		// Per-attribute distribution counts. Exactly one of wantValue,
		// wantAbsent, wantUndef should be 1 — the test pins which
		// bucket the slot lands in so a regression that conflates
		// absent vs undefined fails loudly.
		wantValueCount int // sum across the Values bucket
		wantAbsent     int
		wantUndef      int
	}{
		{
			name:           "string literal",
			slot:           `[ Name = "literal";    Arch = "X86_64" ]`,
			wantMatched:    1,
			wantValueCount: 1,
		},
		{
			name:           "expression resolving to string via another attr",
			slot:           `[ Name = "indirect";   ArchSrc = "X86_64"; Arch = ArchSrc ]`,
			wantMatched:    1,
			wantValueCount: 1,
		},
		{
			name:         "expression that evaluates to undefined (looks defined but isn't)",
			slot:         `[ Name = "undef-expr"; Arch = NoSuchAttr ]`,
			wantNotMatch: 1,
			wantUndef:    1, // critical: NOT counted as absent — the operator should see this is structurally present
		},
		{
			name:         "attribute not published at all",
			slot:         `[ Name = "missing" ]`,
			wantNotMatch: 1,
			wantAbsent:   1, // critical: NOT counted as undefined — slot literally has no Arch attr
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			slot := makeSlotAd(t, tc.slot)
			job := makeJobAd(t, `(TARGET.Arch isnt undefined)`)

			res, err := New(&StaticSlotProvider{Ads: []*classad.ClassAd{slot}}).Analyze(context.Background(), job)
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			pr := res.Predicates[0]

			if pr.Matched != tc.wantMatched {
				t.Errorf("Matched = %d, want %d", pr.Matched, tc.wantMatched)
			}
			if pr.NotMatched != tc.wantNotMatch {
				t.Errorf("NotMatched = %d, want %d", pr.NotMatched, tc.wantNotMatch)
			}
			// `isnt` always produces a bool, never undefined or error;
			// pin that property regardless of slot content. Anything in
			// Undefined or Error here would be a regression — the whole
			// point of writing `X isnt undefined` is to *avoid* the
			// undefined bucket.
			if pr.Undefined != 0 {
				t.Errorf("Undefined = %d, want 0 (`isnt` never returns undefined)", pr.Undefined)
			}
			if pr.ErrorOut != 0 {
				t.Errorf("ErrorOut = %d, want 0", pr.ErrorOut)
			}

			// Per-attribute distribution must distinguish "absent" from
			// "undefined". Operators reading the analysis will conflate
			// the two unless we pin them apart.
			if len(pr.AttributeDistributions) != 1 {
				t.Fatalf("expected 1 distribution, got %d", len(pr.AttributeDistributions))
			}
			d := pr.AttributeDistributions[0]
			if d.Attribute != "Arch" {
				t.Errorf("dist attr = %q, want Arch", d.Attribute)
			}
			gotValueCount := 0
			for _, v := range d.Values {
				gotValueCount += v.Count
			}
			if gotValueCount != tc.wantValueCount {
				t.Errorf("dist Values total = %d, want %d", gotValueCount, tc.wantValueCount)
			}
			if d.Absent != tc.wantAbsent {
				t.Errorf("dist Absent = %d, want %d", d.Absent, tc.wantAbsent)
			}
			if d.Undefined != tc.wantUndef {
				t.Errorf("dist Undefined = %d, want %d", d.Undefined, tc.wantUndef)
			}
		})
	}
}

// TestAnalyzeIsntUndefinedHeterogeneousPool exercises the realistic case:
// a pool where most slots publish Arch but a few don't. This is the
// scenario the user was probably actually seeing — "most slots match,
// but the analyzer reports some don't" can read as "most slots are
// unmatched" if the pool happens to have many incomplete slot ads. The
// test confirms the per-slot accounting is correct so the user's
// confusion (if any) maps to a real pool shape, not an analyzer bug.
func TestAnalyzeIsntUndefinedHeterogeneousPool(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "h1"; Arch = "X86_64" ]`),
		makeSlotAd(t, `[ Name = "h2"; Arch = "X86_64" ]`),
		makeSlotAd(t, `[ Name = "h3"; Arch = "X86_64" ]`),
		makeSlotAd(t, `[ Name = "h4" ]`),                   // missing
		makeSlotAd(t, `[ Name = "h5"; Arch = NoSuchSrc ]`), // resolves to undefined
	}
	job := makeJobAd(t, `(TARGET.Arch isnt undefined)`)
	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	pr := res.Predicates[0]
	if pr.Matched != 3 {
		t.Errorf("Matched = %d, want 3", pr.Matched)
	}
	if pr.NotMatched != 2 {
		t.Errorf("NotMatched = %d, want 2", pr.NotMatched)
	}
	if pr.Undefined != 0 {
		t.Errorf("Undefined = %d, want 0", pr.Undefined)
	}

	// The distribution should split the two failure modes apart so an
	// operator reading the analysis can tell which is which without
	// inspecting individual ads.
	if len(pr.AttributeDistributions) != 1 {
		t.Fatalf("expected 1 distribution, got %d", len(pr.AttributeDistributions))
	}
	d := pr.AttributeDistributions[0]
	if d.Absent != 1 {
		t.Errorf("Absent = %d, want 1 (h4 has no Arch attr)", d.Absent)
	}
	if d.Undefined != 1 {
		t.Errorf("Undefined = %d, want 1 (h5's Arch resolves to undefined)", d.Undefined)
	}
}

// TestAnalyzeSkipsDistributionForJobSideAttrs is the regression test for
// a reported UI noise issue: predicates like `(TARGET.Memory >= RequestMemory)`
// were emitting an "absent on every slot" diagnostic for RequestMemory,
// which is true (slots don't publish job attrs) but useless. The fix
// is to compute attribute distributions only for refs that bind-resolve
// to the slot side; refs that resolve to MY (the job ad) are excluded.
//
// The test verifies that a predicate referencing both a slot-side
// attribute (Memory via TARGET.) and a job-side attribute (RequestMemory
// via bare reference, which binds to MY.) emits a distribution only for
// the slot-side one.
func TestAnalyzeSkipsDistributionForJobSideAttrs(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "small"; Memory = 2048 ]`),
		makeSlotAd(t, `[ Name = "big";   Memory = 16384 ]`),
	}
	job := makeJobAd(t, `(TARGET.Memory >= RequestMemory)`)
	if err := job.Set("RequestMemory", int64(4096)); err != nil {
		t.Fatalf("Set RequestMemory: %v", err)
	}

	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	dists := res.Predicates[0].AttributeDistributions
	// Only Memory should have a distribution. RequestMemory binds to
	// MY (the job ad) and shouldn't appear — emitting "RequestMemory
	// absent on every slot" is the bug under test.
	if len(dists) != 1 {
		t.Fatalf("expected 1 distribution (Memory only), got %d: %+v", len(dists), dists)
	}
	if dists[0].Attribute != "Memory" {
		t.Errorf("attr = %q, want Memory", dists[0].Attribute)
	}
	for _, d := range dists {
		if d.Attribute == "RequestMemory" {
			t.Errorf("RequestMemory distribution should NOT be emitted (binds to MY); got %+v", d)
		}
	}
}

// TestAnalyzeNarrowingScorePerPredicate pins that every predicate gets
// its narrowing score set, not just the chosen narrowing one. The
// frontend sorts predicates by this score, so a regression where some
// predicates keep score 0 by default would invert the display order.
func TestAnalyzeNarrowingScorePerPredicate(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "linux-1"; Arch = "Linux"; Cpus = 8 ]`),
		makeSlotAd(t, `[ Name = "osx-1";   Arch = "OSX";   Cpus = 16 ]`),
		makeSlotAd(t, `[ Name = "osx-2";   Arch = "OSX";   Cpus = 16 ]`),
	}
	job := makeJobAd(t, `Arch == "Linux" && Cpus >= 1`)
	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	// Pred 0 (Arch == Linux): 2 OSX slots fail it but pass Cpus>=1 →
	// removing this predicate would gain 2 matches → score = 2.
	if res.Predicates[0].NarrowingScore != 2 {
		t.Errorf("pred 0 NarrowingScore = %d, want 2", res.Predicates[0].NarrowingScore)
	}
	// Pred 1 (Cpus >= 1): every slot passes → no narrowing → score = 0.
	if res.Predicates[1].NarrowingScore != 0 {
		t.Errorf("pred 1 NarrowingScore = %d, want 0", res.Predicates[1].NarrowingScore)
	}
}

// TestAnalyzeSampleNotMatchedHosts pins the new "non-matching samples"
// dropdown contract. The widget displays both matched and not-matched
// samples; both lists must be populated and capped consistently.
func TestAnalyzeSampleNotMatchedHosts(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "linux-1"; Arch = "Linux" ]`),
		makeSlotAd(t, `[ Name = "linux-2"; Arch = "Linux" ]`),
		makeSlotAd(t, `[ Name = "osx-1";   Arch = "OSX" ]`),
		makeSlotAd(t, `[ Name = "osx-2";   Arch = "OSX" ]`),
	}
	job := makeJobAd(t, `Arch == "Linux"`)
	res, err := New(&StaticSlotProvider{Ads: slots}, WithSampleHostsCap(10)).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	pr := res.Predicates[0]
	if len(pr.SampleMatchedHosts) != 2 {
		t.Errorf("matched samples = %d, want 2", len(pr.SampleMatchedHosts))
	}
	if len(pr.SampleNotMatchedHosts) != 2 {
		t.Errorf("not-matched samples = %d, want 2", len(pr.SampleNotMatchedHosts))
	}
	// The matched / not-matched samples must be disjoint sets — a
	// passing slot shouldn't appear in the failing list and vice versa.
	matchedSet := map[string]bool{}
	for _, h := range pr.SampleMatchedHosts {
		matchedSet[h] = true
	}
	for _, h := range pr.SampleNotMatchedHosts {
		if matchedSet[h] {
			t.Errorf("slot %q appears in both matched and not-matched samples", h)
		}
	}
}

// TestAnalyzeAttrDistributionExampleSlots pins the "click-through to a
// representative slot" contract. Each ValueCount and each
// absent/undefined bucket should carry the name of one slot in that
// bucket so the widget can link to it.
func TestAnalyzeAttrDistributionExampleSlots(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "small-a"; Memory = 2048 ]`),
		makeSlotAd(t, `[ Name = "small-b"; Memory = 2048 ]`),
		makeSlotAd(t, `[ Name = "big";     Memory = 16384 ]`),
		makeSlotAd(t, `[ Name = "no-mem"  ]`),                 // absent
		makeSlotAd(t, `[ Name = "weird";  Memory = NoSuch ]`), // undefined
	}
	job := makeJobAd(t, `TARGET.Memory >= 1024`)
	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	dists := res.Predicates[0].AttributeDistributions
	if len(dists) != 1 {
		t.Fatalf("expected 1 distribution, got %d", len(dists))
	}
	d := dists[0]

	// Each value entry must carry an example slot.
	for _, vc := range d.Values {
		if vc.Example == "" {
			t.Errorf("value %q has empty Example", vc.Value)
		}
	}
	// And specifically, the example for "2048" should be ONE of the
	// two slots that have it (not both — we keep only one per
	// bucket to bound memory on large pools).
	for _, vc := range d.Values {
		if vc.Value == "2048" {
			if vc.Example != "small-a" && vc.Example != "small-b" {
				t.Errorf("Memory=2048 example = %q, want small-a or small-b", vc.Example)
			}
		}
	}

	// Absent / undefined buckets should each carry their own example.
	if d.Absent != 1 || d.AbsentExample != "no-mem" {
		t.Errorf("Absent=%d AbsentExample=%q, want 1/no-mem", d.Absent, d.AbsentExample)
	}
	if d.Undefined != 1 || d.UndefinedExample != "weird" {
		t.Errorf("Undefined=%d UndefinedExample=%q, want 1/weird", d.Undefined, d.UndefinedExample)
	}
}

// TestAnalyzeResourceSuggestionLowerRequest pins the actionable hint
// for `TARGET.Memory >= RequestMemory` shapes: when the predicate is
// narrowing, the analyzer should suggest concrete lower values for
// RequestMemory and report how many additional slots each unlocks. The
// widget reads this and replaces the auto-generated predicate text
// (which most operators don't know what to do with) with a phrase like
// "lowering RequestMemory to 4096 would unlock 3 more slots".
func TestAnalyzeResourceSuggestionLowerRequest(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "tiny";   Memory = 1024 ]`),
		makeSlotAd(t, `[ Name = "small1"; Memory = 4096 ]`),
		makeSlotAd(t, `[ Name = "small2"; Memory = 4096 ]`),
		makeSlotAd(t, `[ Name = "small3"; Memory = 4096 ]`),
		makeSlotAd(t, `[ Name = "big1";   Memory = 16384 ]`),
		makeSlotAd(t, `[ Name = "big2";   Memory = 16384 ]`),
	}
	job := makeJobAd(t, `(TARGET.Memory >= RequestMemory)`)
	if err := job.Set("RequestMemory", int64(8192)); err != nil {
		t.Fatalf("Set RequestMemory: %v", err)
	}

	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	pr := res.Predicates[0]
	if pr.ResourceSuggestion == nil {
		t.Fatalf("expected ResourceSuggestion, got nil; full predicate: %+v", pr)
	}
	s := pr.ResourceSuggestion

	if s.JobAttribute != "RequestMemory" {
		t.Errorf("JobAttribute = %q, want RequestMemory", s.JobAttribute)
	}
	if s.SlotAttribute != "Memory" {
		t.Errorf("SlotAttribute = %q, want Memory", s.SlotAttribute)
	}
	if s.CurrentValue != "8192" {
		t.Errorf("CurrentValue = %q, want 8192", s.CurrentValue)
	}
	if s.Operator != ">=" {
		t.Errorf("Operator = %q, want >=", s.Operator)
	}

	// Failing slots have Memory ∈ {1024, 4096, 4096, 4096}; suggestions
	// must contain the most useful tier — lowering to 4096 unlocks 3
	// slots. Check the option exists with the right additional count.
	found4096 := false
	for _, opt := range s.Options {
		if opt.NewValue == "4096" {
			found4096 = true
			if opt.AdditionalMatches != 3 {
				t.Errorf("Option NewValue=4096 AdditionalMatches=%d, want 3", opt.AdditionalMatches)
			}
		}
		// Every suggested value must be strictly below the current
		// request — values >= current request can't unlock anything
		// for a >= predicate.
		var n int64
		if _, err := fmt.Sscanf(opt.NewValue, "%d", &n); err == nil {
			if n >= 8192 {
				t.Errorf("Option NewValue=%q is not below current request 8192", opt.NewValue)
			}
		}
	}
	if !found4096 {
		t.Errorf("expected suggestion for NewValue=4096; got options %+v", s.Options)
	}
}

// TestAnalyzeResourceSuggestionFlippedOperands verifies that the
// detector handles the equivalent shape with operands swapped:
// `RequestMemory <= TARGET.Memory` should produce the same suggestion
// as `TARGET.Memory >= RequestMemory`. Operators write Requirements in
// either order; pinning both ensures we don't show an unhelpful
// "raise the request" implication for what's really a >= relation.
func TestAnalyzeResourceSuggestionFlippedOperands(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "small"; Memory = 4096 ]`),
		makeSlotAd(t, `[ Name = "big";   Memory = 16384 ]`),
	}
	job := makeJobAd(t, `(RequestMemory <= TARGET.Memory)`)
	if err := job.Set("RequestMemory", int64(8192)); err != nil {
		t.Fatalf("Set RequestMemory: %v", err)
	}

	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	pr := res.Predicates[0]
	if pr.ResourceSuggestion == nil {
		t.Fatalf("expected ResourceSuggestion, got nil")
	}
	if pr.ResourceSuggestion.JobAttribute != "RequestMemory" {
		t.Errorf("JobAttribute = %q, want RequestMemory", pr.ResourceSuggestion.JobAttribute)
	}
	// At least one option must suggest 4096 (the failing slot's value).
	found := false
	for _, opt := range pr.ResourceSuggestion.Options {
		if opt.NewValue == "4096" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected NewValue=4096 in options; got %+v", pr.ResourceSuggestion.Options)
	}
}

// TestAnalyzeResourceSuggestionSkipsNonResourceShape verifies that
// predicates without a Request* attribute don't get suggestions —
// `(TARGET.Arch == "Linux")` is narrowing but no operator wants a
// "lower the value" hint here.
func TestAnalyzeResourceSuggestionSkipsNonResourceShape(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "linux-1"; Arch = "Linux" ]`),
		makeSlotAd(t, `[ Name = "osx-1";   Arch = "OSX" ]`),
		makeSlotAd(t, `[ Name = "osx-2";   Arch = "OSX" ]`),
	}
	job := makeJobAd(t, `Arch == "Linux"`)
	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Predicates[0].ResourceSuggestion != nil {
		t.Errorf("expected no ResourceSuggestion for Arch predicate, got %+v",
			res.Predicates[0].ResourceSuggestion)
	}
}

// TestAnalyzeResourceSuggestionSkipsNonNarrowing verifies that a
// resource predicate that's NOT narrowing (every slot satisfies it)
// doesn't get a suggestion. Surfacing one would be at best confusing
// ("we suggest lowering even though everything matches") and at worst
// wrong (the failing-slots set is empty).
func TestAnalyzeResourceSuggestionSkipsNonNarrowing(t *testing.T) {
	slots := []*classad.ClassAd{
		makeSlotAd(t, `[ Name = "big"; Memory = 16384 ]`),
	}
	job := makeJobAd(t, `(TARGET.Memory >= RequestMemory)`)
	if err := job.Set("RequestMemory", int64(1024)); err != nil {
		t.Fatalf("Set RequestMemory: %v", err)
	}
	res, err := New(&StaticSlotProvider{Ads: slots}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Predicates[0].ResourceSuggestion != nil {
		t.Errorf("non-narrowing predicate should not get a suggestion, got %+v",
			res.Predicates[0].ResourceSuggestion)
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
