package matchanalyzer

import (
	"context"
	"fmt"
	"sort"

	"github.com/PelicanPlatform/classad/ast"
	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/parser"
)

// Analyzer is the entry point for match analysis. Construct one per
// (decomposer, slot-provider) combination and reuse across calls.
type Analyzer struct {
	decomposer Decomposer
	slots      SlotProvider

	// sampleHostsCap is the maximum number of sample slot names captured
	// per predicate. The default is small (10) because the goal is
	// "show the user a few examples to spot-check", not "list every match".
	sampleHostsCap int

	// distinctValuesCap is the maximum number of distinct attribute
	// values displayed per AttributeDistribution. The rest are folded
	// into a single "(other: N)" bucket. Keeps webpage and CLI output
	// readable for high-cardinality attributes (e.g., Machine names).
	distinctValuesCap int
}

// Option configures an Analyzer at construction time.
type Option func(*Analyzer)

// WithDecomposer overrides the default ShallowAndDecomposer.
func WithDecomposer(d Decomposer) Option {
	return func(a *Analyzer) { a.decomposer = d }
}

// WithSampleHostsCap sets the maximum number of sample matched slot names
// captured per predicate. Default 10. Negative values disable the cap.
func WithSampleHostsCap(n int) Option {
	return func(a *Analyzer) { a.sampleHostsCap = n }
}

// WithDistinctValuesCap sets the maximum number of distinct attribute
// values shown per AttributeDistribution before grouping the rest.
// Default 10.
func WithDistinctValuesCap(n int) Option {
	return func(a *Analyzer) { a.distinctValuesCap = n }
}

// New constructs an Analyzer. slots is required; decomposer defaults to
// ShallowAndDecomposer.
func New(slots SlotProvider, opts ...Option) *Analyzer {
	if slots == nil {
		// Constructing without a slot source is a programming error —
		// the analyzer needs slots to do anything. Fail fast at
		// construction rather than crash on the first Analyze call.
		panic("matchanalyzer.New: slots provider is required")
	}
	a := &Analyzer{
		decomposer:        ShallowAndDecomposer{},
		slots:             slots,
		sampleHostsCap:    10,
		distinctValuesCap: 10,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Analyze decomposes the job's Requirements expression, fetches the slot
// pool with a projection covering every attribute the job references, and
// returns per-predicate match statistics.
//
// jobAd must have a "Requirements" attribute (the typical case for a
// submitted job). If absent, Analyze treats Requirements as the literal
// `true` and returns a single trivially-matching predicate; that's not a
// useful analysis but also not an error condition worth aborting on.
func (a *Analyzer) Analyze(ctx context.Context, jobAd *classad.ClassAd) (*Result, error) {
	if jobAd == nil {
		return nil, fmt.Errorf("matchanalyzer: jobAd is nil")
	}

	reqExpr := lookupRequirements(jobAd)

	preds, err := a.decomposer.Decompose(reqExpr)
	if err != nil {
		return nil, fmt.Errorf("matchanalyzer: decompose: %w", err)
	}
	for i := range preds {
		preds[i].Index = i
	}

	allRefs := []string{}
	for _, p := range preds {
		allRefs = unionStrings(allRefs, p.ReferencedSlotAttrs)
	}
	projection := unionStrings(allRefs, IdentityAttrs)

	slots, err := a.slots.Slots(ctx, projection)
	if err != nil {
		return nil, fmt.Errorf("matchanalyzer: fetch slots: %w", err)
	}

	res := &Result{
		JobReferences:           allRefs,
		TotalSlots:              len(slots),
		FullMatches:             0,
		Predicates:              make([]PredicateResult, len(preds)),
		NarrowingPredicateIndex: -1,
	}
	for i, p := range preds {
		res.Predicates[i] = PredicateResult{
			Index:                  p.Index,
			Source:                 p.Source,
			AttributeDistributions: nil,
		}
	}

	// Per-slot evaluation. We do a single pass over slots, evaluating
	// every predicate against each slot. Two reasons to do it this way
	// instead of one pass per predicate:
	//   1) Single pass over the slot list is friendlier to the GC and
	//      to CPU cache (each slot is a sizable struct).
	//   2) FullMatches is the AND of all predicate results on the same
	//      slot — easier to compute when we have all per-slot results
	//      in one place.
	//
	// The "narrowing predicate" calculation is the trickier bit. The
	// useful definition isn't "predicate that fails on the most slots in
	// isolation" — that would be biased toward predicates referencing
	// rare attributes (which are undefined on many slots and thus fail
	// trivially). Instead, the right notion is: "if I dropped this one
	// predicate, how many *additional* slots would match the rest?" The
	// predicate with the highest such number is the narrowing one.
	//
	// To compute that without N^2 work, we count "slots that fail this
	// predicate but pass all others". That equals the additional matches
	// gained by removing the predicate.

	matchedAllOthers := make([]int, len(preds)) // per-predicate counter

	boundExprs := bindPredicates(jobAd, preds)

	// Distributions are computed per *post-bind slot-side attribute*,
	// not per ReferencedSlotAttr (which is conservative and includes
	// bare refs that resolve to the job side). Without this filter, a
	// predicate like `TARGET.Memory >= RequestMemory` would emit a
	// histogram for RequestMemory showing "absent on every slot" — true
	// but useless, since RequestMemory lives on the job, not the slot.
	resolvedSlotAttrs := make([][]string, len(preds))
	distrCollectors := make([]map[string]*attrDistCollector, len(preds))
	for i := range preds {
		resolvedSlotAttrs[i] = boundSlotAttrs(boundExprs[i])
		distrCollectors[i] = make(map[string]*attrDistCollector, len(resolvedSlotAttrs[i]))
		for _, attr := range resolvedSlotAttrs[i] {
			distrCollectors[i][attr] = newAttrDistCollector()
		}
	}

	// perSlotPerPred[predIdx][slotIdx] = outcome. Stored in
	// predicate-major order because computeResourceSuggestion takes a
	// slice of outcomes for ONE predicate across all slots — the
	// memory layout matches that access pattern. Capacity is bounded
	// by len(slots) * len(preds), which for typical pools (<10k slots,
	// <20 preds) fits comfortably.
	perSlotPerPred := make([][]predOutcome, len(preds))
	for i := range perSlotPerPred {
		perSlotPerPred[i] = make([]predOutcome, 0, len(slots))
	}

	for _, slot := range slots {
		results := evalPredicatesAgainstSlot(jobAd, slot, boundExprs)
		if isFullMatch(results) {
			res.FullMatches++
		}
		for i, r := range results {
			perSlotPerPred[i] = append(perSlotPerPred[i], r)
		}
		a.processSlotResults(slot, results, res, matchedAllOthers, distrCollectors, resolvedSlotAttrs)
	}

	// Pick the narrowing predicate: highest matchedAllOthers value, with
	// ties broken in favor of lower index (stable). If the max is zero —
	// either every predicate is satisfied by every slot, or no single
	// predicate is uniquely responsible for narrowing — leave the index
	// at -1 so callers can render "no single narrowing predicate".
	if maxIdx, maxCount := pickNarrowing(matchedAllOthers); maxCount > 0 {
		res.NarrowingPredicateIndex = maxIdx
	}

	// Surface the per-predicate narrowing score on the result so the UI
	// can sort by it without recomputing. Score 0 = predicate is a
	// no-op for matching given the rest; the widget hides those by
	// default behind a "show more" gate.
	for i := range res.Predicates {
		res.Predicates[i].NarrowingScore = matchedAllOthers[i]
	}

	// Materialize the attribute distributions on the result.
	for i := range res.Predicates {
		// Stable order over attribute names so output is deterministic.
		for _, attr := range resolvedSlotAttrs[i] {
			d := distrCollectors[i][attr].finalize(attr, a.distinctValuesCap)
			res.Predicates[i].AttributeDistributions = append(res.Predicates[i].AttributeDistributions, d)
		}
	}

	// Compute resource suggestions for narrowing predicates that match
	// the resource-request shape (TARGET.X op MY.Request*). Done after
	// the main loop so we can use the captured per-slot results to
	// figure out which slot values are unlocked by which Request*
	// reductions. Skipping for non-narrowing predicates (score 0)
	// avoids surfacing suggestions that wouldn't actually help.
	for i, p := range preds {
		if matchedAllOthers[i] == 0 {
			continue
		}
		comp := detectResourceComparison(boundExprs[i])
		if comp == nil {
			continue
		}
		_ = p // kept for future per-predicate metadata if needed
		res.Predicates[i].ResourceSuggestion = computeResourceSuggestion(comp, jobAd, slots, perSlotPerPred[i])
	}

	return res, nil
}

// isFullMatch returns true iff every predicate evaluated to predTrue
// for one slot. Pulled out as a tiny helper so the slot-loop body can
// stay short — the main Analyze function was tipping over the
// cyclomatic-complexity threshold.
func isFullMatch(results []predOutcome) bool {
	for _, r := range results {
		if r != predTrue {
			return false
		}
	}
	return true
}

// processSlotResults folds one slot's per-predicate outcomes into the
// running result. It mutates res, matchedAllOthers, and the distribution
// collectors. Pulled out of Analyze to keep the cyclomatic complexity
// of Analyze itself manageable.
//
// The per-predicate work breaks into three independent pieces:
//   - bucket the outcome (matched / not_matched / undefined / error)
//     and capture an example slot in matched or not-matched samples
//   - update matchedAllOthers (the narrowing-score input) when this
//     predicate fails but every OTHER predicate passes
//   - record this slot's value of every resolved slot-side attribute
//     in the per-attribute distribution collector
func (a *Analyzer) processSlotResults(
	slot *classad.ClassAd,
	results []predOutcome,
	res *Result,
	matchedAllOthers []int,
	distrCollectors []map[string]*attrDistCollector,
	resolvedSlotAttrs [][]string,
) {
	slotName := slotIdentity(slot)
	for i, r := range results {
		pr := &res.Predicates[i]
		a.bucketOutcome(pr, r, slotName)
		if r != predTrue && othersAllTrue(results, i) {
			matchedAllOthers[i]++
		}
		for _, attr := range resolvedSlotAttrs[i] {
			distrCollectors[i][attr].observe(slot, attr, slotName)
		}
	}
}

// bucketOutcome routes a single (predicate, slot) outcome into the
// right counter and sample-list on PredicateResult. Caps both sample
// lists at sampleHostsCap; matched and not-matched samples are
// independent so the operator gets up to sampleHostsCap of each.
//
// Undefined and error outcomes are treated as "non-matches" for sample
// purposes — they're still slots that didn't match, and the operator
// looking at the non-match dropdown wants to see them too.
func (a *Analyzer) bucketOutcome(pr *PredicateResult, r predOutcome, slotName string) {
	switch r {
	case predTrue:
		pr.Matched++
		if a.shouldCaptureSample(len(pr.SampleMatchedHosts), slotName) {
			pr.SampleMatchedHosts = append(pr.SampleMatchedHosts, slotName)
		}
	case predFalse:
		pr.NotMatched++
		if a.shouldCaptureSample(len(pr.SampleNotMatchedHosts), slotName) {
			pr.SampleNotMatchedHosts = append(pr.SampleNotMatchedHosts, slotName)
		}
	case predUndefined:
		pr.Undefined++
		if a.shouldCaptureSample(len(pr.SampleNotMatchedHosts), slotName) {
			pr.SampleNotMatchedHosts = append(pr.SampleNotMatchedHosts, slotName)
		}
	case predError:
		pr.ErrorOut++
		if a.shouldCaptureSample(len(pr.SampleNotMatchedHosts), slotName) {
			pr.SampleNotMatchedHosts = append(pr.SampleNotMatchedHosts, slotName)
		}
	}
}

// shouldCaptureSample returns true iff we have room in the per-bucket
// sample list (or the cap is disabled) AND the slot has a usable
// identity to record. Centralizing the check keeps the four switch
// arms in bucketOutcome readable.
func (a *Analyzer) shouldCaptureSample(currentLen int, slotName string) bool {
	if slotName == "" {
		return false
	}
	if a.sampleHostsCap < 0 {
		return true
	}
	return currentLen < a.sampleHostsCap
}

// othersAllTrue reports whether every predicate other than the one at
// idx evaluated to predTrue for this slot. That's the precondition for
// "removing predicate idx would gain a match" — the narrowing-score
// computation.
func othersAllTrue(results []predOutcome, idx int) bool {
	for j, r := range results {
		if j == idx {
			continue
		}
		if r != predTrue {
			return false
		}
	}
	return true
}

// predOutcome represents the four possible outcomes of evaluating one
// predicate against one slot. Distinguishing undefined from error matters
// because they explain *why* a predicate doesn't match.
type predOutcome int

const (
	predTrue predOutcome = iota
	predFalse
	predUndefined
	predError
)

// evalPredicatesAgainstSlot evaluates every (already-bound) predicate
// expression against the given slot ad and returns one outcome per
// predicate. The expressions are expected to have come through
// bindBareReferences so every AttributeReference is explicitly scoped
// (MY. for job-side, TARGET. for slot-side).
//
// We wire the two ads via classad.MatchClassAd and evaluate against the
// **job** ad, not the slot. That mirrors HTCondor's matching semantics
// for a job's Requirements: MY = job, TARGET = slot. Evaluating against
// the slot would invert this and produce TARGET.x = jobAd.x, which is
// not what an operator reading the predicate expects.
//
// MatchClassAd.NewMatchClassAd calls SetTarget on both ads, which
// mutates them. The caller is expected to pass a job ad it's comfortable
// having TARGET set on (typically a single-use copy from a query); for
// the slot ad we re-set TARGET on every iteration anyway.
func evalPredicatesAgainstSlot(jobAd, slotAd *classad.ClassAd, boundExprs []ast.Expr) []predOutcome {
	classad.NewMatchClassAd(jobAd, slotAd)

	results := make([]predOutcome, len(boundExprs))
	for i, expr := range boundExprs {
		results[i] = classifyPredicateValue(jobAd.EvaluateExpr(expr))
	}
	return results
}

// classifyPredicateValue maps a classad Value to a predOutcome. Anything
// that isn't true / false / undefined / error is treated as error (e.g.,
// a predicate that evaluates to an integer — which shouldn't happen for a
// well-formed Requirements expression but we want the analyzer to be
// defensive).
func classifyPredicateValue(v classad.Value) predOutcome {
	switch {
	case v.IsBool():
		b, err := v.BoolValue()
		if err != nil {
			return predError
		}
		if b {
			return predTrue
		}
		return predFalse
	case v.IsUndefined():
		return predUndefined
	case v.IsError():
		return predError
	default:
		return predError
	}
}

// pickNarrowing returns the index and value of the largest entry. Ties are
// broken in favor of lower indices so the choice is stable across runs.
func pickNarrowing(counts []int) (int, int) {
	maxIdx := -1
	maxCount := 0
	for i, c := range counts {
		if c > maxCount {
			maxCount = c
			maxIdx = i
		}
	}
	return maxIdx, maxCount
}

// lookupRequirements pulls the Requirements expression from a job ad as an
// ast.Expr. The Pelican classad package doesn't expose an ast.Expr accessor
// directly — Lookup returns a wrapper *Expr — so we re-parse the
// expression's string form. This costs one parse per Analyze call, which is
// a rounding error compared to the slot evaluation loop.
//
// If Requirements is missing or unparseable, return literal `true` and let
// downstream produce a vacuously-matching predicate list. We treat parse
// failures of the Requirements string as a corrupt ad rather than as a
// fatal error: better to surface a degenerate analysis than to refuse to
// analyze a job whose Requirements expression we can't replay.
func lookupRequirements(jobAd *classad.ClassAd) ast.Expr {
	wrapper, ok := jobAd.Lookup("Requirements")
	if !ok || wrapper == nil {
		return &ast.BooleanLiteral{Value: true}
	}
	src := wrapper.String()
	if src == "" || src == "undefined" {
		return &ast.BooleanLiteral{Value: true}
	}
	// Wrap-and-parse: the parser entry point that takes a bare
	// expression isn't public, so we parse a tiny ClassAd holding the
	// expression as its single attribute value. The same trick the
	// Pelican classad library uses internally in ParseExpr.
	node, err := parser.Parse(fmt.Sprintf("[__req__ = %s]", src))
	if err != nil {
		return &ast.BooleanLiteral{Value: true}
	}
	if ad, ok := node.(*ast.ClassAd); ok && len(ad.Attributes) == 1 {
		return ad.Attributes[0].Value
	}
	return &ast.BooleanLiteral{Value: true}
}

// slotIdentity returns the most descriptive string name for a slot ad.
// Prefers "Name" (which usually includes both the slot name and host) over
// "Machine" alone. Returns "" if neither is set, which the caller treats
// as "skip this slot for sample-host display".
func slotIdentity(slot *classad.ClassAd) string {
	if name, ok := slot.EvaluateAttrString("Name"); ok && name != "" {
		return name
	}
	if name, ok := slot.EvaluateAttrString("Machine"); ok && name != "" {
		return name
	}
	return ""
}

// attrDistCollector accumulates one slot attribute's value distribution
// across the slot pool. Stored separately from the public
// AttributeDistribution type so we can use a map for O(1) inserts and
// finalize to a sorted slice at the end.
//
// The collector intentionally distinguishes "absent" (the ad has no
// such attribute) from "undefined" (the attribute is there but
// evaluates to undefined). Operators reading the analysis often want
// to know which is which — "Arch isn't published on N slots" is a
// different conversation from "Arch is bound to a missing attr on N
// slots".
//
// Each bucket also records ONE example slot name so the UI can
// "click through to a representative slot" for any value/value-bucket
// in the histogram. We keep only the first one we see — capturing
// every match would balloon memory on large pools without adding
// information beyond the count.
type attrDistCollector struct {
	values        map[string]int
	valueExample  map[string]string
	absent        int
	absentExample string
	undefined     int
	undefExample  string
	errOut        int
	errOutExample string
}

func newAttrDistCollector() *attrDistCollector {
	return &attrDistCollector{
		values:       map[string]int{},
		valueExample: map[string]string{},
	}
}

// observe records one slot's view of the attribute being tracked.
// Distinguishes absent-from-ad from value-undefined by using the
// classad library's Lookup (structural presence check) on top of
// EvaluateAttr (value resolution). slotName is the human-readable slot
// identifier (Name attribute, or Machine fallback) used as the
// example-slot label; pass "" if the slot has no usable identity.
func (c *attrDistCollector) observe(ad *classad.ClassAd, attr, slotName string) {
	if _, ok := ad.Lookup(attr); !ok {
		c.absent++
		if c.absentExample == "" {
			c.absentExample = slotName
		}
		return
	}
	v := ad.EvaluateAttr(attr)
	switch {
	case v.IsUndefined():
		c.undefined++
		if c.undefExample == "" {
			c.undefExample = slotName
		}
	case v.IsError():
		c.errOut++
		if c.errOutExample == "" {
			c.errOutExample = slotName
		}
	default:
		s := valueDisplay(v)
		c.values[s]++
		if _, seen := c.valueExample[s]; !seen {
			c.valueExample[s] = slotName
		}
	}
}

// finalize converts the accumulator into the public AttributeDistribution.
// Values are sorted by descending count; ties broken by value string for
// stability. Anything past topN is folded into a single "(other: N)" entry.
func (c *attrDistCollector) finalize(attr string, topN int) AttributeDistribution {
	out := AttributeDistribution{
		Attribute:        attr,
		Absent:           c.absent,
		AbsentExample:    c.absentExample,
		Undefined:        c.undefined,
		UndefinedExample: c.undefExample,
		ErrorOut:         c.errOut,
		ErrorExample:     c.errOutExample,
	}

	type kv struct {
		k string
		v int
	}
	pairs := make([]kv, 0, len(c.values))
	for k, v := range c.values {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v != pairs[j].v {
			return pairs[i].v > pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})

	if topN <= 0 || len(pairs) <= topN {
		out.Values = make([]ValueCount, 0, len(pairs))
		for _, p := range pairs {
			out.Values = append(out.Values, ValueCount{
				Value:   p.k,
				Count:   p.v,
				Example: c.valueExample[p.k],
			})
		}
		return out
	}

	out.Values = make([]ValueCount, 0, topN+1)
	for _, p := range pairs[:topN] {
		out.Values = append(out.Values, ValueCount{
			Value:   p.k,
			Count:   p.v,
			Example: c.valueExample[p.k],
		})
	}
	otherCount := 0
	for _, p := range pairs[topN:] {
		otherCount += p.v
	}
	// "(other: N distinct)" rolls up the long tail. We don't pick a
	// single example here because no one example fairly represents
	// many distinct values — leave Example empty rather than mislead.
	out.Values = append(out.Values, ValueCount{
		Value: fmt.Sprintf("(other: %d distinct)", len(pairs)-topN),
		Count: otherCount,
	})
	return out
}

// valueDisplay produces a short, comparable string form of a classad value
// suitable for histogram keys. We don't try to be exhaustive — anything
// the histogram needs to bucket should be string-comparable. For lists and
// nested ads, we fall back to the value's String() method.
func valueDisplay(v classad.Value) string {
	switch {
	case v.IsString():
		s, _ := v.StringValue()
		return s
	case v.IsBool():
		b, _ := v.BoolValue()
		if b {
			return "true"
		}
		return "false"
	case v.IsInteger():
		i, _ := v.IntValue()
		return fmt.Sprintf("%d", i)
	case v.IsReal():
		r, _ := v.RealValue()
		return fmt.Sprintf("%g", r)
	default:
		return fmt.Sprintf("%v", v)
	}
}
