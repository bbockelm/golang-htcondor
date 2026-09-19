package matchanalyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/PelicanPlatform/classad/ast"
	"github.com/PelicanPlatform/classad/classad"
)

// resourceComparison describes a predicate of the simple form
//
//	TARGET.X <op> MY.Request*    or    MY.Request* <op> TARGET.X
//
// where the operator is a numeric comparison. Detected by
// detectResourceComparison; consumed by computeResourceSuggestion.
//
// Only flat shapes are handled — `TARGET.Memory >= RequestMemory` yes,
// `TARGET.Memory >= RequestMemory + 100` no. Most real Requirements
// expressions hit the flat form, and the lift to handle arithmetic on
// the job side adds complexity without much payoff for an interactive
// hint UI.
type resourceComparison struct {
	SlotAttr   string // e.g., "Memory"
	JobRequest string // e.g., "RequestMemory"
	Op         string // ">=", "<=", "==", ">", "<"
	// SlotOnLeft tells us which side of the operator the slot
	// attribute is on. Affects how we interpret the operator when
	// computing suggestions: "TARGET.Memory >= RequestMemory" means
	// "slot must have at least this much" (lower the request to
	// unlock more), but "RequestMemory <= TARGET.Memory" is the same
	// statement with the operands swapped.
	SlotOnLeft bool
}

// detectResourceComparison returns a non-nil resourceComparison iff the
// expression is of the flat resource-request shape described above.
// expr must be a bound expression (every AttributeReference explicitly
// scoped); typically this is one of the boundExprs the analyzer holds.
func detectResourceComparison(expr ast.Expr) *resourceComparison {
	bin, ok := expr.(*ast.BinaryOp)
	if !ok || !isComparisonOp(bin.Op) {
		return nil
	}
	leftRef, leftOK := simpleScopedRef(bin.Left)
	rightRef, rightOK := simpleScopedRef(bin.Right)
	if !leftOK || !rightOK {
		return nil
	}

	switch {
	case leftRef.Scope == ast.TargetScope && rightRef.Scope == ast.MyScope && isRequestAttr(rightRef.Name):
		return &resourceComparison{
			SlotAttr:   leftRef.Name,
			JobRequest: rightRef.Name,
			Op:         bin.Op,
			SlotOnLeft: true,
		}
	case leftRef.Scope == ast.MyScope && rightRef.Scope == ast.TargetScope && isRequestAttr(leftRef.Name):
		return &resourceComparison{
			SlotAttr:   rightRef.Name,
			JobRequest: leftRef.Name,
			Op:         bin.Op,
			SlotOnLeft: false,
		}
	}
	return nil
}

// simpleScopedRef returns the AttributeReference iff expr is exactly an
// AttributeReference (no wrapping unary, no parens-only AST nodes — the
// parser flattens parens). The boolean reports success.
func simpleScopedRef(expr ast.Expr) (*ast.AttributeReference, bool) {
	ref, ok := expr.(*ast.AttributeReference)
	return ref, ok
}

// isComparisonOp reports whether the given operator is a numeric
// comparison we can offer suggestions for. We exclude `is`/`isnt` —
// those are identity checks against literal values (typically `undefined`)
// and don't admit "lower the value to unlock more matches".
func isComparisonOp(op string) bool {
	switch op {
	case "==", "!=", ">=", "<=", ">", "<":
		return true
	}
	return false
}

// isRequestAttr reports whether the attribute name is a job-side
// resource request. The HTCondor convention is `Request<Resource>`
// (RequestCpus, RequestMemory, RequestDisk, RequestGPUs, etc.) and
// custom ones like `RequestSomething`. We match the prefix
// case-insensitively because ClassAd attributes are case-insensitive.
func isRequestAttr(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "request") && len(name) > len("request")
}

// computeResourceSuggestion builds the actionable recommendation for a
// resource-comparison predicate. Walks the slot pool, computes per-slot
// failure counts at candidate Request* values, and returns up to a few
// tiers of suggestions ranked by additional matches gained.
//
// Returns nil if a suggestion can't be computed (e.g., the current
// request value isn't numeric, no failing slots have a numeric value
// for the slot attribute, or the operator is one we don't know how to
// invert). Callers treat nil as "no suggestion; fall back to the
// generic narrowing-predicate hint".
//
// `perSlotResults` is the per-slot outcome of THIS predicate; we use
// it to know which slots failed (and so are candidates for unlocking).
// The function does not look at the other predicates' outcomes — a
// suggestion is reported as "additional slots that would PASS THIS
// PREDICATE if you lowered the request", not "additional slots that
// would fully match". The latter is what NarrowingScore measures, but
// for an actionable hint the operator wants to know "does this change
// help at all on this predicate?".
// failingValues accumulates the slot-side values of slots that FAILED a
// predicate, as a frequency histogram rather than a list.
//
// The suggestions only ever ask two things of these values: which
// distinct ones exist, and how many slots sit at or above each. A
// histogram answers both in space proportional to the number of DISTINCT
// values -- which for a resource attribute is tiny, since Cpus is 1, 2,
// 4, 8 and Memory comes in a handful of sizes -- where a list was
// proportional to the number of SLOTS.
type failingValues struct {
	counts map[float64]int
	total  int
}

func newFailingValues() *failingValues {
	return &failingValues{counts: map[float64]int{}}
}

func (f *failingValues) add(v float64) {
	f.counts[v]++
	f.total++
}

func (f *failingValues) empty() bool { return f == nil || f.total == 0 }

func computeResourceSuggestion(
	comp *resourceComparison,
	jobAd *classad.ClassAd,
	failing *failingValues,
) *ResourceSuggestion {
	currentVal := jobAd.EvaluateAttr(comp.JobRequest)
	if !currentVal.IsNumber() {
		return nil
	}
	currentNum, err := currentVal.NumberValue()
	if err != nil {
		return nil
	}

	// Determine the relaxation direction. We support `>=` (and the
	// equivalent flipped `<=`) plus `==`. Other operators are
	// rare in resource Requirements and we simply don't suggest.
	relaxLower := false // true ⇒ lowering the request unlocks slots
	switch comp.Op {
	case ">=", ">":
		relaxLower = comp.SlotOnLeft // TARGET >= MY ⇒ lower MY
	case "<=", "<":
		relaxLower = !comp.SlotOnLeft // MY <= TARGET ⇒ lower MY
	case "==":
		// Equality requires a different strategy — pick the most
		// popular slot value among failing slots — but the unlock
		// direction is "set request to that value". Handled below.
	default:
		return nil
	}

	// The values were accumulated during the slot pass; see Analyze.
	if failing.empty() {
		return nil
	}

	suggestion := &ResourceSuggestion{
		JobAttribute:  comp.JobRequest,
		SlotAttribute: comp.SlotAttr,
		CurrentValue:  formatNumber(currentNum),
		Operator:      comp.Op,
	}

	switch comp.Op {
	case "==":
		suggestion.Options = suggestEqualityOptions(failing)
	default:
		suggestion.Options = suggestRelaxationOptions(failing, currentNum, relaxLower)
	}
	if len(suggestion.Options) == 0 {
		return nil
	}
	return suggestion
}

// suggestRelaxationOptions builds tiered options for `>=`/`<=` shapes.
// For ">=" with relaxLower=true (lower the request):
//
//   - Slots with TARGET.X < current request fail.
//   - For each candidate request value V (V < current), the additional
//     matches gained = count of failing slots with X >= V.
//   - We pick three tiered candidates from the distinct failing values:
//     the largest (smallest reduction, smallest gain), the middle, and
//     the smallest (biggest reduction, biggest gain). This gives the
//     operator a sense of the tradeoff curve without enumerating every
//     unique value.
//
// For "<=" / `MY <= TARGET` shapes the math is the same with sign
// flipped — the failing slots have X > current request, and we'd
// raise the request. We don't surface "raise" suggestions today
// because operators rarely want to advertise needing more — kept here
// in case a future flip wants to enable it.
func suggestRelaxationOptions(failing *failingValues, current float64, relaxLower bool) []ResourceSuggestionOption {
	if !relaxLower || failing.empty() {
		return nil
	}
	// Distinct failing values sorted descending. Each value V is a
	// candidate "if we lower request to V, slots with X >= V (among
	// the previously failing) would now pass."
	distinct := make([]float64, 0, len(failing.counts))
	for v := range failing.counts {
		distinct = append(distinct, v)
	}
	sort.Sort(sort.Reverse(sort.Float64Slice(distinct)))
	if len(distinct) == 0 {
		return nil
	}

	// For each distinct V, how many failing slots sit at or above it.
	// Walking the distinct values descending makes that a running sum,
	// where counting the whole list per candidate was quadratic in the
	// number of slots.
	gainsAt := make(map[float64]int, len(distinct))
	running := 0
	for _, V := range distinct {
		running += failing.counts[V]
		gainsAt[V] = running
	}

	// Pick three tiers: largest, middle, smallest.
	tiers := pickTierIndices(len(distinct))
	out := make([]ResourceSuggestionOption, 0, len(tiers))
	seen := map[float64]bool{}
	for _, idx := range tiers {
		V := distinct[idx]
		if seen[V] {
			continue
		}
		seen[V] = true
		// Only suggest values strictly below the current request —
		// values >= current can't help under a >= predicate.
		if V >= current {
			continue
		}
		out = append(out, ResourceSuggestionOption{
			NewValue:          formatNumber(V),
			AdditionalMatches: gainsAt[V],
		})
	}
	return out
}

// suggestEqualityOptions handles `==` shapes: the predicate fails for
// every slot whose X != current request. The most useful suggestion is
// "set request to the most common value among failing slots" — that
// unlocks the largest single bucket. We surface up to three buckets
// in descending popularity.
func suggestEqualityOptions(failing *failingValues) []ResourceSuggestionOption {
	if failing.empty() {
		return nil
	}
	counts := failing.counts
	type pair struct {
		v float64
		n int
	}
	pairs := make([]pair, 0, len(counts))
	for v, n := range counts {
		pairs = append(pairs, pair{v, n})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].n != pairs[j].n {
			return pairs[i].n > pairs[j].n
		}
		// Tiebreak by value ascending for determinism.
		return pairs[i].v < pairs[j].v
	})
	if len(pairs) > 3 {
		pairs = pairs[:3]
	}
	out := make([]ResourceSuggestionOption, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, ResourceSuggestionOption{
			NewValue:          formatNumber(p.v),
			AdditionalMatches: p.n,
		})
	}
	return out
}

// pickTierIndices selects up to three indices from a slice of length n,
// representing largest / middle / smallest tiers. Returns sorted-and-
// deduplicated indices so callers can iterate in display order.
func pickTierIndices(n int) []int {
	if n == 0 {
		return nil
	}
	if n == 1 {
		return []int{0}
	}
	if n == 2 {
		return []int{0, 1}
	}
	// 3+: top, middle, bottom.
	return []int{0, n / 2, n - 1}
}

// formatNumber renders a float64 as a string suitable for display.
// Integer-valued floats are formatted without a fractional part
// (RequestMemory=8192 should display as "8192", not "8192.0"); other
// values use %g for compact non-misleading output.
func formatNumber(n float64) string {
	if n == float64(int64(n)) {
		return fmt.Sprintf("%d", int64(n))
	}
	return fmt.Sprintf("%g", n)
}
