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
func computeResourceSuggestion(
	comp *resourceComparison,
	jobAd *classad.ClassAd,
	slots []*classad.ClassAd,
	perSlotResults []predOutcome,
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

	// Collect TARGET.X numeric values from FAILING slots. These are
	// the slots where lowering (or matching) the request might help.
	failingValues := []float64{}
	for i, slot := range slots {
		if perSlotResults[i] == predTrue {
			continue
		}
		v := slot.EvaluateAttr(comp.SlotAttr)
		if !v.IsNumber() {
			continue
		}
		n, err := v.NumberValue()
		if err != nil {
			continue
		}
		failingValues = append(failingValues, n)
	}
	if len(failingValues) == 0 {
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
		suggestion.Options = suggestEqualityOptions(failingValues)
	default:
		suggestion.Options = suggestRelaxationOptions(failingValues, currentNum, relaxLower)
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
func suggestRelaxationOptions(failingValues []float64, current float64, relaxLower bool) []ResourceSuggestionOption {
	if !relaxLower {
		return nil
	}
	// Distinct failing values sorted descending. Each value V is a
	// candidate "if we lower request to V, slots with X >= V (among
	// the previously failing) would now pass."
	distinct := distinctSorted(failingValues, false /* descending */)
	if len(distinct) == 0 {
		return nil
	}

	// For each distinct V, count how many failing values are >= V.
	// Sorted descending, so the count grows monotonically as we walk.
	gainsAt := make(map[float64]int, len(distinct))
	cumulative := 0
	for _, V := range distinct {
		// Count failing values >= V. Since distinct is sorted
		// descending and we walk top-down, "this many failing values
		// are at the visited values so far".
		n := 0
		for _, v := range failingValues {
			if v >= V {
				n++
			}
		}
		gainsAt[V] = n
		cumulative = n
	}
	_ = cumulative // (keeps the loop above readable; cumulative isn't used)

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
func suggestEqualityOptions(failingValues []float64) []ResourceSuggestionOption {
	counts := map[float64]int{}
	for _, v := range failingValues {
		counts[v]++
	}
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

// distinctSorted deduplicates a float64 slice and returns it sorted.
// `ascending` chooses the direction.
func distinctSorted(values []float64, ascending bool) []float64 {
	if len(values) == 0 {
		return nil
	}
	seen := map[float64]struct{}{}
	for _, v := range values {
		seen[v] = struct{}{}
	}
	out := make([]float64, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	if ascending {
		sort.Float64s(out)
	} else {
		sort.Slice(out, func(i, j int) bool { return out[i] > out[j] })
	}
	return out
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
