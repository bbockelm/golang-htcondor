package matchanalyzer

import (
	"fmt"
	"strings"
)

// RenderText returns a human-readable, condor_q-style text rendering of the
// analysis. Designed for CLI output and log lines, not for screens of HTML.
//
// Output shape (best-effort to match condor_q's familiar format):
//
//	Analysis of job vs. <N> slots in pool:
//	  Total slots considered: 943
//	  Slots fully matching:    0
//	  Narrowing predicate:     #2  Arch == "OSX"
//
//	Per-predicate breakdown:
//	  #0  RequestCpus <= TARGET.Cpus
//	      matched=943  not_matched=0  undefined=0  error=0
//	      Cpus: 8 → 521, 16 → 308, 32 → 114
//	  #1  RequestMemory <= TARGET.Memory
//	      ...
//	  #2  Arch == "OSX"
//	      matched=0  not_matched=943  undefined=0  error=0
//	      Arch: linux → 943, undefined → 0
//
// We deliberately don't try to fancy-format aligned columns — Go log
// captures wrap unhelpfully on terminals and most consumers will run this
// through a structured logger anyway.
func RenderText(r *Result) string {
	if r == nil {
		return "(no analysis result)"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Analysis of job vs. %d slots:\n", r.TotalSlots)
	fmt.Fprintf(&b, "  Slots fully matching:    %d / %d\n", r.FullMatches, r.TotalSlots)
	if r.NarrowingPredicateIndex >= 0 && r.NarrowingPredicateIndex < len(r.Predicates) {
		np := r.Predicates[r.NarrowingPredicateIndex]
		fmt.Fprintf(&b, "  Narrowing predicate:     #%d  %s\n", np.Index, np.Source)
	} else if r.FullMatches < r.TotalSlots {
		// We had failures but no single predicate stood out as the
		// narrowing one. Either every predicate equally fails on the
		// non-matching slots, or no slot matches everything-but-one.
		fmt.Fprintln(&b, "  Narrowing predicate:     (none — no single predicate is uniquely responsible)")
	}

	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Per-predicate breakdown:")
	for _, pr := range r.Predicates {
		fmt.Fprintf(&b, "  #%d  %s\n", pr.Index, pr.Source)
		fmt.Fprintf(&b, "      matched=%d  not_matched=%d  undefined=%d  error=%d\n",
			pr.Matched, pr.NotMatched, pr.Undefined, pr.ErrorOut)
		if len(pr.SampleMatchedHosts) > 0 {
			fmt.Fprintf(&b, "      sample matches:     %s\n", strings.Join(pr.SampleMatchedHosts, ", "))
		}
		if len(pr.SampleNotMatchedHosts) > 0 {
			fmt.Fprintf(&b, "      sample non-matches: %s\n", strings.Join(pr.SampleNotMatchedHosts, ", "))
		}
		for _, dist := range pr.AttributeDistributions {
			fmt.Fprintf(&b, "      %s:", dist.Attribute)
			parts := make([]string, 0, len(dist.Values))
			for _, v := range dist.Values {
				parts = append(parts, fmt.Sprintf(" %s → %d", v.Value, v.Count))
			}
			// "absent" (attribute not in ad) and "undefined" (attribute
			// in ad but resolves to undefined) are reported separately
			// so the operator can tell which slots are publishing what
			// — "Arch absent on 12 slots" vs "Arch defined but undefined
			// on 12 slots" are different problems.
			if dist.Absent > 0 {
				parts = append(parts, fmt.Sprintf(" absent → %d", dist.Absent))
			}
			if dist.Undefined > 0 {
				parts = append(parts, fmt.Sprintf(" undefined → %d", dist.Undefined))
			}
			if dist.ErrorOut > 0 {
				parts = append(parts, fmt.Sprintf(" error → %d", dist.ErrorOut))
			}
			b.WriteString(strings.Join(parts, ","))
			b.WriteString("\n")
		}
	}
	return b.String()
}
