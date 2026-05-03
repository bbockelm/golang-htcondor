// Package matchanalyzer reproduces (a subset of) HTCondor's
// `condor_q -better-analyze`: given a job ClassAd and the slot ads visible
// from a collector, it explains *why* the job isn't matching as much of the
// pool as the user might expect, by breaking the job's Requirements into
// independently-evaluable predicates and reporting per-predicate match
// statistics over the slot pool.
//
// The package is intentionally split into small, swappable pieces:
//
//   - Decomposer turns a Requirements expression into a list of Predicates.
//     Today's only implementation, ShallowAndDecomposer, splits on top-level
//     `&&` and treats each conjunct as one predicate. That covers the
//     common case (Requirements written as a conjunction of simple
//     conditions). A future CNFDecomposer or DeepDecomposer can plug into
//     the same interface without changing Analyzer or callers.
//
//   - SlotProvider supplies slot ads. Implementations are responsible for
//     honoring the requested-attributes projection — analysis only ever
//     reads the slot attributes referenced by the job's Requirements, so a
//     provider should fetch only those (plus a small fixed projection of
//     identity attrs like Name / Machine for sample-host display) to keep
//     collector load bounded.
//
//   - Analyzer ties the two together and produces a Result.
//
// The Result is JSON-serializable for direct use in MCP tools, web UIs, or
// log lines.
package matchanalyzer

import (
	"context"

	"github.com/PelicanPlatform/classad/ast"
	"github.com/PelicanPlatform/classad/classad"
)

// IdentityAttrs is the small fixed set of slot attributes the analyzer
// always wants in addition to whatever the job's Requirements references.
// They name and locate the slot for "sample matching hosts" output.
//
// SlotProviders should always include these in their projection regardless
// of the request, because the analysis output is far more useful when each
// matched slot can be identified by Name / Machine.
var IdentityAttrs = []string{"Name", "Machine", "SlotID"}

// Predicate is a single sub-expression of the job's Requirements that the
// analyzer evaluates independently against each slot ad. The granularity is
// controlled by the active Decomposer; today every Predicate is a top-level
// conjunct, but the type is general enough to represent finer slices later.
type Predicate struct {
	// Index is this Predicate's position in the parent Result's Predicates
	// slice. Stored on the Predicate so callers can reference predicates by
	// index without comparing structs.
	Index int

	// Source is a human-readable rendering of the predicate, suitable for
	// display in CLI / log output. Comes from the AST node's String() (so
	// it's normalized, not the user's exact source spacing).
	Source string

	// Expr is the AST node to evaluate. The analyzer evaluates it against
	// each slot via classad.MatchClassAd so TARGET. references resolve
	// against the slot.
	Expr ast.Expr

	// ReferencedSlotAttrs are the slot-side attributes this predicate reads
	// (i.e., bare references and TARGET.x references). The analyzer uses
	// them to drive per-attribute value distributions in the output, and
	// callers can use them to decide what slot projection to request.
	ReferencedSlotAttrs []string
}

// Decomposer is the interface that turns a Requirements expression into the
// list of Predicates the analyzer will evaluate. Keep this interface
// deliberately small so deeper decomposition algorithms can be added later
// without breaking callers.
type Decomposer interface {
	// Decompose returns one or more Predicates for the given Requirements
	// expression. Implementations must always return at least one
	// Predicate; if no decomposition is possible, return a single
	// Predicate wrapping the whole expression.
	//
	// The Index field on returned Predicates is overwritten by the
	// analyzer; implementations need not set it.
	Decompose(req ast.Expr) ([]Predicate, error)
}

// SlotProvider supplies slot ads for analysis. The interface separates the
// fetching/caching policy from the analysis itself so tests can inject a
// fixed slot pool and production can wire in a collector with caching.
//
// requiredAttrs is the union of attributes the analyzer needs for this
// invocation — the IdentityAttrs plus every attribute referenced by the
// job's Requirements. Implementations are free to fetch a superset (for
// caching reasons), but must never return less.
type SlotProvider interface {
	Slots(ctx context.Context, requiredAttrs []string) ([]*classad.ClassAd, error)
}

// Result is the JSON-serializable output of an Analyze call.
type Result struct {
	// JobReferences is the union of slot attributes referenced by the
	// job's Requirements expression (across all predicates). Useful for
	// debugging "why was this attribute requested in the projection?".
	JobReferences []string `json:"job_references,omitempty"`

	// TotalSlots is the number of slot ads the analyzer evaluated against.
	TotalSlots int `json:"total_slots"`

	// FullMatches is the number of slots that match the entire
	// Requirements expression (all predicates true simultaneously). This
	// is the headline number a user wants to know.
	FullMatches int `json:"full_matches"`

	// Predicates contains per-predicate match statistics in the order the
	// Decomposer produced them. The same order is used by Index references.
	Predicates []PredicateResult `json:"predicates"`

	// NarrowingPredicateIndex points at the Predicate whose failure most
	// reduces the match count — i.e., the predicate that, on its own,
	// fails on the largest number of slots that *would otherwise have
	// matched the rest of the Requirements*.
	//
	// -1 when FullMatches == TotalSlots (nothing is narrowing) or when no
	// single predicate is uniquely worst.
	NarrowingPredicateIndex int `json:"narrowing_predicate_index"`
}

// PredicateResult is the per-predicate slice of the analysis.
type PredicateResult struct {
	// Index matches the Predicate.Index that produced this result.
	Index int `json:"index"`

	// Source is the human-readable predicate text (copied from Predicate.Source).
	Source string `json:"source"`

	// Matched / NotMatched / Undefined / ErrorOut count slot ads by the
	// outcome of evaluating *this predicate alone* against them. The four
	// counts sum to the total slot count.
	//
	// ErrorOut and Undefined are split out separately because in ClassAd
	// semantics they are distinct: an undefined attribute reference yields
	// UNDEFINED, while a type mismatch (e.g. comparing a list to an int)
	// yields ERROR. Both produce non-matches at the top level, but the
	// distinction tells the user *why*.
	Matched    int `json:"matched"`
	NotMatched int `json:"not_matched"`
	Undefined  int `json:"undefined"`
	ErrorOut   int `json:"error"`

	// SampleMatchedHosts is a small set of slots that satisfied this
	// predicate in isolation. Populated up to a configurable cap; useful
	// for spot-checking that a predicate is doing what the user thinks it
	// is doing.
	SampleMatchedHosts []string `json:"sample_matched_hosts,omitempty"`

	// AttributeDistributions is a per-slot-attribute histogram of values,
	// computed for each slot attribute this predicate references. The
	// purpose is the canonical -better-analyze output: "Arch was Linux for
	// 943 slots and OSX for 0". Each entry covers one attribute the
	// predicate referenced.
	AttributeDistributions []AttributeDistribution `json:"attribute_distributions,omitempty"`
}

// AttributeDistribution is a value histogram for one slot attribute.
type AttributeDistribution struct {
	// Attribute is the slot attribute name (e.g., "Arch").
	Attribute string `json:"attribute"`

	// Values lists the distinct values seen, sorted by descending count.
	// Capped to a small number for display; remainder folded into "Other".
	Values []ValueCount `json:"values"`

	// Undefined / ErrorOut count slots where the attribute was undefined
	// or evaluated to an error (e.g., not present in the ad).
	Undefined int `json:"undefined,omitempty"`
	ErrorOut  int `json:"error,omitempty"`
}

// ValueCount is one entry in an AttributeDistribution.
type ValueCount struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}
