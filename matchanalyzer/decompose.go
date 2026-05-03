package matchanalyzer

import (
	"sort"

	"github.com/PelicanPlatform/classad/ast"
)

// ShallowAndDecomposer splits a Requirements expression on top-level `&&`
// and treats each conjunct as one Predicate. This is the same heuristic
// `condor_q -better-analyze` uses by default, and it covers the overwhelming
// majority of Requirements expressions written in the wild — they're
// conjunctions of simple atomic conditions.
//
// What this *doesn't* do (intentionally, to keep the implementation simple):
//
//   - It doesn't push negations inward (De Morgan's laws). `!(A && B)` is
//     left as a single predicate rather than decomposed into `!A || !B`.
//   - It doesn't convert to CNF. A predicate like `(A && B) || C` is
//     treated as one atomic predicate.
//   - It doesn't simplify away constant subexpressions.
//
// All of those are valid future Decomposer implementations; the Decomposer
// interface keeps that door open.
type ShallowAndDecomposer struct{}

// Decompose implements Decomposer. It walks the expression tree depth-first
// through `&&` nodes, collecting each non-`&&` leaf into the predicate
// slice. The Index field on each returned Predicate is left as 0; the
// analyzer is responsible for assigning final indices.
func (ShallowAndDecomposer) Decompose(req ast.Expr) ([]Predicate, error) {
	if req == nil {
		// An empty Requirements is the trivial case — vacuously true,
		// represented as a single literal-true predicate. Returning an
		// empty slice would force every caller to special-case it.
		return []Predicate{
			{
				Source:              "true",
				Expr:                &ast.BooleanLiteral{Value: true},
				ReferencedSlotAttrs: nil,
			},
		}, nil
	}

	var leaves []ast.Expr
	collectAndLeaves(req, &leaves)

	preds := make([]Predicate, 0, len(leaves))
	for _, leaf := range leaves {
		preds = append(preds, Predicate{
			Source:              leaf.String(),
			Expr:                leaf,
			ReferencedSlotAttrs: collectSlotAttrRefs(leaf),
		})
	}
	return preds, nil
}

// collectAndLeaves performs the recursive split. We unwrap parenthesized
// groupings implicitly because the AST doesn't carry parens — `(A && B) && C`
// and `A && (B && C)` parse to the same tree shape.
func collectAndLeaves(expr ast.Expr, out *[]ast.Expr) {
	if bin, ok := expr.(*ast.BinaryOp); ok && bin.Op == "&&" {
		collectAndLeaves(bin.Left, out)
		collectAndLeaves(bin.Right, out)
		return
	}
	*out = append(*out, expr)
}

// collectSlotAttrRefs walks an expression and returns the sorted, distinct
// names of attributes it references that *might* resolve against the slot.
// We err on the side of over-inclusion:
//
//   - Bare AttributeReference (NoScope, e.g., `Arch`). In ClassAd matching
//     semantics with a MatchClassAd setup, a bare reference is looked up
//     in the evaluation scope first and falls back to the target. Since
//     we evaluate the predicate against the slot ad, "slot is the
//     evaluation scope" means bare refs hit the slot first; we include
//     them to keep the slot projection complete.
//   - AttributeReference with TargetScope (e.g., `TARGET.Arch`). Always slot.
//
// MyScope (`MY.RequestMemory`) is *not* a slot reference — it points at
// the job ad — so we skip it. ParentScope is also skipped (rare in slot
// matching contexts).
//
// The cost of over-inclusion is requesting a few extra attributes from the
// collector projection, which is cheap. The cost of *under*-inclusion would
// be a slot ad missing the attribute the predicate needs, producing
// spurious "undefined" outcomes — much worse for the user. The conservative
// choice is the right one.
//
// The function returns a sorted slice for stable cache keys downstream.
func collectSlotAttrRefs(expr ast.Expr) []string {
	seen := map[string]struct{}{}
	walkAttrRefs(expr, seen)
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func walkAttrRefs(expr ast.Expr, seen map[string]struct{}) {
	if expr == nil {
		return
	}
	switch v := expr.(type) {
	case *ast.AttributeReference:
		switch v.Scope {
		case ast.NoScope, ast.TargetScope:
			seen[v.Name] = struct{}{}
		case ast.MyScope, ast.ParentScope:
			// MY.x refers to the job ad; PARENT.x refers to the parent
			// (rare in slot matching contexts). Neither is a slot
			// reference, so don't add to the projection.
		}
	case *ast.BinaryOp:
		walkAttrRefs(v.Left, seen)
		walkAttrRefs(v.Right, seen)
	case *ast.UnaryOp:
		walkAttrRefs(v.Expr, seen)
	case *ast.FunctionCall:
		for _, arg := range v.Args {
			walkAttrRefs(arg, seen)
		}
	case *ast.ConditionalExpr:
		walkAttrRefs(v.Condition, seen)
		walkAttrRefs(v.TrueExpr, seen)
		walkAttrRefs(v.FalseExpr, seen)
	case *ast.ElvisExpr:
		walkAttrRefs(v.Left, seen)
		walkAttrRefs(v.Right, seen)
	case *ast.SelectExpr:
		// expr.attr — we treat the *root* of the selection chain as
		// potentially a slot reference. For the common case
		// `TARGET.Arch` this is already handled by AttributeReference
		// with TargetScope. For `someExpr.attr` we walk into someExpr.
		walkAttrRefs(v.Record, seen)
	case *ast.SubscriptExpr:
		walkAttrRefs(v.Container, seen)
		walkAttrRefs(v.Index, seen)
	case *ast.ListLiteral:
		for _, elem := range v.Elements {
			walkAttrRefs(elem, seen)
		}
	}
	// Literal types contribute nothing to attribute references.
}

// unionStrings returns the sorted distinct union of any number of string
// slices. Used by the analyzer to combine each predicate's referenced
// attrs into a single projection request.
func unionStrings(lists ...[]string) []string {
	seen := map[string]struct{}{}
	for _, list := range lists {
		for _, s := range list {
			seen[s] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
