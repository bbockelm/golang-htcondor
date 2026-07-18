package matchanalyzer

import (
	"sort"
	"strings"

	"github.com/PelicanPlatform/classad/ast"
	"github.com/PelicanPlatform/classad/classad"
)

// boundSlotAttrs returns the slot-side (TargetScope) attribute names
// referenced by an already-bound expression — i.e., one that has been
// run through bindBareReferences so every reference is explicitly
// scoped. The returned list drives per-attribute distributions: we only
// want to histogram attributes that the predicate actually reads from
// the slot. References that bind-resolved to MY (the job ad) shouldn't
// appear, because reporting "Absent on every slot" for `RequestMemory`
// is misleading — the value lives on the job, not on the slots, and the
// operator can read it directly off the job ad.
//
// The returned list is sorted and deduplicated for stable output.
func boundSlotAttrs(expr ast.Expr) []string {
	seen := map[string]struct{}{}
	walkBoundSlotAttrs(expr, seen)
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func walkBoundSlotAttrs(expr ast.Expr, seen map[string]struct{}) {
	if expr == nil {
		return
	}
	switch v := expr.(type) {
	case *ast.AttributeReference:
		// After binding, only TargetScope refs read from the slot.
		// Bare references (NoScope) shouldn't appear here — bind
		// converts them all — but if one slips through (e.g., a
		// future Decomposer that bypasses bind), include it
		// conservatively rather than silently drop it.
		if v.Scope == ast.TargetScope || v.Scope == ast.NoScope {
			seen[v.Name] = struct{}{}
		}
	case *ast.ParenExpr:
		// classad v0.1.0+ preserves parentheses as a node (matching the
		// reference ClassAd unparser); descend through it transparently.
		walkBoundSlotAttrs(v.Inner, seen)
	case *ast.BinaryOp:
		walkBoundSlotAttrs(v.Left, seen)
		walkBoundSlotAttrs(v.Right, seen)
	case *ast.UnaryOp:
		walkBoundSlotAttrs(v.Expr, seen)
	case *ast.FunctionCall:
		for _, a := range v.Args {
			walkBoundSlotAttrs(a, seen)
		}
	case *ast.ConditionalExpr:
		walkBoundSlotAttrs(v.Condition, seen)
		walkBoundSlotAttrs(v.TrueExpr, seen)
		walkBoundSlotAttrs(v.FalseExpr, seen)
	case *ast.ElvisExpr:
		walkBoundSlotAttrs(v.Left, seen)
		walkBoundSlotAttrs(v.Right, seen)
	case *ast.SelectExpr:
		walkBoundSlotAttrs(v.Record, seen)
	case *ast.SubscriptExpr:
		walkBoundSlotAttrs(v.Container, seen)
		walkBoundSlotAttrs(v.Index, seen)
	case *ast.ListLiteral:
		for _, e := range v.Elements {
			walkBoundSlotAttrs(e, seen)
		}
	}
}

// bindPredicates pre-binds bare references in every predicate's
// expression to the appropriate scope (MY. for job-side, TARGET. for
// slot-side). The job's attribute set doesn't change across the slot
// loop, so doing this once up front is much cheaper than rewriting per
// slot. See bindBareReferences below for the why — short version: the
// Pelican classad evaluator doesn't fall back from self to target for
// bare references, so without this pass `TARGET.Memory >= RequestMemory`
// reports "undefined" against every slot instead of "not_matched" for
// the slots that actually do publish Memory.
func bindPredicates(jobAd *classad.ClassAd, preds []Predicate) []ast.Expr {
	out := make([]ast.Expr, len(preds))
	for i, p := range preds {
		out[i] = bindBareReferences(jobAd, p.Expr)
	}
	return out
}

// bindBareReferences rewrites a Requirements (sub-)expression so every
// bare AttributeReference is explicitly scoped (MY. or TARGET.). The
// rewrite mirrors HTCondor's classic matching semantics for bare
// references in a job's Requirements:
//
//   - If the attribute is defined on the job ad, the reference resolves
//     to the job (MY.x).
//   - Otherwise it resolves to the target ad — the slot (TARGET.x).
//
// Without this pass the Pelican classad library — whose
// evaluateAttributeReference does NOT fall back from self to target —
// produces wrong-but-undetectable results: a predicate like
// `TARGET.Memory >= RequestMemory` evaluated against the slot ad reports
// "undefined" because slots don't publish RequestMemory, even though the
// job has it. Operators see a non-actionable bucket of undefined
// predicates instead of the real not_matched count.
//
// We rewrite once per predicate up front (job attributes don't change
// across the slot loop) so the per-slot evaluator stays cheap. The
// returned expression shares structure with the input where possible —
// only nodes that change are reconstructed, so a predicate with no bare
// references is returned identical to the input.
//
// Note that we do NOT mutate the input expression. Predicates are
// shared across the slot loop and would race if we did.
func bindBareReferences(jobAd *classad.ClassAd, expr ast.Expr) ast.Expr {
	jobAttrs := jobAttrLowerSet(jobAd)
	return rewriteBareRefs(expr, jobAttrs)
}

// jobAttrLowerSet returns the lower-cased set of attribute names defined
// on the job ad. Lower-cased because ClassAd attribute names are
// case-insensitive — `RequestMemory` and `requestmemory` are the same
// attribute, and an operator who writes one or the other in
// Requirements should get the same lookup behavior.
func jobAttrLowerSet(jobAd *classad.ClassAd) map[string]bool {
	if jobAd == nil {
		return nil
	}
	names := jobAd.GetAttributes()
	if len(names) == 0 {
		return nil
	}
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[strings.ToLower(n)] = true
	}
	return out
}

// rewriteBareRefs is the recursive worker for bindBareReferences. The
// switch covers every AST node type the parser produces; new node types
// must be added here or they'll silently pass through (which is
// acceptable — leaving bare refs alone in unknown contexts is
// conservative).
func rewriteBareRefs(expr ast.Expr, jobAttrs map[string]bool) ast.Expr {
	if expr == nil {
		return nil
	}
	switch v := expr.(type) {
	case *ast.AttributeReference:
		if v.Scope != ast.NoScope {
			return v
		}
		if jobAttrs[strings.ToLower(v.Name)] {
			return &ast.AttributeReference{Name: v.Name, Scope: ast.MyScope}
		}
		// Not on the job — assume slot. Even if the slot doesn't have
		// it either, evaluating TARGET.x → undefined is the right
		// outcome (and matches what an operator would expect from
		// reading the predicate).
		return &ast.AttributeReference{Name: v.Name, Scope: ast.TargetScope}
	case *ast.ParenExpr:
		inner := rewriteBareRefs(v.Inner, jobAttrs)
		if inner == v.Inner {
			return v
		}
		return &ast.ParenExpr{Inner: inner}
	case *ast.BinaryOp:
		left := rewriteBareRefs(v.Left, jobAttrs)
		right := rewriteBareRefs(v.Right, jobAttrs)
		if left == v.Left && right == v.Right {
			return v
		}
		return &ast.BinaryOp{Op: v.Op, Left: left, Right: right}
	case *ast.UnaryOp:
		inner := rewriteBareRefs(v.Expr, jobAttrs)
		if inner == v.Expr {
			return v
		}
		return &ast.UnaryOp{Op: v.Op, Expr: inner}
	case *ast.FunctionCall:
		newArgs, changed := rewriteBareRefSlice(v.Args, jobAttrs)
		if !changed {
			return v
		}
		return &ast.FunctionCall{Name: v.Name, Args: newArgs}
	case *ast.ConditionalExpr:
		c := rewriteBareRefs(v.Condition, jobAttrs)
		t := rewriteBareRefs(v.TrueExpr, jobAttrs)
		f := rewriteBareRefs(v.FalseExpr, jobAttrs)
		if c == v.Condition && t == v.TrueExpr && f == v.FalseExpr {
			return v
		}
		return &ast.ConditionalExpr{Condition: c, TrueExpr: t, FalseExpr: f}
	case *ast.ElvisExpr:
		l := rewriteBareRefs(v.Left, jobAttrs)
		r := rewriteBareRefs(v.Right, jobAttrs)
		if l == v.Left && r == v.Right {
			return v
		}
		return &ast.ElvisExpr{Left: l, Right: r}
	case *ast.SelectExpr:
		// Only the record (left side of "."), not the attr name —
		// `someExpr.Attr` keeps Attr as a literal name.
		rec := rewriteBareRefs(v.Record, jobAttrs)
		if rec == v.Record {
			return v
		}
		return &ast.SelectExpr{Record: rec, Attr: v.Attr}
	case *ast.SubscriptExpr:
		c := rewriteBareRefs(v.Container, jobAttrs)
		i := rewriteBareRefs(v.Index, jobAttrs)
		if c == v.Container && i == v.Index {
			return v
		}
		return &ast.SubscriptExpr{Container: c, Index: i}
	case *ast.ListLiteral:
		newElems, changed := rewriteBareRefSlice(v.Elements, jobAttrs)
		if !changed {
			return v
		}
		return &ast.ListLiteral{Elements: newElems}
	}
	// Literals (Integer/Real/String/Bool/Undefined/Error) and
	// RecordLiteral pass through unchanged.
	return expr
}

// rewriteBareRefSlice applies rewriteBareRefs to each element, returning the new
// slice and whether any element changed (identity-compared, so an all-unchanged
// slice lets the caller preserve the original node and its structure sharing).
func rewriteBareRefSlice(exprs []ast.Expr, jobAttrs map[string]bool) ([]ast.Expr, bool) {
	out := make([]ast.Expr, len(exprs))
	changed := false
	for i, e := range exprs {
		out[i] = rewriteBareRefs(e, jobAttrs)
		if out[i] != e {
			changed = true
		}
	}
	return out, changed
}
