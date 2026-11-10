package matchanalyzer

import (
	"github.com/PelicanPlatform/classad/ast"
	"github.com/PelicanPlatform/classad/classad"
)

// frozenAd is a ClassAd's attributes in a form that is only ever copied,
// never evaluated or matched. It is what may be shared between analyses.
//
// A *classad.ClassAd is not handed to two analyses. The analyzer only
// reads slot ads (it evaluates with EvaluateExprAgainst, which binds TARGET
// for one evaluation without writing either ad), but binding with
// NewMatchClassAd or SetTarget writes the ad, and so does any change a
// caller makes. With one slot ad shared, one analysis's TARGET binding
// could replace another's, so the slot's TARGET.* expressions read the
// other user's job. Private copies keep that from depending on every
// reader staying read-only.
//
// The expression trees are shared, not copied: evaluation never writes to
// them. Everything matching or a caller's change does write belongs to
// the *classad.ClassAd that thaw builds, one per use.
type frozenAd []ast.AttributeAssignment

// freeze copies ad's attributes. The caller must own ad: reading its
// attribute list sorts it in place the first time.
func freeze(ad *classad.ClassAd) frozenAd {
	tree := ad.AST()
	if tree == nil {
		return frozenAd{}
	}
	out := make(frozenAd, len(tree.Attributes))
	for i, attr := range tree.Attributes {
		out[i] = *attr
	}
	return out
}

// thaw returns a new ClassAd holding f's attributes, which the caller owns
// outright. The assignments are copied as well as the list, because
// replacing an existing attribute's value writes through to its
// assignment.
func (f frozenAd) thaw() *classad.ClassAd {
	vals := make([]ast.AttributeAssignment, len(f))
	copy(vals, f)
	attrs := make([]*ast.AttributeAssignment, len(vals))
	for i := range vals {
		attrs[i] = &vals[i]
	}
	return classad.FromAST(&ast.ClassAd{Attributes: attrs})
}

// privateCopy returns a ClassAd with ad's attributes that shares nothing
// evaluation or matching writes to. The caller must own ad (see freeze).
func privateCopy(ad *classad.ClassAd) *classad.ClassAd {
	return freeze(ad).thaw()
}
