package poolpolicy

import (
	"fmt"
	"strings"

	"github.com/PelicanPlatform/classad/ast"
	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/parser"
)

// CheckProjection refuses a projection naming anything outside the
// allowlist, and refuses "*" outright -- asking for every attribute is
// exactly what the allowlist exists to prevent.
//
// Refusing rather than silently dropping the attribute is deliberate. A
// projection quietly shortened comes back as an ad with the field absent,
// which reads as "this slot has no owner" rather than "you may not see
// it", and an agent will report the former as fact.
func (p *Policy) CheckProjection(privileged bool, adType string, projection []string) error {
	if !p.Restricts(privileged) {
		return nil
	}
	allowed := p.allowed(adType)
	for _, a := range projection {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if a == "*" {
			return fmt.Errorf("projection '*' is not available at this site: "+
				"name the attributes you need, from %s", attrHint(p, adType))
		}
		if !allowed[strings.ToLower(a)] {
			return fmt.Errorf("attribute %q is not available at this site: "+
				"pool queries are restricted to attributes that describe machines rather than "+
				"the people running on them. Available: %s", a, attrHint(p, adType))
		}
	}
	return nil
}

// ClampProjection returns the projection to send to the collector when the
// caller named none. A restricted caller's default cannot be the library's
// or the ad's full contents, so it becomes the allowlist itself.
func (p *Policy) ClampProjection(privileged bool, adType string, projection []string) []string {
	if !p.Restricts(privileged) {
		return projection
	}
	if len(projection) > 0 {
		return projection
	}
	return p.AllowedAttrs(adType)
}

// FilterAd drops the attributes a restricted caller may not see from an ad
// already fetched. For the paths that have no projection to clamp -- the
// collector watch stream sends whole ads -- this is the only control point.
func (p *Policy) FilterAd(privileged bool, adType string, ad map[string]interface{}) map[string]interface{} {
	if !p.Restricts(privileged) || ad == nil {
		return ad
	}
	allowed := p.allowed(adType)
	out := make(map[string]interface{}, len(ad))
	for k, v := range ad {
		if allowed[strings.ToLower(k)] {
			out[k] = v
		}
	}
	return out
}

// CheckConstraint refuses a constraint that names an attribute outside the
// allowlist.
//
// Checked, not merely stripped from the output, because a constraint is an
// oracle for an attribute it never returns: `RemoteOwner == "alice@wisc.edu"`
// answers "is alice running anywhere" from the count alone. This is the same
// reason claim ids are refused in constraints rather than only in results.
//
// The walk fails closed. Every node type the ClassAd grammar has is handled
// explicitly and an unrecognised one is refused, so a grammar that grows a
// node this code has not seen refuses the constraint rather than walking
// past the subtree containing it.
func (p *Policy) CheckConstraint(privileged bool, adType string, constraint string) error {
	if !p.Restricts(privileged) {
		return nil
	}
	c := strings.TrimSpace(constraint)
	if c == "" || strings.EqualFold(c, "true") {
		return nil
	}
	expr, err := parser.ParseExpr(c)
	if err != nil {
		return fmt.Errorf("invalid constraint %q: %w", constraint, err)
	}
	return p.walk(expr, p.allowed(adType), adType)
}

func (p *Policy) walk(e ast.Expr, allowed map[string]bool, adType string) error {
	switch n := e.(type) {
	case nil:
		return nil

	// Literals name nothing.
	case *ast.IntegerLiteral, *ast.RealLiteral, *ast.StringLiteral,
		*ast.BooleanLiteral, *ast.UndefinedLiteral, *ast.ErrorLiteral:
		return nil

	case *ast.AttributeReference:
		name := n.Name
		if !allowed[strings.ToLower(name)] {
			return fmt.Errorf("the constraint names %q, which is not available at this site: "+
				"pool queries are restricted to attributes that describe machines rather than "+
				"the people running on them. Available: %s", name, attrHint(p, adType))
		}
		return nil

	case *ast.UnaryOp:
		return p.walk(n.Expr, allowed, adType)
	case *ast.BinaryOp:
		if err := p.walk(n.Left, allowed, adType); err != nil {
			return err
		}
		return p.walk(n.Right, allowed, adType)
	case *ast.ParenExpr:
		return p.walk(n.Inner, allowed, adType)
	case *ast.ElvisExpr:
		if err := p.walk(n.Left, allowed, adType); err != nil {
			return err
		}
		return p.walk(n.Right, allowed, adType)
	case *ast.ConditionalExpr:
		for _, sub := range []ast.Expr{n.Condition, n.TrueExpr, n.FalseExpr} {
			if err := p.walk(sub, allowed, adType); err != nil {
				return err
			}
		}
		return nil
	case *ast.ListLiteral:
		for _, sub := range n.Elements {
			if err := p.walk(sub, allowed, adType); err != nil {
				return err
			}
		}
		return nil

	case *ast.FunctionCall:
		// eval() builds an attribute reference out of a string, so no
		// walk of its arguments can tell what it will read. Refused for
		// the same reason the private-attribute check refuses it.
		if strings.EqualFold(n.Name, "eval") {
			return fmt.Errorf("the constraint calls eval(), which is not available at this site: " +
				"it can name an attribute that this check cannot see")
		}
		for _, sub := range n.Args {
			if err := p.walk(sub, allowed, adType); err != nil {
				return err
			}
		}
		return nil

	// A record literal, attribute selection or subscript can reach an
	// attribute by a route this check cannot follow to a name. Neither is
	// needed to select slots, so both are refused rather than guessed at.
	case *ast.RecordLiteral, *ast.SelectExpr, *ast.SubscriptExpr, *ast.ClassAd:
		return fmt.Errorf("this constraint is more than pool queries accept at this site: " +
			"use comparisons and boolean operators over attribute names")

	default:
		return fmt.Errorf("this constraint uses an expression this site cannot check (%T); "+
			"use comparisons and boolean operators over attribute names", e)
	}
}

// attrHint names what the caller may use instead, bounded so an error
// message stays readable.
func attrHint(p *Policy, adType string) string {
	attrs := p.AllowedAttrs(adType)
	const max = 12
	if len(attrs) > max {
		return strings.Join(attrs[:max], ", ") + ", and others"
	}
	return strings.Join(attrs, ", ")
}

// FilterClassAd returns an ad holding only the attributes a restricted
// caller may read. The collector watch stream has no projection to clamp
// -- it sends whole ads as they change -- so this is its control point.
//
// A new ad rather than Delete on the one passed in: the ad belongs to
// whatever cached or streamed it, and may be read by other watchers at the
// same time. Mutating it to serve one caller would redact it for everyone
// and race while doing so.
func (p *Policy) FilterClassAd(privileged bool, adType string, ad *classad.ClassAd) *classad.ClassAd {
	if !p.Restricts(privileged) || ad == nil {
		return ad
	}
	allowed := p.allowed(adType)
	out := classad.New()
	for _, name := range ad.GetAttributes() {
		if !allowed[strings.ToLower(name)] {
			continue
		}
		if expr, ok := ad.Lookup(name); ok && expr != nil {
			out.InsertExpr(name, expr)
		}
	}
	return out
}
