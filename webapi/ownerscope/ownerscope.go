// Package ownerscope confines an untrusted ClassAd constraint to one
// owner's jobs.
//
// It is the single implementation of the parse-and-reserialize AND that
// every owner-scoped read relies on. Splicing a caller's constraint raw
// into "(owner) && (c)" does not confine it: ClassAd "||" binds looser
// than "&&", so an unbalanced input such as `true) || (true` escapes the
// enclosing AND and matches every job. Re-serializing the constraint
// through the ClassAd parser yields a balanced expression the enclosing
// parentheses do confine, and an input that will not parse is refused
// rather than widened.
package ownerscope

import (
	"errors"
	"fmt"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// Constrain returns `attr == value` ANDed with constraint. An empty or
// literal "true" constraint yields the scope clause alone. attr is
// trusted (a constant at every call site); value and constraint are not.
func Constrain(attr, value, constraint string) (string, error) {
	if value == "" {
		return "", errors.New("no authenticated owner to scope to")
	}
	scope := fmt.Sprintf("%s == %s", attr, StringLit(value))
	c := strings.TrimSpace(constraint)
	if c == "" || strings.EqualFold(c, "true") {
		return scope, nil
	}
	safe, err := Balanced(c)
	if err != nil {
		return "", fmt.Errorf("constraint is not a valid ClassAd expression: %w", err)
	}
	return fmt.Sprintf("(%s) && (%s)", scope, safe), nil
}

// Balanced parses an untrusted ClassAd expression and returns its
// re-serialized form, safe to splice as one operand of a larger
// expression. It errors on anything that does not parse as one complete
// expression.
func Balanced(constraint string) (string, error) {
	expr, err := classad.ParseExpr(constraint)
	if err != nil {
		return "", err
	}
	return expr.String(), nil
}

// StringLit quotes s as a ClassAd string literal.
func StringLit(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
