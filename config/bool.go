package config

import (
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// StringIsBooleanParam is HTCondor's string_is_boolean_param. A value is
// first read as a literal: "true", "1", "false" or "0" (the words in any
// case), followed only by whitespace. Anything else is parsed as a ClassAd
// expression, and is a boolean when it evaluates to a boolean or to a number
// (non-zero is true), so "1 + 1 == 2" is true. "yes", "t", "on" and the like
// are not booleans: as expressions they are attribute references that
// evaluate to UNDEFINED. ok is false when s is not a boolean.
func StringIsBooleanParam(s string) (result, ok bool) {
	if v, ok := booleanLiteral(s); ok {
		return v, true
	}
	expr, err := parseConfigExpr(s)
	if err != nil {
		return false, false
	}
	r := expr.Eval(classad.New())
	switch {
	case r.IsBool():
		b, _ := r.BoolValue()
		return b, true
	case r.IsInteger():
		n, _ := r.IntValue()
		return n != 0, true
	case r.IsReal():
		f, _ := r.RealValue()
		return f != 0, true
	}
	return false, false
}

// booleanLiteral is the literal half of string_is_boolean_param.
func booleanLiteral(s string) (result, ok bool) {
	var n int
	switch {
	case len(s) >= 4 && strings.EqualFold(s[:4], "true"):
		result, n = true, 4
	case strings.HasPrefix(s, "1"):
		result, n = true, 1
	case len(s) >= 5 && strings.EqualFold(s[:5], "false"):
		result, n = false, 5
	case strings.HasPrefix(s, "0"):
		result, n = false, 1
	default:
		return false, false
	}
	for n < len(s) && cIsSpace(s[n]) {
		n++
	}
	return result, n == len(s)
}

// GetBool is HTCondor's param_boolean: key's value read by
// StringIsBooleanParam, or def when key is unset or its value is not a
// boolean. A knob in the generated defaults table is never unset, so its
// table default applies rather than def, as in param_boolean.
func (c *Config) GetBool(key string, def bool) bool {
	v, ok := c.Get(key)
	if !ok {
		return def
	}
	if b, ok := StringIsBooleanParam(v); ok {
		return b
	}
	return def
}
