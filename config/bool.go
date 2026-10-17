package config

import (
	"log/slog"
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
	result, ok, _ = stringIsBooleanParam(s)
	return result, ok
}

// stringIsBooleanParam is StringIsBooleanParam that also reports whether s
// starts with a literal. As in string_is_boolean_param, result is then the
// literal's value even when s is not a boolean ("false # comment",
// "falsey"), and param_boolean returns it.
func stringIsBooleanParam(s string) (result, ok, literal bool) {
	result, prefix, whole := booleanLiteral(s)
	if whole {
		return result, true, true
	}
	if b, ok := booleanExpr(s); ok {
		return b, true, prefix
	}
	return result, false, prefix
}

// booleanExpr is the expression half of string_is_boolean_param.
func booleanExpr(s string) (result, ok bool) {
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

// booleanLiteral is the literal half of string_is_boolean_param: prefix
// reports that s starts with a literal, whose value is result, and whole
// that only whitespace follows it.
func booleanLiteral(s string) (result, prefix, whole bool) {
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
		return false, false, false
	}
	for n < len(s) && cIsSpace(s[n]) {
		n++
	}
	return result, true, n == len(s)
}

// GetBool is HTCondor's param_boolean: key's value read by
// StringIsBooleanParam, or def when key is unset. A knob in the generated
// defaults table is never unset, so its table default applies rather than
// def, as in param_boolean.
//
// A value that is not a boolean is logged as an error naming the knob. As in
// param_boolean, GetBool then returns the value of the literal it starts with
// ("false  # only our CA" and "falsey" are false: HTCondor has no inline
// comments), or def if it starts with none ("no"). HTCondor's daemons exit
// on such a value instead; a library cannot.
func (c *Config) GetBool(key string, def bool) bool {
	v, ok := c.Get(key)
	if !ok {
		return def
	}
	b, ok, literal := stringIsBooleanParam(v)
	if ok {
		return b
	}
	if !literal {
		b = def
	}
	slog.Default().Error("config: not a valid boolean; set it to True or False",
		"knob", key, "value", v, "using", b)
	return b
}
