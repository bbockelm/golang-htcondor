package config

import (
	"strings"
	"testing"
)

// TestStringIsBooleanParam pins the values HTCondor's string_is_boolean_param
// accepts: the true/false/1/0 literals, and any ClassAd expression that
// evaluates to a boolean or a number. The words other parsers in this module
// accept ("yes", "t", "on") are attribute references, which are not booleans.
func TestStringIsBooleanParam(t *testing.T) {
	tests := []struct {
		in         string
		want, isOK bool
	}{
		{"true", true, true},
		{"TRUE", true, true},
		{"True  ", true, true},
		{"1", true, true},
		{"false", false, true},
		{"FaLsE\t", false, true},
		{"0", false, true},
		{" true", true, true},      // not a literal, but a boolean expression
		{"10", true, true},         // an integer expression, non-zero
		{"0.0", false, true},       // a real expression, zero
		{"1 + 1 == 2", true, true}, // an expression
		{"2 < 1 || false", false, true},
		{"yes", false, false},
		{"no", false, false},
		{"t", false, false},
		{"on", false, false},
		{"truex", false, false},
		{`"true"`, false, false}, // a string is not a boolean
		{"", false, false},
	}
	for _, tt := range tests {
		got, ok := StringIsBooleanParam(tt.in)
		if ok != tt.isOK || (ok && got != tt.want) {
			t.Errorf("StringIsBooleanParam(%q) = (%v, %v), want (%v, %v)", tt.in, got, ok, tt.want, tt.isOK)
		}
	}
}

// TestGetBool shows GetBool returns def for an unset knob or one whose value
// is not a boolean, and the generated table's default for a knob that has
// one, as param_boolean does.
func TestGetBool(t *testing.T) {
	cfg, err := NewFromReader(strings.NewReader("A = false\nB = no\nC = 3 > 2\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		key       string
		def, want bool
	}{
		{"A", true, false},
		{"B", true, true}, // not a boolean: the default
		{"B", false, false},
		{"C", false, true},
		{"UNSET_KNOB_FOR_TEST", true, true},
		{"UNSET_KNOB_FOR_TEST", false, false},
		{"AUTH_SSL_CLIENT_USE_DEFAULT_CAS", false, true}, // table default is true
	} {
		if got := cfg.GetBool(tt.key, tt.def); got != tt.want {
			t.Errorf("GetBool(%q, %v) = %v, want %v", tt.key, tt.def, got, tt.want)
		}
	}
}
