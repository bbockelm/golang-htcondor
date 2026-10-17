package config

import (
	"bytes"
	"log/slog"
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

// TestGetBool shows GetBool returns def for an unset knob, and the generated
// table's default for a knob that has one, as param_boolean does. A value that
// is not a boolean is logged and, as in param_boolean, gives the value of the
// literal it starts with, or def if it starts with none.
// Not parallel: it replaces the default logger.
func TestGetBool(t *testing.T) {
	cfg, err := NewFromReader(strings.NewReader(`A = false
B = no
C = 3 > 2
D = false   # only our CA
E = falsey
F = TRUEish
G = 0 || true
H = 1 + 1 == 2
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		key       string
		def, want bool
		logged    bool
	}{
		{"A", true, false, false},
		{"B", true, true, true}, // no literal: the default
		{"B", false, false, true},
		{"C", false, true, false},
		{"D", true, false, true}, // HTCondor has no inline comments
		{"E", true, false, true},
		{"F", false, true, true},
		{"G", false, true, false}, // a literal prefix, but a valid expression
		{"H", false, true, false},
		{"UNSET_KNOB_FOR_TEST", true, true, false},
		{"UNSET_KNOB_FOR_TEST", false, false, false},
		{"AUTH_SSL_CLIENT_USE_DEFAULT_CAS", false, true, false}, // table default is true
	} {
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
		got := cfg.GetBool(tt.key, tt.def)
		slog.SetDefault(prev)
		if got != tt.want {
			t.Errorf("GetBool(%q, %v) = %v, want %v", tt.key, tt.def, got, tt.want)
		}
		out := buf.String()
		if logged := out != ""; logged != tt.logged {
			t.Errorf("GetBool(%q, %v) logged %q, want logged = %v", tt.key, tt.def, out, tt.logged)
		} else if logged && (!strings.Contains(out, "level=ERROR") || !strings.Contains(out, "knob="+tt.key)) {
			t.Errorf("GetBool(%q, %v) logged %q, want an error naming the knob", tt.key, tt.def, out)
		}
	}
}
