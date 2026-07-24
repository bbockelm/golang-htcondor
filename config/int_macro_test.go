package config

import (
	"fmt"
	"strings"
	"testing"
)

// TestINTMacroEvaluatesExpression covers HTCondor's $INT(name)/$REAL(name)
// semantics: the argument is a macro name whose expanded value is evaluated as a
// ClassAd expression. The motivating case is a hostname guard,
// `HOSTCHECK = "$(FULL_HOSTNAME)" == "a" || "$(FULL_HOSTNAME)" == "b"`, used as
// `if $INT(HOSTCHECK)`.
func TestINTMacroEvaluatesExpression(t *testing.T) {
	newCfg := func(vals map[string]string) *Config {
		return &Config{values: vals, evaluating: make(map[string]bool)}
	}

	cases := []struct {
		name string
		vals map[string]string
		expr string
		want string
	}{
		{
			name: "boolean expression true",
			vals: map[string]string{
				"FULL_HOSTNAME": "ap43.uw.osg-htc.org",
				"HOSTCHECK":     `"$(FULL_HOSTNAME)" == "ap43.uw.osg-htc.org" || "$(FULL_HOSTNAME)" == "ospool-ap4043.chtc.wisc.edu"`,
			},
			expr: "$INT(HOSTCHECK)",
			want: "1",
		},
		{
			name: "boolean expression false",
			vals: map[string]string{
				"FULL_HOSTNAME": "other.example.org",
				"HOSTCHECK":     `"$(FULL_HOSTNAME)" == "ap43.uw.osg-htc.org" || "$(FULL_HOSTNAME)" == "ospool-ap4043.chtc.wisc.edu"`,
			},
			expr: "$INT(HOSTCHECK)",
			want: "0",
		},
		{
			name: "arithmetic expression",
			vals: map[string]string{"X": "3 + 4"},
			expr: "$INT(X)",
			want: "7",
		},
		{
			name: "plain integer literal (fast path)",
			vals: map[string]string{"N": "42"},
			expr: "$INT(N)",
			want: "42",
		},
		{
			name: "real truncates to int",
			vals: map[string]string{"R": "3.9"},
			expr: "$INT(R)",
			want: "3",
		},
		{
			name: "REAL of expression",
			vals: map[string]string{"R": "1.5 + 2"},
			expr: "$REAL(R)",
			want: "3.5",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newCfg(tc.vals)
			got, err := cfg.expandMacrosWithFunctions(tc.expr)
			if err != nil {
				t.Fatalf("%s: %v", tc.expr, err)
			}
			if got != tc.want {
				t.Errorf("%s = %q, want %q", tc.expr, got, tc.want)
			}
		})
	}
}

// TestIfINTGuardsKnob is the end-to-end reproduction: `if $INT(HOSTCHECK)`
// guarding a JOB_QUEUE_LOG assignment. The block must be taken only when the
// hostname matches -- previously $INT errored, the if silently went false, and
// the knob was never set.
func TestIfINTGuardsKnob(t *testing.T) {
	// Use a knob with no param default so Get() reflects only the conditional
	// (JOB_QUEUE_LOG has a built-in default that would mask the "unset" case).
	const tmpl = `FULL_HOSTNAME = %s
HOSTCHECK = "$(FULL_HOSTNAME)" == "ap43.uw.osg-htc.org" || "$(FULL_HOSTNAME)" == "ospool-ap4043.chtc.wisc.edu"
if $INT(HOSTCHECK)
  TEST_GUARDED_KNOB = /var/lib/condor/job_queue/job_queue.log
endif
`
	t.Run("hostname matches -> knob set", func(t *testing.T) {
		cfg, err := NewFromReader(strings.NewReader(fmt.Sprintf(tmpl, "ap43.uw.osg-htc.org")))
		if err != nil {
			t.Fatal(err)
		}
		got, ok := cfg.Get("TEST_GUARDED_KNOB")
		if !ok || got != "/var/lib/condor/job_queue/job_queue.log" {
			t.Errorf("TEST_GUARDED_KNOB = %q (set=%v), want the guarded path", got, ok)
		}
	})
	t.Run("hostname differs -> knob unset", func(t *testing.T) {
		cfg, err := NewFromReader(strings.NewReader(fmt.Sprintf(tmpl, "other.example.org")))
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := cfg.Get("TEST_GUARDED_KNOB"); ok {
			t.Errorf("TEST_GUARDED_KNOB unexpectedly set to %q on a non-matching host", got)
		}
	})
}
