package config

import (
	"sort"
	"strings"
	"testing"
)

// TestSkipDefaultsRawParse verifies that ConfigOptions.SkipDefaults yields a
// Config containing only what the parsed source defines — no param_info.in
// defaults, no time constants, no auto-detected macros. This is the primitive
// the differential config fuzzer builds on: it mirrors HTCondor's
// Parse_config_string on a fresh MACRO_SET with a NULL defaults table.
func TestSkipDefaultsRawParse(t *testing.T) {
	input := "FOO = bar\n" +
		"BAZ = $(FOO)/qux\n" +
		"N = $(FOO:default)\n" +
		"U = $(UNDEFINED_THING)\n"
	c, err := NewFromReaderWithOptions(strings.NewReader(input), ConfigOptions{SkipDefaults: true})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	got := map[string]string{}
	for _, k := range c.Keys() {
		v, _ := c.Get(k)
		got[k] = v
	}
	want := map[string]string{
		"FOO": "bar",
		"BAZ": "bar/qux",
		"N":   "bar", // $(FOO:default) — FOO is defined, so the default is unused
		"U":   "",    // undefined reference expands to empty
	}
	if len(got) != len(want) {
		keys := c.Keys()
		sort.Strings(keys)
		t.Fatalf("raw parse produced %d keys %v, want %d (no defaults should leak in)", len(got), keys, len(want))
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %q, want %q", k, got[k], w)
		}
	}
}

// TestSkipDefaultsFalseLoadsDefaults is the control: without SkipDefaults, the
// param_info.in table is present, so a well-known default key resolves.
func TestSkipDefaultsFalseLoadsDefaults(t *testing.T) {
	withDefaults, err := NewFromReaderWithOptions(strings.NewReader("FOO = bar\n"), ConfigOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(withDefaults.Keys()) <= 1 {
		t.Fatal("expected param defaults to be loaded when SkipDefaults is false")
	}
}
