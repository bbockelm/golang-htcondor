package config

import (
	"strings"
	"testing"
)

// TestLookupIsCaseInsensitive covers HTCondor's rule that parameter names do
// not distinguish case. Before this, a Config would answer only to the exact
// spelling used in the file.
func TestLookupIsCaseInsensitive(t *testing.T) {
	cfg, err := NewFromReaderWithOptions(
		strings.NewReader("PELICAN_PORT = 8444\nlower_case_knob = yes\n"),
		ConfigOptions{SkipDefaults: true})
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"PELICAN_PORT", "pelican_port", "Pelican_Port"} {
		if v, ok := cfg.Get(name); !ok || v != "8444" {
			t.Errorf("Get(%q) = %q, %v; want \"8444\", true", name, v, ok)
		}
	}
	// ... and in the other direction, for a knob written in lower case.
	for _, name := range []string{"lower_case_knob", "LOWER_CASE_KNOB"} {
		if v, ok := cfg.Get(name); !ok || v != "yes" {
			t.Errorf("Get(%q) = %q, %v; want \"yes\", true", name, v, ok)
		}
	}
}

// TestLocalNameLookupIsCaseInsensitive is the case that motivated this. A
// daemon started with "-local-name cache_a" has to find a CACHE_A.* definition:
// the local name arrives from the command line while the key is written in a
// config file, and nothing makes an operator match their own capitalization.
func TestLocalNameLookupIsCaseInsensitive(t *testing.T) {
	const text = `
PELICAN_PORT = 8444
CACHE_A.PELICAN_PORT = 9444
lower_b.PELICAN_PORT = 9555
PELICAN.CACHE_C.PELICAN_PORT = 9666
`
	for _, tc := range []struct{ localName, want string }{
		{"", "8444"},
		{"CACHE_A", "9444"},
		{"cache_a", "9444"}, // differs in case from the definition
		{"lower_b", "9555"},
		{"LOWER_B", "9555"}, // differs in case from the definition
		{"cache_c", "9666"}, // reached through <SUBSYS>.<LOCALNAME>.<KEY>
	} {
		cfg, err := NewFromReaderWithOptions(strings.NewReader(text),
			ConfigOptions{Subsystem: "PELICAN", LocalName: tc.localName, SkipDefaults: true})
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := cfg.Get("PELICAN_PORT"); got != tc.want {
			t.Errorf("local name %q: got %s, want %s", tc.localName, got, tc.want)
		}
	}
}

// TestRedefinitionInDifferentCaseReplaces checks that two spellings of one knob
// do not both survive, which would make the winner depend on map iteration
// order.
func TestRedefinitionInDifferentCaseReplaces(t *testing.T) {
	cfg, err := NewFromReaderWithOptions(
		strings.NewReader("SOME_KNOB = first\nsome_knob = second\n"),
		ConfigOptions{SkipDefaults: true})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := cfg.Get("SOME_KNOB"); got != "second" {
		t.Errorf("later definition should win regardless of case: got %q", got)
	}
	if n := len(cfg.values); n != 1 {
		t.Errorf("one knob should be stored once, found %d entries: %v", n, cfg.values)
	}
}

// TestDefinedIsCaseInsensitive covers "if defined X" in the config language.
func TestDefinedIsCaseInsensitive(t *testing.T) {
	cfg, err := NewFromReaderWithOptions(
		strings.NewReader("SOME_KNOB = 1\nif defined some_knob\n  RESULT = found\nendif\n"),
		ConfigOptions{SkipDefaults: true})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := cfg.Get("RESULT"); got != "found" {
		t.Errorf("`defined` should not distinguish case: RESULT = %q", got)
	}
}
