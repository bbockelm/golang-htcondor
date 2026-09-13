package config

import (
	"strings"
	"testing"
)

// newTestConfig is an empty Config with no host configuration behind
// it: these tests are about what parsing stores, not about defaults.
func newTestConfig() *Config {
	return &Config{
		values:     map[string]string{},
		evaluating: map[string]bool{},
	}
}

// parseStatements parses text and returns its statements.
func parseStatements(t *testing.T, src string) []Statement {
	t.Helper()
	stmts, err := Parse(NewLexer(strings.NewReader(src)))
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	return stmts
}

func assignments(stmts []Statement) []*Assignment {
	var out []*Assignment
	for _, s := range stmts {
		if a, ok := s.(*Assignment); ok {
			out = append(out, a)
		}
	}
	return out
}

// TestPlusAssignmentIsParsed covers the lexer's lookahead. It used to
// test the character AFTER the first one, so a single-character
// attribute name was lexed as ILLEGAL — and because the grammar has no
// error production for a stray '+', the statement disappeared with no
// diagnostic at all.
func TestPlusAssignmentIsParsed(t *testing.T) {
	for _, src := range []string{
		"+X = 1\n",
		"+Xy = 1\n",
		"+_private = 1\n",
		"+LongAttributeName = 1\n",
	} {
		got := assignments(parseStatements(t, src))
		if len(got) != 1 {
			t.Errorf("%q produced %d assignments, want 1", src, len(got))
			continue
		}
		if !got[0].ClassAdExpr {
			t.Errorf("%q: ClassAdExpr = false, want true", src)
		}
	}
}

// TestPlusAssignmentStoresUnderTheCustomPrefix: the parser strips the
// '+', so without canonicalization the assignment is indistinguishable
// from an ordinary macro of the same name — which is exactly how every
// + attribute came to be silently dropped by the submit builder.
func TestPlusAssignmentStoresUnderTheCustomPrefix(t *testing.T) {
	cfg := newTestConfig()
	if err := cfg.ExecuteStatements(parseStatements(t, "+Tag = \"nightly\"\n")); err != nil {
		t.Fatalf("ExecuteStatements: %v", err)
	}

	got, ok := cfg.Get(CustomAttrPrefix + "Tag")
	if !ok {
		t.Fatalf("%sTag is not defined; keys: %v", CustomAttrPrefix, cfg.Keys())
	}
	if got != `"nightly"` {
		t.Errorf("%sTag = %q, want %q", CustomAttrPrefix, got, `"nightly"`)
	}

	// The bare name must NOT be defined: a custom attribute is not a
	// configuration macro, and a submit command called Tag would
	// otherwise collide with it.
	if _, ok := cfg.Get("Tag"); ok {
		t.Error("+Tag also defined the bare macro Tag; the two namespaces have to stay separate")
	}
}

// MY.Tag is HTCondor's other spelling for the same thing, and already
// lands under the prefix. Both forms have to agree.
func TestMyPrefixAndPlusAgree(t *testing.T) {
	plus := newTestConfig()
	if err := plus.ExecuteStatements(parseStatements(t, "+Tag = \"nightly\"\n")); err != nil {
		t.Fatalf("ExecuteStatements: %v", err)
	}
	my := newTestConfig()
	if err := my.ExecuteStatements(parseStatements(t, "MY.Tag = \"nightly\"\n")); err != nil {
		t.Fatalf("ExecuteStatements: %v", err)
	}

	a, aok := plus.Get(CustomAttrPrefix + "Tag")
	b, bok := my.Get(CustomAttrPrefix + "Tag")
	if !aok || !bok || a != b {
		t.Errorf("+Tag gave (%q,%v) and MY.Tag gave (%q,%v); the two spellings must agree", a, aok, b, bok)
	}
}

// A later assignment wins, whichever spelling each one used.
func TestCustomAttributeLastAssignmentWins(t *testing.T) {
	cfg := newTestConfig()
	if err := cfg.ExecuteStatements(parseStatements(t, "+Tag = \"first\"\nMY.Tag = \"second\"\n")); err != nil {
		t.Fatalf("ExecuteStatements: %v", err)
	}
	if got, _ := cfg.Get(CustomAttrPrefix + "Tag"); got != `"second"` {
		t.Errorf("%sTag = %q, want %q", CustomAttrPrefix, got, `"second"`)
	}
}

// An ordinary macro must not acquire the prefix.
func TestPlainAssignmentIsNotACustomAttribute(t *testing.T) {
	cfg := newTestConfig()
	if err := cfg.ExecuteStatements(parseStatements(t, "Tag = nightly\n")); err != nil {
		t.Fatalf("ExecuteStatements: %v", err)
	}
	if _, ok := cfg.Get(CustomAttrPrefix + "Tag"); ok {
		t.Errorf("plain assignment Tag was stored as a custom attribute")
	}
	if got, ok := cfg.Get("Tag"); !ok || got != "nightly" {
		t.Errorf("Tag = %q (present=%v), want nightly", got, ok)
	}
}
