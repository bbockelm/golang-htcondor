package config

// Behaviors of HTCondor's config-file reader and macro expansion
// (config.cpp, v25.14.1) that the differential fuzzer (fuzz/config) found the
// Go parser getting wrong. Each expectation was checked with condor 25.14.1:
// CONDOR_CONFIG=<file> condor_config_val NAME. They run here without the
// C++ oracle so ordinary CI keeps them.

import (
	"errors"
	"strings"
	"testing"
)

func parseFor(t *testing.T, text string, compat bool) (*Config, error) {
	t.Helper()
	return NewFromReaderWithOptions(strings.NewReader(text), ConfigOptions{SkipDefaults: true, HTCondorCompat: compat})
}

func wantValues(t *testing.T, text string, want map[string]string) {
	t.Helper()
	for _, compat := range []bool{false, true} {
		c, err := parseFor(t, text, compat)
		if err != nil {
			t.Fatalf("compat=%v: parse %q: %v", compat, text, err)
		}
		for k, w := range want {
			got, ok := c.Get(k)
			if !ok || got != w {
				t.Errorf("compat=%v: %q: %s = %q (defined %v), want %q", compat, text, k, got, ok, w)
			}
		}
	}
}

func wantRejected(t *testing.T, text string) {
	t.Helper()
	if _, err := parseFor(t, text, true); err == nil {
		t.Errorf("compat: %q parsed, want an error", text)
	}
}

func TestParityUseIsKeywordOnlyBeforeColon(t *testing.T) {
	wantValues(t, "FOO = 1\nfoo = 2\nUSE = $(Foo)\n", map[string]string{"USE": "2"})
	c, _ := parseFor(t, "USE = x\n", false)
	if _, ok := c.Get("ROLE"); ok {
		t.Error("USE = x defined ROLE; it is an ordinary assignment")
	}
}

func TestParityWordsBeforeOperatorIgnored(t *testing.T) {
	wantValues(t, "foo bar = baz\n", map[string]string{"foo": "baz"})
	wantValues(t, "0 0=\nX = [$(0)]\n", map[string]string{"X": "[]"})
	wantRejected(t, "foo bar\n")
	wantRejected(t, "0 00\n")
}

// A name is any run of identifier characters. The Go lexer used to reject
// a digit-leading name, and the default (lenient) parse dropped the line
// without a word.
func TestParityDigitLeadingName(t *testing.T) {
	wantValues(t, "0 = 1\n", map[string]string{"0": "1"})
	wantValues(t, "1 = MYVAR\nMYVAR = v\nR = $($(1))\n", map[string]string{"R": "v"})
	wantValues(t, "a.b/c = 1\n", map[string]string{"a.b/c": "1"})
}

func TestParityLastLineWithoutNewline(t *testing.T) {
	wantValues(t, "T = v ", map[string]string{"T": "v "})
	wantValues(t, "T = v \n", map[string]string{"T": "v"})
}

func TestParityBytesKept(t *testing.T) {
	wantValues(t, "B = \xff\n", map[string]string{"B": "\xff"})
}

// A ':' starting a line inside an if body is dropped (pre-8.1.5
// compatibility); a line that was only ':' is then a line with no operator.
func TestParityColonPrefixInIfBody(t *testing.T) {
	wantValues(t, "if true\n:A = 1\nendif\n", map[string]string{"A": "1"})
	wantRejected(t, "if 1\n:\nendif\n")
}

func TestParityHereDocNeedsWhitespaceBeforeAt(t *testing.T) {
	wantRejected(t, "H@=end\nx\n@end\n")
	wantValues(t, "H @=end\nx\n#comment\ny\n@end\n", map[string]string{"H": "x\ny"})
}

func TestParitySelfReference(t *testing.T) {
	wantValues(t, "S = $(s)\n", map[string]string{"S": ""})
	wantValues(t, "P = one\nP = $(p) two\n", map[string]string{"P": "one two"})
	wantValues(t, "Q = $(Q:dflt)\n", map[string]string{"Q": "dflt"})
}

func TestParityEnvDefault(t *testing.T) {
	t.Setenv("CFG_PARITY_SET", "set")
	wantValues(t, "A = $ENV(CFG_PARITY_UNSET:dflt)\nB = $ENV(CFG_PARITY_UNSET)\nC = $ENV(CFG_PARITY_SET:dflt)\n",
		map[string]string{"A": "dflt", "B": "UNDEFINED", "C": "set"})
}

func TestParityContinuation(t *testing.T) {
	wantValues(t, "A = x\\\ny\n", map[string]string{"A": "xy"})
	wantValues(t, "A = x \\\n   y\n", map[string]string{"A": "x y"})
	// A '#' line inside a continued line contributes only its last character.
	wantValues(t, "A = x \\\n# c\nB = 2\n", map[string]string{"A": "x c", "B": "2"})
}

func TestParityAppend(t *testing.T) {
	wantValues(t, "A = 1\nA += 2\nL = a\nL +,= b\nM = a\nM +&&= b\nN += z\n",
		map[string]string{"A": "1 2", "L": "a,b", "M": "a && b", "N": "z"})
}

func TestParityExpansion(t *testing.T) {
	wantValues(t, "DN = $DIRNAME(/a/b/c)\nBN = $BASENAME(/a/b/c)\nNAME = MINUTE\nMINUTE = 60\nVAL = $($(NAME))\n",
		map[string]string{"DN": "/a/b/", "BN": "c", "VAL": "60"})
	// Under old ClassAd semantics 0x10 is not a number.
	wantValues(t, "I = $INT(0x10)\nJ = $INT(2.7)\n", map[string]string{"I": "", "J": "2"})
	wantValues(t, "D = a$(DOLLAR)(D)b\n", map[string]string{"D": "a$(D)b"})
}

func TestParityIfConditions(t *testing.T) {
	wantValues(t, "X =\nif defined X\nY = yes\nelse\nY = no\nendif\n", map[string]string{"Y": "no"})
	// HTCondor rejects comparisons; the Go default keeps them as an extension.
	wantRejected(t, "B = 2\nif $(B) > 1\nY = yes\nendif\n")
	c, err := parseFor(t, "B = 2\nif $(B) > 1\nY = yes\nendif\n", false)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := c.Get("Y"); got != "yes" {
		t.Errorf("default mode: Y = %q, want yes", got)
	}
}

func TestNoIncludeRefusesIncludeKeepsEnv(t *testing.T) {
	t.Setenv("CFG_PARITY_SET", "set")
	opts := ConfigOptions{SkipDefaults: true, NoInclude: true}
	if _, err := NewFromReaderWithOptions(strings.NewReader("include ifexist : /nonexistent\n"), opts); err == nil {
		t.Error("include parsed with NoInclude")
	}
	c, err := NewFromReaderWithOptions(strings.NewReader("E = $ENV(CFG_PARITY_SET)\n"), opts)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := c.Get("E"); got != "set" {
		t.Errorf("E = %q, want set", got)
	}
}

// HTCondor loops forever on a reference cycle and crashes on the constructs
// below; the Go side reports an error instead of a value.
func TestExpansionErrors(t *testing.T) {
	for _, tc := range []struct {
		text, key string
		want      error
	}{
		{"A = $(B)\nB = $(A)\n", "A", ErrMacroLoop},
		{"A = x$(B)\nB = y$(A)\n", "A", ErrMacroLoop},
		{"A = $SUBSTR(B,0)\nB = $(A)\n", "A", ErrMacroLoop},
		{"A = $Fdd(a/b)\n", "A", ErrHTCondorUndefined},
		{"A = $F(\"\")\n", "A", ErrHTCondorUndefined},
	} {
		c, err := parseFor(t, tc.text, true)
		if err != nil {
			t.Fatalf("%q: %v", tc.text, err)
		}
		if _, _, err := c.GetChecked(tc.key); !errors.Is(err, tc.want) {
			t.Errorf("%q: GetChecked(%s) error = %v, want %v", tc.text, tc.key, err, tc.want)
		}
		if raw, ok := c.Get(tc.key); !ok || raw == "" {
			t.Errorf("%q: Get(%s) = %q, want the raw value", tc.text, tc.key, raw)
		}
	}
	if _, err := parseFor(t, "A B+\n", true); !errors.Is(err, ErrHTCondorUndefined) {
		t.Errorf("a line ending in '+': error = %v, want ErrHTCondorUndefined", err)
	}
}
