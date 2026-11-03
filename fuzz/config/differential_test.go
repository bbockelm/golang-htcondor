package fuzzconfig

import (
	"fmt"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/config/oracle"
)

// requireOracle skips when the C++ oracle is not linked (i.e. the test was not
// built with -tags libcondor_utils). See hack/config-fuzz-env.sh.
func requireOracle(t testing.TB) {
	if !oracle.Available {
		t.Skip("differential config test needs the C++ oracle: `source hack/config-fuzz-env.sh` then run with -tags libcondor_utils")
	}
}

// seedCase is a hand-written config source. When reason is empty, the Go and
// C++ engines are expected to AGREE (parity). When reason is non-empty, the
// case is a KNOWN divergence the fuzzer already surfaced (see
// design_notes/CONFIG_FUZZ_FINDINGS.md): the
// test asserts it still diverges, so if the Go side is fixed to match HTCondor
// the case flips and we get told to promote it to parity.
//
// class, on a known divergence, names the FAMILY the input belongs to. Without
// one, only this exact input is recognized, and the fuzzer re-reports the same
// finding under every mutation of it -- which is what we want while the
// divergence is still ours to fix, and noise once it is not.
type seedCase struct {
	input  string
	reason string
	class  *divergenceClass
}

// divergenceClass recognizes a divergence by its SHAPE rather than by the
// input that produced it. A recorded class is matched against every divergence
// the fuzzer finds, and a match is not reported: the finding is one we already
// have, reached from a different input.
//
// A class is a decision that a whole family will not be fixed, so each one is
// written as narrowly as the family allows and is pinned from both sides --
// TestDivergenceClassesMatchTheirSeeds proves it still recognizes the seed it
// was written for, and TestDivergenceClassesRejectOtherShapes proves it does
// not quietly swallow anything else.
type divergenceClass struct {
	name string
	// match sees the two canonical tables from a comparison where the two
	// sides disagreed.
	match func(goTable, cppTable string) bool
}

// selectorSpacing is the unparser difference recorded against
// `0=$EVAL({0 .A})`: C++ writes a selector on a numeric literal with no space
// before the dot, producing text its own lexer then rejects, and Go keeps the
// space. Every input that reaches an expression of this shape -- and the
// fuzzer reaches a fresh one most nights, since one character of mutation is
// enough -- produces the same two tables modulo that space.
var selectorSpacing = divergenceClass{
	name: "C++ drops the space before a selector dot",
	match: func(goTable, cppTable string) bool {
		return goTable != cppTable && stripSpaceBeforeDot(goTable) == cppTable
	},
}

// stripSpaceBeforeDot removes the blanks immediately before each '.'. Only the
// Go side is rewritten, so the reverse shape -- C++ keeping a space Go drops --
// is a divergence this class does not recognize, and is reported.
func stripSpaceBeforeDot(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			trimmed := strings.TrimRight(b.String(), " \t")
			b.Reset()
			b.WriteString(trimmed)
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// recognize returns the recorded class that accounts for this divergence, or
// nil when it is a new one.
func recognize(res divergenceResult) *divergenceClass {
	for _, sc := range seeds {
		if sc.class == nil {
			continue
		}
		if sc.class.match(res.goTable, res.cppTable) {
			return sc.class
		}
	}
	return nil
}

// seeds double as the fuzz seed corpus. Non-deterministic constructs
// ($RANDOM_CHOICE, $RANDOM_INTEGER) are intentionally excluded.
var seeds = []seedCase{
	// --- parity: Go and HTCondor agree ---
	{input: "FOO = bar\nBAZ = $(FOO)/qux\n"},
	{input: "TEN = $(MINUTE)\nHOST = $(FULL_HOSTNAME)\n"},
	{input: "A = $(UNDEF:fallback)\nB = $(MINUTE:99)\n"},
	{input: "U = [$(NOPE)]\n"},
	{input: "P = one\nP = $(P) two\n"},
	{input: "S = $SUBSTR(abcdef,1,3)\n"},
	{input: "R = $REAL(3)\n"},
	{input: "if defined MINUTE\n  X = yes\nelse\n  X = no\nendif\n"},
	{input: "BLOB @=end\nline1\nline2\n@end\n"},
	{input: "   SPACED    =     trimmed   \n"},
	{input: "EMPTY =\n"},
	{input: "D = a$(DOLLAR)b\n"},                   // fixed: $(DOLLAR) -> literal '$'
	{input: "# a comment\n\nK = v   # trailing\n"}, // fixed: '#' inside a value is literal
	{input: "C : colonval\n"},                      // fixed: colon is an assignment operator
	{input: "LONG = a \\\n b \\\n c\n"},            // continuation, joined by HTCondor's own file reader
	{input: "if 1 > 0\n  Y = t\nendif\n"},          // parity in HTCondorCompat: Go rejects it too
	{input: "0\n"},                                 // fuzzer finding: bare non-assignment line; compat rejects it like HTCondor
	{input: "FOO = bar\n0\n"},                      // a bad line among good ones fails the whole parse in compat
	{input: "foo bar\n"},                           // no operator: a config file rejects it (Parse_macros), as Go does

	// --- known divergence ---
	{
		// Found by FuzzConfigParseExpand.
		input: "0=$EVAL({0 .A})",
		reason: "a selector on a numeric literal: HTCondor's unparser writes text " +
			"its own parser cannot read. Both sides parse `0 .A` as attribute A " +
			"selected from 0, and both are right about that; C++ then unparses it " +
			"as `0.A`, with no space, and `$EVAL({0.A})` comes back EMPTY -- its " +
			"lexer reads `0.` as a real and chokes on the `A`. Go keeps the space, " +
			"so `{ 0 .A }` parses back to the expression it came from. Go's output " +
			"round-trips and C++'s does not, so this one is recorded rather than " +
			"matched. (Go has its own instance of the same shape, reachable only " +
			"from an expression this config language cannot write: `(0).A` " +
			"unparses to `0.A`, which Go's parser then rejects. That belongs in " +
			"the ClassAd library, not here.)",
		class: &selectorSpacing,
	},

	// --- former divergences, fixed; each checked against condor 25.14.1 ---
	{input: "DN = $DIRNAME(/a/b/c)\n"},             // -> /a/b/ (param()'s expand_macro has $DIRNAME)
	{input: "BN = $BASENAME(/a/b/c)\n"},            // -> c
	{input: "NAME = MINUTE\nVAL = $($(NAME))\n"},   // the result of an expansion is expanded again -> 60
	{input: "FOO = 1\nfoo = 2\nUSE = $(Foo)\n"},    // 'use' is a keyword only before ':' -> USE=2
	{input: "I = $INT(0x10)\n"},                    // old ClassAd semantics: not an integer -> ""
	{input: "foo bar = baz\n"},                     // words before the operator are ignored -> foo=baz
	{input: "0 = 1\n"},                             // a name is any run of identifier characters
	{input: "E = $ENV(CFG_FUZZ_UNSET_VAR:dflt)\n"}, // $ENV default -> dflt
	{input: "T = v "},                              // last line without a newline keeps its whitespace
	{input: "B = \xff\n"},                          // bytes are kept as is
	{input: "H@=end\nx\n@end\n"},                   // illegal identifier H@
	{input: "S = $(s)\n"},                          // self-reference with no prior value -> ""
	{input: "A = x\\\ny\n"},                        // continuation joins without a space -> xy
	{input: "A = x \\\n# c\nB = 2\n"},              // a commented continuation line leaves its last character -> "x c"
	{input: "SUM = 1\nSUM += 2\nL = a\nL +,= b\n"}, // += appends with a space, +,= with a comma
	{input: "if defined MINUTE\n  X = $(MINUTE)\nelif true\n  X = 0\nendif\n"},

	// --- ClassAd expressions inside $INT/$REAL/$STRING/$EVAL, which the Go side
	// evaluates with github.com/PelicanPlatform/classad (parity as of v0.31.4) ---
	{input: "I = $INT(0//)\n"},                                      // '//' starts a comment -> 0
	{input: "I = $INT(!-00)\n"},                                     // -00 is a negative real under old semantics -> 1
	{input: "R = $REAL(10000000000000000000%1)\n"},                  // out-of-range integer literal becomes 0
	{input: "I = $INT(\"\x7f\xb4\" > \"\x7f\x84\")\n"},              // strings compare as bytes -> 1
	{input: "I = $INT(0;)\n"},                                       // a trailing ';' is not one expression -> ""
	{input: "Z = $EVAL(.0)\nR = $EVAL(1.5)\nL = $EVAL({1, 1+1})\n"}, // ClassAdUnParser forms: 0.0, 1.500000000000000E+00, { 1,1 + 1 }

	// A leading dot is a root-scope reference, not decoration: it survives the
	// round trip and resolves against the outermost ad (classad v0.33.3).
	{input: "L = $EVAL({1, 1+ .A0})\n"},
}

// divergence runs both engines on the same preluded source and returns a
// non-empty description if they disagree (in parse acceptance or expanded
// table), or "" if they agree. skip is non-empty when the input cannot be
// compared:
//   - it holds a NUL byte, which the oracle's C-string interface cannot carry;
//   - the Go engine found a construct on which HTCondor's own code has no
//     defined result: an expansion that never terminates (a reference cycle;
//     HTCondor loops forever or overflows its stack), or one where HTCondor
//     reads out of bounds or crashes (config.ErrHTCondorUndefined). The Go
//     engine runs first to find these, so the oracle never sees them;
//   - a C++ exception escaped.
func divergence(input string) divergenceResult {
	if strings.IndexByte(input, 0) >= 0 {
		return divergenceResult{skip: "NUL byte (the oracle takes a C string)"}
	}
	full := Prelude(input)
	goRes := GoParseExpand(full)
	if goRes.Uncomparable != "" {
		return divergenceResult{skip: goRes.Uncomparable}
	}
	cppRes := oracle.ParseExpand(full)
	if cppRes.Panic {
		return divergenceResult{skip: "C++ oracle exception"}
	}

	if goRes.Parsed != cppRes.Parsed {
		return divergenceResult{desc: fmt.Sprintf("parse-acceptance: go.parsed=%v cpp.parsed=%v", goRes.Parsed, cppRes.Parsed)}
	}
	if !goRes.Parsed {
		return divergenceResult{} // both rejected — agree
	}
	res := divergenceResult{
		goTable:  StripRefEnv(Canon(goRes.Table)),
		cppTable: StripRefEnv(Canon(cppRes.Table)),
	}
	if res.goTable != res.cppTable {
		res.desc = "expanded-table:\n--- go ---\n" + res.goTable + "--- cpp ---\n" + res.cppTable +
			"--- first diff ---\n" + firstDiff(res.goTable, res.cppTable)
	}
	return res
}

// divergenceResult is one comparison: desc is non-empty when the two sides
// disagree, skip when the input could not be compared at all, and the two
// tables are the canonical output each side produced (empty when neither ran,
// which is why a class matcher never sees a skipped or parse-acceptance case
// as a pair of differing tables).
type divergenceResult struct {
	desc     string
	skip     string
	goTable  string
	cppTable string
}

func firstDiff(a, b string) string {
	al := strings.Split(a, "\n")
	bl := strings.Split(b, "\n")
	for i := 0; i < len(al) || i < len(bl); i++ {
		var av, bv string
		if i < len(al) {
			av = al[i]
		}
		if i < len(bl) {
			bv = bl[i]
		}
		if av != bv {
			return fmt.Sprintf("go : %q\ncpp: %q\n", av, bv)
		}
	}
	return "(length mismatch)\n"
}

func indent(s string) string {
	return "  | " + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n  | ")
}

// TestConfigSeeds checks each seed against its expectation: parity seeds must
// agree; known-divergence seeds must still diverge (a flip means Go changed —
// investigate and re-file).
func TestConfigSeeds(t *testing.T) {
	requireOracle(t)
	for i, sc := range seeds {
		sc := sc
		t.Run(fmt.Sprintf("seed%02d", i), func(t *testing.T) {
			res := divergence(sc.input)
			if res.skip != "" {
				t.Errorf("seed is not comparable (%s):\n%s", res.skip, indent(sc.input))
			}
			switch {
			case sc.reason == "" && res.desc != "":
				t.Errorf("unexpected divergence on:\n%s\n%s", indent(sc.input), res.desc)
			case sc.reason != "" && res.desc == "":
				t.Errorf("known divergence now AGREES — promote to parity and remove reason:\n%s\nwas: %s",
					indent(sc.input), sc.reason)
			case sc.reason != "" && res.desc != "":
				t.Logf("known divergence (expected): %s\ninput:\n%s", sc.reason, indent(sc.input))
			}
		})
	}
}

// knownDivergentInputs lets the fuzz target skip the exact seeds we already
// know diverge without paying for the comparison. A mutation of one of them
// still runs, and is then weighed against the recorded classes by recognize:
// a known divergence with no class is reported again, because it is one we
// still mean to fix.
var knownDivergentInputs = func() map[string]bool {
	m := make(map[string]bool)
	for _, sc := range seeds {
		if sc.reason != "" {
			m[sc.input] = true
		}
	}
	return m
}()

// FuzzConfigParseExpand is the coverage-guided differential target. Run with:
//
//	source hack/config-fuzz-env.sh
//	go test -tags libcondor_utils -run x -fuzz FuzzConfigParseExpand ./fuzz/config/
func FuzzConfigParseExpand(f *testing.F) {
	requireOracle(f)
	for _, sc := range seeds {
		f.Add(sc.input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 8192 || knownDivergentInputs[input] {
			t.Skip()
		}
		res := divergence(input)
		if res.skip != "" || res.desc == "" {
			return
		}
		if c := recognize(res); c != nil {
			// Already recorded, reached from another input. Reporting it
			// would fail the nightly every night on a divergence nobody
			// intends to fix, and bury the run's real findings.
			t.Skipf("known divergence class: %s", c.name)
		}
		t.Errorf("Go vs HTCondor config divergence:\ninput:\n%s\n%s", indent(input), res.desc)
	})
}

// TestDivergenceClassesMatchTheirSeeds runs each classed seed and checks that
// its own class recognizes the divergence it produces. Without this a matcher
// could drift until it matches nothing, and the fuzzer would go back to
// reporting the family every night with nobody noticing why.
func TestDivergenceClassesMatchTheirSeeds(t *testing.T) {
	requireOracle(t)
	for _, sc := range seeds {
		if sc.class == nil {
			continue
		}
		t.Run(sc.class.name, func(t *testing.T) {
			res := divergence(sc.input)
			if res.skip != "" || res.desc == "" {
				t.Fatalf("seed no longer diverges, so its class cannot be checked:\n%s", indent(sc.input))
			}
			if recognize(res) != sc.class {
				t.Errorf("%q does not recognize its own seed:\n%s\n%s",
					sc.class.name, indent(sc.input), res.desc)
			}
		})
	}
}

// TestDivergenceClassesRejectOtherShapes is the other half: a class that
// matched too much would silently swallow real findings, and a fuzz run that
// reports nothing looks exactly like a clean one. Each pair below is a
// divergence that must still be reported.
func TestDivergenceClassesRejectOtherShapes(t *testing.T) {
	cases := []struct {
		name     string
		goTable  string
		cppTable string
	}{
		{"agreement is not a divergence", "A\x1f{ 0.B }\n", "A\x1f{ 0.B }\n"},
		{"neither side ran", "", ""},
		{"a different value", "A\x1f1\n", "A\x1f2\n"},
		{"a different selector", "A\x1f{ 0 .B }\n", "A\x1f{ 0 .C }\n"},
		{"the space is ours to drop, not theirs", "A\x1f{ 0.B }\n", "A\x1f{ 0 .B }\n"},
		{"a space somewhere else entirely", "A\x1f0.5\n", "A\x1f 0.5\n"},
		{"one attribute of two still differs", "A\x1f{ 0 .B }\nC\x1f1\n", "A\x1f{ 0.B }\nC\x1f2\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := divergenceResult{goTable: tc.goTable, cppTable: tc.cppTable}
			if c := recognize(res); c != nil {
				t.Errorf("recognized as %q, so this divergence would never be reported", c.name)
			}
		})
	}
}

// TestStripSpaceBeforeDot pins the rewrite selectorSpacing is built on.
func TestStripSpaceBeforeDot(t *testing.T) {
	cases := map[string]string{
		"{ 0 .B }":   "{ 0.B }",
		"{ 0   .B }": "{ 0.B }",
		"{ 0\t.B }":  "{ 0.B }",
		"{ 0.B }":    "{ 0.B }",
		"1.5":        "1.5",
		" .A0":       ".A0",
		"a . b":      "a. b",
		"no dots":    "no dots",
		"":           "",
	}
	for in, want := range cases {
		if got := stripSpaceBeforeDot(in); got != want {
			t.Errorf("stripSpaceBeforeDot(%q) = %q, want %q", in, got, want)
		}
	}
}
