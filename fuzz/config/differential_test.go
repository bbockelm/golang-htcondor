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
type seedCase struct {
	input  string
	reason string
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

	// --- known divergences in the ClassAd library (github.com/PelicanPlatform/classad),
	// which $INT/$REAL/$STRING/$EVAL use to evaluate their argument; condor 25.14.1
	// results checked with condor_config_val ---
	{input: "I = $INT(0//)\n",
		reason: "classad: libclassad's lexer takes // as a comment ($INT(0//) -> 0); the Go parser rejects it (-> \"\")."},
	{input: "I = $INT(!-00)\n",
		reason: "classad: libclassad lexes -00 as a negative real under old semantics (!-00 -> true -> 1); the Go parser rejects 00 (-> \"\")."},
	{input: "R = $REAL(10000000000000000000%1)\n",
		reason: "classad: libclassad turns an out-of-range integer literal into 0 (0%1 -> 0); the Go parser rejects it (-> \"\")."},
	{input: "I = $INT(\"\x7f\xb4\" > \"\x7f\x84\")\n",
		reason: "classad: libclassad compares string bytes (-> 1); the Go library replaces invalid UTF-8 with U+FFFD, so the strings are equal (-> 0)."},
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
func divergence(input string) (desc, skip string) {
	if strings.IndexByte(input, 0) >= 0 {
		return "", "NUL byte (the oracle takes a C string)"
	}
	full := Prelude(input)
	goRes := GoParseExpand(full)
	if goRes.Uncomparable != "" {
		return "", goRes.Uncomparable
	}
	cppRes := oracle.ParseExpand(full)
	if cppRes.Panic {
		return "", "C++ oracle exception"
	}

	if goRes.Parsed != cppRes.Parsed {
		return fmt.Sprintf("parse-acceptance: go.parsed=%v cpp.parsed=%v", goRes.Parsed, cppRes.Parsed), ""
	}
	if !goRes.Parsed {
		return "", "" // both rejected — agree
	}
	g := StripRefEnv(Canon(goRes.Table))
	c := StripRefEnv(Canon(cppRes.Table))
	if g != c {
		return "expanded-table:\n--- go ---\n" + g + "--- cpp ---\n" + c + "--- first diff ---\n" + firstDiff(g, c), ""
	}
	return "", ""
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
			desc, skip := divergence(sc.input)
			if skip != "" {
				t.Errorf("seed is not comparable (%s):\n%s", skip, indent(sc.input))
			}
			switch {
			case sc.reason == "" && desc != "":
				t.Errorf("unexpected divergence on:\n%s\n%s", indent(sc.input), desc)
			case sc.reason != "" && desc == "":
				t.Errorf("known divergence now AGREES — promote to parity and remove reason:\n%s\nwas: %s",
					indent(sc.input), sc.reason)
			case sc.reason != "" && desc != "":
				t.Logf("known divergence (expected): %s\ninput:\n%s", sc.reason, indent(sc.input))
			}
		})
	}
}

// knownDivergentInputs lets the fuzz target skip the exact seeds we already
// know diverge, so it doesn't just rediscover them. (Mutated inputs that hit
// the same class still surface — that is the point.)
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
		desc, skip := divergence(input)
		if skip != "" || desc == "" {
			return
		}
		t.Errorf("Go vs HTCondor config divergence:\ninput:\n%s\n%s", indent(input), desc)
	})
}
