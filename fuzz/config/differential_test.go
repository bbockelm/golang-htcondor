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

	// --- intentional Go extensions (will always diverge; NOT bugs) ---
	{input: "DN = $DIRNAME(/a/b/c)\n",
		reason: "INTENTIONAL: Go adds $DIRNAME (-> /a/b/); HTCondor has no $DIRNAME (uses $Fp). Kept as an extension."},
	{input: "BN = $BASENAME(/a/b/c)\n",
		reason: "INTENTIONAL: Go adds $BASENAME (-> c); HTCondor has no $BASENAME (uses $Fn). Kept as an extension."},
	{input: "NAME = MINUTE\nVAL = $($(NAME))\n",
		reason: "INTENTIONAL: nested $($(NAME)) — Go re-expands the inner macro's result (-> 60); HTCondor is single-pass and leaves $(MINUTE). Kept as an extension."},

	// --- known divergences still to resolve (findings) ---
	{input: "FOO = 1\nfoo = 2\nUSE = $(Foo)\n",
		reason: "'use' keyword: HTCondor's file reader takes 'use' as the metaknob keyword only before ':', so 'USE = $(Foo)' is an ordinary assignment (USE=2); Go's lexer always takes it as the keyword and runs a role directive (sets ROLE='= 2')."},
	{input: "I = $INT(0x10)\n",
		reason: "$INT: HTCondor evaluates the arg as a ClassAd expression ($INT(0x10)->0) and EXCEPTs (aborts) on non-integers like 5x3; Go leaves it literal. Not worth replicating the abort."},
	{input: "foo bar = baz\n",
		reason: "extra words before the operator: HTCondor's file reader ignores words between the name and '='/':' ('foo bar = baz' sets foo=baz; '0 0=' sets 0=''); Go rejects the line."},
	{input: "0 = 1\n",
		reason: "digit-leading name: HTCondor accepts any run of identifier characters as a name ('0 = 1' sets 0=1); Go's lexer requires a letter or '_' first and rejects the line."},
	{input: "E = $ENV(CFG_FUZZ_UNSET_VAR:dflt)\n",
		reason: "$ENV default: HTCondor's $ENV(NAME:default) yields default when NAME is unset; Go looks up the literal 'NAME:default' and yields empty."},
	{input: "T = v ",
		reason: "last line without a newline: HTCondor's reader keeps its trailing whitespace (T='v '); Go trims it."},
	{input: "B = \xff\n",
		reason: "non-UTF-8 byte: HTCondor stores the byte as is; Go's rune lexer replaces it with U+FFFD."},
	{input: "H@=end\nx\n@end\n",
		reason: "'@=' needs whitespace before it: HTCondor reads the name as 'H@' and rejects it (Illegal Identifier); Go accepts it as a here-doc."},
	{input: "S = $(s)\n",
		reason: "self-reference with no prior value: HTCondor expands $(S) inside S's own definition to the previous value, empty here (S=''); Go leaves '$(s)' unexpanded."},
}

// divergence runs both engines on the same preluded source and returns a
// non-empty description if they disagree (in parse acceptance or expanded
// table), or "" if they agree. skip is non-empty when the input cannot be
// compared: it would make the Go engine touch the host, or a C++ exception
// escaped.
func divergence(input string) (desc, skip string) {
	full := Prelude(input)
	if ReadsHost(full) {
		return "", "include directive (would read a host file or run a command)"
	}
	cppRes := oracle.ParseExpand(full)
	if cppRes.Panic {
		return "", "C++ oracle exception"
	}
	goRes := GoParseExpand(full)

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
