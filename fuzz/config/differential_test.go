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
	// oracle, when set, says which side of one upstream change this case
	// belongs to. A recorded divergence whose requirement the linked oracle
	// does not meet is expected to AGREE instead of being skipped, so both
	// oracles are asserted rather than one going unchecked.
	oracle *oracleReq
}

// divergesHere reports whether this seed is expected to diverge against the
// oracle that is actually linked.
func (sc seedCase) divergesHere() bool { return sc.reason != "" && sc.oracle.met() }

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
	// sides disagreed. A nil match accepts any pair, which is only safe
	// with an input predicate narrow enough to stand on its own.
	match func(goTable, cppTable string) bool
	// input, when set, must also accept the input that produced the
	// divergence. It is for a family defined by what was WRITTEN rather
	// than by how the two tables differ -- an upstream change to the
	// language itself, where the tables can differ in any number of ways
	// but only one kind of source reaches it.
	input func(string) bool
	// oracle, when set, limits the class to oracles on one side of an
	// upstream change, so it cannot excuse a divergence an HTCondor
	// without that change should never produce.
	oracle *oracleReq
}

// accepts reports whether this class accounts for a divergence.
func (c *divergenceClass) accepts(input string, res divergenceResult) bool {
	if !c.oracle.met() {
		return false
	}
	if c.input != nil && !c.input(input) {
		return false
	}
	if c.match != nil && !c.match(res.goTable, res.cppTable) {
		return false
	}
	return c.match != nil || c.input != nil
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
		return goTable != cppTable && cppDropsSpaceBeforeDot(goTable, cppTable)
	},
}

// cppDropsSpaceBeforeDot reports whether the C++ table is the Go table with
// blanks deleted at SOME of the places where Go wrote them before a '.'. Some
// rather than all is the point: a value can carry a dot the unparser never
// touches, as `0=0 .$EVAL({0 .A})` does, where both sides keep the space
// outside the expression and only C++ drops the one inside it.
//
// Nothing else may differ, and the blanks may only go missing on the C++ side,
// so the reverse shape -- C++ keeping a space Go drops -- is a divergence this
// class does not recognize, and is reported.
func cppDropsSpaceBeforeDot(goTable, cppTable string) bool {
	i, j := 0, 0
	for i < len(goTable) && j < len(cppTable) {
		if goTable[i] == cppTable[j] {
			i++
			j++
			continue
		}
		k := i
		for k < len(goTable) && (goTable[k] == ' ' || goTable[k] == '\t') {
			k++
		}
		if k == i || k == len(goTable) || goTable[k] != '.' {
			return false
		}
		i = k
	}
	return i == len(goTable) && j == len(cppTable)
}

// attrNameEscaping is the unparser difference recorded against
// `0=$EVAL({'<0xFA>'})`: C++ renders a quoted attribute name through its
// STRING escaper, so a byte isprint() rejects comes out as \NNN octal
// (and a tab as \t), while Go writes the byte.
//
// C++'s own lexer does not undo it. Lexer::tokenizeStringOrIdentifier copies
// a quoted identifier's bytes verbatim, backslashes and all, so `'\372'`
// reads back as the FOUR characters, not the one byte -- and the two
// different names therefore unparse to the same text. `0=$EVAL({'\372'})`
// written with a literal backslash AGREES with Go, which is that collision
// seen from the other side.
//
// Go's output round-trips and C++'s does not, so this is recorded rather
// than matched, for the same reason as selectorSpacing above.
var attrNameEscaping = divergenceClass{
	name: "C++ octal-escapes a non-printable byte in a quoted attribute name",
	input: func(in string) bool {
		return strings.Contains(in, "'") && hasNonPrintableByte(in)
	},
	match: func(goTable, cppTable string) bool {
		return goTable != cppTable && cppEscapesSomeNonPrintables(goTable, cppTable)
	},
}

// cppEscapesSomeNonPrintables reports whether the C++ table is the Go table
// with SOME of its non-printable bytes replaced by the escape C++ writes for
// them. Some rather than all is the point, exactly as in
// cppDropsSpaceBeforeDot: a byte outside the expression reaches both tables
// untouched, as `0=\xde$EVAL({'\xde'})` does, where only the one inside the
// quoted name is escaped.
//
// Nothing else may differ, and the escapes may only appear on the C++ side.
func cppEscapesSomeNonPrintables(goTable, cppTable string) bool {
	escaped := false
	i, j := 0, 0
	for i < len(goTable) && j < len(cppTable) {
		if goTable[i] == cppTable[j] {
			i++
			j++
			continue
		}
		n := escapeLenFor(goTable[i], cppTable[j:])
		if n == 0 {
			return false
		}
		escaped = true
		i++
		j += n
	}
	return escaped && i == len(goTable) && j == len(cppTable)
}

// escapeLenFor returns the length of the escape C++ writes for b when cpp
// starts with it, and 0 when it does not. The named escapes come from
// ClassAdUnParser::UnparseString; everything else isprint() rejects is three
// octal digits.
func escapeLenFor(b byte, cpp string) int {
	if b >= 0x20 && b <= 0x7e {
		return 0
	}
	if len(cpp) < 2 || cpp[0] != '\\' {
		return 0
	}
	named := map[byte]byte{'\a': 'a', '\b': 'b', '\f': 'f', '\n': 'n', '\r': 'r', '\t': 't', '\v': 'v'}
	if c, ok := named[b]; ok {
		if cpp[1] == c {
			return 2
		}
		return 0
	}
	if len(cpp) < 4 {
		return 0
	}
	want := [3]byte{'0' + (b >> 6), '0' + ((b >> 3) & 7), '0' + (b & 7)}
	if cpp[1] == want[0] && cpp[2] == want[1] && cpp[3] == want[2] {
		return 4
	}
	return 0
}

// hasNonPrintableByte reports whether s holds a byte C's isprint() rejects in
// the C locale, which is the test C++ escapes on.
//
// The bytes the canonical table is BUILT from -- the unit separator between a
// name and its value, and the newline between rows -- are not part of any
// value and are skipped, or every table would answer yes.
func hasNonPrintableByte(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\x1f' || c == '\x1e' || c == '\n' {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return true
		}
	}
	return false
}

// tripleQuote is the language change HTCONDOR-3993 made: three quotes in a
// row now switch classic ClassAd parsing to new-ClassAd quoting rules. An
// HTCondor that knows the marker reads `""""` as a quote opening a new-style
// string; one that does not chokes on it.
//
// It covers BOTH quote characters. The change is one edit to the lexer's
// tokenizeString(delim), which is called with `"` for a string literal and
// with a single quote for a quoted attribute name, so three single quotes
// are a marker as much as `"""` is. Upstream describes the change in terms
// of double-quotes only; the nightly found the single-quote half of it.
//
// The two tables can differ in any number of ways as a result -- a value
// expands or does not, a macro function reads its argument or returns
// nothing -- so this class is defined by what was WRITTEN rather than by how
// the tables differ. That is only safe because the trigger is narrow: three
// consecutive quotes do not appear in config by accident, and the class is
// further limited to oracles that actually carry the change.
//
// Go's classic-ClassAd lexer does not implement the marker. Until it does --
// which is a change in the ClassAd library this parser sits on, and one that
// alters how input that parses today is read -- this records the difference
// rather than hiding it.
var tripleQuote = divergenceClass{
	name:   "C++ reads three quotes as a new-ClassAd quoting marker",
	input:  hasTripleQuote,
	oracle: &oracleReq{ticket: "HTCONDOR-3993", has: true},
}

// hasTripleQuote reports whether s contains three of the SAME quote character
// in a row. Three mixed quotes are not a marker, and must stay reportable.
func hasTripleQuote(s string) bool {
	return strings.Contains(s, `"""`) || strings.Contains(s, "'''")
}

// unaryMinusFold is the unparser difference recorded against
// `0=$EVAL({- 0})`.
//
// C++'s lexer folds a sign into a numeric literal only when the two are
// ADJACENT: `-0` is a negative literal, `- 0` is a unary-minus operator
// applied to 0. Evaluating a list does not evaluate its elements -- the value
// IS the unevaluated ExprList -- so unparsing the result unparses that
// operator, and sink.cpp spells unary minus `" -"`, with a leading space.
// `{- 0}` therefore comes back `{  -0 }`: the sign survives on a zero, and
// there is a second space.
//
// Go folds the sign at unparse time whatever the spacing, so the element is a
// literal: `{ 0 }`, with the integer zero unsigned and no operator spelling to
// print.
//
// Recorded rather than fixed because the folding is wanted. A folded literal
// is a VALUE -- it can be stored, indexed and compared as a number -- where a
// unary-minus node is an expression that has to be evaluated on every read.
// Keeping it is a deliberate choice for the database built on this library,
// and matching C++ here would mean giving that up to reproduce the spelling
// of an operator.
//
// Only unary MINUS on a NUMERIC LITERAL reaches this. `{+ 0}`, `{! 0}` and
// `{~ 1}` agree, because Go folds none of those; `{- a}` agrees, because
// there is no literal to fold onto; `{-0}` agrees, because C++ folds it too.
var unaryMinusFold = divergenceClass{
	name: "Go folds a unary minus onto a numeric literal, C++ keeps the operator",
	match: func(goTable, cppTable string) bool {
		return goTable != cppTable && foldUnaryMinus(cppTable) == goTable
	},
}

// foldUnaryMinus rewrites C++'s rendering of a unary minus on a numeric
// literal into Go's: the leading space of the `" -"` operator goes, and an
// INTEGER -0 becomes 0. A real keeps its sign, because Go keeps it too
// (`{- 0.0}` is `{ -0.0 }` on both sides but for the space).
//
// It rewrites only a space that sits immediately before a '-' that is
// immediately followed by a digit, which is the one shape the operator
// produces. `a - b` has a space after the minus and `a -b` has no digit, so
// neither is touched: a real disagreement about either is still reported.
func foldUnaryMinus(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' || i+2 >= len(s) || s[i+1] != '-' || !isASCIIDigit(s[i+2]) {
			b.WriteByte(s[i])
			continue
		}
		j := i + 2
		for j < len(s) && isASCIIDigit(s[j]) {
			j++
		}
		// A bare -0 is the integer zero, which Go writes unsigned. -0.
		// or -0E is the start of a real, whose sign Go keeps.
		if s[i+2:j] == "0" && (j >= len(s) || (s[j] != '.' && s[j] != 'E' && s[j] != 'e')) {
			b.WriteByte('0')
		} else {
			b.WriteByte('-')
			b.WriteString(s[i+2 : j])
		}
		i = j - 1
	}
	return b.String()
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

// parserDepth is the limit recorded against a very long chain of unary
// operators inside a macro function, e.g. `0=$EVAL(!!!...!!”)`.
//
// C++'s ClassAd parser is recursive descent, so every nested operator is a C
// stack frame, and src/classad/source.cpp caps the nesting at
// MAX_PARSER_DEPTH = 500 to keep deep input from overflowing the stack.
// Past it the parse FAILS, and a macro function whose argument does not parse
// expands to nothing. Go's parser is table-driven (goyacc) with its stack on
// the heap, so it has no such frame to run out of: it parses the chain and
// evaluates it, and `$EVAL` returns the value.
//
// This is recorded rather than implemented because the limit is an artifact
// of how the C++ parser is BUILT, not a rule of the language. The cut-off is
// not even 500 operators -- it is 500 minus whatever the enclosing expression
// already consumed, which for `$EVAL(...)` lands at 401 -- so matching it
// would mean reproducing the shape of C++'s call chain, and would move with
// any refactor of it. A limit on Go's side would be a defensible thing to
// have for its own sake, but it would be a different limit at a different
// place, and it would not make these two agree.
//
// Defined by what was WRITTEN, like tripleQuote: once the depth is exceeded
// the whole argument is gone, so the two tables can differ in any way at all.
// That is safe here because the trigger cannot occur by accident.
var parserDepth = divergenceClass{
	name:  "C++ refuses to parse past its recursive-descent depth limit",
	input: hasDeepOperatorChain,
}

// deepOperatorChain is where hasDeepOperatorChain starts calling a run of
// stacked unary operators deep.
//
// Deliberately well below the 401 that was measured for `$EVAL`, because the
// cut-off depends on how deep the chain already sits when it starts, and a
// chain somewhere more nested reaches the limit sooner. Being low costs
// nothing: a class is only ever consulted about an input that ALREADY
// diverged, so a chain this long that both sides handle is never excused by
// it, and no config file written by a person has a run of 200 operators.
const deepOperatorChain = 200

// hasDeepOperatorChain reports whether s stacks that many unary operators.
// Only the unary operators count: these are the ones that nest without
// anything between them, so a run of them in the source is a run of nested
// expressions, which is not true of any binary operator.
//
// Whitespace between them does not break the run. `! ! !0` is three nested
// expressions exactly as `!!!0` is, and it reaches the same limit in the same
// place -- the fuzzer found the spaced form the same night, and a predicate
// that counted only adjacent characters reported it as something new.
func hasDeepOperatorChain(s string) bool {
	run := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '!', '~', '-', '+':
			run++
			if run >= deepOperatorChain {
				return true
			}
		case ' ', '\t', '\r', '\n':
			// does not nest, does not interrupt
		default:
			run = 0
		}
	}
	return false
}

// recognize returns the recorded class that accounts for this divergence, or
// nil when it is a new one.
func recognize(input string, res divergenceResult) *divergenceClass {
	for _, sc := range seeds {
		if sc.class == nil {
			continue
		}
		if sc.class.accepts(input, res) {
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
	{
		// Found by FuzzConfigParseExpand, after the class above was recorded:
		// the same unparser difference with a second dot in the value that
		// neither side rewrites. Kept as a seed so the class is pinned against
		// the shape where C++ drops one space and keeps another.
		input:  "0=0 .$EVAL({0 .A})",
		reason: "selectorSpacing, reached with a dot outside the expression",
		class:  &selectorSpacing,
	},
	{
		// Found by FuzzConfigParseExpand.
		input: "0=$EVAL({'\xfa'})",
		reason: "a non-printable byte in a quoted attribute name: HTCondor's " +
			"unparser writes text its own parser reads as something else. " +
			"ClassAdUnParser::UnparseAux runs an identifier through the STRING " +
			"escaper with `'` as the delimiter, so a byte isprint() rejects " +
			"comes out as \\NNN octal -- but Lexer::tokenizeStringOrIdentifier " +
			"copies a quoted identifier's bytes verbatim, backslashes and all. " +
			"`'\\372'` therefore reads back as the FOUR characters, not the one " +
			"byte, and the two different names unparse to the same text: the " +
			"literal-backslash spelling of this seed AGREES with Go, which is " +
			"that collision seen from the other side. Go writes the byte, which " +
			"round-trips, so this is recorded rather than matched -- the same " +
			"trade as selectorSpacing above.",
		class: &attrNameEscaping,
	},
	{
		// The same class reached by a control byte rather than a high one:
		// C++ escapes on isprint(), not on the top bit, so a tab in a
		// quoted name comes out as \t.
		input:  "0=$EVAL({'a\tb'})",
		reason: "attrNameEscaping, reached with a control byte",
		class:  &attrNameEscaping,
	},
	{
		// Found by FuzzConfigParseExpand after the class was recorded: the
		// same byte OUTSIDE the expression as well, where neither side
		// escapes it. Kept as a seed so the class is pinned against the
		// shape where C++ escapes one occurrence and leaves another.
		input:  "0=\xde$EVAL({'\xde'})",
		reason: "attrNameEscaping, reached with the same byte outside the expression",
		class:  &attrNameEscaping,
	},

	{
		// Found by FuzzConfigParseExpand, and upstream rather than ours.
		input: `0=$INT("""">"")`,
		reason: "HTCONDOR-3993 made three double-quotes a marker that switches " +
			"classic ClassAd parsing to new-ClassAd quoting. C++ reads the rest " +
			"as a new-style string and $INT gets a value it can parse; Go's " +
			"lexer has no such marker, chokes, and the macro expands to " +
			"nothing. Implementing it means changing how `\"\"\"\"` is read in " +
			"the ClassAd library this parser sits on, which changes input that " +
			"parses today -- so it is recorded here rather than quietly fixed.",
		class:  &tripleQuote,
		oracle: &oracleReq{ticket: "HTCONDOR-3993", has: true},
	},
	{
		// Found by FuzzConfigParseExpand against HTCondor main, and the
		// other half of the same change: the marker is read by the lexer's
		// tokenizeString, which handles both quote characters, so three
		// single quotes open a new-style QUOTED ATTRIBUTE NAME. `$EVAL`
		// then has a name to look up, which is undefined, where Go's lexer
		// chokes and the macro expands to nothing.
		input: `0=$EVAL('''')`,
		reason: "HTCONDOR-3993 reaches single quotes too: three of them switch " +
			"classic ClassAd parsing to new-ClassAd quoting for an attribute " +
			"name, so C++ reads an attribute and evaluates it to UNDEFINED " +
			"while Go reads nothing. Same lexer change as the double-quote " +
			"seed above, same reason for recording it rather than " +
			"implementing it here.",
		class:  &tripleQuote,
		oracle: &oracleReq{ticket: "HTCONDOR-3993", has: true},
	},

	{
		// Found by FuzzConfigParseExpand against HTCondor main, and
		// reproduces against the pinned 25.14 oracle too, so it is ours
		// rather than drift.
		input: "0=$EVAL({- 0})",
		reason: "C++ folds a sign into a numeric literal only when the two are " +
			"ADJACENT, so `- 0` stays a unary-minus OPERATOR applied to 0. " +
			"Evaluating a list does not evaluate its elements, so unparsing " +
			"the result unparses that operator, which sink.cpp spells with a " +
			"leading space: `{  -0 }`, sign intact on a zero. Go folds the " +
			"sign whatever the spacing and writes the literal `{ 0 }`. The " +
			"folding is wanted and is not going to change: a folded literal " +
			"is a value that can be stored, indexed and compared as a number, " +
			"where a unary-minus node is an expression to evaluate on every " +
			"read.",
		class: &unaryMinusFold,
	},
	{
		// Found by FuzzConfigParseExpand. Not drift: it reproduces against
		// the pinned 25.14 oracle too, at the same 401.
		input: "0=$EVAL(" + strings.Repeat("!", 401) + "'')",
		reason: "C++'s ClassAd parser is recursive descent and caps nesting at " +
			"MAX_PARSER_DEPTH = 500 (src/classad/source.cpp) so that deep input " +
			"cannot overflow the C stack. Past the cap the parse fails and $EVAL " +
			"expands to nothing; Go's parser is table-driven with its stack on " +
			"the heap, parses the chain, and evaluates it to UNDEFINED. The cap " +
			"is a property of how that parser is built rather than of the " +
			"language -- the cut-off here is 401 rather than 500 because the " +
			"enclosing $EVAL has already spent the rest -- so it is recorded " +
			"rather than reproduced.",
		class: &parserDepth,
	},

	{
		// The same limit reached with the operators spaced apart, which
		// nests identically. Kept as a seed because the first version of
		// the predicate counted only adjacent characters and missed it.
		input:  "0=$EVAL(" + strings.Repeat(strings.Repeat("!", 120)+" ", 4) + "'')",
		reason: "parserDepth, reached with whitespace between the operators",
		class:  &parserDepth,
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
			case !sc.divergesHere() && res.desc != "":
				if sc.reason != "" {
					t.Errorf("this oracle is on the other side of %s, so the two should AGREE here:\n%s\n%s",
						sc.oracle.ticket, indent(sc.input), res.desc)
					break
				}
				t.Errorf("unexpected divergence on:\n%s\n%s", indent(sc.input), res.desc)
			case sc.divergesHere() && res.desc == "":
				t.Errorf("known divergence now AGREES — promote to parity and remove reason:\n%s\nwas: %s",
					indent(sc.input), sc.reason)
			case sc.divergesHere():
				t.Logf("known divergence (expected): %s\ninput:\n%s", sc.reason, indent(sc.input))
			case sc.reason != "":
				t.Logf("recorded divergence, not applicable to this oracle (%s): %s",
					sc.oracle.ticket, sc.reason)
			}
		})
	}
}

// knownDivergentInputs lets the fuzz target skip the exact seeds we already
// know diverge without paying for the comparison. A mutation of one of them
// still runs, and is then weighed against the recorded classes by recognize:
// a known divergence with no class is reported again, because it is one we
// still mean to fix.
//
// It is built when the fuzz target starts rather than at package init: which
// seeds diverge HERE depends on the probed traits, and those are not settled
// until TestMain has run. Built at init, every oracle-scoped seed reads as
// agreeing and is left out of the set.
func knownDivergentInputs() map[string]bool {
	m := make(map[string]bool)
	for _, sc := range seeds {
		if sc.divergesHere() {
			m[sc.input] = true
		}
	}
	return m
}

// FuzzConfigParseExpand is the coverage-guided differential target. Run with:
//
//	source hack/config-fuzz-env.sh
//	go test -tags libcondor_utils -run x -fuzz FuzzConfigParseExpand ./fuzz/config/
func FuzzConfigParseExpand(f *testing.F) {
	requireOracle(f)
	for _, sc := range seeds {
		f.Add(sc.input)
	}
	known := knownDivergentInputs()
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 8192 || known[input] {
			t.Skip()
		}
		res := divergence(input)
		if res.skip != "" || res.desc == "" {
			return
		}
		if c := recognize(input, res); c != nil {
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
			if !sc.divergesHere() {
				t.Skipf("this oracle is on the other side of %s, so the seed does not diverge here", sc.oracle.ticket)
			}
			res := divergence(sc.input)
			if res.skip != "" || res.desc == "" {
				t.Fatalf("seed no longer diverges, so its class cannot be checked:\n%s", indent(sc.input))
			}
			if recognize(sc.input, res) != sc.class {
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
	// Every class is made live for this test, whichever oracle is linked.
	// A class limited to an upstream change the local oracle does not have
	// would otherwise accept nothing, and each case below would pass
	// without exercising anything -- the quiet way a rejection test stops
	// testing rejection.
	defer withAllTraits()()

	cases := []struct {
		name     string
		input    string
		goTable  string
		cppTable string
	}{
		{"agreement is not a divergence", "A=1", "A\x1f{ 0.B }\n", "A\x1f{ 0.B }\n"},
		{"neither side ran", "A=1", "", ""},
		{"a different value", "A=1", "A\x1f1\n", "A\x1f2\n"},
		{"a different selector", "A=1", "A\x1f{ 0 .B }\n", "A\x1f{ 0 .C }\n"},
		{"the space is ours to drop, not theirs", "A=1", "A\x1f{ 0.B }\n", "A\x1f{ 0 .B }\n"},
		{"a space somewhere else entirely", "A=1", "A\x1f0.5\n", "A\x1f 0.5\n"},
		{"one attribute of two still differs", "A=1", "A\x1f{ 0 .B }\nC\x1f1\n", "A\x1f{ 0.B }\nC\x1f2\n"},
		// Two quotes are not three: the input predicate of the
		// triple-quote class must not reach an ordinary quoted value.
		{"a plain quoted string", `A="x"`, "A\x1f\n", "A\x1fx\n"},
		{"an empty string pair", `A=""`, "A\x1f\n", "A\x1fy\n"},
		// The same, for the single-quote half of the marker.
		{"a quoted attribute name", `A=$EVAL('b')`, "A\x1f\n", "A\x1fx\n"},
		{"an empty quoted name", `A=$EVAL('')`, "A\x1f\n", "A\x1fy\n"},
		// Three quotes, but not three of the SAME quote: not a marker.
		{"mixed quotes", "A=\"'\"'", "A\x1f\n", "A\x1fy\n"},
		// A few stacked operators are ordinary; only a run long enough to
		// reach C++'s parser depth limit is the recorded family.
		{"a short operator chain", "A=$EVAL(!!!!0)", "A\x1f0\n", "A\x1f1\n"},
		// Long, but not a CHAIN: the operators are separated, so nothing
		// nests and no parser runs out of depth.
		{"many operators, not stacked", "A=$EVAL(" + strings.Repeat("0-", 300) + "0)", "A\x1f0\n", "A\x1f1\n"},
		// The unary-minus fold rewrites the C++ side only, and only a space
		// before a '-' that a digit follows. None of these is that shape.
		{"a different number entirely", "A=1", "A\x1f{ 0 }\n", "A\x1f{  -1 }\n"},
		{"the fold is ours, not theirs", "A=1", "A\x1f{  -0 }\n", "A\x1f{ 0 }\n"},
		{"a binary minus, spaced", "A=1", "A\x1f{ a -b }\n", "A\x1f{ a - b }\n"},
		{"a minus before a name, not a digit", "A=1", "A\x1f{ -a }\n", "A\x1f{  -a }\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := divergenceResult{goTable: tc.goTable, cppTable: tc.cppTable}
			if c := recognize(tc.input, res); c != nil {
				t.Errorf("recognized as %q, so this divergence would never be reported", c.name)
			}
		})
	}
}

// TestTripleQuoteClassIsLiveOnlyForOraclesThatHaveIt pins both halves of an
// oracle-scoped class: it accounts for the family against an HTCondor that
// carries the change, and accounts for nothing at all against one that does
// not -- where such a divergence would be a real finding about this parser
// rather than a difference between two HTCondors.
func TestTripleQuoteClassIsLiveOnlyForOraclesThatHaveIt(t *testing.T) {
	// Any table difference; the class is defined by the input.
	res := divergenceResult{goTable: "0\x1f\n", cppTable: "0\x1f0\n"}
	const input = `0=$INT("""">"")`

	t.Run("an oracle that has it", func(t *testing.T) {
		defer withAllTraits()()
		if got := recognize(input, res); got != &tripleQuote {
			t.Errorf("against an oracle that has HTCONDOR-3993 this is the recorded family, got %v", got)
		}
		// Two quotes are not three: an ordinary quoted value is not this
		// family however the tables differ.
		if got := recognize(`0=$INT("a">"b")`, res); got == &tripleQuote {
			t.Error("an input without three consecutive quotes is not this family")
		}
		// The same lexer change, reached through the other quote character:
		// a quoted attribute name rather than a string literal.
		if got := recognize(`0=$EVAL('''')`, res); got != &tripleQuote {
			t.Errorf("three single quotes are the same family, got %v", got)
		}
		if got := recognize(`0=$EVAL('a')`, res); got == &tripleQuote {
			t.Error("one single-quoted attribute name is not this family")
		}
	})

	t.Run("an oracle that does not", func(t *testing.T) {
		defer withTraits(nil)()
		if got := recognize(input, res); got != nil {
			t.Errorf("against an oracle without the change this must be reported, not excused as %q", got.name)
		}
	})
}

// TestKnownDivergentInputsFollowTheProbe pins the set the fuzz target skips
// to the traits, in both directions. An oracle-scoped seed belongs in it only
// against the oracle it was recorded against; against the other one the two
// sides agree, the comparison is worth paying for, and a divergence there is
// a finding.
func TestKnownDivergentInputsFollowTheProbe(t *testing.T) {
	const scoped = `0=$INT("""">"")`

	func() {
		defer withAllTraits()()
		if !knownDivergentInputs()[scoped] {
			t.Error("an oracle that has the change diverges on this seed, so the fuzz target should skip it")
		}
	}()

	func() {
		defer withTraits(nil)()
		if knownDivergentInputs()[scoped] {
			t.Error("an oracle without the change agrees here, so this seed must still be compared")
		}
	}()
}

// withAllTraits makes every recorded trait read as present, and returns a
// function that puts back what was probed.
func withAllTraits() func() {
	all := map[string]bool{}
	for _, tr := range oracleTraits {
		all[tr.ticket] = true
	}
	return withTraits(all)
}

// withTraits swaps in a trait set for the duration of one test and returns
// the function that puts back what was probed. Every override goes through
// here, and the returned function is deferred: a test that leaves the traits
// swapped changes which oracle EVERY later test and the fuzz seed corpus
// believe they are facing, which TestMain checks for at the end of the run.
func withTraits(have map[string]bool) func() {
	saved := oracleHas
	oracleHas = have
	return func() { oracleHas = saved }
}

// TestCppDropsSpaceBeforeDot pins the walk selectorSpacing is built on.
func TestCppDropsSpaceBeforeDot(t *testing.T) {
	cases := []struct {
		goTable  string
		cppTable string
		want     bool
	}{
		{"{ 0 .B }", "{ 0.B }", true},
		{"{ 0   .B }", "{ 0.B }", true},
		{"{ 0   .B }", "{ 0 .B }", true}, // part of the run, not all of it
		{"{ 0\t.B }", "{ 0.B }", true},
		{"0 .{ 0 .A }", "0 .{ 0.A }", true}, // only the dot inside the expression
		{"{ 0 .B }{ 0 .C }", "{ 0.B }{ 0.C }", true},
		{"{ 0.B }", "{ 0 .B }", false}, // the space is ours to drop, not theirs
		{"a b", "ab", false},           // a blank not before a dot
		{"a .b", "a .c", false},        // a real difference alongside
		{"a .b", "a .b", true},         // identical: the caller rules this out
		{"", "", true},
		{"a .b", "", false},
	}
	for _, tc := range cases {
		if got := cppDropsSpaceBeforeDot(tc.goTable, tc.cppTable); got != tc.want {
			t.Errorf("cppDropsSpaceBeforeDot(%q, %q) = %v, want %v",
				tc.goTable, tc.cppTable, got, tc.want)
		}
	}
}
