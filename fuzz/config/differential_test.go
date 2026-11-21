package fuzzconfig

import (
	"fmt"
	"strings"
	"testing"

	"github.com/htcondor/golang-htcondor/fuzz/config/oracle"
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
// It is asked only about the INPUT. Asking it about a table would need the
// bytes the table is BUILT from excluded -- the unit separator between a name
// and its value, and the newline between rows -- and that exclusion is wrong
// for a value that holds one of those bytes itself, which
// `0=$EVAL({'<0x1f>'})` does. The tables are compared byte by byte instead,
// by cppEscapesSomeNonPrintables.
func hasNonPrintableByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c > 0x7e {
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
		return goTable != cppTable && cppKeepsSomeUnaryMinus(goTable, cppTable)
	},
}

// cppKeepsSomeUnaryMinus reports whether the C++ table is the Go table with
// SOME of its numeric literals written as C++ writes the unary-minus
// operator instead: an EXTRA space, then the sign, then the digits -- and an
// integer zero that Go writes unsigned where C++ keeps the sign.
//
// Some rather than all is the point, as it is in cppDropsSpaceBeforeDot.
// A NEGATIVE LITERAL is spelled `-10` by both sides, and inside a list it
// sits after the `{ ` that both sides write, so `{ -10 }` is identical on
// both. Rewriting every space-before-a-signed-number -- which is what the
// first form of this class did -- deleted that structural space too and the
// class stopped recognizing its own family as soon as a list held both, as
// `0=$EVAL({-10%- 0})` does.
//
// A real disagreement is still reported: `a - b` has a space after the minus
// and `a -b` has no digit after it, so neither is a shape this accepts.
func cppKeepsSomeUnaryMinus(goTable, cppTable string) bool {
	folded := false
	i, j := 0, 0
	for i < len(goTable) && j < len(cppTable) {
		if goTable[i] == cppTable[j] {
			i++
			j++
			continue
		}
		// C++ must have the operator here: a space, the sign, a digit.
		if j+2 >= len(cppTable) || cppTable[j] != ' ' || cppTable[j+1] != '-' || !isASCIIDigit(cppTable[j+2]) {
			return false
		}
		end := j + 2
		for end < len(cppTable) && isASCIIDigit(cppTable[end]) {
			end++
		}
		want := "-" + cppTable[j+2:end]
		// A bare -0 is the integer zero, which Go writes unsigned. -0.
		// or -0E is the start of a real, whose sign Go keeps.
		if cppTable[j+2:end] == "0" && (end >= len(cppTable) || (cppTable[end] != '.' && cppTable[end] != 'E' && cppTable[end] != 'e')) {
			want = "0"
		}
		if !strings.HasPrefix(goTable[i:], want) {
			return false
		}
		folded = true
		i += len(want)
		j = end
	}
	return folded && i == len(goTable) && j == len(cppTable)
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

// nestingDepth is the limit recorded against an expression nested deeper
// than C++ will go, e.g. `0=$EVAL(!!!...!!”)` or `0=$EVAL(1+1+1+...+1)`.
//
// C++ gives up on deep expressions twice over, and both caps are reached
// through `$EVAL`:
//
//   - The EVALUATOR stops at EvalState::MAX_CLASSAD_RECURSION = 400
//     (src/classad/classad/exprTree.h), charged one level per Operation node
//     by the RecursionGuard in operators.cpp. Past it Operation::_Evaluate
//     returns false.
//   - The PARSER stops at MAX_PARSER_DEPTH = 500 (src/classad/source.cpp),
//     charged per recursive-descent frame, so the parse fails.
//
// Either way `$EVAL` has no value to use, and config.cpp falls back to the
// macro-expanded body -- which for a body with no `$` in it is the empty
// string. Go's parser is table-driven with its stack on the heap and its
// evaluator stops at maxEvalDepth = 2000, so it parses the expression,
// evaluates it, and `$EVAL` returns the value.
//
// Which cap bites depends on the shape, and the two are far enough apart to
// tell apart by measurement:
//
//	!!!...true          evaluates at 400, fails at 401   (evaluator)
//	1+1+1+...+1         evaluates at 400, fails at 401   (evaluator)
//	true?true?...:2:2   evaluates at 400, fails at 401   (evaluator)
//	((((...1...))))     evaluates at 165, fails at 166   (parser)
//
// The binary chain settles it. parseAdditiveExpression builds a left-
// associative chain in a WHILE LOOP, so the parser never goes deep -- yet
// the cut-off is the same 401 as the unary chain, which is the evaluator's
// 400 and not, as this class first recorded, the parser's 500 minus what the
// enclosing $EVAL had already spent. Parens do recurse in the parser, about
// three frames each, and show the 500 cap on its own at 166.
//
// Recorded rather than reproduced. Matching would mean lowering the Go
// evaluator's limit to 400 AND giving it a way to report that evaluation
// FAILED rather than produced ERROR, since C++ renders a genuine error value
// as `error` and renders this as nothing -- a change in the ClassAd library
// this parser sits on, which would make it refuse expressions it handles
// today for the sake of input no config file contains.
//
// Defined by what was WRITTEN, like tripleQuote: once C++ gives up the whole
// argument is gone, so the two tables can differ in any way at all.
var nestingDepth = divergenceClass{
	name:  "C++ gives up on an expression nested deeper than it will go",
	input: hasDeepNesting,
	match: cppDroppedTheMacroResult,
}

// cppDroppedTheMacroResult reports whether every row the two tables disagree
// about is the Go row with ONE run of characters cut out of it -- the shape
// of a macro function that produced nothing where Go produced a value.
//
// This is the half that does not depend on spotting the nesting in the text,
// and it is here because the input predicate has now been too narrow four
// times: spaces between the operators, vertical tabs between them, a quote
// in front that never closed, and a quote in front that closed at the far
// end. Each time a recorded divergence was reported as a new finding, and
// the last two were the same hole a night apart -- a quote read as a string
// literal when C++ never read it as one at all. With both halves required,
// the text
// predicate can be generous without the class excusing anything else, because
// a real disagreement about a VALUE does not have this shape: `0` against `1`
// is not `0` with a run deleted.
//
// A deletion rather than an empty value, because the macro function need not
// be the whole line. `0=A"$EVAL(...)` leaves C++ with `A"` and Go with
// `A"undefined`, and the rows still differ by exactly the result.
func cppDroppedTheMacroResult(goTable, cppTable string) bool {
	goRows, cppRows := tableRows(goTable), tableRows(cppTable)
	dropped := false
	for name, goVal := range goRows {
		cppVal, ok := cppRows[name]
		if !ok {
			return false
		}
		if goVal == cppVal {
			continue
		}
		if !isOneRunDeleted(goVal, cppVal) {
			return false
		}
		dropped = true
	}
	// An attribute only C++ produced leaves every Go row matching, so
	// dropped stays false and the difference is reported. That is also
	// what happens when the rows read identically although the tables did
	// not: nothing was examined, so nothing is excused.
	return dropped
}

// tableRows splits a canonical table into name -> value.
func tableRows(table string) map[string]string {
	rows := make(map[string]string)
	for _, line := range strings.Split(table, "\n") {
		if line == "" {
			continue
		}
		name, value, found := strings.Cut(line, "\x1f")
		if !found {
			continue
		}
		rows[name] = value
	}
	return rows
}

// isOneRunDeleted reports whether cpp is go with one contiguous run removed.
func isOneRunDeleted(goVal, cppVal string) bool {
	if len(cppVal) >= len(goVal) {
		return false
	}
	pre := 0
	for pre < len(cppVal) && goVal[pre] == cppVal[pre] {
		pre++
	}
	suf := 0
	for suf < len(cppVal)-pre && goVal[len(goVal)-1-suf] == cppVal[len(cppVal)-1-suf] {
		suf++
	}
	return pre+suf == len(cppVal)
}

// The two counts hasDeepNesting compares against, both well below the
// cut-offs measured for the caps they stand for: 166 openers for the parser,
// 401 operators for the evaluator.
//
// Low on purpose. The cut-off depends on how deep the expression already sits
// when the chain starts, so a chain somewhere more nested reaches either cap
// sooner than a bare one does, and a threshold set just under the measured
// number misses exactly those. Being low is safe here only because the class
// also requires cppDroppedTheMacroResult: a 300-operator chain that C++
// evaluates correctly scores far above these numbers and is still reported,
// because its two tables differ about a VALUE rather than by a deletion.
// TestDivergenceClassesRejectOtherShapes holds that case.
//
// Without that second half the threshold had to sit just under the cut-off,
// and a chain that started deep was reported as a new finding every time.
const (
	deepBrackets = 120
	deepChain    = 120
)

// hasDeepNesting reports whether any line of s is nested deeply enough to
// reach one of C++'s two caps.
//
// Two counts, because the caps are charged against different things. Nested
// brackets are counted by how many are open at once, which is what the
// recursive-descent parser spends frames on. Operators are counted by chain
// length: a run of them with at most one operand between consecutive ones,
// which is what nests into the Operation tree the evaluator walks. `!!!!`
// nests with nothing between the operators; `1+1+1` and `true?true?` nest
// with one operand between each pair, and are the shapes that reach the
// evaluator cap while the parser stays shallow -- parseAdditiveExpression
// builds a left-associative chain in a loop.
//
// Anything else ends a chain: a closing bracket, a comma, a second operand
// in a row, a `$`, punctuation. That is what keeps the count from standing
// for scattered operator characters -- an ordinary `START = (A > 1) && (B <
// 2) && ...` scores 2, because each `)` ends the chain it is in -- and it is
// why both counts are per line, since config is line-oriented and an
// expression lives on one.
//
// Whitespace between operators does not break a chain: `! ! !0` is three
// nested expressions exactly as `!!!0` is. All six bytes C calls space
// count, the vertical tab among them. The fuzzer reached this class the
// first time with spaces, which an earlier predicate counting only adjacent
// characters missed, and reached it again with vertical tabs breaking the
// run into pieces of 152, 183 and 66 -- a 401-deep chain that scored 183.
func hasDeepNesting(s string) bool {
	for len(s) > 0 {
		line := s
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			line, s = s[:i], s[i+1:]
		} else {
			s = ""
		}
		brackets, chain := nestingCounts(line)
		if brackets >= deepBrackets || chain >= deepChain {
			return true
		}
	}
	return false
}

// nestingCounts returns the most brackets open at once on one line and the
// longest operator chain on it. See hasDeepNesting for what each counts.
func nestingCounts(line string) (brackets, chain int) {
	open, run := 0, 0
	operand := false
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case isClassAdSpace(c):
			// does not nest, does not interrupt
		case c == '(' || c == '{' || c == '[':
			open++
			if open > brackets {
				brackets = open
			}
			run, operand = 0, false
		case c == ')' || c == '}' || c == ']':
			if open > 0 {
				open--
			}
			run, operand = 0, false
		case isChainOperator(c):
			run++
			operand = false
			if run > chain {
				chain = run
			}
		case c == '"' || c == '\'':
			// A CLOSED string literal with no macro function inside it is
			// one operand, however many operator characters are written in
			// it. Skipping it is what keeps a line of quoted text from
			// reading as a deep expression.
			//
			// Nothing else may be skipped. What gets skipped leaves both
			// counts -- the whole rest of the line, when the quote never
			// closes -- so a quote mistaken for a literal hides everything
			// written after it. Two kinds are not literals, and the
			// nightly reported each as a new finding on a night of its own:
			//
			//   - A quote that never closes. `0=A"$EVAL(!!!...)` scored
			//     zero, its 401-operator chain inside a string with no end.
			//   - A quote that closes past a macro function.
			//     `0=a'00$EVAL(!!!...'')` and `0='$EVAL(!!!...'')` each
			//     scored one, the chain hidden between two quotes that
			//     look balanced.
			//
			// One test covers both, because the text between the quotes
			// decides it rather than the quotes do. `$EVAL(...)` is
			// expanded wherever it is written, quotes and all, so no
			// literal holds one: the ClassAd text is the ARGUMENT, and the
			// quotes around it are macro characters C++ never reads as
			// quotes. A quote with no end spans the rest of the line, so
			// it fails the same test as soon as a `$` follows it -- and
			// when none does, the `$EVAL` is in front of the quote, which
			// puts the quote inside the argument, where C++'s parse fails
			// on the unterminated literal long before any cap and Go's
			// fails with it. Measured: no divergence to recognize.
			end := endOfLiteral(line, i)
			if strings.IndexByte(line[i:end], '$') >= 0 {
				run, operand = 0, false
				continue
			}
			i, operand = end, true
		case isOperandByte(c):
			// one operand between two operators keeps the chain; a
			// second one in a row is two expressions side by side.
			if operand {
				run, operand = 0, false
				continue
			}
			for i+1 < len(line) && isOperandByte(line[i+1]) {
				i++
			}
			operand = true
		default:
			run, operand = 0, false
		}
	}
	return brackets, chain
}

// isClassAdSpace reports whether b is one of the six bytes C's isspace()
// accepts in the C locale, which is what the ClassAd lexer skips.
func isClassAdSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\v' || b == '\f' || b == '\r'
}

// isChainOperator reports whether b begins an expression that holds another.
// Brackets are counted separately, against the parser's cap.
func isChainOperator(b byte) bool {
	return strings.IndexByte("!~+-*/%<>=&|^?:", b) >= 0
}

// isOperandByte reports whether b can appear in a bare operand -- an
// identifier or a number. A quoted string is handled separately, by
// endOfLiteral.
func isOperandByte(b byte) bool {
	return b == '_' || b == '.' || isASCIIDigit(b) ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// endOfLiteral returns the index of the quote closing the literal that opens
// at i, or i itself when the quote never closes -- an empty span, which is
// no literal and swallows nothing. A backslash escapes the next byte, as it
// does in the ClassAd lexer.
func endOfLiteral(line string, i int) int {
	q := line[i]
	for j := i + 1; j < len(line); j++ {
		switch line[j] {
		case '\\':
			j++
		case q:
			return j
		}
	}
	return i
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
		// Found by FuzzConfigParseExpand: the byte is the canonical table's
		// own unit separator, which an earlier form of this class excluded
		// from its input test and so did not recognize.
		input:  "0=$EVAL({'\x1f'})",
		reason: "attrNameEscaping, reached with the table's own separator byte",
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
		// Found by FuzzConfigParseExpand after the class was recorded: a
		// negative LITERAL beside the operator, which both sides spell the
		// same way. Kept as a seed so the class is pinned against the shape
		// where only one of the two signs is C++'s operator.
		input:  "0=$EVAL({-10%- 0})",
		reason: "unaryMinusFold, reached beside a negative literal",
		class:  &unaryMinusFold,
	},
	{
		// Found by FuzzConfigParseExpand. Not drift: it reproduces against
		// the pinned 25.14 oracle too, at the same 401.
		input: "0=$EVAL(" + strings.Repeat("!", 401) + "'')",
		reason: "libclassad stops evaluating at MAX_CLASSAD_RECURSION = 400 " +
			"(src/classad/classad/exprTree.h), charged one level per Operation " +
			"node, so at 401 Operation::_Evaluate returns false, $EVAL has no " +
			"value to use and expands to nothing. Go's evaluator stops at 2000, " +
			"so it evaluates the chain to UNDEFINED. Recorded rather than " +
			"reproduced: see nestingDepth.",
		class: &nestingDepth,
	},

	{
		// The same limit reached with the operators spaced apart, which
		// nests identically. Kept as a seed because the first version of
		// the predicate counted only adjacent characters and missed it.
		input:  "0=$EVAL(" + strings.Repeat(strings.Repeat("!", 120)+" ", 4) + "'')",
		reason: "nestingDepth, reached with whitespace between the operators",
		class:  &nestingDepth,
	},

	{
		// Found by FuzzConfigParseExpand, and the reason this class was
		// generalized: 401 operators again, but broken into runs of 152,
		// 183 and 66 by vertical tabs. The lexer skips a vertical tab like
		// any other space, so the chain nests all 401 deep, while a
		// predicate that treated it as a break scored the input 183 and
		// reported a recorded divergence as a new one.
		input: "0=$EVAL(" + strings.Repeat("!", 152) + "\v" +
			strings.Repeat("!", 183) + "\v" + strings.Repeat("!", 66) + "'')",
		reason: "nestingDepth, reached with vertical tabs between the operators",
		class:  &nestingDepth,
	},

	{
		// Found by FuzzConfigParseExpand on the re-run after the class was
		// generalized, and the reason it now has a match half as well. The
		// chain is the same 401; what hid it is the unterminated quote in
		// front, which the predicate read as a string literal running to
		// the end of the line and so counted nothing at all.
		input:  "0=A\"$EVAL(" + strings.Repeat("!", 401) + "'')",
		reason: "nestingDepth, behind a quote that never closes",
		class:  &nestingDepth,
	},

	{
		// Found by FuzzConfigParseExpand the night after that one, the
		// same hole through the other door: here the quote DOES close, on
		// the `''` at the far end, so the literal swallowed the chain
		// between them. It is not a literal -- it opens straight after the
		// `a`, and ClassAd has no two operands in a row.
		input:  "0=a'00$EVAL(" + strings.Repeat("!", 401) + "'')",
		reason: "nestingDepth, behind a quote that closes at the far end",
		class:  &nestingDepth,
	},

	{
		// The same hole with the quote in operand position, where a
		// literal CAN open -- so it is the `$EVAL` between the two quotes
		// that says this is not one, not where the first quote sits.
		input:  "0='$EVAL(" + strings.Repeat("!", 401) + "'')",
		reason: "nestingDepth, behind a quote that opens a value and closes at the far end",
		class:  &nestingDepth,
	},

	{
		// The macro function in the MIDDLE of a value, so what C++ drops
		// is a run with text on both sides of it rather than the whole
		// value. `0=A$EVAL(...)B` is `AundefinedB` here and `AB` there.
		input:  "0=A$EVAL(" + strings.Repeat("!", 401) + "'')B",
		reason: "nestingDepth, with the result dropped from mid-value",
		class:  &nestingDepth,
	},

	{
		// The evaluator cap reached with no deep parse at all.
		// parseAdditiveExpression builds a left-associative chain in a
		// while loop, so C++'s recursive-descent parser stays shallow here
		// -- and the cut-off is still 401, which is what tells the
		// evaluator's cap apart from the parser's.
		input:  "0=$EVAL(1" + strings.Repeat("+1", 401) + ")",
		reason: "nestingDepth, reached by a left-associative binary chain",
		class:  &nestingDepth,
	},

	{
		// The same cap through a ternary chain, which nests with an
		// operand between each pair of operators.
		input: "A=" + strings.Repeat("true?", 401) + "1" + strings.Repeat(":2", 401) +
			"\n0=$EVAL(A)",
		reason: "nestingDepth, reached by a ternary chain",
		class:  &nestingDepth,
	},

	{
		// The PARSER cap, which parens reach on their own at about three
		// frames each -- 166, well before the evaluator's 400.
		input: "A=" + strings.Repeat("(", 166) + "1" + strings.Repeat(")", 166) +
			"\n0=$EVAL(A)",
		reason: "nestingDepth, reached by nested parentheses against " +
			"MAX_PARSER_DEPTH = 500 rather than the evaluator's 400",
		class: &nestingDepth,
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

// firstLongLine returns the line of s with the most nesting on it, for a
// failure message that names the counts that decided the case.
func firstLongLine(s string) string {
	best, bestScore := "", -1
	for _, line := range strings.Split(s, "\n") {
		b, c := nestingCounts(line)
		if b+c > bestScore {
			best, bestScore = line, b+c
		}
	}
	return best
}

// TestOneRunDeleted pins the match half. The run C++ drops is not always at
// the end of the value -- a macro function can sit anywhere in it -- and a
// rule that only recognized a dropped SUFFIX would narrow the class back to
// where it keeps failing.
func TestOneRunDeleted(t *testing.T) {
	deleted := [][2]string{
		{"undefined", ""},         // the whole value
		{"A\"undefined", "A\""},   // text before
		{"AundefinedB", "AB"},     // text on both sides
		{"undefinedB", "B"},       // text after
		{"xxundefinedxx", "xxxx"}, // repeated text around it
	}
	for _, c := range deleted {
		if !isOneRunDeleted(c[0], c[1]) {
			t.Errorf("isOneRunDeleted(%q, %q) = false, want true", c[0], c[1])
		}
	}
	kept := [][2]string{
		{"0", "1"},     // a different value, same length
		{"0", "0"},     // no difference at all
		{"ab", "ba"},   // reordered, not deleted
		{"abc", "axc"}, // substituted, not deleted
		{"ab", "abc"},  // C++ produced MORE
	}
	for _, c := range kept {
		if isOneRunDeleted(c[0], c[1]) {
			t.Errorf("isOneRunDeleted(%q, %q) = true, want false", c[0], c[1])
		}
	}
}

// TestCppDroppedTheMacroResult pins the whole-table rule, which has to say
// NO whenever it did not actually see the difference. The tables come in as
// text and are read row by row; anything the reading loses must leave the
// class refusing to excuse, not excusing by default.
func TestCppDroppedTheMacroResult(t *testing.T) {
	yes := [][2]string{
		{"0\x1fundefined\n", "0\x1f\n"},
		{"0\x1fAundefinedB\nA\x1f1\n", "0\x1fAB\nA\x1f1\n"},
	}
	for _, c := range yes {
		if !cppDroppedTheMacroResult(c[0], c[1]) {
			t.Errorf("cppDroppedTheMacroResult(%q, %q) = false, want true", c[0], c[1])
		}
	}
	no := [][2]string{
		// a real disagreement about a value
		{"0\x1f0\n", "0\x1f1\n"},
		// one side has an attribute the other does not, each way round
		{"0\x1fx\nA\x1f1\n", "0\x1fx\n"},
		{"0\x1fx\n", "0\x1fx\nA\x1f1\n"},
		// a second row differs in a way that is not a deletion
		{"0\x1fundefined\nA\x1f1\n", "0\x1f\nA\x1f2\n"},
		// the tables differ only in text the row reader drops, so the
		// difference was never examined and must not be excused
		{"0\x1fx\nmalformed\n", "0\x1fx\n"},
	}
	for _, c := range no {
		if cppDroppedTheMacroResult(c[0], c[1]) {
			t.Errorf("cppDroppedTheMacroResult(%q, %q) = true, want false", c[0], c[1])
		}
	}
}

// TestDeepNestingPredicate pins hasDeepNesting from both sides. A class
// defined by what was written is only as good as its predicate: too narrow
// and the nightly reports a recorded divergence as a new one, which is how
// this class was widened three times; too wide and it excuses a real bug
// that happens to arrive on a line with operators on it.
//
// The deep cases are the shapes measured against the oracle, each at the
// count where C++ gives up. The ordinary ones are what config looks like.
func TestDeepNestingPredicate(t *testing.T) {
	deep := map[string]string{
		"unary chain":  "0=$EVAL(" + strings.Repeat("!", 401) + "true)",
		"spaced unary": "0=$EVAL(" + strings.Repeat("! ", 401) + "true)",
		"vertical tabs": "0=$EVAL(" + strings.Repeat("!", 152) + "\v" +
			strings.Repeat("!", 183) + "\v" + strings.Repeat("!", 66) + "'')",
		// 405 operators in runs of 81, so only counting ACROSS the vertical
		// tabs reaches the cap. The nightly's own input has a run of 183 in
		// it and would be called deep even by a predicate that stopped at
		// each tab.
		"vertical tabs, no long run": "0=$EVAL(" +
			strings.Repeat(strings.Repeat("!", 81)+"\v", 5) + "'')",
		"binary chain":     "0=$EVAL(1" + strings.Repeat("+1", 401) + ")",
		"ternary chain":    "A=" + strings.Repeat("true?", 401) + "1" + strings.Repeat(":2", 401),
		"nested parens":    "A=" + strings.Repeat("(", 166) + "1" + strings.Repeat(")", 166),
		"nested lists":     "A=" + strings.Repeat("{", 166) + "1" + strings.Repeat("}", 166),
		"deep on line two": "A = 1\nB=$EVAL(" + strings.Repeat("!", 401) + "true)\n",
		// An unterminated quote is not a literal. Reading it as one hid a
		// whole 401-operator chain behind two characters.
		"behind an unterminated quote": "0=A\"$EVAL(" + strings.Repeat("!", 401) + "'')",
		"behind an unterminated apostrophe": "0=it's $EVAL(" +
			strings.Repeat("!", 401) + "true)",
		// A quote that DOES close, at the far end of the line, so reading
		// it as a literal swallows the chain written between the two.
		// It opens straight after an operand, where no literal can.
		"behind a quote that closes at the far end": "0=a'00$EVAL(" +
			strings.Repeat("!", 401) + "'')",
		"behind a double quote that closes at the far end": "0=a\"00$EVAL(" +
			strings.Repeat("!", 401) + "true)\"",
		// The same, with the quote where a literal could legitimately
		// open. Only the `$EVAL` spanned tells this one apart.
		"behind a quote that opens the value and closes at the far end": "0='$EVAL(" +
			strings.Repeat("!", 401) + "'')",
		// A quote in operand position, where a literal CAN open, that
		// never closes. Config does not read quotes at all, so the
		// `$EVAL` is expanded and the chain reaches the cap all the same.
		"behind an unterminated quote in operand position": "A=\"$EVAL(" +
			strings.Repeat("!", 401) + "true)",
	}
	for name, in := range deep {
		if !hasDeepNesting(in) {
			b, c := nestingCounts(firstLongLine(in))
			t.Errorf("%s: not called deep (brackets %d, chain %d)", name, b, c)
		}
	}

	ordinary := map[string]string{
		"a long requirements": "START = (Owner == \"alice\") && (Memory > 1024) && " +
			"(Disk > 100) && (Cpus >= 2) && (OpSys == \"LINUX\")\n",
		"operators packed together": "R = (A>1)&&(B<2)&&(C==3)&&(D!=4)&&(E>=5)&&(F<=6)&&(G=?=7)\n",
		"a path list":               "PATH = /a/b/c:/d/e/f:/g/h/i:/j/k/l\n",
		"many short expressions":    strings.Repeat("X = (a+b) * (c-d) / (e%f)\n", 200),
		"operator characters in quoted text": "Y = " +
			strings.Repeat("\"a+b?c:d\" ", 100) + "\n",
		// one string literal, and every operator character is inside it,
		// in a chain past the threshold so that skipping the literal is
		// what decides the case
		"an operator chain inside a string": "Y = \"" +
			strings.Repeat("+a", 400) + "\"\n",
		// The same chain inside a literal that opens after an operator
		// rather than at the start of the value, which is still operand
		// position and so still a literal.
		"an operator chain inside a string mid-expression": "Y = 1 + \"" +
			strings.Repeat("+a", 400) + "\"\n",
		"a run of macro references": strings.Repeat("$(A)", 200) + "\n",
	}
	for name, in := range ordinary {
		if hasDeepNesting(in) {
			b, c := nestingCounts(firstLongLine(in))
			t.Errorf("%s: called deep (brackets %d, chain %d)", name, b, c)
		}
	}
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
		// A few stacked operators are ordinary; only a chain long enough
		// to reach one of C++'s caps is the recorded family.
		{"a short operator chain", "A=$EVAL(!!!!0)", "A\x1f0\n", "A\x1f1\n"},
		// Long, and it does nest -- 300 subtractions is a 300-deep
		// left-associative tree -- but C++ evaluates 400 levels, so this
		// one it gets right and a disagreement about it is a real finding.
		// The case the thresholds are set against.
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
