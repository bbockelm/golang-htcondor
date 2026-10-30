package config

import (
	"strings"
	"testing"
)

func TestLexerBasicTokens(t *testing.T) {
	input := "FOO = bar"
	lex := NewLexer(strings.NewReader(input))

	tok := lex.NextToken()
	if tok.Token != IDENT || tok.Lit != "FOO" {
		t.Errorf("Expected IDENT FOO, got %d %q", tok.Token, tok.Lit)
	}

	tok = lex.NextToken()
	if tok.Token != ASSIGN {
		t.Errorf("Expected ASSIGN, got %d", tok.Token)
	}
	if tok.Lit != "bar" {
		t.Errorf("Expected value 'bar', got %q", tok.Lit)
	}
}

func TestLexerMacroExpansion(t *testing.T) {
	input := "FOO = $(BAR)"
	lex := NewLexer(strings.NewReader(input))

	tok := lex.NextToken()
	if tok.Token != IDENT || tok.Lit != "FOO" {
		t.Errorf("Expected IDENT FOO, got %d %q", tok.Token, tok.Lit)
	}

	tok = lex.NextToken()
	if tok.Token != ASSIGN {
		t.Errorf("Expected ASSIGN, got %d", tok.Token)
	}

	if tok.Lit != "$(BAR)" {
		t.Errorf("Expected $(BAR), got %q", tok.Lit)
	}
}

func TestLexerNestedMacros(t *testing.T) {
	// At the start of a statement a macro reference is a parameter
	// NAME -- "$(K) = value" defines whatever $(K) expands to, which
	// condor_config_val accepts -- so it lexes as IDENT. This test used
	// to assert STRING here, from before names could contain macro
	// references at all.
	lex := NewLexer(strings.NewReader("$(FOO:$(BAR))"))
	tok := lex.NextToken()
	if tok.Token != IDENT {
		t.Errorf("at statement start: expected IDENT, got %d", tok.Token)
	}
	if tok.Lit != "$(FOO:$(BAR))" {
		t.Errorf("Expected $(FOO:$(BAR)), got %q", tok.Lit)
	}

	// The nesting and the colon default are carried through whole
	// either way -- the token's literal is the reference as written,
	// and expansion happens later.
	//
	// (There is no "same reference, mid-statement" case to compare
	// against here: an if/elif condition and a use directive are each
	// read to end of line as a single token, and a value is carried in
	// the ASSIGN token, so a bare $(...) does not stand alone
	// elsewhere.)
	lex = NewLexer(strings.NewReader("PREFIX_$(FOO:$(BAR))_SUFFIX = v"))
	tok = lex.NextToken()
	if tok.Token != IDENT {
		t.Errorf("embedded reference: expected IDENT, got %d", tok.Token)
	}
	if tok.Lit != "PREFIX_$(FOO:$(BAR))_SUFFIX" {
		t.Errorf("Expected the whole name, got %q", tok.Lit)
	}
	if tok := lex.NextToken(); tok.Token != ASSIGN || tok.Lit != "v" {
		t.Errorf("expected ASSIGN with value \"v\", got %d %q", tok.Token, tok.Lit)
	}
}

func TestLexerComments(t *testing.T) {
	input := `
# This is a comment
FOO = bar # inline comment
	`
	lex := NewLexer(strings.NewReader(input))

	tok := lex.NextToken()
	if tok.Token != IDENT || tok.Lit != "FOO" {
		t.Errorf("Expected IDENT FOO, got %d %q", tok.Token, tok.Lit)
	}
}

func TestLexerLineContinuation(t *testing.T) {
	input := "FOO = this is a \\\nvery long value"
	lex := NewLexer(strings.NewReader(input))

	tok := lex.NextToken()
	if tok.Token != IDENT || tok.Lit != "FOO" {
		t.Errorf("Expected IDENT FOO, got %d %q", tok.Token, tok.Lit)
	}

	tok = lex.NextToken()
	if tok.Token != ASSIGN {
		t.Errorf("Expected ASSIGN, got %d", tok.Token)
	}

	expected := "this is a very long value"
	if tok.Lit != expected {
		t.Errorf("Expected %q, got %q", expected, tok.Lit)
	}
}

// TestLexerContinuationKeepsWhitespace pins the rule the two tests above
// cannot see, because both write exactly one space before the backslash and
// so agree whether the run is kept or replaced by a separator.
//
// getline_implementation trims the physical line with isspace() and only
// THEN tests its last character for a backslash. So whitespace before the
// backslash is part of the value, nothing is inserted in its place, and
// whitespace AFTER the backslash still continues the line.
func TestLexerContinuationKeepsWhitespace(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"run before the backslash is kept", "FOO = a   \\\n   b", "a   b"},
		{"nothing is inserted", "FOO = a\\\nb", "ab"},
		{"tabs count too", "FOO = a\t\t\\\n\t\tb", "a\t\tb"},
		{"whitespace after the backslash still continues", "FOO = a \\   \nb", "a b"},
		{"a blank continuation line ends the value", "FOO = a   \\\n\nB = 1", "a   "},
		{"an empty left half contributes no separator", "FOO =\\\nbar", "bar"},
		{"the backslash test spans the whole logical line", "FOO = a\\\\\n\nb", "ab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lex := NewLexer(strings.NewReader(tt.input))
			lex.NextToken() // FOO
			tok := lex.NextToken()
			if tok.Token != ASSIGN {
				t.Fatalf("expected ASSIGN, got %d", tok.Token)
			}
			if tok.Lit != tt.want {
				t.Errorf("input %q: got %q, want %q", tt.input, tok.Lit, tt.want)
			}
		})
	}
}

// TestLexerAttributeNames pins the name scan for submit's +Attr and -Attr
// forms. Parse_macros prefixes "MY." to whatever it scanned before the first
// whitespace or operator and never runs is_valid_param_name() on it, so the
// charset is wider than a macro name's -- and a '-' opener is a token in its
// own right.
func TestLexerAttributeNames(t *testing.T) {
	tests := []struct {
		input    string
		wantTok  int
		wantName string
		wantVal  string
	}{
		{"+a-b = 7", PLUS, "a-b", "7"},
		{"+0.5 = 7", PLUS, "0.5", "7"},
		{"+a*b = 7", PLUS, "a*b", "7"},
		{"+A =", PLUS, "A", ""},
		{"-Foo = 7", MINUS, "Foo", "7"},
		{"-a-b = 7", MINUS, "a-b", "7"},
		{"-1 = 7", MINUS, "1", "7"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			lex := NewLexer(strings.NewReader(tt.input))
			tok := lex.NextToken()
			if tok.Token != tt.wantTok {
				t.Fatalf("first token: got %d, want %d", tok.Token, tt.wantTok)
			}
			name := lex.NextToken()
			if name.Token != IDENT || name.Lit != tt.wantName {
				t.Fatalf("name: got %d %q, want IDENT %q", name.Token, name.Lit, tt.wantName)
			}
			val := lex.NextToken()
			if val.Token != ASSIGN || val.Lit != tt.wantVal {
				t.Errorf("value: got %d %q, want ASSIGN %q", val.Token, val.Lit, tt.wantVal)
			}
		})
	}
}

// TestLexerQueueTailWithoutParens pins the item-list scan. HTCondor anchors
// on the in/from keyword and takes the rest of the line, so parentheses are
// optional; a qualifier only counts as one when something on the line
// terminates it.
func TestLexerQueueTailWithoutParens(t *testing.T) {
	tests := []struct {
		input     string
		wantTok   int
		wantItems []string
		wantLit   string
	}{
		{input: "queue in a b", wantTok: ITEMS, wantItems: []string{"a", "b"}},
		{input: "queue in 0 00", wantTok: ITEMS, wantItems: []string{"0", "00"}},
		{input: "queue in a, b , c", wantTok: ITEMS, wantItems: []string{"a", "b", "c"}},
		{input: "queue in a b # c", wantTok: ITEMS, wantItems: []string{"a", "b", "#", "c"}},
		{input: "queue in a)", wantTok: ITEMS, wantItems: []string{"a)"}},
		{input: "queue in files", wantTok: ITEMS, wantItems: []string{"files"}},
		{input: "queue in [1:2]", wantTok: ITEMS, wantItems: []string{"[1:2]"}},
		{input: "queue in files x", wantTok: ILLEGAL},
		{input: "queue in [1:2] x", wantTok: ILLEGAL},
		{input: "queue from a b", wantTok: STRING, wantLit: "a b"},
		{input: "queue from table x", wantTok: ILLEGAL},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			lex := NewLexer(strings.NewReader(tt.input))
			lex.NextToken() // queue
			lex.NextToken() // in / from
			tok := lex.NextToken()
			if tok.Token != tt.wantTok {
				t.Fatalf("got token %d (%q), want %d", tok.Token, tok.Lit, tt.wantTok)
			}
			if tt.wantItems != nil {
				if len(tok.Items) != len(tt.wantItems) {
					t.Fatalf("got items %q, want %q", tok.Items, tt.wantItems)
				}
				for i := range tt.wantItems {
					if tok.Items[i] != tt.wantItems[i] {
						t.Fatalf("got items %q, want %q", tok.Items, tt.wantItems)
					}
				}
			}
			if tt.wantLit != "" && tok.Lit != tt.wantLit {
				t.Errorf("got lit %q, want %q", tok.Lit, tt.wantLit)
			}
		})
	}
}

func TestLexerKeywords(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"if", IF},
		{"elif", ELIF},
		{"else", ELSE},
		{"endif", ENDIF},
		{"defined", DEFINED},
		{"version", VERSION},
		{"include", INCLUDE},
		{"use", USE},
		{"true", TRUE},
		{"false", FALSE},
		{"yes", YES},
		{"no", NO},
	}

	for _, tt := range tests {
		lex := NewLexer(strings.NewReader(tt.input))
		tok := lex.NextToken()

		if tok.Token != tt.expected {
			t.Errorf("input=%q: expected token=%d, got=%d",
				tt.input, tt.expected, tok.Token)
		}
	}
}

func TestLexerSubsystemVariables(t *testing.T) {
	input := "MASTER.LOWPORT = 20000"
	lex := NewLexer(strings.NewReader(input))

	tok := lex.NextToken()
	if tok.Token != IDENT || tok.Lit != "MASTER.LOWPORT" {
		t.Errorf("Expected IDENT MASTER.LOWPORT, got %d %q", tok.Token, tok.Lit)
	}

	tok = lex.NextToken()
	if tok.Token != ASSIGN {
		t.Errorf("Expected ASSIGN, got %d", tok.Token)
	}

	if tok.Lit != "20000" {
		t.Errorf("Expected 20000, got %q", tok.Lit)
	}
}

func TestLexerStrings(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`"hello world"`, "hello world"},
		{`'single quotes'`, "single quotes"},
		{`"escaped \"quote\""`, `escaped "quote"`},
	}

	for _, tt := range tests {
		lex := NewLexer(strings.NewReader(tt.input))
		tok := lex.NextToken()

		if tok.Token != STRING {
			t.Errorf("input=%q: expected STRING, got=%d", tt.input, tok.Token)
		}

		if tok.Lit != tt.expected {
			t.Errorf("input=%q: expected %q, got %q",
				tt.input, tt.expected, tok.Lit)
		}
	}
}

func TestLexerNumbers(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"123", "123"},
		{"456.789", "456.789"},
		{"-42", "-42"},
		{"-3.14", "-3.14"},
	}

	// A number is only a number away from the start of a statement: the first
	// token on a line is a parameter name, and HTCondor lets one start with a
	// digit. "queue" puts the lexer past the statement start.
	for _, tt := range tests {
		lex := NewLexer(strings.NewReader("queue " + tt.input))
		lex.NextToken() // QUEUE
		tok := lex.NextToken()

		if tok.Token != NUMBER {
			t.Errorf("input=%q: expected NUMBER, got=%d", tt.input, tok.Token)
		}

		if tok.Lit != tt.expected {
			t.Errorf("input=%q: expected %q, got=%q",
				tt.input, tt.expected, tok.Lit)
		}
	}
}

func TestLexerComplexValue(t *testing.T) {
	input := "ADMIN_MACHINES = condor.cs.wisc.edu, $(HOSTNAME), \\\n    stork.cs.wisc.edu"
	lex := NewLexer(strings.NewReader(input))

	tok := lex.NextToken()
	if tok.Token != IDENT || tok.Lit != "ADMIN_MACHINES" {
		t.Errorf("Expected IDENT ADMIN_MACHINES, got %d %q", tok.Token, tok.Lit)
	}

	tok = lex.NextToken()
	if tok.Token != ASSIGN {
		t.Errorf("Expected ASSIGN, got %d", tok.Token)
	}

	// Line continuation drops the backslash-newline and the continuation
	// line's leading whitespace, and joins what is left on directly. The
	// single space in the result is the one written before the backslash,
	// not a separator the lexer inserted -- see TestLexerContinuationKeepsWhitespace.
	expected := "condor.cs.wisc.edu, $(HOSTNAME), stork.cs.wisc.edu"
	if tok.Lit != expected {
		t.Errorf("Expected %q, got %q", expected, tok.Lit)
	}
}

// TestLexerStatementStartNames pins the lexer to HTCondor's parameter-name
// rule rather than Go's identifier rule. config.cpp scans the name at the
// start of a line as the run of characters before the first whitespace or
// operator and then checks it with is_valid_param_name(), whose charset is
// condor_isidchar(): [A-Za-z0-9_./]. Nothing says the first character has to
// be a letter, so `0 = x` names a macro "0".
//
// The values are what libcondor_utils 26.2.0 does with the same submit files;
// see fuzz/submit.
func TestLexerStatementStartNames(t *testing.T) {
	for _, tt := range []struct {
		input string
		name  string
		value string
	}{
		{"0 = x\n", "0", "x"},
		{"0abc = x\n", "0abc", "x"},
		{"456.789 = x\n", "456.789", "x"},
		{"_x = 1\n", "_x", "1"},
		{"a/b = 1\n", "a/b", "1"},
		{"foo.bar = 1\n", "foo.bar", "1"},
		{"0 : x\n", "0", "x"}, // ':' assigns, the same as '='
	} {
		lex := NewLexer(strings.NewReader(tt.input))
		name := lex.NextToken()
		if name.Token != IDENT || name.Lit != tt.name {
			t.Errorf("input=%q: name token=%d lit=%q, want IDENT %q",
				tt.input, name.Token, name.Lit, tt.name)
			continue
		}
		val := lex.NextToken()
		if val.Token != ASSIGN || val.Lit != tt.value {
			t.Errorf("input=%q: value token=%d lit=%q, want ASSIGN %q",
				tt.input, val.Token, val.Lit, tt.value)
		}
	}
}

// TestLexerValueTrimsCarriageReturn pins the other half of the same rule:
// getline_implementation trims the line with isspace() before it is split into
// name and value, so a file written on Windows produces the same values as one
// written on Unix. A '\r' away from the end of the line is not trailing
// whitespace and survives.
func TestLexerValueTrimsCarriageReturn(t *testing.T) {
	for _, tt := range []struct {
		input string
		value string
	}{
		{"executable = /bin/sleep\r\n", "/bin/sleep"},
		{"executable =\r/bin/sleep\n", "/bin/sleep"},
		{"executable = /bin/sleep \r\n", "/bin/sleep"},
		{"executable = /bin/sl\reep\n", "/bin/sl\reep"},
		{"executable = /bin/sleep\v\f\n", "/bin/sleep"},
	} {
		lex := NewLexer(strings.NewReader(tt.input))
		lex.NextToken() // the name
		val := lex.NextToken()
		if val.Token != ASSIGN || val.Lit != tt.value {
			t.Errorf("input=%q: token=%d lit=%q, want ASSIGN %q",
				tt.input, val.Token, val.Lit, tt.value)
		}
	}
}
