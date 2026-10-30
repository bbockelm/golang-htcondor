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

	// Line continuation removes the backslash-newline and trailing whitespace before it,
	// then replaces with a single space. Leading whitespace on the continuation line is skipped.
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
