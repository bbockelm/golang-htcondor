package config

import (
	"strings"
	"testing"
)

func TestHeredocBasic(t *testing.T) {
	input := `SCRIPT @=END
#!/bin/bash
echo "Hello World"
exit 0
@END
`
	lex := NewLexer(strings.NewReader(input))

	tok := lex.NextToken()
	if tok.Token != IDENT || tok.Lit != "SCRIPT" {
		t.Errorf("Expected IDENT SCRIPT, got %d %q", tok.Token, tok.Lit)
	}

	tok = lex.NextToken()
	if tok.Token != ASSIGN {
		t.Errorf("Expected ASSIGN, got %d", tok.Token)
	}

	expected := "#!/bin/bash\necho \"Hello World\"\nexit 0"
	if tok.Lit != expected {
		t.Errorf("Expected %q, got %q", expected, tok.Lit)
	}
}

func TestHeredocWithIndentation(t *testing.T) {
	input := `CONFIG @=EOF
    line1
    line2
    line3
@EOF
`
	lex := NewLexer(strings.NewReader(input))

	tok := lex.NextToken()
	if tok.Token != IDENT || tok.Lit != "CONFIG" {
		t.Errorf("Expected IDENT CONFIG, got %d %q", tok.Token, tok.Lit)
	}

	tok = lex.NextToken()
	if tok.Token != ASSIGN {
		t.Errorf("Expected ASSIGN, got %d", tok.Token)
	}

	expected := "    line1\n    line2\n    line3"
	if tok.Lit != expected {
		t.Errorf("Expected %q, got %q", expected, tok.Lit)
	}
}

func TestHeredocEmpty(t *testing.T) {
	input := `EMPTY @=END
@END
`
	lex := NewLexer(strings.NewReader(input))

	tok := lex.NextToken()
	if tok.Token != IDENT || tok.Lit != "EMPTY" {
		t.Errorf("Expected IDENT EMPTY, got %d %q", tok.Token, tok.Lit)
	}

	tok = lex.NextToken()
	if tok.Token != ASSIGN {
		t.Errorf("Expected ASSIGN, got %d", tok.Token)
	}

	if tok.Lit != "" {
		t.Errorf("Expected empty string, got %q", tok.Lit)
	}
}

func TestHeredocWithMacros(t *testing.T) {
	input := `SCRIPT @=END
BASE_DIR=$(HOME)/condor
LOG=$(BASE_DIR)/log
@END
`
	lex := NewLexer(strings.NewReader(input))

	tok := lex.NextToken()
	if tok.Token != IDENT || tok.Lit != "SCRIPT" {
		t.Errorf("Expected IDENT SCRIPT, got %d %q", tok.Token, tok.Lit)
	}

	tok = lex.NextToken()
	if tok.Token != ASSIGN {
		t.Errorf("Expected ASSIGN, got %d", tok.Token)
	}

	expected := "BASE_DIR=$(HOME)/condor\nLOG=$(BASE_DIR)/log"
	if tok.Lit != expected {
		t.Errorf("Expected %q, got %q", expected, tok.Lit)
	}
}

func TestHeredocMultipleInFile(t *testing.T) {
	input := `FIRST @=TAG1
line1
line2
@TAG1
SECOND = normal_value
THIRD @=TAG2
line3
line4
@TAG2
`
	lex := NewLexer(strings.NewReader(input))

	// First variable
	tok := lex.NextToken()
	if tok.Token != IDENT || tok.Lit != "FIRST" {
		t.Errorf("Expected IDENT FIRST, got %d %q", tok.Token, tok.Lit)
	}

	tok = lex.NextToken()
	if tok.Token != ASSIGN {
		t.Errorf("Expected ASSIGN, got %d", tok.Token)
	}

	expected := "line1\nline2"
	if tok.Lit != expected {
		t.Errorf("FIRST: Expected %q, got %q", expected, tok.Lit)
	}

	// Second variable (normal)
	tok = lex.NextToken()
	if tok.Token != IDENT || tok.Lit != "SECOND" {
		t.Errorf("Expected IDENT SECOND, got %d %q", tok.Token, tok.Lit)
	}

	tok = lex.NextToken()
	if tok.Token != ASSIGN {
		t.Errorf("Expected ASSIGN, got %d", tok.Token)
	}

	if tok.Lit != "normal_value" {
		t.Errorf("SECOND: Expected 'normal_value', got %q", tok.Lit)
	}

	// Third variable (heredoc)
	tok = lex.NextToken()
	if tok.Token != IDENT || tok.Lit != "THIRD" {
		t.Errorf("Expected IDENT THIRD, got %d %q", tok.Token, tok.Lit)
	}

	tok = lex.NextToken()
	if tok.Token != ASSIGN {
		t.Errorf("Expected ASSIGN, got %d", tok.Token)
	}

	expected = "line3\nline4"
	if tok.Lit != expected {
		t.Errorf("THIRD: Expected %q, got %q", expected, tok.Lit)
	}
}

func TestConfigWithHeredoc(t *testing.T) {
	input := `SIMPLE = value1
SCRIPT @=END
#!/bin/bash
echo "$(SIMPLE)"
@END
OUTPUT = value2
`
	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("NewFromReader failed: %v", err)
	}

	simple, _ := cfg.Get("SIMPLE")
	if simple != "value1" {
		t.Errorf("SIMPLE: expected 'value1', got %q", simple)
	}

	script, _ := cfg.Get("SCRIPT")
	// Macros are expanded when we Get(), so $(SIMPLE) becomes "value1". A
	// '#' line inside @= is a comment, as anywhere in a config file: condor
	// 25.14.1 drops the #! line too.
	expected := "echo \"value1\""
	if script != expected {
		t.Errorf("SCRIPT: expected %q, got %q", expected, script)
	}

	output, _ := cfg.Get("OUTPUT")
	if output != "value2" {
		t.Errorf("OUTPUT: expected 'value2', got %q", output)
	}
}

func TestHeredocMacroExpansion(t *testing.T) {
	input := `BASE = /opt/condor
WRAPPER @=EOF
#!/bin/bash
CONDOR_HOME=$(BASE)
export PATH=$CONDOR_HOME/bin:$PATH
exec "$@"
@EOF
`
	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("NewFromReader failed: %v", err)
	}

	wrapper, _ := cfg.Get("WRAPPER")
	// Note: $(BASE) in the heredoc should be preserved as-is in the stored value,
	// but when we Get() it, macro expansion happens
	// The #! line is a comment and is dropped, as in condor 25.14.1.
	expected := "CONDOR_HOME=/opt/condor\nexport PATH=$CONDOR_HOME/bin:$PATH\nexec \"$@\""
	if wrapper != expected {
		t.Errorf("WRAPPER: expected %q, got %q", expected, wrapper)
	}
}
