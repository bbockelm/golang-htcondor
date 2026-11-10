package config

import (
	"strings"
	"testing"
)

// TestNestedMacroWithDefault tests the HTCondor example:
// MAX_ALLOC_CPUS = $(NUMCPUS:$(DETECTED_CPUS_LIMIT))-1
func TestNestedMacroWithDefault(t *testing.T) {
	input := `
DETECTED_CPUS_LIMIT = 8
MAX_ALLOC_CPUS = $(NUMCPUS:$(DETECTED_CPUS_LIMIT))-1
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// NUMCPUS is not defined, so it should use the default $(DETECTED_CPUS_LIMIT)
	// which should expand to 8, then append -1
	val, ok := cfg.Get("MAX_ALLOC_CPUS")
	if !ok {
		t.Fatal("MAX_ALLOC_CPUS not defined")
	}

	expected := "8-1"
	if val != expected {
		t.Errorf("MAX_ALLOC_CPUS = %q, want %q", val, expected)
	}
	t.Logf("MAX_ALLOC_CPUS = %s", val)
}

// TestDoubleIndirection tests simple double indirection: $($(VAR))
func TestDoubleIndirection(t *testing.T) {
	input := `
POINTER = TARGET
TARGET = hello world
RESULT = $($(POINTER))
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	val, ok := cfg.Get("RESULT")
	if !ok {
		t.Fatal("RESULT not defined")
	}

	expected := "hello world"
	if val != expected {
		t.Errorf("RESULT = %q, want %q", val, expected)
	}
	t.Logf("RESULT = %s", val)
}

// TestDoubleIndirectionWithNumber tests double indirection through a
// parameter whose name is a number. A name is any run of identifier
// characters, digits included: condor 25.14.1 expands RESULT to "test value".
func TestDoubleIndirectionWithNumber(t *testing.T) {

	input := `
1 = MYVAR
MYVAR = test value
RESULT = $($(1))
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// Debug: check if "1" is set
	if val, ok := cfg.Get("1"); ok {
		t.Logf("1 = %s", val)
	} else {
		t.Logf("1 is not defined")
	}

	val, ok := cfg.Get("RESULT")
	if !ok {
		t.Fatal("RESULT not defined")
	}

	expected := "test value"
	if val != expected {
		t.Errorf("RESULT = %q, want %q", val, expected)
	}
	t.Logf("RESULT = %s", val)
}

// TestTripleIndirection tests triple-nested macros: $($($(VAR)))
func TestTripleIndirection(t *testing.T) {
	input := `
PTR1 = PTR2
PTR2 = TARGET
TARGET = final value
RESULT = $($($(PTR1)))
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	val, ok := cfg.Get("RESULT")
	if !ok {
		t.Fatal("RESULT not defined")
	}

	expected := "final value"
	if val != expected {
		t.Errorf("RESULT = %q, want %q", val, expected)
	}
	t.Logf("RESULT = %s", val)
}

// TestDoubleIndirectionInExpression tests $($(VAR)) in a larger expression
func TestDoubleIndirectionInExpression(t *testing.T) {
	input := `
VAR_NAME = MY_VALUE
MY_VALUE = 42
RESULT = prefix $($(VAR_NAME)) suffix
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	val, ok := cfg.Get("RESULT")
	if !ok {
		t.Fatal("RESULT not defined")
	}

	expected := "prefix 42 suffix"
	if val != expected {
		t.Errorf("RESULT = %q, want %q", val, expected)
	}
	t.Logf("RESULT = %s", val)
}

// TestMultipleDoubleIndirections tests multiple $($(VAR)) in one expression
func TestMultipleDoubleIndirections(t *testing.T) {
	input := `
PTR1 = VAL1
PTR2 = VAL2
VAL1 = first
VAL2 = second
RESULT = $($(PTR1)) and $($(PTR2))
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	val, ok := cfg.Get("RESULT")
	if !ok {
		t.Fatal("RESULT not defined")
	}

	expected := "first and second"
	if val != expected {
		t.Errorf("RESULT = %q, want %q", val, expected)
	}
	t.Logf("RESULT = %s", val)
}

// TestDoubleIndirectionWithParenthesesInValue tests that parentheses in values don't break things
func TestDoubleIndirectionWithParenthesesInValue(t *testing.T) {
	input := `
VAR_NAME = EXPR
EXPR = (a > b) && (c < d)
RESULT = $($(VAR_NAME))
	`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	val, ok := cfg.Get("RESULT")
	if !ok {
		t.Fatal("RESULT not defined")
	}

	expected := "(a > b) && (c < d)"
	if val != expected {
		t.Errorf("RESULT = %q, want %q", val, expected)
	}
	t.Logf("RESULT = %s", val)
}
