package config

import (
	"strings"
	"testing"
)

// TestEvalFunction tests the $EVAL() function with various expressions
func TestEvalFunction(t *testing.T) {
	// Based on HTCondor manual examples, but adapted for available ClassAd functions
	// The expression is evaluated in an empty ClassAd, so config values
	// reach it through $(...), not as attribute names.
	input := `slist = "a,B,c"
X = 10
Y = 20
PRODUCT = $(X) * $(Y)
SUM_EXPR = $(X) + $(Y)

EVAL_SLIST = $EVAL(slist)
EVAL_PRODUCT = $EVAL(PRODUCT)
EVAL_SUM = $EVAL(SUM_EXPR)
`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{
			name:     "EVAL string",
			key:      "EVAL_SLIST",
			expected: "a,B,c",
		},
		{
			name:     "EVAL expression with variables",
			key:      "EVAL_PRODUCT",
			expected: "200",
		},
		{
			name:     "EVAL arithmetic expression",
			key:      "EVAL_SUM",
			expected: "30",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, ok := cfg.Get(tt.key)
			if !ok {
				t.Errorf("%s not defined", tt.key)
				return
			}
			if val != tt.expected {
				t.Errorf("%s = %q, want %q", tt.key, val, tt.expected)
			}
		})
	}
}

// TestEvalWithUndefined tests $EVAL with undefined variables
func TestEvalWithUndefined(t *testing.T) {
	input := `UNDEFINED_RESULT = $EVAL(UNDEFINED_VAR)`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	val, ok := cfg.Get("UNDEFINED_RESULT")
	if !ok {
		t.Error("UNDEFINED_RESULT not defined")
	} else if val != "undefined" {
		t.Errorf("UNDEFINED_RESULT = %q, want 'undefined'", val)
	}
}

// TestEvalWithArithmetic tests $EVAL with simple arithmetic. A config name
// is not a ClassAd attribute: condor 25.14.1 expands `$EVAL(X * Y)` to
// "undefined", and `P = $(X) * $(Y)` / `$EVAL(P)` to 200.
func TestEvalWithArithmetic(t *testing.T) {
	input := `X = 10
Y = 20
S = $(X) + $(Y)
P = $(X) * $(Y)
C = $(X) > 5
SUM = $EVAL(S)
PRODUCT = $EVAL(P)
COMPARE = $EVAL(C)
BARE = $EVAL(X * Y)
`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	tests := []struct {
		key      string
		expected string
	}{
		{"SUM", "30"},
		{"PRODUCT", "200"},
		{"COMPARE", "true"},
		{"BARE", "undefined"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			val, ok := cfg.Get(tt.key)
			if !ok {
				t.Errorf("%s not defined", tt.key)
				return
			}
			if val != tt.expected {
				t.Errorf("%s = %q, want %q", tt.key, val, tt.expected)
			}
		})
	}
}

// TestEvalWithConditional tests $EVAL with conditional expressions
func TestEvalWithConditional(t *testing.T) {
	input := `X = 10
SC = $(X) > 5 ? "high" : "low"
RESULT = $EVAL(SC)
`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	val, ok := cfg.Get("RESULT")
	if !ok {
		t.Error("RESULT not defined")
	} else if val != "high" {
		t.Errorf("RESULT = %q, want 'high'", val)
	}
}

// TestEvalWithMacroVariable tests that expressions with parentheses
// must use a variable (as per HTCondor documentation)
func TestEvalWithMacroVariable(t *testing.T) {
	input := `EXPR = $(X) > 5 ? 100 : 0
X = 10
RESULT = $EVAL(EXPR)
`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	val, ok := cfg.Get("RESULT")
	if !ok {
		t.Error("RESULT not defined")
	} else if val != "100" {
		t.Errorf("RESULT = %q, want '100'", val)
	}
}
