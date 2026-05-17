package config

import (
	"strings"
	"testing"
)

func TestErrorAsAttributeName(t *testing.T) {
	// Test that "error = value" is treated as an assignment, not a directive
	input := `
error = error.txt
warning = warning.log
`
	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	errorVal, ok := cfg.Get("error")
	if !ok {
		t.Fatal("Expected 'error' attribute to be set")
	}
	if errorVal != "error.txt" {
		t.Errorf("Expected error='error.txt', got '%s'", errorVal)
	}

	warningVal, ok := cfg.Get("warning")
	if !ok {
		t.Fatal("Expected 'warning' attribute to be set")
	}
	if warningVal != "warning.log" {
		t.Errorf("Expected warning='warning.log', got '%s'", warningVal)
	}
}

func TestErrorAsDirective(t *testing.T) {
	// Test that "error: message" is treated as a directive
	input := `
error: This is an error message
`
	_, err := NewFromReader(strings.NewReader(input))
	if err == nil {
		t.Fatal("Expected error directive to cause an error")
	}

	// Check that the error message contains our text
	if !strings.Contains(err.Error(), "This is an error message") {
		t.Errorf("Expected error message to contain 'This is an error message', got: %v", err)
	}
}

func TestErrorWithSpaces(t *testing.T) {
	// Test that "error = value" with spaces works
	input := `
error  =  spaced.txt
`
	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	errorVal, ok := cfg.Get("error")
	if !ok {
		t.Fatal("Expected 'error' attribute to be set")
	}
	if errorVal != "spaced.txt" {
		t.Errorf("Expected error='spaced.txt', got '%s'", errorVal)
	}
}

// TestErrorWithWidePadding covers column-aligned submit descriptions
// where many spaces sit between the key and `=`. Real-world examples:
//
//	executable          = /path/to/x
//	error               = $(Cluster).err
//	warning             = warn.log
//
// The previous lexer lookahead only peeked 10 bytes after `error` /
// `warning`, so any padding wider than that caused the lexer to
// classify the line as an ERROR / WARNING directive rather than an
// assignment. The submission would then fail with
// `configuration error: = ..err` (the value, parsed as a directive
// message). Regression coverage so a future refactor doesn't lose it.
func TestErrorWithWidePadding(t *testing.T) {
	// 15-space and 30-space padding both must work.
	for _, n := range []int{15, 30, 128} {
		pad := strings.Repeat(" ", n)
		input := "error" + pad + "= file.err\n" +
			"warning" + pad + "= file.warn\n"
		cfg, err := NewFromReader(strings.NewReader(input))
		if err != nil {
			t.Fatalf("padding=%d: NewFromReader: %v", n, err)
		}
		if got, ok := cfg.Get("error"); !ok || got != "file.err" {
			t.Errorf("padding=%d: error attribute = %q ok=%v; want %q true",
				n, got, ok, "file.err")
		}
		if got, ok := cfg.Get("warning"); !ok || got != "file.warn" {
			t.Errorf("padding=%d: warning attribute = %q ok=%v; want %q true",
				n, got, ok, "file.warn")
		}
	}
}
