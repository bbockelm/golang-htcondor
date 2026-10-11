package config

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// Test function macros

func TestFunctionENV(t *testing.T) {
	_ = os.Setenv("TEST_VAR", "test_value")
	defer func() { _ = os.Unsetenv("TEST_VAR") }()

	cfg := &Config{
		values: make(map[string]string),
	}

	result, err := cfg.evaluateFunctionMacro("ENV(TEST_VAR)")
	if err != nil {
		t.Fatalf("ENV function failed: %v", err)
	}

	if result != "test_value" {
		t.Errorf("Expected 'test_value', got %q", result)
	}
}

func TestFunctionINT(t *testing.T) {
	cfg := &Config{
		values: make(map[string]string),
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"INT(42)", "42"},
		{"INT(3.14)", "3"},
		{"INT(99.9)", "99"},
		{"INT(0)", "0"},
	}

	for _, tt := range tests {
		result, err := cfg.evaluateFunctionMacro(tt.input)
		if err != nil {
			t.Errorf("%s failed: %v", tt.input, err)
			continue
		}

		if result != tt.expected {
			t.Errorf("%s: expected %q, got %q", tt.input, tt.expected, result)
		}
	}
}

func TestFunctionSTRING(t *testing.T) {
	cfg := &Config{
		values: make(map[string]string),
	}

	result, err := cfg.evaluateFunctionMacro("STRING(hello world)")
	if err != nil {
		t.Fatalf("STRING function failed: %v", err)
	}

	if result != "hello world" {
		t.Errorf("Expected 'hello world', got %q", result)
	}
}

func TestFunctionRANDOM_INTEGER(t *testing.T) {
	cfg := &Config{
		values: make(map[string]string),
	}

	// Test with min, max
	result, err := cfg.evaluateFunctionMacro("RANDOM_INTEGER(1, 10)")
	if err != nil {
		t.Fatalf("RANDOM_INTEGER function failed: %v", err)
	}

	// Parse and verify it's in range
	var num int
	if _, err := fmt.Sscanf(result, "%d", &num); err != nil {
		t.Fatalf("Result is not a number: %q", result)
	}

	if num < 1 || num > 10 {
		t.Errorf("Random number %d out of range [1, 10]", num)
	}

	// Test with step
	result, err = cfg.evaluateFunctionMacro("RANDOM_INTEGER(0, 100, 10)")
	if err != nil {
		t.Fatalf("RANDOM_INTEGER with step failed: %v", err)
	}

	if _, err := fmt.Sscanf(result, "%d", &num); err != nil {
		t.Fatalf("Result is not a number: %q", result)
	}

	if num < 0 || num > 100 || num%10 != 0 {
		t.Errorf("Random number %d not aligned to step 10 in range [0, 100]", num)
	}
}

// $SUBSTR's first argument is a macro NAME, not a string: in condor 25.14.1
// `H = hello` / `$SUBSTR(H,1,3)` is "ell", and `$SUBSTR(hello,1,3)` is empty.
func TestFunctionSUBSTR(t *testing.T) {
	cfg := &Config{
		values: map[string]string{"H": "hello"},
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"SUBSTR(H, 0, 5)", "hello"},
		{"SUBSTR(H, 1, 3)", "ell"},
		{"SUBSTR(H, 2)", "llo"},
		{"SUBSTR(H, -2)", "lo"},
		{"SUBSTR(H, 10)", ""},
		{"SUBSTR(hello, 1, 3)", ""}, // not a macro name
	}

	for _, tt := range tests {
		result, err := cfg.evaluateFunctionMacro(tt.input)
		if err != nil {
			t.Errorf("%s failed: %v", tt.input, err)
			continue
		}

		if result != tt.expected {
			t.Errorf("%s: expected %q, got %q", tt.input, tt.expected, result)
		}
	}
}

func TestFunctionREAL(t *testing.T) {
	cfg := &Config{
		values: make(map[string]string),
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"REAL(42)", "42"},
		{"REAL(3.14)", "3.14"},
		{"REAL(0)", "0"},
	}

	for _, tt := range tests {
		result, err := cfg.evaluateFunctionMacro(tt.input)
		if err != nil {
			t.Errorf("%s failed: %v", tt.input, err)
			continue
		}

		if result != tt.expected {
			t.Errorf("%s: expected %q, got %q", tt.input, tt.expected, result)
		}
	}
}

func TestExpandMacrosWithFunctions(t *testing.T) {
	_ = os.Setenv("MY_VAR", "from_env")
	defer func() { _ = os.Unsetenv("MY_VAR") }()

	cfg := &Config{
		values: map[string]string{
			"FOO": "bar",
			"NUM": "42",
		},
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"$(FOO)", "bar"},
		{"$ENV(MY_VAR)", "from_env"},
		{"$INT(3.14)", "3"},
		{"prefix_$(FOO)_suffix", "prefix_bar_suffix"},
		{"$INT(NUM)", "42"},
		// A special function's body runs to the first ')', so a nested
		// $(NUM) is cut short; condor 25.14.1 yields ")" here too.
		{"$INT($(NUM))", ")"},
	}

	for _, tt := range tests {
		result, err := cfg.expandMacrosWithFunctions(tt.input)
		if err != nil {
			t.Errorf("%s failed: %v", tt.input, err)
			continue
		}

		if result != tt.expected {
			t.Errorf("%s: expected %q, got %q", tt.input, tt.expected, result)
		}
	}
}

func TestFunctionRANDOM_CHOICE(t *testing.T) {
	cfg := &Config{
		values: make(map[string]string),
	}

	// Test that RANDOM_CHOICE returns one of the provided options
	result, err := cfg.evaluateFunctionMacro("RANDOM_CHOICE(a,b,c,d,e)")
	if err != nil {
		t.Fatalf("RANDOM_CHOICE function failed: %v", err)
	}

	validChoices := map[string]bool{"a": true, "b": true, "c": true, "d": true, "e": true}
	if !validChoices[result] {
		t.Errorf("RANDOM_CHOICE returned invalid choice: %q", result)
	}

	// Test with single choice
	result, err = cfg.evaluateFunctionMacro("RANDOM_CHOICE(only_option)")
	if err != nil {
		t.Fatalf("RANDOM_CHOICE with single option failed: %v", err)
	}
	if result != "only_option" {
		t.Errorf("RANDOM_CHOICE with single option: expected 'only_option', got %q", result)
	}
}

func TestFunctionCHOICE(t *testing.T) {
	cfg := &Config{
		values: make(map[string]string),
	}

	// Matching condor 25.14.1: a single list item is the NAME of a list
	// macro, an out-of-range index yields "" and an invalid one is 0 (both
	// with an error message, never a failure).
	cfg.values["L"] = "a,b,c"
	tests := []struct {
		input       string
		expected    string
		shouldError bool
	}{
		{"CHOICE(0, first, second, third)", "first", false},
		{"CHOICE(1, first, second, third)", "second", false},
		{"CHOICE(2, first, second, third)", "third", false},
		{"CHOICE(1,L)", "b", false},
		{"CHOICE(0, only)", "", false},      // no list macro named "only"
		{"CHOICE(3, a, b, c)", "", false},   // index out of bounds
		{"CHOICE(-1, a, b, c)", "a", false}, // invalid index reads as 0
	}

	for _, tt := range tests {
		result, err := cfg.evaluateFunctionMacro(tt.input)
		if tt.shouldError {
			if err == nil {
				t.Errorf("%s: expected error but got none", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("%s failed: %v", tt.input, err)
				continue
			}
			if result != tt.expected {
				t.Errorf("%s: expected %q, got %q", tt.input, tt.expected, result)
			}
		}
	}
}

func TestFunctionDIRNAME(t *testing.T) {
	cfg := &Config{
		values: make(map[string]string),
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"DIRNAME(/path/to/file.txt)", "/path/to/"},
		{"DIRNAME(/path/to/dir/)", "/path/to/dir/"},
		{"DIRNAME(file.txt)", ""},
		{"DIRNAME(/file.txt)", "/"},
	}

	for _, tt := range tests {
		result, err := cfg.evaluateFunctionMacro(tt.input)
		if err != nil {
			t.Errorf("%s failed: %v", tt.input, err)
			continue
		}

		if result != tt.expected {
			t.Errorf("%s: expected %q, got %q", tt.input, tt.expected, result)
		}
	}
}

func TestFunctionBASENAME(t *testing.T) {
	cfg := &Config{
		values: make(map[string]string),
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"BASENAME(/path/to/file.txt)", "file.txt"},
		{"BASENAME(/path/to/archive.tar.gz)", "archive.tar.gz"},
		{"BASENAME(/path/to/archive.tar.gz, .tar.gz)", "archive"},
		{"BASENAME(/path/to/archive.tar.gz, .gz)", "archive.tar"},
		{"BASENAME(file.txt)", "file.txt"},
		{"BASENAME(file)", "file"},
	}

	for _, tt := range tests {
		result, err := cfg.evaluateFunctionMacro(tt.input)
		if err != nil {
			t.Errorf("%s failed: %v", tt.input, err)
			continue
		}

		if result != tt.expected {
			t.Errorf("%s: expected %q, got %q", tt.input, tt.expected, result)
		}
	}
}

func TestFilenameFunc(t *testing.T) {
	cfg := &Config{
		values: make(map[string]string),
	}

	tests := []struct {
		input    string
		expected string
	}{
		// Test individual options
		{"Fp(/path/to/file.txt)", "/path/to/"},
		{"Fn(/path/to/file.txt)", "file"},
		{"Fx(/path/to/file.txt)", ".txt"},
		{"Fnx(/path/to/file.txt)", "file.txt"},

		// Test with 'b' modifier
		{"Fxb(/path/to/file.txt)", "txt"},

		// Test directory functions
		{"Fd(/path/to/dir/file.txt)", "dir/"},
		{"Fdb(/path/to/dir/file.txt)", "dir"},

		// Test quote functions
		{"Fq(/path/to/file.txt)", "\"/path/to/file.txt\""},
		{"Fqa(/path/to/file.txt)", "'/path/to/file.txt'"},
	}

	for _, tt := range tests {
		result, err := cfg.evaluateFunctionMacro(tt.input)
		if err != nil {
			t.Errorf("%s failed: %v", tt.input, err)
			continue
		}

		if result != tt.expected {
			t.Errorf("%s: expected %q, got %q", tt.input, tt.expected, result)
		}
	}
}

// TestFunctionSTRINGEvaluatesMacroExpr is the regression for the CHTC deployment bug:
// $STRING(name) must look up the macro, evaluate its value as a ClassAd expression, and
// return the string -- not echo the name. This is the exact shape a CHTC AP uses to derive
// its per-host include file (and thus JOB_EPOCH_HISTORY): a toLower() over the hostname fed
// through $STRING, then used to build LOCAL. The old no-op left LC_* as the literal name, so
// LOCAL pointed at a nonexistent file and per-host settings fell back to defaults.
func TestFunctionSTRINGEvaluatesMacroExpr(t *testing.T) {
	body := `MY_HOST = AP2001.CHTC.WISC.EDU
_LC_HOST = toLower("$(MY_HOST)")
LC_HOST = $STRING(_LC_HOST)
LOCAL = /etc/condor/hosts/$(LC_HOST).local`
	cfg, err := NewFromReaderWithOptions(strings.NewReader(body), ConfigOptions{Subsystem: "SCHEDD"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, _ := cfg.Get("LC_HOST"); got != "ap2001.chtc.wisc.edu" {
		t.Errorf("LC_HOST = %q, want ap2001.chtc.wisc.edu (STRING must evaluate toLower(), not echo the name)", got)
	}
	if got, _ := cfg.Get("LOCAL"); got != "/etc/condor/hosts/ap2001.chtc.wisc.edu.local" {
		t.Errorf("LOCAL = %q, want the per-host include path", got)
	}
}

// TestFunctionSTRINGPassesThroughPlainValue confirms a value that is not a ClassAd
// expression (a bare path) passes through unchanged rather than becoming "undefined".
func TestFunctionSTRINGPassesThroughPlainValue(t *testing.T) {
	body := `SOMEPATH = /var/lib/condor/history/epoch_history
P = $STRING(SOMEPATH)`
	cfg, err := NewFromReaderWithOptions(strings.NewReader(body), ConfigOptions{Subsystem: "SCHEDD"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, _ := cfg.Get("P"); got != "/var/lib/condor/history/epoch_history" {
		t.Errorf("P = %q, want the plain path passed through", got)
	}
}
