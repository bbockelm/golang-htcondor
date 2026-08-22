package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvaluateConditionDefined(t *testing.T) {
	cfg := &Config{
		values: map[string]string{
			"FOO": "bar",
		},
		evaluating: make(map[string]bool),
	}

	tests := []struct {
		condition string
		expected  bool
	}{
		{"defined(FOO)", true},
		{"defined(BAR)", false},
		{"defined(NONEXISTENT)", false},
	}

	for _, tt := range tests {
		result, err := cfg.evaluateCondition(tt.condition)
		if err != nil {
			t.Errorf("%s failed: %v", tt.condition, err)
			continue
		}

		if result != tt.expected {
			t.Errorf("%s: expected %v, got %v", tt.condition, tt.expected, result)
		}
	}
}

func TestEvaluateConditionTruthy(t *testing.T) {
	cfg := &Config{
		values:     make(map[string]string),
		evaluating: make(map[string]bool),
	}

	tests := []struct {
		value    string
		expected bool
	}{
		{"true", true},
		{"TRUE", true},
		{"yes", true},
		{"YES", true},
		{"1", true},
		{"on", true},
		{"false", false},
		{"FALSE", false},
		{"no", false},
		{"NO", false},
		{"0", false},
		{"off", false},
		{"", false},
		{"anything", true}, // Non-empty strings are truthy
	}

	for _, tt := range tests {
		result := cfg.isTruthy(tt.value)
		if result != tt.expected {
			t.Errorf("isTruthy(%q): expected %v, got %v", tt.value, tt.expected, result)
		}
	}
}

func TestEvaluateConditionComparison(t *testing.T) {
	cfg := &Config{
		values: map[string]string{
			"NUM": "42",
			"STR": "hello",
		},
		evaluating: make(map[string]bool),
	}

	tests := []struct {
		condition string
		expected  bool
	}{
		{"$(NUM) == 42", true},
		{"$(NUM) != 43", true},
		{"$(NUM) > 40", true},
		{"$(NUM) < 50", true},
		{"$(NUM) >= 42", true},
		{"$(NUM) <= 42", true},
		{"$(STR) == hello", true},
		{"$(STR) != world", true},
	}

	for _, tt := range tests {
		result, err := cfg.evaluateCondition(tt.condition)
		if err != nil {
			t.Errorf("%s failed: %v", tt.condition, err)
			continue
		}

		if result != tt.expected {
			t.Errorf("%s: expected %v, got %v", tt.condition, tt.expected, result)
		}
	}
}

func TestEvaluateConditionLogical(t *testing.T) {
	cfg := &Config{
		values: map[string]string{
			"FOO": "bar",
			"NUM": "42",
		},
		evaluating: make(map[string]bool),
	}

	tests := []struct {
		condition string
		expected  bool
	}{
		{"defined(FOO) && defined(NUM)", true},
		{"defined(FOO) && defined(BAR)", false},
		{"defined(FOO) || defined(BAR)", true},
		{"defined(BAZ) || defined(QUX)", false},
		{"!defined(BAR)", true},
		{"!defined(FOO)", false},
	}

	for _, tt := range tests {
		result, err := cfg.evaluateCondition(tt.condition)
		if err != nil {
			t.Errorf("%s failed: %v", tt.condition, err)
			continue
		}

		if result != tt.expected {
			t.Logf("Condition: %q", tt.condition)
			t.Logf("Config values: %v", cfg.values)
			t.Errorf("%s: expected %v, got %v", tt.condition, tt.expected, result)
		}
	}
}

func TestEvaluateVersionCondition(t *testing.T) {
	cfg := &Config{
		values: map[string]string{
			"CONDOR_VERSION": "9.0.0",
		},
		evaluating: make(map[string]bool),
	}

	tests := []struct {
		condition string
		expected  bool
	}{
		{"version >= 8.0.0", true},
		{"version > 8.0.0", true},
		{"version < 10.0.0", true},
		{"version <= 9.0.0", true},
		{"version == 9.0.0", true},
		{"version != 8.0.0", true},
		{"version >= 10.0.0", false},
	}

	for _, tt := range tests {
		result, err := cfg.evaluateCondition(tt.condition)
		if err != nil {
			t.Errorf("%s failed: %v", tt.condition, err)
			continue
		}

		if result != tt.expected {
			t.Errorf("%s: expected %v, got %v", tt.condition, tt.expected, result)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"9.0.0", "8.0.0", 1},
		{"8.0.0", "9.0.0", -1},
		{"9.0.0", "9.0.0", 0},
		{"9.0.1", "9.0.0", 1},
		{"9.0", "9.0.0", 0},
		{"10.0.0", "9.9.9", 1},
		{"$CondorVersion: 9.0.0", "9.0.0", 0},
	}

	for _, tt := range tests {
		result := compareVersions(tt.v1, tt.v2)
		if result != tt.expected {
			t.Errorf("compareVersions(%q, %q): expected %d, got %d", tt.v1, tt.v2, tt.expected, result)
		}
	}
}

// TestElifBranches covers `elif`, which did not parse at all until the
// conditional keywords were removed from the identifier rule: goyacc
// reported elif_clause as "never reduced", so every configuration
// containing an elif was a syntax error. Each case checks which branch
// actually ran, not merely that the input parses.
func TestElifBranches(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			"elif taken when if is false",
			"if false\nbranch = if\nelif true\nbranch = elif\nendif\n",
			"elif",
		},
		{
			"elif skipped when if is true",
			"if true\nbranch = if\nelif true\nbranch = elif\nendif\n",
			"if",
		},
		{
			"second elif taken",
			"if false\nbranch = if\nelif false\nbranch = elif1\nelif true\nbranch = elif2\nendif\n",
			"elif2",
		},
		{
			"else after elif",
			"if false\nbranch = if\nelif false\nbranch = elif\nelse\nbranch = else\nendif\n",
			"else",
		},
		{
			"no branch taken",
			"branch = none\nif false\nbranch = if\nelif false\nbranch = elif\nendif\n",
			"none",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := NewFromReader(strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got, _ := cfg.Get("branch"); got != tc.want {
				t.Errorf("branch = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestElifInRootConfigFile is the same thing through the root
// configuration file, which is where an unparseable elif would stop a
// daemon from starting.
func TestElifInRootConfigFile(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "condor_config")
	body := "if false\nBRANCH = if\nelif true\nBRANCH = elif\nendif\n"
	if err := os.WriteFile(root, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONDOR_CONFIG", root)

	cfg, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got, _ := cfg.Get("BRANCH"); got != "elif" {
		t.Errorf("Get(BRANCH) = %q, want elif", got)
	}
}
