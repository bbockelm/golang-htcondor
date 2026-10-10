package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecuteAssignment(t *testing.T) {
	cfg := &Config{
		values: make(map[string]string),
	}
	cfg.initBuiltins()

	stmt := &Assignment{
		Name:  "FOO",
		Value: "bar",
	}

	if err := cfg.executeAssignment(stmt); err != nil {
		t.Fatalf("executeAssignment failed: %v", err)
	}

	if cfg.values["FOO"] != "bar" {
		t.Errorf("Expected FOO=bar, got FOO=%s", cfg.values["FOO"])
	}
}

func TestExecuteAssignmentWithMacro(t *testing.T) {
	cfg := &Config{
		values: map[string]string{
			"BAR": "hello",
		},
	}
	cfg.initBuiltins()

	stmt := &Assignment{
		Name:  "FOO",
		Value: "$(BAR)_world",
	}

	if err := cfg.executeAssignment(stmt); err != nil {
		t.Fatalf("executeAssignment failed: %v", err)
	}

	val, _ := cfg.Get("FOO")
	if val != "hello_world" {
		t.Errorf("Expected FOO=hello_world, got FOO=%s", val)
	}
}

func TestExecuteConditionalTrue(t *testing.T) {
	cfg := &Config{
		values: map[string]string{
			"ENABLE_FEATURE": "true",
		},
	}
	cfg.initBuiltins()

	cond := &Conditional{
		Condition: "defined(ENABLE_FEATURE)",
		ThenBlock: []Statement{
			&Assignment{Name: "FEATURE_ENABLED", Value: "yes"},
		},
		ElseBlock: []Statement{
			&Assignment{Name: "FEATURE_ENABLED", Value: "no"},
		},
	}

	if err := cfg.executeConditional(cond); err != nil {
		t.Fatalf("executeConditional failed: %v", err)
	}

	if cfg.values["FEATURE_ENABLED"] != "yes" {
		t.Errorf("Expected FEATURE_ENABLED=yes, got %s", cfg.values["FEATURE_ENABLED"])
	}
}

func TestExecuteConditionalFalse(t *testing.T) {
	cfg := &Config{
		values: make(map[string]string),
	}
	cfg.initBuiltins()

	cond := &Conditional{
		Condition: "defined(NONEXISTENT)",
		ThenBlock: []Statement{
			&Assignment{Name: "RESULT", Value: "then"},
		},
		ElseBlock: []Statement{
			&Assignment{Name: "RESULT", Value: "else"},
		},
	}

	if err := cfg.executeConditional(cond); err != nil {
		t.Fatalf("executeConditional failed: %v", err)
	}

	if cfg.values["RESULT"] != "else" {
		t.Errorf("Expected RESULT=else, got %s", cfg.values["RESULT"])
	}
}

func TestExecuteConditionalElif(t *testing.T) {
	cfg := &Config{
		values: map[string]string{
			"NUM": "2",
		},
	}
	cfg.initBuiltins()

	cond := &Conditional{
		Condition: "$(NUM) == 1",
		ThenBlock: []Statement{
			&Assignment{Name: "RESULT", Value: "one"},
		},
		ElseIfBlock: []ElseIf{
			{
				Condition: "$(NUM) == 2",
				Block: []Statement{
					&Assignment{Name: "RESULT", Value: "two"},
				},
			},
		},
		ElseBlock: []Statement{
			&Assignment{Name: "RESULT", Value: "other"},
		},
	}

	if err := cfg.executeConditional(cond); err != nil {
		t.Fatalf("executeConditional failed: %v", err)
	}

	if cfg.values["RESULT"] != "two" {
		t.Errorf("Expected RESULT=two, got %s", cfg.values["RESULT"])
	}
}

func TestExecuteIncludeFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test.config")

	content := "INCLUDED_VAR = from_file"
	if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	cfg := &Config{
		values:        make(map[string]string),
		includedFiles: make(map[string]bool),
	}
	cfg.initBuiltins()

	inc := &IncludeDirective{
		Type: "include",
		Path: configFile,
	}

	if err := cfg.executeInclude(inc); err != nil {
		t.Fatalf("executeInclude failed: %v", err)
	}

	if cfg.values["INCLUDED_VAR"] != "from_file" {
		t.Errorf("Expected INCLUDED_VAR=from_file, got %s", cfg.values["INCLUDED_VAR"])
	}
}

func TestExecuteIncludeGlob(t *testing.T) {
	// Create temporary config files
	tmpDir := t.TempDir()

	for i := 1; i <= 3; i++ {
		configFile := filepath.Join(tmpDir, fmt.Sprintf("config%d.conf", i))
		content := fmt.Sprintf("VAR%d = value%d", i, i)
		if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	cfg := &Config{
		values:        make(map[string]string),
		includedFiles: make(map[string]bool),
	}
	cfg.initBuiltins()

	inc := &IncludeDirective{
		Type: "include",
		Path: filepath.Join(tmpDir, "*.conf"),
	}

	if err := cfg.executeInclude(inc); err != nil {
		t.Fatalf("executeInclude with glob failed: %v", err)
	}

	// Check that all files were included
	for i := 1; i <= 3; i++ {
		varName := fmt.Sprintf("VAR%d", i)
		expected := fmt.Sprintf("value%d", i)
		if cfg.values[varName] != expected {
			t.Errorf("Expected %s=%s, got %s", varName, expected, cfg.values[varName])
		}
	}
}

func TestExecuteIncludeIfexist(t *testing.T) {
	cfg := &Config{
		values:        make(map[string]string),
		includedFiles: make(map[string]bool),
	}
	cfg.initBuiltins()

	inc := &IncludeDirective{
		Type: "include_ifexist",
		Path: "/nonexistent/file.config",
	}

	// Should not fail for missing file
	if err := cfg.executeInclude(inc); err != nil {
		t.Fatalf("executeInclude ifexist failed: %v", err)
	}
}

func TestExecuteIncludeCommand(t *testing.T) {
	cfg := &Config{
		values:        make(map[string]string),
		includedFiles: make(map[string]bool),
	}
	cfg.initBuiltins()

	inc := &IncludeDirective{
		Type: "include_command",
		Path: "echo 'CMD_VAR = from_command'",
	}

	if err := cfg.executeInclude(inc); err != nil {
		t.Fatalf("executeInclude command failed: %v", err)
	}

	if cfg.values["CMD_VAR"] != "from_command" {
		t.Errorf("Expected CMD_VAR=from_command, got %s", cfg.values["CMD_VAR"])
	}
}

func TestExecuteCircularInclude(t *testing.T) {
	tmpDir := t.TempDir()
	config1 := filepath.Join(tmpDir, "config1.conf")
	config2 := filepath.Join(tmpDir, "config2.conf")

	// config1 includes config2
	content1 := fmt.Sprintf(`VAR1 = value1
include "%s"`, config2)
	if err := os.WriteFile(config1, []byte(content1), 0600); err != nil {
		t.Fatalf("Failed to create config1: %v", err)
	}

	// config2 includes config1 (circular)
	content2 := fmt.Sprintf(`VAR2 = value2
include "%s"`, config1)
	if err := os.WriteFile(config2, []byte(content2), 0600); err != nil {
		t.Fatalf("Failed to create config2: %v", err)
	}

	cfg := &Config{
		values:        make(map[string]string),
		includedFiles: make(map[string]bool),
	}
	cfg.initBuiltins()

	inc := &IncludeDirective{
		Type: "include",
		Path: config1,
	}

	err := cfg.executeInclude(inc)
	if err == nil {
		t.Fatal("Expected circular include error, got nil")
	}

	if !strings.Contains(err.Error(), "circular") {
		t.Errorf("Expected circular include error, got: %v", err)
	}
}

func TestExecuteUse(t *testing.T) {
	cfg := &Config{
		values: make(map[string]string),
	}
	cfg.initBuiltins()

	use := &UseDirective{
		Role: "Manager",
	}

	if err := cfg.executeUse(use); err != nil {
		t.Fatalf("executeUse failed: %v", err)
	}

	if cfg.values["ROLE"] != "Manager" {
		t.Errorf("Expected ROLE=Manager, got %s", cfg.values["ROLE"])
	}
}

func TestExecuteError(t *testing.T) {
	cfg := &Config{
		values: make(map[string]string),
	}
	cfg.initBuiltins()

	errorDir := &ErrorDirective{
		Message: "This is an error",
	}

	err := cfg.executeError(errorDir)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !strings.Contains(err.Error(), "This is an error") {
		t.Errorf("Expected error message 'This is an error', got: %v", err)
	}
}

func TestExecuteWarning(t *testing.T) {
	cfg := &Config{
		values: make(map[string]string),
	}
	cfg.initBuiltins()

	warning := &WarningDirective{
		Message: "This is a warning",
	}

	// Warning should not return an error
	if err := cfg.executeWarning(warning); err != nil {
		t.Fatalf("executeWarning failed: %v", err)
	}
}

func TestNewFromReaderWithParser(t *testing.T) {
	input := `
FOO = bar
BAR = $(FOO)_baz

if defined(FOO)
  COND_VAR = yes
endif
`

	cfg, err := NewFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("NewFromReader failed: %v", err)
	}

	fooVal, _ := cfg.Get("FOO")
	if fooVal != "bar" {
		t.Errorf("Expected FOO=bar, got %s", fooVal)
	}

	barVal, _ := cfg.Get("BAR")
	if barVal != "bar_baz" {
		t.Errorf("Expected BAR=bar_baz, got %s", barVal)
	}

	condVal, _ := cfg.Get("COND_VAR")
	if condVal != "yes" {
		t.Errorf("Expected COND_VAR=yes, got %s", condVal)
	}
}
