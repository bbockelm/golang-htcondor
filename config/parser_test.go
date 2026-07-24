package config

import (
	"strings"
	"testing"
)

func TestParseSimpleAssignment(t *testing.T) {
	input := "FOO = bar"
	lex := NewLexer(strings.NewReader(input))

	stmts, err := Parse(lex)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(stmts) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(stmts))
	}

	assignment, ok := stmts[0].(*Assignment)
	if !ok {
		t.Fatalf("Expected Assignment, got %T", stmts[0])
	}

	if assignment.Name != "FOO" {
		t.Errorf("Expected name 'FOO', got %q", assignment.Name)
	}

	if assignment.Value != "bar" {
		t.Errorf("Expected value 'bar', got %q", assignment.Value)
	}
}

func TestParseMultipleAssignments(t *testing.T) {
	input := `
FOO = 123
BAR = hello world
BAZ = $(FOO)
`
	lex := NewLexer(strings.NewReader(input))

	stmts, err := Parse(lex)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(stmts) != 3 {
		t.Fatalf("Expected 3 statements, got %d", len(stmts))
	}

	// Check first assignment
	assignment, ok := stmts[0].(*Assignment)
	if !ok {
		t.Fatalf("Statement 0: Expected Assignment, got %T", stmts[0])
	}
	if assignment.Name != "FOO" || assignment.Value != "123" {
		t.Errorf("Statement 0: Expected FOO=123, got %s=%s", assignment.Name, assignment.Value)
	}

	// Check second assignment
	assignment, ok = stmts[1].(*Assignment)
	if !ok {
		t.Fatalf("Statement 1: Expected Assignment, got %T", stmts[1])
	}
	if assignment.Name != "BAR" {
		t.Errorf("Statement 1: Expected name BAR, got %s", assignment.Name)
	}

	// Check third assignment
	assignment, ok = stmts[2].(*Assignment)
	if !ok {
		t.Fatalf("Statement 2: Expected Assignment, got %T", stmts[2])
	}
	if assignment.Name != "BAZ" {
		t.Errorf("Statement 2: Expected name BAZ, got %s", assignment.Name)
	}
}

func TestParseIfStatement(t *testing.T) {
	input := `
if defined(MASTER)
  PORT = 9618
endif
`
	lex := NewLexer(strings.NewReader(input))

	stmts, err := Parse(lex)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(stmts) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(stmts))
	}

	conditional, ok := stmts[0].(*Conditional)
	if !ok {
		t.Fatalf("Expected Conditional, got %T", stmts[0])
	}

	if conditional.Condition != "defined(MASTER)" {
		t.Errorf("Expected condition 'defined(MASTER)', got %q", conditional.Condition)
	}

	if len(conditional.ThenBlock) != 1 {
		t.Fatalf("Expected 1 statement in then block, got %d", len(conditional.ThenBlock))
	}

	assignment, ok := conditional.ThenBlock[0].(*Assignment)
	if !ok {
		t.Fatalf("Expected Assignment in then block, got %T", conditional.ThenBlock[0])
	}

	if assignment.Name != "PORT" || assignment.Value != "9618" {
		t.Errorf("Expected PORT=9618, got %s=%s", assignment.Name, assignment.Value)
	}
}

func TestParseIncludeDirective(t *testing.T) {
	input := `include "/etc/condor/config.d/*.config"`
	lex := NewLexer(strings.NewReader(input))

	stmts, err := Parse(lex)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(stmts) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(stmts))
	}

	include, ok := stmts[0].(*IncludeDirective)
	if !ok {
		t.Fatalf("Expected IncludeDirective, got %T", stmts[0])
	}

	if include.Type != "include" {
		t.Errorf("Expected type 'include', got %q", include.Type)
	}

	if include.Path != "/etc/condor/config.d/*.config" {
		t.Errorf("Expected path '/etc/condor/config.d/*.config', got %q", include.Path)
	}
}

func TestParseIncludeDirectiveWithColon(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedType string
		expectedPath string
	}{
		{
			name:         "include with colon",
			input:        `include : "/etc/condor/config.d/*.config"`,
			expectedType: "include",
			expectedPath: "/etc/condor/config.d/*.config",
		},
		{
			name:         "include ifexist with colon",
			input:        `include ifexist : "/opt/condor/local.config"`,
			expectedType: "include_ifexist",
			expectedPath: "/opt/condor/local.config",
		},
		{
			name:         "include command with colon",
			input:        `include command : "echo 'VAR = value'"`,
			expectedType: "include_command",
			expectedPath: "echo 'VAR = value'",
		},
		{
			name:         "include with pipe syntax",
			input:        `include : "echo 'VAR = value' |"`,
			expectedType: "include_command",
			expectedPath: "echo 'VAR = value'",
		},
		{
			// HTCondor include paths are unquoted and run to end of line.
			name:         "include unquoted path",
			input:        `include : /etc/condor/config.d/00-common`,
			expectedType: "include",
			expectedPath: "/etc/condor/config.d/00-common",
		},
		{
			// The real-world config that motivated this: an unquoted command
			// with an absolute path, flags, and arguments.
			name:         "include command unquoted with args",
			input:        `include command : /usr/bin/sudo /usr/local/sbin/htcondor/config_sync.sh -d /usr/local/etc/condor -r origin -b master`,
			expectedType: "include_command",
			expectedPath: "/usr/bin/sudo /usr/local/sbin/htcondor/config_sync.sh -d /usr/local/etc/condor -r origin -b master",
		},
		{
			name:         "include ifexist unquoted path",
			input:        `include ifexist : /opt/condor/local.config`,
			expectedType: "include_ifexist",
			expectedPath: "/opt/condor/local.config",
		},
		{
			name:         "include unquoted pipe command",
			input:        `include : /usr/bin/generate-config |`,
			expectedType: "include_command",
			expectedPath: "/usr/bin/generate-config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lex := NewLexer(strings.NewReader(tt.input))
			stmts, err := Parse(lex)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			if len(stmts) != 1 {
				t.Fatalf("Expected 1 statement, got %d", len(stmts))
			}

			include, ok := stmts[0].(*IncludeDirective)
			if !ok {
				t.Fatalf("Expected IncludeDirective, got %T", stmts[0])
			}

			if include.Type != tt.expectedType {
				t.Errorf("Expected type %q, got %q", tt.expectedType, include.Type)
			}

			if include.Path != tt.expectedPath {
				t.Errorf("Expected path %q, got %q", tt.expectedPath, include.Path)
			}
		})
	}
}
