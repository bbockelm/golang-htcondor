package config

import (
	"strings"
	"testing"
)

// A parameter NAME may contain a macro reference; HTCondor expands the
// left-hand side before storing. The shipped metaknobs rely on it --
// $FEATURE.ScheddUsermapFile is
//
//	SCHEDD_CLASSAD_USER_MAP_NAMES = $(SCHEDD_CLASSAD_USER_MAP_NAMES) $(1)
//	CLASSAD_USER_MAPFILE_$(1) = $(2)
//
// so `use FEATURE : AssignAccountingGroup(<map>)` could not be parsed at
// all. The failure took the whole config file with it, and the daemon
// then ran on compiled-in defaults.
func TestMacroReferenceInParameterName(t *testing.T) {
	cases := []struct {
		name   string
		config string
		want   map[string]string
	}{
		{
			name:   "simple suffix",
			config: "NAME = one\nCLASSAD_USER_MAPFILE_$(NAME) = /etc/map\n",
			want:   map[string]string{"CLASSAD_USER_MAPFILE_one": "/etc/map"},
		},
		{
			name:   "macro in the middle",
			config: "A = x\nPREFIX_$(A)_SUFFIX = v\n",
			want:   map[string]string{"PREFIX_x_SUFFIX": "v"},
		},
		{
			name:   "whole name from a macro",
			config: "K = DYNAMIC_KEY\n$(K) = value\n",
			want:   map[string]string{"DYNAMIC_KEY": "value"},
		},
		{
			name:   "nested reference",
			config: "INNER = A\nOUTER_A = picked\nX_$(OUTER_$(INNER)) = done\n",
			want:   map[string]string{"X_picked": "done"},
		},
		{
			name:   "two references in one name",
			config: "A = 1\nB = 2\nP_$(A)_$(B) = both\n",
			want:   map[string]string{"P_1_2": "both"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewFromReader(strings.NewReader(tc.config))
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			for k, want := range tc.want {
				got, ok := c.Get(k)
				if !ok {
					t.Errorf("%s is not defined; the name did not expand", k)
					continue
				}
				if got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
		})
	}
}

// The real thing: the metaknob chain an OSPool access point actually
// uses. condor_config_val resolves these; so must we.
func TestAssignAccountingGroupMetaknob(t *testing.T) {
	c, err := NewFromReader(strings.NewReader(
		"use FEATURE : AssignAccountingGroup(/etc/condor/project-map.txt)\n"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if got, _ := c.Get("CLASSAD_USER_MAPFILE_AssignAccountingGroup"); got != "/etc/condor/project-map.txt" {
		t.Errorf("CLASSAD_USER_MAPFILE_AssignAccountingGroup = %q, want the map file", got)
	}
	if got, _ := c.Get("SCHEDD_CLASSAD_USER_MAP_NAMES"); !strings.Contains(got, "AssignAccountingGroup") {
		t.Errorf("SCHEDD_CLASSAD_USER_MAP_NAMES = %q, want it to name the map", got)
	}
	if got, _ := c.Get("JOB_TRANSFORM_NAMES"); !strings.Contains(got, "AssignAccountingGroup") {
		t.Errorf("JOB_TRANSFORM_NAMES = %q, want the transform", got)
	}
}

// An unterminated reference is refused, and on ITS line.
//
// A macro reference does not span lines, so the lexer stops at the
// newline rather than swallowing the rest of the file looking for a
// ')'. Reporting it there matters: the error used to surface as a
// complaint about the NEXT statement, sending the reader to the wrong
// line. condor_config_val refuses the same file with "Illegal
// Identifier: <BAD_$(UNCLOSED>" at line 1.
//
// Parsed in HTCondor-compat mode because that is what the daemons use;
// the library's lenient default drops unparseable lines by design.
func TestUnterminatedMacroReferenceInNameIsRefusedOnItsLine(t *testing.T) {
	lex := NewLexer(strings.NewReader("BAD_$(UNCLOSED = x\nGOOD = kept\n"))
	_, err := ParseStrict(lex)
	if err == nil {
		t.Fatal("an unterminated macro reference in a parameter name was accepted")
	}
	if !strings.Contains(err.Error(), "line 1") {
		t.Errorf("error points at the wrong line: %v", err)
	}
}
