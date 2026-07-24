package config

import (
	"strings"
	"testing"
)

// TestMacroExpansionSubsystemScoping verifies macro expansion honors the same
// subsystem/local-name scoping that Get() does, matching HTCondor. The
// motivating case is the predefined Is<Subsystem> family (param_defaults:
// IsMaster=false, MASTER.IsMaster=true, ...): `if $(IsMaster)` must be true
// only under SUBSYSTEM=MASTER, and a `SUBSYS.KNOB` override must reach `$(KNOB)`.
func TestMacroExpansionSubsystemScoping(t *testing.T) {
	// The Is<Subsystem> booleans: true only for the matching subsystem.
	isCases := []struct {
		subsys string
		macro  string
		want   string
	}{
		{"MASTER", "IsMaster", "true"},
		{"COLLECTOR", "IsCollector", "true"},
		{"SCHEDD", "IsSchedd", "true"},
		{"STARTD", "IsStartd", "true"},
		{"NEGOTIATOR", "IsNegotiator", "true"},
		// A non-daemon subsystem sees them all false -- the htcondordb case, where
		// `if $(IsMaster)` correctly skips a master-only block.
		{"HTCONDORDB", "IsMaster", "false"},
		{"HTCONDORDB", "IsCollector", "false"},
		{"COLLECTOR", "IsMaster", "false"},
	}
	for _, tc := range isCases {
		cfg, err := NewFromReaderWithOptions(strings.NewReader(""), ConfigOptions{Subsystem: tc.subsys})
		if err != nil {
			t.Fatal(err)
		}
		got, _ := cfg.expandMacrosWithFunctions("$(" + tc.macro + ")")
		if got != tc.want {
			t.Errorf("subsys=%s: $(%s) expanded to %q, want %q", tc.subsys, tc.macro, got, tc.want)
		}
		// Expansion must agree with Get(), which already scopes.
		if viaGet, _ := cfg.Get(tc.macro); viaGet != tc.want {
			t.Errorf("subsys=%s: Get(%s)=%q, want %q", tc.subsys, tc.macro, viaGet, tc.want)
		}
	}

	// A user-defined SUBSYS.KNOB override must reach $(KNOB) during expansion.
	cfg, err := NewFromReaderWithOptions(strings.NewReader(
		"FOO = base\nMASTER.FOO = master-only\n"), ConfigOptions{Subsystem: "MASTER"})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := cfg.expandMacrosWithFunctions("$(FOO)"); got != "master-only" {
		t.Errorf("$(FOO) under MASTER expanded to %q, want %q (scoped override missed)", got, "master-only")
	}
	// A different subsystem falls back to the unscoped value.
	cfg2, err := NewFromReaderWithOptions(strings.NewReader(
		"FOO = base\nMASTER.FOO = master-only\n"), ConfigOptions{Subsystem: "SCHEDD"})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := cfg2.expandMacrosWithFunctions("$(FOO)"); got != "base" {
		t.Errorf("$(FOO) under SCHEDD expanded to %q, want %q (should not see MASTER scope)", got, "base")
	}
}

// TestIfIsMasterConditional exercises the end-to-end conditional: a master-only
// block guarded by `if $(IsMaster)` runs under MASTER and is skipped otherwise.
func TestIfIsMasterConditional(t *testing.T) {
	const cfgText = `if $(IsMaster)
  MASTER_ONLY = yes
endif
`
	for _, tc := range []struct {
		subsys  string
		wantSet bool
	}{
		{"MASTER", true},
		{"HTCONDORDB", false},
		{"SCHEDD", false},
	} {
		cfg, err := NewFromReaderWithOptions(strings.NewReader(cfgText), ConfigOptions{Subsystem: tc.subsys})
		if err != nil {
			t.Fatalf("subsys=%s: %v", tc.subsys, err)
		}
		_, ok := cfg.Get("MASTER_ONLY")
		if ok != tc.wantSet {
			t.Errorf("subsys=%s: MASTER_ONLY set=%v, want %v", tc.subsys, ok, tc.wantSet)
		}
	}
}
