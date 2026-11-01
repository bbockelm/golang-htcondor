package config

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The platform macros are host-dependent, so they cannot be pinned to literal
// values the way the rest of this package's parity expectations are: ARCH is
// "arm64" on one machine and "X86_64" on another. They are compared against
// condor_config_val instead, which means this test does real work exactly
// where it matters -- the Linux CI containers, whose values nobody can check
// by hand from a Mac.
//
// It is the test that would have caught the bug it was written for: this
// package reported OPSYS=OSX, which is HTCondor's OPSYSLEGACY, while a modern
// macOS machine advertises OPSYS=macOS. Harmless while nothing compared the
// value, and a job that matches no machine once condor_submit pins
// TARGET.OpSys to it.
var platformMacros = []string{
	"ARCH",
	"OPSYS",
	"OPSYSVER",
	"OPSYSMAJORVER",
	"OPSYSANDVER",
	"OPSYSNAME",
	"OPSYSSHORTNAME",
	"OPSYSLONGNAME",
	"OPSYSLEGACY",
	"UNAME_ARCH",
	"UNAME_OPSYS",
	"UTSNAME_SYSNAME",
	"UTSNAME_RELEASE",
	"UTSNAME_VERSION",
	"UTSNAME_MACHINE",
}

// condorConfigVal asks the real tool for a macro, with no configuration file
// so that both sides are answering from detection alone. A macro the tool does
// not define comes back as "Not defined: NAME", which is reported as unset.
func condorConfigVal(t *testing.T, name string) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// The name is one of platformMacros, not caller input.
	cmd := exec.CommandContext(ctx, "condor_config_val", name) //nolint:gosec
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG=/dev/null")
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	value := strings.TrimSpace(string(out))
	if value == "" || strings.HasPrefix(value, "Not defined:") {
		return "", false
	}
	return value, true
}

func TestPlatformMacrosMatchCondorConfigVal(t *testing.T) {
	if _, err := exec.LookPath("condor_config_val"); err != nil {
		// A skip is the right answer on a machine with no HTCondor, and the
		// wrong one in the container that has it: this is the only check of
		// the Linux values, so a silent skip there would report a comparison
		// that never happened. The Docker test job sets this to say the tool
		// must be present.
		if os.Getenv("HTCONDOR_REQUIRE_CONFIG_ORACLE") != "" {
			t.Fatal("condor_config_val is not on PATH, but HTCONDOR_REQUIRE_CONFIG_ORACLE says it should be")
		}
		t.Skip("condor_config_val not available")
	}

	c := NewEmpty()
	for _, name := range platformMacros {
		want, wantSet := condorConfigVal(t, name)
		got, gotSet := c.Get(name)
		switch {
		case !wantSet && !gotSet:
			// Neither side has it, which is a match: UTSNAME_* on Windows,
			// or a version HTCondor could not determine either.
		case !wantSet:
			t.Errorf("%s = %q here, but condor_config_val defines no such macro", name, got)
		case !gotSet:
			t.Errorf("%s is unset here; condor_config_val says %q", name, want)
		case got != want:
			t.Errorf("%s = %q, condor_config_val says %q", name, got, want)
		}
	}
}

// The two names this package used to invent are not HTCondor's, so a config
// file referring to either got nothing. Nothing should define them now.
func TestInventedPlatformMacroNamesAreGone(t *testing.T) {
	c := NewEmpty()
	for _, name := range []string{"OPSYS_VER", "OPSYS_AND_VER"} {
		if v, ok := c.Get(name); ok {
			t.Errorf("%s = %q is defined; HTCondor spells it without the underscores", name, v)
		}
	}
}
