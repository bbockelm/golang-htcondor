package main

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver"
)

// TestLoadRevocationOracles pins how HTTP_API_OAUTH2_REVOCATION_ORACLES maps
// onto the three states the httpserver package distinguishes.
//
// The condor config system cannot tell "set to blank" from "not set", and both
// arrive here as an empty string. That ambiguity is why "none" exists as an
// explicit spelling: for a security control, quietly resolving a blank value
// into "you get the defaults" is the wrong default, and quietly resolving it
// into "no oracles at all" is worse. So blank means defaults, and turning
// everything off has to be said out loud.
func TestLoadRevocationOracles(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}

	load := func(t *testing.T, value string, set bool) []string {
		t.Helper()
		cfg := config.NewEmpty()
		if set {
			cfg.Set("HTTP_API_OAUTH2_REVOCATION_ORACLES", value)
		}
		return loadRevocationOracles(cfg, logger)
	}

	t.Run("unset means defaults", func(t *testing.T) {
		if got := load(t, "", false); got != nil {
			t.Errorf("got %v, want nil (nil selects the package defaults)", got)
		}
	})

	t.Run("blank means defaults, not none", func(t *testing.T) {
		for _, blank := range []string{"", "   ", "\t"} {
			if got := load(t, blank, true); got != nil {
				t.Errorf("value %q gave %v, want nil", blank, got)
			}
		}
	})

	t.Run("none means an empty non-nil slice", func(t *testing.T) {
		// Non-nil is the whole point: httpserver reads nil as "defaults"
		// and empty-non-nil as "none", so returning nil here would
		// silently re-enable the oracles the operator just turned off.
		got := load(t, "none", true)
		if got == nil {
			t.Fatalf("got nil, want an empty non-nil slice")
		}
		if len(got) != 0 {
			t.Errorf("got %v, want empty", got)
		}
	})

	t.Run("none is recognized case-insensitively and among others", func(t *testing.T) {
		for _, value := range []string{"NONE", "None", "schedd-acl, none"} {
			got := load(t, value, true)
			if got == nil || len(got) != 0 {
				t.Errorf("value %q gave %v, want an empty non-nil slice", value, got)
			}
		}
	})

	t.Run("names pass through", func(t *testing.T) {
		got := load(t, "schedd-userrec, schedd-acl", true)
		if strings.Join(got, ",") != "schedd-userrec,schedd-acl" {
			t.Errorf("got %v", got)
		}
	})

	t.Run("unknown names pass through for httpserver to reject", func(t *testing.T) {
		// Deliberately not validated here: httpserver logs and skips
		// unknown names, so a typo degrades one defense-in-depth layer
		// instead of stopping the daemon from starting.
		got := load(t, "nonsense", true)
		if strings.Join(got, ",") != "nonsense" {
			t.Errorf("got %v, want the name passed through", got)
		}
	})

	t.Run("the strict oracle name is routable", func(t *testing.T) {
		got := load(t, httpserver.OracleScheddUserRecStrict, true)
		if strings.Join(got, ",") != "schedd-userrec-strict" {
			t.Errorf("got %v", got)
		}
	})
}
