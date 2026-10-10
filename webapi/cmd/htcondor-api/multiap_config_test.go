package main

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

func TestLoadMultiAPConfig(t *testing.T) {
	cfg := config.NewEmpty()
	mc, err := loadMultiAPConfig(cfg, "ap1", "")
	if err != nil || mc.Enabled() {
		t.Fatalf("no constraint: %+v, %v; want single-AP mode", mc, err)
	}

	cfg.Set("HTTP_API_SCHEDD_CONSTRAINT", ` regexp("^ap", Name) `)
	cfg.Set("HTTP_API_HUB_NAME", "hub@db")
	cfg.Set("HTTP_API_MULTI_AP_STALE", "exclude")
	cfg.Set("HTTP_API_JOB_ID_CODEC", "at")
	mc, err = loadMultiAPConfig(cfg, "", "")
	if err != nil || !mc.Enabled() || mc.ScheddConstraint != `regexp("^ap", Name)` ||
		mc.HubName != "hub@db" || mc.Stale != "exclude" || mc.JobIDCodec != "at" {
		t.Fatalf("multi: %+v, %v", mc, err)
	}

	// A named schedd contradicts the constraint: refused, never silently
	// preferred.
	for _, tc := range []struct{ name, addr string }{{"ap1", ""}, {"", "<1.2.3.4:9618>"}} {
		if _, err := loadMultiAPConfig(cfg, tc.name, tc.addr); err == nil || !strings.Contains(err.Error(), "HTTP_API_SCHEDD_CONSTRAINT") {
			t.Errorf("schedd %q addr %q with a constraint: err = %v, want a startup error", tc.name, tc.addr, err)
		}
	}
}
