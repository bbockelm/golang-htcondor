package main

import (
	"strings"
	"testing"
	"time"

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

	if mc.BulkFresh != 0 {
		t.Errorf("BulkFresh unset = %v, want 0 (never skip)", mc.BulkFresh)
	}
	for v, want := range map[string]time.Duration{"30": 30 * time.Second, "0": 0} {
		cfg.Set("HTTP_API_BULK_FRESH_SECONDS", v)
		if mc, err = loadMultiAPConfig(cfg, "", ""); err != nil || mc.BulkFresh != want {
			t.Errorf("HTTP_API_BULK_FRESH_SECONDS=%s: %v, %v; want %v", v, mc.BulkFresh, err, want)
		}
	}
	for _, bad := range []string{"-5", "soon"} {
		cfg.Set("HTTP_API_BULK_FRESH_SECONDS", bad)
		if _, err = loadMultiAPConfig(cfg, "", ""); err == nil {
			t.Errorf("HTTP_API_BULK_FRESH_SECONDS=%s accepted", bad)
		}
	}
	cfg.Set("HTTP_API_BULK_FRESH_SECONDS", "")

	// Hub selection: unset is zero (multiap's defaults); set, it is read.
	if mc.HubSwitchAfter != 0 || mc.HubSwitchMargin != 0 || mc.HubFailAfter != 0 {
		t.Errorf("hub selection unset = %v/%d/%d, want zeros", mc.HubSwitchAfter, mc.HubSwitchMargin, mc.HubFailAfter)
	}
	cfg.Set("HTTP_API_HUB_NAME", "hub-a@db, hub-b@db")
	cfg.Set("HTTP_API_HUB_SWITCH_SECONDS", "90")
	cfg.Set("HTTP_API_HUB_SWITCH_MARGIN", "2")
	cfg.Set("HTTP_API_HUB_FAIL_AFTER", "3")
	cfg.Set("HTTP_API_HUB_SETTLE_SECONDS", "45")
	if mc, err = loadMultiAPConfig(cfg, "", ""); err != nil || mc.HubName != "hub-a@db, hub-b@db" ||
		mc.HubSwitchAfter != 90*time.Second || mc.HubSwitchMargin != 2 || mc.HubFailAfter != 3 || mc.HubSettle != 45*time.Second {
		t.Errorf("hub selection: %+v, %v", mc, err)
	}
	for _, k := range []string{"HTTP_API_HUB_SWITCH_SECONDS", "HTTP_API_HUB_SWITCH_MARGIN", "HTTP_API_HUB_FAIL_AFTER", "HTTP_API_HUB_SETTLE_SECONDS"} {
		cfg.Set(k, "soon")
		if _, err = loadMultiAPConfig(cfg, "", ""); err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s=soon: err = %v, want it refused by name", k, err)
		}
		cfg.Set(k, "")
	}
	cfg.Set("HTTP_API_HUB_NAME", "hub@db")

	// A named schedd contradicts the constraint: refused, never silently
	// preferred.
	for _, tc := range []struct{ name, addr string }{{"ap1", ""}, {"", "<1.2.3.4:9618>"}} {
		if _, err := loadMultiAPConfig(cfg, tc.name, tc.addr); err == nil || !strings.Contains(err.Error(), "HTTP_API_SCHEDD_CONSTRAINT") {
			t.Errorf("schedd %q addr %q with a constraint: err = %v, want a startup error", tc.name, tc.addr, err)
		}
	}
}

func TestLoadAPAssignmentConfig(t *testing.T) {
	cfg := config.NewEmpty()
	cfg.Set("HTTP_API_SCHEDD_CONSTRAINT", `regexp("^ap", Name)`)
	mc, err := loadMultiAPConfig(cfg, "", "")
	if err != nil || len(mc.Assignment.Backends) != 0 || mc.Assignment.Stale != 0 {
		t.Fatalf("unset: %+v %v; want the default chain", mc.Assignment, err)
	}
	cfg.Set("HTTP_API_AP_ASSIGNMENT", "mapfile, rest")
	cfg.Set("HTTP_API_AP_ASSIGNMENT_DEFAULT", " ap01.example.org ")
	cfg.Set("HTTP_API_AP_ASSIGNMENT_MAPFILE", "/etc/condor/assign.map")
	cfg.Set("HTTP_API_AP_ASSIGNMENT_REST_URL", "https://assign.example.org")
	cfg.Set("HTTP_API_AP_ASSIGNMENT_REST_TOKEN_FILE", "/etc/condor/assign.token")
	cfg.Set("HTTP_API_AP_ASSIGNMENT_STALE_SECONDS", "600")
	mc, err = loadMultiAPConfig(cfg, "", "")
	a := mc.Assignment
	if err != nil || strings.Join(a.Backends, ",") != "mapfile,rest" || a.Default != "ap01.example.org" ||
		a.Mapfile != "/etc/condor/assign.map" || a.RESTURL != "https://assign.example.org" ||
		a.RESTTokenFile != "/etc/condor/assign.token" || a.Stale != 10*time.Minute {
		t.Fatalf("set: %+v %v", a, err)
	}
	cfg.Set("HTTP_API_AP_ASSIGNMENT_STALE_SECONDS", "0")
	if mc, err = loadMultiAPConfig(cfg, "", ""); err != nil || mc.Assignment.Stale >= 0 {
		t.Errorf("STALE_SECONDS=0: %v %v; want never covered", mc.Assignment.Stale, err)
	}
	cfg.Set("HTTP_API_AP_ASSIGNMENT_STALE_SECONDS", "an hour")
	if _, err = loadMultiAPConfig(cfg, "", ""); err == nil {
		t.Error("a bad STALE_SECONDS was accepted")
	}
	cfg.Set("HTTP_API_AP_ASSIGNMENT_STALE_SECONDS", "")
	// An unknown backend refuses to start.
	cfg.Set("HTTP_API_AP_ASSIGNMENT", "mapfile, ldap")
	if _, err = loadMultiAPConfig(cfg, "", ""); err == nil || !strings.Contains(err.Error(), "ldap") {
		t.Errorf("unknown backend: %v", err)
	}
}
