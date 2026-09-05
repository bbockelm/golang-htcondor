package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIsDefaultSeparatesSiteConfigFromBuiltins covers the distinction the
// admin config view needs: HTCondor ships thousands of parameters, and an
// operator reading that page cares about the handful their deployment
// actually set.
func TestIsDefaultSeparatesSiteConfigFromBuiltins(t *testing.T) {
	cfg := NewEmpty()

	// Pick a knob that comes from param_info.in rather than hardcoding a
	// value, so this test doesn't break when upstream defaults move.
	var key, builtin string
	for _, candidate := range []string{"MAX_JOBS_RUNNING", "SCHEDD_INTERVAL", "UPDATE_INTERVAL"} {
		if v, ok := cfg.DefaultValue(candidate); ok {
			key, builtin = candidate, v
			break
		}
	}
	if key == "" {
		t.Skip("no known param default present in this build")
	}

	if !cfg.IsDefault(key) {
		t.Errorf("%s should be default on a fresh config", key)
	}

	cfg.Set(key, builtin+"-changed")
	if cfg.IsDefault(key) {
		t.Errorf("%s should not be default after being set", key)
	}
	if got, _ := cfg.DefaultValue(key); got != builtin {
		t.Errorf("DefaultValue changed after Set: got %q want %q", got, builtin)
	}

	// Setting it back to the built-in string makes it default again. This
	// is deliberate: the question the UI asks is "does this differ from
	// what HTCondor ships", not "did someone type it somewhere".
	cfg.Set(key, builtin)
	if !cfg.IsDefault(key) {
		t.Errorf("%s should be default again after being set back", key)
	}
}

func TestIsDefaultForUnknownKey(t *testing.T) {
	cfg := NewEmpty()
	// A key HTCondor never heard of exists only because someone defined
	// it, so it is by definition not a default.
	cfg.Set("SOME_SITE_LOCAL_KNOB", "value")
	if cfg.IsDefault("SOME_SITE_LOCAL_KNOB") {
		t.Errorf("a key with no built-in default must not report as default")
	}
	if _, ok := cfg.DefaultValue("SOME_SITE_LOCAL_KNOB"); ok {
		t.Errorf("DefaultValue should report no default for an unknown key")
	}
}

func TestIsDefaultIsCaseInsensitive(t *testing.T) {
	// HTCondor parameter names are case-insensitive, and the admin view
	// renders whatever spelling the config file used.
	cfg := NewEmpty()
	if _, ok := cfg.DefaultValue("MAX_JOBS_RUNNING"); !ok {
		t.Skip("MAX_JOBS_RUNNING not present in this build")
	}
	if !cfg.IsDefault("max_jobs_running") {
		t.Errorf("lower-cased lookup should find the same default")
	}
	cfg.Set("Max_Jobs_Running", "1")
	if cfg.IsDefault("MAX_JOBS_RUNNING") {
		t.Errorf("a mixed-case Set should mark the same key non-default")
	}
}

// TestIsDefaultAfterConfigFileLoad is the path that actually matters: values
// arriving from a condor_config file must read as non-default.
func TestIsDefaultAfterConfigFileLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "condor_config")
	if err := os.WriteFile(path, []byte("MAX_JOBS_RUNNING = 4242\n"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("CONDOR_CONFIG", path)

	cfg, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := cfg.DefaultValue("MAX_JOBS_RUNNING"); !ok {
		t.Skip("MAX_JOBS_RUNNING not present in this build")
	}
	if v, _ := cfg.Get("MAX_JOBS_RUNNING"); v != "4242" {
		t.Fatalf("config file not loaded: MAX_JOBS_RUNNING=%q", v)
	}
	if cfg.IsDefault("MAX_JOBS_RUNNING") {
		t.Errorf("a value set by the config file must not read as default")
	}

	// And an untouched neighbour still does, or the filter would show
	// everything and be useless.
	untouched := 0
	for _, k := range cfg.Keys() {
		if cfg.IsDefault(k) {
			untouched++
		}
	}
	if untouched == 0 {
		t.Errorf("no key reported as default; the snapshot is not working")
	}
	t.Logf("%d of %d keys still at their built-in default", untouched, len(cfg.Keys()))
}

// TestSkipDefaultsHasNoOpinion pins that a Config built without the built-in
// table does not claim everything is non-default.
func TestSkipDefaultsHasNoOpinion(t *testing.T) {
	cfg, err := NewWithOptions(ConfigOptions{SkipDefaults: true})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	cfg.Set("ANYTHING", "x")
	if cfg.IsDefault("ANYTHING") {
		t.Errorf("IsDefault must be false when there is no baseline to compare against")
	}
	if _, ok := cfg.DefaultValue("ANYTHING"); ok {
		t.Errorf("DefaultValue must report nothing when defaults were skipped")
	}
}
