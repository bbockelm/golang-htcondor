package config

import (
	"path/filepath"
	"testing"
)

// TestConfigFileOptionIgnoresEnvironment shows ConfigOptions.ConfigFile is read
// instead of $CONDOR_CONFIG, with its local configuration chain, and that
// CONFIG_ROOT follows it.
func TestConfigFileOptionIgnoresEnvironment(t *testing.T) {
	envDir := t.TempDir()
	envRoot := filepath.Join(envDir, "condor_config")
	writeFile(t, envRoot, "WHICH = env\nONLY_IN_ENV = yes\n")
	t.Setenv("CONDOR_CONFIG", envRoot)

	tmp := t.TempDir()
	localDir := filepath.Join(tmp, "config.d")
	mkdirs(t, localDir)
	root := filepath.Join(tmp, "condor_config")
	writeFile(t, root, "WHICH = explicit\nLOCAL_CONFIG_DIR = "+localDir+"\n")
	writeFile(t, filepath.Join(localDir, "10-extra.conf"), "FROM_LOCAL_DIR = yes\n")

	cfg, err := NewWithOptions(ConfigOptions{ConfigFile: root})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	if v, _ := cfg.Get("WHICH"); v != "explicit" {
		t.Errorf("WHICH = %q, want explicit", v)
	}
	if _, ok := cfg.Get("ONLY_IN_ENV"); ok {
		t.Error("ONLY_IN_ENV is set: the $CONDOR_CONFIG file was read")
	}
	if v, _ := cfg.Get("FROM_LOCAL_DIR"); v != "yes" {
		t.Errorf("FROM_LOCAL_DIR = %q, want yes (local chain not read)", v)
	}
	if v, _ := cfg.Get("CONFIG_ROOT"); v != tmp {
		t.Errorf("CONFIG_ROOT = %q, want %q", v, tmp)
	}

	// A missing explicit file is an error, not a silent fall back to the
	// environment's.
	if _, err := NewWithOptions(ConfigOptions{ConfigFile: filepath.Join(tmp, "missing")}); err == nil {
		t.Error("missing ConfigFile loaded without error")
	}
}
