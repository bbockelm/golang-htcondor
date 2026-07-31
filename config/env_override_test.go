package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCondorEnvOverridesConfigFile is the regression guard for issue #168: a
// _CONDOR_<PARAM> environment variable must override the value of <PARAM> read
// from the on-disk configuration, matching condor_config_val. condor_config's
// real_config inserts environment macros only after every configuration file has
// been processed, so an env var has higher precedence than a config file.
func TestCondorEnvOverridesConfigFile(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "condor_config")
	body := "SHARED_PORT_PORT = 9620\nONLY_IN_FILE = fromfile\n"
	if err := os.WriteFile(root, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONDOR_CONFIG", root)
	t.Setenv("_CONDOR_SHARED_PORT_PORT", "9621")

	cfg, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got, _ := cfg.Get("SHARED_PORT_PORT"); got != "9621" {
		t.Errorf("Get(SHARED_PORT_PORT) = %q, want 9621 (env must override the config file)", got)
	}
	// A param the environment does not set must still come from the file.
	if got, _ := cfg.Get("ONLY_IN_FILE"); got != "fromfile" {
		t.Errorf("Get(ONLY_IN_FILE) = %q, want fromfile", got)
	}
}

// TestCondorEnvOverridesConfigDir confirms the env override also beats a value
// set in the LOCAL_CONFIG_DIR (config.d) chain, not just the root config -- the
// env macros are applied after the whole file chain, including config.d.
func TestCondorEnvOverridesConfigDir(t *testing.T) {
	tmp := t.TempDir()
	confd := filepath.Join(tmp, "config.d")
	if err := os.MkdirAll(confd, 0o750); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(tmp, "condor_config")
	if err := os.WriteFile(root, []byte("LOCAL_CONFIG_DIR = "+confd+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confd, "50-port.config"),
		[]byte("SHARED_PORT_PORT = 9620\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONDOR_CONFIG", root)
	t.Setenv("_CONDOR_SHARED_PORT_PORT", "9621")

	cfg, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got, _ := cfg.Get("SHARED_PORT_PORT"); got != "9621" {
		t.Errorf("Get(SHARED_PORT_PORT) = %q, want 9621 (env must override config.d)", got)
	}
}

// TestCondorEnvLocalConfigDirOverridesValueButNotScan pins the asymmetric
// behavior of _condor_LOCAL_CONFIG_DIR, which matches condor_config's
// real_config: environment macros are inserted only AFTER the config.d scan has
// already run, so a _CONDOR_LOCAL_CONFIG_DIR env var overrides the *value* of
// LOCAL_CONFIG_DIR but does NOT cause the directory it names to be scanned. The
// directory actually scanned is the one the config *files* named.
//
//   - fileConfd  is named by the root config's LOCAL_CONFIG_DIR -> IS scanned
//   - envConfd   is named only by _CONDOR_LOCAL_CONFIG_DIR      -> is NOT scanned
func TestCondorEnvLocalConfigDirOverridesValueButNotScan(t *testing.T) {
	tmp := t.TempDir()
	fileConfd := filepath.Join(tmp, "file.d")
	envConfd := filepath.Join(tmp, "env.d")
	for _, d := range []string{fileConfd, envConfd} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}

	root := filepath.Join(tmp, "condor_config")
	if err := os.WriteFile(root, []byte("LOCAL_CONFIG_DIR = "+fileConfd+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A marker in each directory's config.d, so we can tell which was scanned.
	if err := os.WriteFile(filepath.Join(fileConfd, "50-x.config"),
		[]byte("FROM_FILE_DIR = yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(envConfd, "50-y.config"),
		[]byte("FROM_ENV_DIR = yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONDOR_CONFIG", root)
	t.Setenv("_CONDOR_LOCAL_CONFIG_DIR", envConfd)

	cfg, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The env var overrides the VALUE of LOCAL_CONFIG_DIR...
	if got, _ := cfg.Get("LOCAL_CONFIG_DIR"); got != envConfd {
		t.Errorf("Get(LOCAL_CONFIG_DIR) = %q, want %q (env overrides the value)", got, envConfd)
	}
	// ...but the directory that was actually SCANNED is the file-configured one
	// (the env var comes too late to influence the scan).
	if got, _ := cfg.Get("FROM_FILE_DIR"); got != "yes" {
		t.Errorf("Get(FROM_FILE_DIR) = %q, want yes: the file-configured config.d must still be scanned", got)
	}
	// The env-named directory must NOT have been scanned.
	if got, ok := cfg.Get("FROM_ENV_DIR"); ok && got != "" {
		t.Errorf("Get(FROM_ENV_DIR) = %q: the _CONDOR_LOCAL_CONFIG_DIR directory must NOT be scanned", got)
	}
}

// TestCondorEnvOverrideAppliesWithoutConfigFile guards the ONLY_ENV path: env
// overrides must still be applied when no configuration file is read, since they
// are applied after the (here empty) file chain rather than before it.
func TestCondorEnvOverrideAppliesWithoutConfigFile(t *testing.T) {
	t.Setenv("CONDOR_CONFIG", "ONLY_ENV")
	t.Setenv("_CONDOR_SHARED_PORT_PORT", "9622")

	cfg, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got, _ := cfg.Get("SHARED_PORT_PORT"); got != "9622" {
		t.Errorf("Get(SHARED_PORT_PORT) = %q, want 9622 (env must apply even with ONLY_ENV)", got)
	}
}
