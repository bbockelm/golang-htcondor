package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A demo pool lives entirely under a temporary directory, which on
// Linux is /tmp -- and DAGMan treats a default node log under /tmp as a
// fatal error. Every workflow submitted to a demo aborted in its first
// second, before a node was submitted, with the reason only in the
// manager job's own log.
func TestMiniCondorConfigLetsDAGManKeepItsNodeLogUnderTmp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "condor_config")
	if err := writeMiniCondorConfig(path, t.TempDir(), "/usr", nil); err != nil {
		t.Fatalf("writeMiniCondorConfig: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the config: %v", err)
	}
	if !strings.Contains(string(body), "DAGMAN_AVOID_SLASH_TMP = FALSE") {
		t.Errorf("the demo config does not relax DAGMan's /tmp check, so every DAG aborts:\n%s", body)
	}
}

// DAGMan only reads that config because the manager job is handed
// CONDOR_CONFIG. The schedd gives a scheduler-universe job only the
// environment its own ad carries -- it does not inherit the server's --
// so without this condor_dagman reads the SYSTEM configuration: a
// different pool, different directories, and nothing to say so.
func TestDemoDagmanEnvironmentNamesThisDemosConfig(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "condor_config")
	env := demoDagmanEnvironment(configFile)

	got, ok := env["CONDOR_CONFIG"]
	if !ok {
		t.Fatalf("CONDOR_CONFIG is not in the DAGMan environment: %v", env)
	}
	if got != configFile {
		t.Errorf("CONDOR_CONFIG = %q, want this demo's own config %q", got, configFile)
	}
}

// An empty value would be worse than none: it names a config file that
// does not exist rather than falling back to the system one.
func TestDemoDagmanEnvironmentIsEmptyWithoutAConfigFile(t *testing.T) {
	if env := demoDagmanEnvironment(""); len(env) != 0 {
		t.Errorf("want no environment without a config file, got %v", env)
	}
}
