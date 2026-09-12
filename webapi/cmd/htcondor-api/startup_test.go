package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig lays down a root config (plus optional config.d files) and
// points CONDOR_CONFIG at it.
func writeConfig(t *testing.T, root string, dropins map[string]string) {
	t.Helper()
	dir := t.TempDir()
	confDir := filepath.Join(dir, "config.d")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "LOCAL_CONFIG_DIR = " + confDir + "\n" + root
	path := filepath.Join(dir, "condor_config")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, content := range dropins {
		if err := os.WriteFile(filepath.Join(confDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CONDOR_CONFIG", path)
}

// A configuration that cannot be parsed must stop the daemon.
//
// It used to log a warning and continue with an empty config, which is
// worse than not starting: UID_DOMAIN and TRUST_DOMAIN silently become
// the local hostname, the signing key and schedd are wherever the
// compiled defaults point, and every authorization decision is then
// made against configuration the operator never wrote.
func TestConfigParseFailureRefusesToStart(t *testing.T) {
	writeConfig(t, "", map[string]string{"99-broken.conf": "THIS IS NOT VALID = = =\n"})

	cfg, err := loadConfigWithDefaults()
	if err == nil {
		t.Fatal("a config that cannot be parsed was accepted")
	}
	if cfg != nil {
		t.Error("a config was returned alongside the error")
	}
	if !strings.Contains(err.Error(), "99-broken.conf") {
		t.Errorf("the error does not name the offending file: %v", err)
	}
}

// A CONDOR_CONFIG naming a file that is not there is an error, the same
// answer condor_config_val gives:
//
//	File specified in CONDOR_CONFIG environment variable:
//	"/tmp/definitely-not-there" does not exist.
//
// (Having no configuration at all -- nothing in the environment and
// nothing on the default search path -- is separate, and the config
// package returns no error for it, so a development box with no
// HTCondor install still starts. That belongs to the loader's tests,
// not here, because it depends on what is installed on the machine
// running the test.)
func TestMissingConfigFileIsAnError(t *testing.T) {
	t.Setenv("CONDOR_CONFIG", filepath.Join(t.TempDir(), "does-not-exist"))

	if _, err := loadConfigWithDefaults(); err == nil {
		t.Error("a CONDOR_CONFIG pointing at a missing file was accepted")
	}
}

// With no HTTP_API_LOG the daemon logs to $(LOG)/HttpApiLog, the C++
// convention. It used to log to stdout, which condor_master discards --
// so a master-started daemon produced no diagnostics anywhere, which is
// exactly how an operator ends up with a daemon that exits 1 in silence.
func TestLoggerDefaultsToTheLogDirectory(t *testing.T) {
	logDir := t.TempDir()
	writeConfig(t, "LOG = "+logDir+"\n", nil)

	cfg, err := loadConfigWithDefaults()
	if err != nil {
		t.Fatalf("loadConfigWithDefaults: %v", err)
	}
	logger, err := createLogger(cfg)
	if err != nil {
		t.Fatalf("createLogger: %v", err)
	}
	_ = logger

	want := filepath.Join(logDir, "HttpApiLog")
	if _, err := os.Stat(want); err != nil {
		t.Errorf("no log file at %s: %v", want, err)
	}
}

// Under condor_master an unwritable log file is fatal rather than a
// silent fall back to stdout: the master discards stdout, so falling
// back means the daemon runs -- or fails -- with its diagnostics going
// nowhere at all.
func TestUnwritableLogIsFatalUnderCondorMaster(t *testing.T) {
	writeConfig(t, "HTTP_API_LOG = /proc/definitely-not-writable/HttpApiLog\n", nil)
	t.Setenv("CONDOR_INHERIT", "1234 <127.0.0.1:9618>")

	cfg, err := loadConfigWithDefaults()
	if err != nil {
		t.Fatalf("loadConfigWithDefaults: %v", err)
	}
	if _, err := createLogger(cfg); err == nil {
		t.Fatal("an unwritable log file was accepted while running under condor_master")
	} else if !strings.Contains(err.Error(), "condor_master") {
		t.Errorf("the error does not explain why stdout is not an option: %v", err)
	}
}

// Standalone, the same unwritable path still falls back to stdout: a
// developer running the binary by hand can see the output, so there is
// somewhere for it to go.
func TestUnwritableLogFallsBackWhenStandalone(t *testing.T) {
	writeConfig(t, "HTTP_API_LOG = /proc/definitely-not-writable/HttpApiLog\n", nil)
	t.Setenv("CONDOR_INHERIT", "")

	cfg, err := loadConfigWithDefaults()
	if err != nil {
		t.Fatalf("loadConfigWithDefaults: %v", err)
	}
	logger, err := createLogger(cfg)
	if err != nil {
		t.Fatalf("standalone should fall back to stdout, got: %v", err)
	}
	_ = logger
}

// A failure before the logger exists still has to be findable.
//
// condor_master discards a daemon's stdout and stderr, so a daemon that
// dies during config load leaves nothing behind -- the master records
// only that it exited. That is what an unparseable config produced: the
// parse failure takes $(LOG) down with it, so even the fallback had
// nowhere to write.
func TestStartupFailureIsWrittenToTheLogFile(t *testing.T) {
	logDir := t.TempDir()
	writeConfig(t, "LOG = "+logDir+"\n", map[string]string{
		"95-broken.conf": "BROKEN_$(UNCLOSED = x\n",
	})

	_, err := loadConfigWithDefaults()
	if err == nil {
		t.Fatal("the broken config was accepted")
	}
	reportStartupFailureToLog(err)

	logFile := filepath.Join(logDir, "HttpApiLog")
	b, readErr := os.ReadFile(logFile)
	if readErr != nil {
		t.Fatalf("nothing was written to %s: %v", logFile, readErr)
	}
	if !strings.Contains(string(b), "FATAL") || !strings.Contains(string(b), "95-broken.conf") {
		t.Errorf("the log does not carry the reason: %s", b)
	}
}
