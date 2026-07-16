package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadFromEnvironmentProcessesLocalChain is the end-to-end guard for the bug
// where LoadFromEnvironment read only the root config file and silently ignored
// LOCAL_CONFIG_DIR (config.d) and LOCAL_CONFIG_FILE -- so LOG (or any knob)
// defined there fell back to the param default (e.g. LOG=$(LOCAL_DIR)/log). It
// also covers the LOCAL_CONFIG_DIR_EXCLUDE_REGEXP filter and tolerance of a
// missing LOCAL_CONFIG_FILE entry.
func TestLoadFromEnvironmentProcessesLocalChain(t *testing.T) {
	tmp := t.TempDir()
	confd := filepath.Join(tmp, "config.d")
	if err := os.MkdirAll(confd, 0o755); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(tmp, "condor_config")
	missing := filepath.Join(tmp, "absent.local") // never created -> must be tolerated
	localFile := filepath.Join(tmp, "override.local")
	rootBody := strings.Join([]string{
		"LOCAL_DIR = /var",
		"LOG = $(LOCAL_DIR)/log", // the default-shaped value config.d must override
		`LOCAL_CONFIG_DIR_EXCLUDE_REGEXP = .*[.]py$`,
		"LOCAL_CONFIG_DIR = " + confd,
		"REQUIRE_LOCAL_CONFIG_FILE = false",
		"LOCAL_CONFIG_FILE = " + missing + " " + localFile,
		"",
	}, "\n")
	if err := os.WriteFile(root, []byte(rootBody), 0o600); err != nil {
		t.Fatal(err)
	}
	// config.d: a real override plus a decoy script that must be excluded.
	if err := os.WriteFile(filepath.Join(confd, "50-log.config"), []byte("LOG = /var/log/condor\nFROM_DIR = yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confd, "99-helper.py"), []byte("LOG = /EXCLUDED\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// LOCAL_CONFIG_FILE is processed after config.d, so it wins ties.
	if err := os.WriteFile(localFile, []byte("FROM_FILE = yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONDOR_CONFIG", root)
	cfg, err := NewWithOptions(ConfigOptions{Subsystem: "COLLECTOR"})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}

	for key, want := range map[string]string{
		"LOG":       "/var/log/condor", // config.d override, NOT $(LOCAL_DIR)/log
		"FROM_DIR":  "yes",             // config.d was processed
		"FROM_FILE": "yes",             // LOCAL_CONFIG_FILE was processed (missing entry tolerated)
	} {
		if got, _ := cfg.Get(key); got != want {
			t.Errorf("Get(%q) = %q, want %q", key, got, want)
		}
	}
	if got, _ := cfg.Get("LOG"); got == "/EXCLUDED" {
		t.Error("LOG picked up the excluded .py file; LOCAL_CONFIG_DIR_EXCLUDE_REGEXP not honored")
	}
	// A dependent expansion must see the overridden LOG (the reported symptom).
	cfg.Set("ADDR", "$(LOG)/.collector_address")
	if got, _ := cfg.Get("ADDR"); got != "/var/log/condor/.collector_address" {
		t.Errorf("$(LOG) expansion = %q, want /var/log/condor/.collector_address", got)
	}
}

// TestSubsystemLocalNameScoping verifies HTCondor's <SUBSYS>/<LOCALNAME> prefix
// precedence in Get: <SUBSYS>.<LOCALNAME>.<KEY> beats <LOCALNAME>.<KEY> beats
// <SUBSYS>.<KEY> beats the bare <KEY>. This is what lets an htc-collector view
// host (-local-name HTCVIEW) take distinct values under one condor_master.
func TestSubsystemLocalNameScoping(t *testing.T) {
	body := strings.Join([]string{
		"K = plain",
		"COLLECTOR.K = subsys",
		"HTCVIEW.K = local",
		"COLLECTOR.HTCVIEW.K = both",
		"ONLYLOCAL = plain2",
		"HTCVIEW.ONLYLOCAL = local2",
		"EMPTYABLE = someaddr",
		"HTCVIEW.EMPTYABLE =",
		"",
	}, "\n")

	cases := []struct {
		subsys, local, key, want string
	}{
		{"COLLECTOR", "HTCVIEW", "K", "both"},           // most specific wins
		{"COLLECTOR", "", "K", "subsys"},                // subsystem scope
		{"", "HTCVIEW", "K", "local"},                   // local-name scope
		{"", "", "K", "plain"},                          // bare
		{"COLLECTOR", "HTCVIEW", "ONLYLOCAL", "local2"}, // falls through to local scope
		{"COLLECTOR", "", "ONLYLOCAL", "plain2"},        // no subsys-scoped def -> bare
		{"COLLECTOR", "HTCVIEW", "EMPTYABLE", ""},       // an empty scoped value suppresses the bare one
		{"COLLECTOR", "", "EMPTYABLE", "someaddr"},      // other daemons still see the bare value
	}
	for _, tc := range cases {
		cfg, err := NewFromReaderWithOptions(strings.NewReader(body),
			ConfigOptions{Subsystem: tc.subsys, LocalName: tc.local, SkipDefaults: true})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got, _ := cfg.Get(tc.key); got != tc.want {
			t.Errorf("subsys=%q local=%q Get(%q) = %q, want %q", tc.subsys, tc.local, tc.key, got, tc.want)
		}
	}
}
