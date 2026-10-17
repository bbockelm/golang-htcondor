package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/cedar/commands"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

// writeDaemonConfig writes CONDOR_CONFIG for a test daemon.
func writeDaemonConfig(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("LOCAL_CONFIG_FILE =\nLOCAL_CONFIG_DIR =\n"+text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newConfigDaemon(t *testing.T, text string) (*Daemon, string) {
	t.Helper()
	cfgFile := filepath.Join(t.TempDir(), "condor_config")
	writeDaemonConfig(t, cfgFile, text)
	t.Setenv("CONDOR_CONFIG", cfgFile)
	cfg, err := config.NewWithOptions(config.ConfigOptions{Subsystem: "TESTD"})
	if err != nil {
		t.Fatal(err)
	}
	log, err := logging.New(&logging.Config{OutputPath: filepath.Join(t.TempDir(), "log")})
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(Options{Subsys: "TESTD", Config: cfg, Logger: log, ShutdownGrace: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return d, cfgFile
}

// A security config built before a reconfig maps SciTokens through the
// CERTIFICATE_MAPFILE the reconfig names, and a reconfig re-reads the files
// the map file includes.
func TestServerSecurityConfigSciTokensFollowReconfig(t *testing.T) {
	dir := t.TempDir()
	inc := filepath.Join(dir, "included")
	if err := os.WriteFile(inc, []byte(`SCITOKENS /^https:\/\/issuer\.example,(.*)$/ \1`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mapPath := filepath.Join(dir, "certificate_mapfile")
	if err := os.WriteFile(mapPath, []byte("@include "+inc+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	d, cfgFile := newConfigDaemon(t, "")
	sc, err := d.ServerSecurityConfig(commands.DC_NOP, "DEFAULT")
	if err != nil {
		t.Fatal(err)
	}
	const name = "https://issuer.example,alice"
	if user, ok := sc.SciTokensMapper(name); ok {
		t.Fatalf("mapped %q with no CERTIFICATE_MAPFILE", user)
	}

	writeDaemonConfig(t, cfgFile, "CERTIFICATE_MAPFILE = "+mapPath+"\nCERTIFICATE_MAPFILE_ASSUME_HASH_KEYS = true\n")
	d.Reconfigure()
	if user, ok := sc.SciTokensMapper(name); !ok || user != "alice" {
		t.Fatalf("after reconfig: map = %q, %v; want alice", user, ok)
	}

	if err := os.WriteFile(inc, []byte(`SCITOKENS /^https:\/\/issuer\.example,(.*)$/ new-\1`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d.Reconfigure()
	if user, ok := sc.SciTokensMapper(name); !ok || user != "new-alice" {
		t.Errorf("after editing the included file and reconfig: map = %q, %v; want new-alice", user, ok)
	}
}

func TestInstallSecurityLevelsSetsHandshakeDeadline(t *testing.T) {
	d, _ := newConfigDaemon(t, "SEC_TCP_SESSION_DEADLINE = 45\n")
	base, err := d.ServerSecurityConfig(commands.DC_NOP, "DEFAULT")
	if err != nil {
		t.Fatal(err)
	}
	srv := cedarserver.New(base)
	if err := d.InstallSecurityLevels(srv); err != nil {
		t.Fatal(err)
	}
	if srv.HandshakeDeadline != 45*time.Second {
		t.Errorf("HandshakeDeadline = %v; want 45s from SEC_TCP_SESSION_DEADLINE", srv.HandshakeDeadline)
	}
}
