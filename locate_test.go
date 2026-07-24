package htcondor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

func cfgFrom(t *testing.T, kv map[string]string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	var b strings.Builder
	for k, v := range kv {
		b.WriteString(k + " = " + v + "\n")
	}
	p := filepath.Join(dir, "condor_config")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONDOR_CONFIG", p)
	c, err := config.New()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAddressFilePath(t *testing.T) {
	// Explicit override wins.
	c := cfgFrom(t, map[string]string{"HTCONDORDB_ADDRESS_FILE": "/custom/path", "LOG": "/var/log/condor"})
	if got := AddressFilePath(c, "HTCONDORDB"); got != "/custom/path" {
		t.Errorf("override: got %q", got)
	}
	// Default from LOG, lower-cased subsys.
	c = cfgFrom(t, map[string]string{"LOG": "/var/log/condor"})
	if got, want := AddressFilePath(c, "HTCONDORDB"), "/var/log/condor/.htcondordb_address"; got != want {
		t.Errorf("default: got %q want %q", got, want)
	}
}

func TestReadAddressFileAndResolver(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".htcondordb_address")
	if err := os.WriteFile(p, []byte("\n<127.0.0.1:9618?sock=abc>\nextra\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ReadAddressFile(p)
	if err != nil || got != "<127.0.0.1:9618?sock=abc>" {
		t.Fatalf("ReadAddressFile = %q, %v", got, err)
	}
	// Resolver re-reads: rewrite reflects on the next call (the restart case).
	resolve := FileAddressResolver(p)
	if err := os.WriteFile(p, []byte("<127.0.0.1:9618?sock=NEW>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, _ := resolve(); v != "<127.0.0.1:9618?sock=NEW>" {
		t.Fatalf("resolver did not re-read: %q", v)
	}
	if _, err := ReadAddressFile(filepath.Join(dir, "gone")); err == nil {
		t.Error("missing file should error")
	}
}

func TestLocalDaemonAddress(t *testing.T) {
	dir := t.TempDir()
	af := filepath.Join(dir, ".htcondordb_address")

	// File present -> file preferred over the host fallback.
	if err := os.WriteFile(af, []byte("<file-addr>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := cfgFrom(t, map[string]string{"HTCONDORDB_ADDRESS_FILE": af, "HTCONDORDB_HOST": "host-addr:9618"})
	resolve, _, err := LocalDaemonAddress(c, "HTCONDORDB")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := resolve(); v != "<file-addr>" {
		t.Errorf("file present: got %q want <file-addr>", v)
	}
	// File missing -> fall back to host.
	_ = os.Remove(af)
	if v, _ := resolve(); v != "host-addr:9618" {
		t.Errorf("file missing: got %q want host fallback", v)
	}
	// Host only (no LOG, no address file) -> host.
	c = cfgFrom(t, map[string]string{"HTCONDORDB_HOST": "only-host:9618"})
	resolve, _, err = LocalDaemonAddress(c, "HTCONDORDB")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := resolve(); v != "only-host:9618" {
		t.Errorf("host only: got %q", v)
	}
}
