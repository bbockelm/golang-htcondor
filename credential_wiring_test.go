package htcondor

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

// TestCredentialCacheListCredentialDir checks the privileged directory lister returns the
// directory's entries. Off-root (as under `go test`), droppriv degrades to the current
// identity, so this exercises the read path and the DirEntry plumbing.
func TestCredentialCacheListCredentialDir(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"tok_a", "tok_b"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := NewCredentialCache().ListCredentialDir(dir)
	if err != nil {
		t.Fatalf("ListCredentialDir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "tok_a,tok_b" {
		t.Errorf("entries = %v, want [tok_a tok_b]", names)
	}
	// A missing directory is an error (surfaced, not swallowed here).
	if _, err := NewCredentialCache().ListCredentialDir(filepath.Join(dir, "nope")); err == nil {
		t.Error("expected error listing a missing directory")
	}
}

func mustConfig(t *testing.T, text string) *config.Config {
	t.Helper()
	cfg, err := config.NewFromReader(strings.NewReader(text))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// TestGetSecurityConfigWiresCredentials verifies every config the builders produce carries
// the privileged reader, so outbound (client) auth can read root-owned credentials -- the
// gap that made the master's DC_SET_READY fail on hostkey.pem.
func TestGetSecurityConfigWiresCredentials(t *testing.T) {
	cfg := mustConfig(t, "SEC_CLIENT_AUTHENTICATION_METHODS = SSL,TOKEN\n")
	sc, err := GetSecurityConfig(cfg, 60000, "CLIENT")
	if err != nil {
		t.Fatal(err)
	}
	if sc.Credentials == nil {
		t.Fatal("client SecurityConfig.Credentials is nil; outbound auth cannot read root-owned credentials")
	}
	// The hardcoded fallback (cfg == nil path) must also carry it.
	sc, err = GetSecurityConfigOrDefault(t.Context(), nil, 60000, "CLIENT", "peer")
	if err != nil {
		t.Fatal(err)
	}
	if sc.Credentials == nil {
		t.Error("fallback SecurityConfig.Credentials is nil")
	}
}

// TestGetSecurityConfigDaemonTokenDir verifies the daemon-vs-tool token directory choice:
// an explicit SEC_TOKEN_DIRECTORY always wins; a daemon with none falls back to
// SEC_TOKEN_SYSTEM_DIRECTORY; a non-daemon does not.
func TestGetSecurityConfigDaemonTokenDir(t *testing.T) {
	const sysDir = "/etc/condor/tokens.d"
	base := "SEC_CLIENT_AUTHENTICATION_METHODS = TOKEN\nSEC_TOKEN_SYSTEM_DIRECTORY = " + sysDir + "\n"

	restore := runningAsDaemon
	t.Cleanup(func() { runningAsDaemon = restore })

	// Daemon, no explicit dir -> system dir.
	runningAsDaemon = func() bool { return true }
	sc, err := GetSecurityConfig(mustConfig(t, base), 60000, "CLIENT")
	if err != nil {
		t.Fatal(err)
	}
	if sc.TokenDir != sysDir {
		t.Errorf("daemon TokenDir = %q, want %q", sc.TokenDir, sysDir)
	}

	// Daemon, but explicit SEC_TOKEN_DIRECTORY -> explicit wins.
	sc, err = GetSecurityConfig(mustConfig(t, base+"SEC_TOKEN_DIRECTORY = /custom/tokens.d\n"), 60000, "CLIENT")
	if err != nil {
		t.Fatal(err)
	}
	if sc.TokenDir != "/custom/tokens.d" {
		t.Errorf("explicit TokenDir = %q, want /custom/tokens.d", sc.TokenDir)
	}

	// Non-daemon, no explicit dir -> do NOT use the root-only system dir.
	runningAsDaemon = func() bool { return false }
	sc, err = GetSecurityConfig(mustConfig(t, base), 60000, "CLIENT")
	if err != nil {
		t.Fatal(err)
	}
	if sc.TokenDir != "" {
		t.Errorf("non-daemon TokenDir = %q, want empty (system dir is root-only)", sc.TokenDir)
	}
}
