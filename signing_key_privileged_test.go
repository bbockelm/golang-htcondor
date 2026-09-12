//go:build linux

package htcondor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/droppriv"
)

// Minting a token reads the pool signing key, which on an access point
// is root-owned: /etc/condor/passwords.d/POOL is root:root 0600 and the
// directory holding it is not traversable by the condor account. The
// daemon doing the minting has dropped to that account, so the read has
// to re-elevate -- the same treatment every other credential gets.
//
// Without it the daemon fails to mint any token at all, with the same
// shape as the KEK failure an operator hit:
//
//	failed to read key file /etc/condor/passwords.d/POOL: permission denied
//
// Requires root; skipped otherwise.
func TestGenerateJWTReadsARootOnlySigningKeyAfterDrop(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("test requires root privileges")
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: root-only is the fixture
		t.Fatal(err)
	}
	// The key is "scrambled" on disk (XOR 0xdeadbeef); the content does
	// not matter here, only that it is 16 bytes and unreadable to the
	// dropped account.
	if err := os.WriteFile(filepath.Join(dir, "POOL"), []byte("0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}

	mgr, err := droppriv.NewManager(droppriv.Config{Enabled: true, CondorUser: "nobody"})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.Start(); err != nil {
		t.Fatalf("Start (drop to nobody): %v", err)
	}
	defer func() { _ = mgr.Stop() }()

	// Precondition: the plain read really is denied, so a pass cannot be
	// an artifact of a readable fixture.
	if _, err := os.ReadFile(filepath.Join(dir, "POOL")); err == nil { //nolint:gosec // G304: test path
		t.Fatal("the signing key was readable as nobody; the fixture proves nothing")
	}

	tok, err := security.GenerateJWT(dir, "POOL", "alice@example.org", "example.org", 1, 1<<40, nil)
	if err != nil {
		t.Fatalf("GenerateJWT after drop: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
}
