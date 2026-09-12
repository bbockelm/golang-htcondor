//go:build linux

package droppriv

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestOpenAsRootElevatesAfterDrop is the regression guard for the *AsRoot
// elevation: after dropping to a non-root user, a plain os.Open of a root-owned
// 0600 file must fail, but OpenAsRoot must succeed because it re-elevates to
// root (thread-isolated) for the read and then restores the dropped identity.
// Requires root; skipped otherwise.
func TestOpenAsRootElevatesAfterDrop(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("test requires root privileges")
	}

	dir := t.TempDir()
	// Let the dropped user traverse the dir so the test isolates the file's
	// 0600 mode rather than directory permissions.
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: the dir must be world-traversable so the dropped user reaches the 0600 file under test
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("topsecret"), 0o600); err != nil {
		t.Fatal(err) // root-owned, 0600
	}

	mgr, err := NewManager(Config{Enabled: true, CondorUser: "nobody"})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.Start(); err != nil {
		t.Fatalf("Start (drop to nobody): %v", err)
	}
	defer func() { _ = mgr.Stop() }()

	// As nobody, a plain open of the root-owned 0600 file must be denied.
	if f, err := os.Open(secret); err == nil { //nolint:gosec // G304: secret is a test-controlled temp path
		_ = f.Close()
		t.Fatal("plain os.Open of a root-owned 0600 file succeeded as nobody; expected EACCES")
	}

	// OpenAsRoot must succeed by re-elevating for the read.
	f, err := mgr.OpenAsRoot(secret)
	if err != nil {
		t.Fatalf("OpenAsRoot after drop failed (no re-elevation?): %v", err)
	}
	data, _ := io.ReadAll(f)
	_ = f.Close()
	if string(data) != "topsecret" {
		t.Errorf("OpenAsRoot read %q, want topsecret", data)
	}

	// The elevation must have been scoped: we should still be dropped, not root.
	if os.Geteuid() == 0 {
		t.Error("euid is root after OpenAsRoot; elevation was not restored")
	}
}

// TestOpenMaybeAsRootReadsARootOnlyCredentialAfterDrop is the case an
// access point actually presents: condor_master starts the daemon as
// root, it drops to condor, and its credentials -- KEK, OAuth2 client
// secret, pool signing key -- are root-owned and root-readable, often
// under a directory the dropped user cannot even traverse.
//
// Reading them with a plain os.Open fails there with "permission
// denied", which is what an operator saw as
//
//	Server failed: failed to create server: KEK setup: load master KEK:
//	kek file: stat /etc/condor/htcondor-api/kek: permission denied
//
// Requires root; skipped otherwise.
func TestOpenMaybeAsRootReadsARootOnlyCredentialAfterDrop(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("test requires root privileges")
	}

	dir := t.TempDir()
	// 0700 root: the dropped user cannot even stat what is inside,
	// which is how /etc/condor/htcondor-api is normally staged.
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: 0700 root is the fixture -- the dropped user must not be able to traverse it
		t.Fatal(err)
	}
	kek := filepath.Join(dir, "kek")
	if err := os.WriteFile(kek, []byte("0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}

	mgr, err := NewManager(Config{Enabled: true, CondorUser: "nobody"})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.Start(); err != nil {
		t.Fatalf("Start (drop to nobody): %v", err)
	}
	defer func() { _ = mgr.Stop() }()

	// Precondition: the ordinary read is refused, so the test is not
	// passing for want of a real denial.
	if _, err := os.ReadFile(kek); err == nil { //nolint:gosec // G304: test-controlled temp path
		t.Fatal("a root-only credential was readable as nobody; the fixture proves nothing")
	}

	got, err := ReadFileMaybeAsRoot(kek)
	if err != nil {
		t.Fatalf("ReadFileMaybeAsRoot after drop: %v", err)
	}
	if string(got) != "0123456789abcdef" {
		t.Errorf("read %q, want the credential", got)
	}
	if os.Geteuid() == 0 {
		t.Error("euid is root afterwards; the elevation was not restored")
	}
}
