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
	if err := os.Chmod(dir, 0o755); err != nil {
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
	if f, err := os.Open(secret); err == nil {
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
