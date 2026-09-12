package droppriv

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// The ordinary case: a readable file needs no privilege machinery.
func TestOpenMaybeAsRootReadsAReadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cred")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ReadFileMaybeAsRoot(path)
	if err != nil {
		t.Fatalf("ReadFileMaybeAsRoot: %v", err)
	}
	if string(got) != "secret" {
		t.Errorf("read %q, want %q", got, "secret")
	}
}

// A missing file reports not-exist, not a permission problem: root
// would not change the answer, and the caller's message depends on
// telling those apart (the KEK loader prints the openssl recipe only
// for not-exist).
func TestOpenMaybeAsRootPreservesNotExist(t *testing.T) {
	_, err := OpenMaybeAsRoot(filepath.Join(t.TempDir(), "absent"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error = %v, want fs.ErrNotExist", err)
	}
}

// Denied and unable to elevate: the caller must still see a permission
// error, with the elevation failure noted rather than substituted.
func TestOpenMaybeAsRootReportsDenialWhenItCannotElevate(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the denial this checks cannot be produced")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cred")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Take away search permission on the parent, which is what
	// /etc/condor/htcondor-api (mode 0700 root) does to a daemon
	// running as condor.
	if err := os.Chmod(dir, 0o000); err != nil { //nolint:gosec // G302: removing all access is the point of the fixture
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: restores the dir so t.TempDir can clean it up

	_, err := OpenMaybeAsRoot(path)
	if err == nil {
		t.Fatal("an unreadable credential was opened")
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("error = %v, want a permission error", err)
	}
}
