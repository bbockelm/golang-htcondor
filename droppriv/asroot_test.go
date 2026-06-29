package droppriv

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestAsRootAccessibleFiles checks the *AsRoot operations against
// normally-accessible paths. This exercises the no-elevation paths (already
// root, or unprivileged best-effort on Linux, or the non-Linux stub) and must
// work everywhere. The privileged regression — that *AsRoot actually re-elevates
// after a drop — is in the root-only test in asroot_privileged_test.go.
func TestAsRootAccessibleFiles(t *testing.T) {
	dir := t.TempDir()

	sub := filepath.Join(dir, "a", "b")
	if err := MkdirAllAsRoot(sub, 0o755); err != nil {
		t.Fatalf("MkdirAllAsRoot: %v", err)
	}
	if fi, err := os.Stat(sub); err != nil || !fi.IsDir() {
		t.Fatalf("MkdirAllAsRoot did not create dir: %v", err)
	}

	p := filepath.Join(sub, "f")
	wf, err := OpenFileAsRoot(p, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFileAsRoot: %v", err)
	}
	if _, err := wf.WriteString("hello"); err != nil {
		t.Fatal(err)
	}
	_ = wf.Close()

	rf, err := OpenAsRoot(p)
	if err != nil {
		t.Fatalf("OpenAsRoot: %v", err)
	}
	b, _ := io.ReadAll(rf)
	_ = rf.Close()
	if string(b) != "hello" {
		t.Errorf("OpenAsRoot read %q, want hello", b)
	}
}
