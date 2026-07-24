package logging

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOnRotateFiresWithNewFile verifies File() returns the live log file and OnRotate is
// called with the new file after a rotation -- the contract the daemon's stdout/stderr
// capture relies on to follow the log across rotations.
func TestOnRotateFiresWithNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	l, err := New(&Config{OutputPath: path, MaxLogSize: 200, MaxNumLogs: 2, DefaultLevel: VerbosityInfo, SkipGlobalInstall: true})
	if err != nil {
		t.Fatal(err)
	}
	if l.File() == nil {
		t.Fatal("File() is nil for a file-backed logger")
	}
	orig := l.File()

	var gotName string
	var calls int
	l.OnRotate(func(f *os.File) { calls++; gotName = f.Name() })

	// Write enough to trip size-based rotation (MaxLogSize=200).
	for i := 0; i < 50; i++ {
		l.Info(DestinationGeneral, "some log line to grow the file past the rotation threshold")
	}

	if calls == 0 {
		t.Fatal("OnRotate never fired despite exceeding MaxLogSize")
	}
	if gotName != path {
		t.Errorf("OnRotate new file = %q, want the active path %q", gotName, path)
	}
	if l.File() == orig {
		t.Error("File() still returns the pre-rotation file")
	}
}
