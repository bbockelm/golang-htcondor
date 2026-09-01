package classadlog

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func ino(t *testing.T, fi os.FileInfo) uint64 {
	t.Helper()
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no syscall.Stat_t on this platform")
	}
	return uint64(st.Ino) //nolint:unconvert // Ino width varies by platform
}

// TestStatOpenIdentifiesTheReadFd checks StatOpen reflects the file descriptor actually open, not
// the path -- the property a job-queue tailer relies on to avoid binding a read's offset to a file
// that replaced the path mid-read.
func TestStatOpenIdentifiesTheReadFd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "job_queue.log")
	if err := os.WriteFile(path, []byte("107 1 CreationTimestamp 1000\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	p := NewParser(path)

	// No file open yet -> error.
	if _, err := p.StatOpen(); err == nil {
		t.Error("StatOpen should error when no file is open")
	}

	if err := p.Open(); err != nil {
		t.Fatal(err)
	}
	fi, err := p.StatOpen()
	if err != nil {
		t.Fatalf("StatOpen while open: %v", err)
	}
	openIno := ino(t, fi)

	// Rotate: replace the path with a DIFFERENT file (new inode), as a compaction does.
	other := filepath.Join(dir, "job_queue.log.new")
	if err := os.WriteFile(other, []byte("107 2 CreationTimestamp 1000\n101 1.0 Job Machine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
	}

	// StatOpen still reflects the fd we hold (old inode), while os.Stat(path) sees the new file.
	fi2, err := p.StatOpen()
	if err != nil {
		t.Fatalf("StatOpen after rotate: %v", err)
	}
	if ino(t, fi2) != openIno {
		t.Errorf("StatOpen inode changed after rotation (%d -> %d); it must track the open fd, not the path",
			openIno, ino(t, fi2))
	}
	pathFI, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if ino(t, pathFI) == openIno {
		t.Skip("filesystem reused the inode for the new file; cannot distinguish fd-stat from path-stat here")
	}
	// The whole point: fd-stat != path-stat after a rotation.
	if ino(t, fi2) == ino(t, pathFI) {
		t.Errorf("StatOpen returned the path's new inode, not the open fd's")
	}

	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.StatOpen(); err == nil {
		t.Error("StatOpen should error after Close")
	}
}
