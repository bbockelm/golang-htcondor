package spool

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The REST upload paths accept up to a gigabyte and hand the schedd a
// stream, never holding the bytes. A fan-out cannot replay a stream, so
// the tar has to live somewhere -- and for those sizes that is a file,
// not a []byte.
func TestSpillReplaysTheSameBytes(t *testing.T) {
	payload := strings.Repeat("abcdefgh", 1024) // 8 KB
	f, err := Spill(strings.NewReader(payload), t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if f.Size() != int64(len(payload)) {
		t.Errorf("Size() = %d, want %d", f.Size(), len(payload))
	}
	// Three reads, all identical: one per proc in a fan-out.
	for i := 0; i < 3; i++ {
		r, err := f.Reader()
		if err != nil {
			t.Fatalf("reader %d: %v", i, err)
		}
		got, err := io.ReadAll(r)
		_ = r.Close()
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if string(got) != payload {
			t.Errorf("read %d returned %d bytes, want %d", i, len(got), len(payload))
		}
	}
}

// Concurrent readers must not share an offset. A shared *os.File has one
// between them, so two procs reading at once would each get part of the
// tar -- and a short tar spools cleanly and fails later on a missing
// file, so the damage is silent.
func TestSpillReadersAreIndependentUnderConcurrency(t *testing.T) {
	payload := strings.Repeat("xyz", 4096)
	f, err := Spill(strings.NewReader(payload), t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	var wg sync.WaitGroup
	bad := make([]int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := f.Reader()
			if err != nil {
				bad[i] = -1
				return
			}
			defer func() { _ = r.Close() }()
			b, err := io.ReadAll(r)
			if err != nil {
				bad[i] = -2
				return
			}
			bad[i] = len(b)
		}(i)
	}
	wg.Wait()
	for i, n := range bad {
		if n != len(payload) {
			t.Errorf("concurrent reader %d got %d bytes, want %d", i, n, len(payload))
		}
	}
}

// A stream past the limit is an error, not a truncation. A truncated tar
// spools without complaint and fails at run time on a missing file,
// which is the worst outcome available: the caller is told it worked.
func TestSpillRefusesRatherThanTruncates(t *testing.T) {
	const limit = 4096
	_, err := Spill(strings.NewReader(strings.Repeat("q", limit*2)), t.TempDir(), limit)
	if err == nil {
		t.Fatal("a stream past the limit was accepted; it would have been truncated")
	}
	if !strings.Contains(err.Error(), "transfer_input_files") {
		t.Errorf("the error should steer to URL transfer, got: %v", err)
	}
}

// A stream exactly at the limit is fine: the check is "more than", and
// an off-by-one here would reject a legitimate upload.
func TestSpillAcceptsExactlyTheLimit(t *testing.T) {
	const limit = 4096
	f, err := Spill(strings.NewReader(strings.Repeat("q", limit)), t.TempDir(), limit)
	if err != nil {
		t.Fatalf("a stream exactly at the limit was rejected: %v", err)
	}
	defer func() { _ = f.Close() }()
	if f.Size() != limit {
		t.Errorf("Size() = %d, want %d", f.Size(), limit)
	}
}

// Nothing is left behind: these are uploads, and a server that leaks a
// gigabyte per call fills the buffer directory and then the disk.
func TestSpillCleansUp(t *testing.T) {
	dir := t.TempDir()
	f, err := Spill(bytes.NewReader([]byte("small")), dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected one buffer file, found %d", len(entries))
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if entries, _ = os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("Close left %d file(s) behind in %s", len(entries), dir)
	}
	// Twice is safe: handlers close on several paths.
	if err := f.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// A rejected upload must not leave its partial buffer behind either.
func TestSpillCleansUpAfterRefusing(t *testing.T) {
	dir := t.TempDir()
	if _, err := Spill(strings.NewReader(strings.Repeat("q", 9000)), dir, 4096); err == nil {
		t.Fatal("expected a refusal")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a refused upload left %d file(s) in %s", len(entries), dir)
	}
}

// The buffer directory is a caller's choice: spilling a gigabyte into a
// small /tmp is a way to take the server down with it.
func TestSpillHonoursTheBufferDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "buffers")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := Spill(strings.NewReader("data"), dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the buffer did not land in the requested directory %s", dir)
	}
}
