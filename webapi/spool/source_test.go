package spool

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// The REST upload paths accept up to a gigabyte and hand the schedd a
// stream, never holding the bytes. A fan-out cannot replay a stream, so
// the tar has to live somewhere -- and for those sizes that is a file,
// not a []byte. See growing_test.go for the pipelining behaviour; this
// file covers the buffer file's lifecycle and the in-memory Source.
// The buffer file's lifecycle, ported from the Spill tests that these
// replaced when Growing took over the REST path: the properties are the
// same, the buffer just fills while it is being read now.

func TestGrowingAcceptsExactlyTheLimit(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 1024)
	g, err := NewGrowing(t.TempDir(), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()

	if err := g.Fill(bytes.NewReader(payload)); err != nil {
		t.Fatalf("a stream of exactly the limit was refused: %v", err)
	}
	if g.Size() != int64(len(payload)) {
		t.Errorf("Size = %d, want %d", g.Size(), len(payload))
	}
}

func TestGrowingCleansUp(t *testing.T) {
	dir := t.TempDir()
	g, err := NewGrowing(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Fill(bytes.NewReader([]byte("tar"))); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertEmptyDir(t, dir)

	// Twice is safe: the fan-out's defer runs on every path, including
	// the ones that already closed.
	if err := g.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// A refused upload must not leave its partial file behind. A gigabyte
// per rejected call, kept until the process exits, fills the buffer
// directory and then the disk.
func TestGrowingCleansUpAfterRefusing(t *testing.T) {
	dir := t.TempDir()
	g, err := NewGrowing(dir, 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Fill(bytes.NewReader(bytes.Repeat([]byte("y"), 4096))); err == nil {
		t.Fatal("Fill accepted a stream past its limit")
	}
	if err := g.Close(); err != nil {
		t.Fatalf("Close after a refusal: %v", err)
	}
	assertEmptyDir(t, dir)
}

func TestGrowingHonoursTheBufferDirectory(t *testing.T) {
	dir := t.TempDir()
	g, err := NewGrowing(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if err := g.Fill(bytes.NewReader([]byte("tar"))); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("the buffer directory holds %d files, want 1", len(entries))
	}
}

func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the buffer directory still holds %v", names)
	}
}

func TestBytesReplaysTheSameBytes(t *testing.T) {
	src := Bytes("a tar, in memory")
	for i := 0; i < 3; i++ {
		r, err := src.Reader()
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		_ = r.Close()
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(src) {
			t.Fatalf("read %d: got %q, want %q", i, got, src)
		}
	}
	if src.Size() != int64(len(src)) {
		t.Errorf("Size = %d, want %d", src.Size(), len(src))
	}
}
