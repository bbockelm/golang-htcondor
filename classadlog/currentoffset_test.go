package classadlog

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// The property CurrentOffset exists for: a given entry's offset is the same whatever offset the
// pass began at. A caller recording "I have processed the log through here" can only compare such
// a mark across a restart or a rewind if the mark does not depend on where reading started --
// which is exactly what GetNextOffset, folding in consumed bytes only at Close, cannot provide.
func TestCurrentOffsetIsAbsoluteAndPerEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job_queue.log")
	const content = `105
103 1.0 Owner "alice"
103 1.0 JobStatus 1
106
105
103 2.0 Owner "bob"
106
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	// Read the whole file, recording the offset just past each entry.
	read := func(from int64) (offs []int64, n int) {
		p := NewParser(path)
		p.SetNextOffset(from)
		if err := p.Open(); err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer func() { _ = p.Close() }()
		for {
			_, err := p.ReadEntry()
			if errors.Is(err, io.EOF) {
				return offs, n
			}
			if err != nil {
				t.Fatalf("ReadEntry: %v", err)
			}
			offs = append(offs, p.CurrentOffset())
			n++
		}
	}

	all, n := read(0)
	if n != 7 {
		t.Fatalf("read %d entries, want 7", n)
	}
	// Strictly increasing: each entry has its own position, which is what lets one be compared
	// against a recorded mark.
	for i := 1; i < len(all); i++ {
		if all[i] <= all[i-1] {
			t.Fatalf("offsets not strictly increasing at %d: %v", i, all)
		}
	}
	if last := all[len(all)-1]; last != int64(len(content)) {
		t.Errorf("last entry ends at %d, want %d (end of file)", last, len(content))
	}

	// Now resume from the middle, as a restart does. The entries that follow must report the SAME
	// offsets as they did on the full pass -- if they shifted, a mark recorded before the restart
	// would not mean the same thing after it.
	resumeAfter := 3 // skip the first transaction's 4 entries
	tail, _ := read(all[resumeAfter])
	want := all[resumeAfter+1:]
	if len(tail) != len(want) {
		t.Fatalf("resumed read got %d entries, want %d", len(tail), len(want))
	}
	for i := range want {
		if tail[i] != want[i] {
			t.Errorf("entry %d after resume is at %d, was at %d on the full pass -- the offset "+
				"depends on where reading started", i, tail[i], want[i])
		}
	}
}

// GetNextOffset reports the offset the pass started at until Close folds in the consumed bytes.
// Pinning that is what makes the need for CurrentOffset legible: the two differ mid-pass, and a
// caller that wants a per-entry position must not reach for the older one.
func TestCurrentOffsetDiffersFromGetNextOffsetMidPass(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job_queue.log")
	if err := os.WriteFile(path, []byte("105\n103 1.0 Owner \"alice\"\n106\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := NewParser(path)
	if err := p.Open(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ReadEntry(); err != nil {
		t.Fatal(err)
	}
	if got := p.GetNextOffset(); got != 0 {
		t.Errorf("GetNextOffset mid-pass = %d, want 0 (it only advances at Close)", got)
	}
	if got := p.CurrentOffset(); got != 4 {
		t.Errorf("CurrentOffset after one entry = %d, want 4", got)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if got, cur := p.GetNextOffset(), p.CurrentOffset(); got != cur {
		t.Errorf("after Close GetNextOffset=%d CurrentOffset=%d, want equal", got, cur)
	}
}
