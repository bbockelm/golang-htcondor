package classadlog

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFileSize(t *testing.T, path string, n int) {
	t.Helper()
	if err := os.WriteFile(path, make([]byte, n), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestProbeDetectsUnreadTailWhenLastSizeRacesAhead is the regression for the wedged tailer.
// The reader reads to EOF, then Update() stats the path -- and if the writer appended during the
// read, lastSize is cached AHEAD of the reader's consumed offset. A later Probe must still report
// ProbeAddition for the un-consumed tail; keying the append check on lastSize (rather than the
// current offset) returned ProbeNoChange, stranding the tail until the file next shrank.
func TestProbeDetectsUnreadTailWhenLastSizeRacesAhead(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "job_queue.log")

	// Initial 20 bytes; first probe from offset 0 sees them.
	writeFileSize(t, f, 20)
	p := NewProber()
	if r, err := p.Probe(f, 0); err != nil || r != ProbeAddition {
		t.Fatalf("first probe = %v, %v; want ProbeAddition", r, err)
	}

	// Reader consumed only 20 bytes (offset=20). The writer then appended 80 more (file=100)
	// during/after the read, and Update() stats the path -> lastSize races ahead to 100.
	writeFileSize(t, f, 100)
	if err := p.Update(f); err != nil {
		t.Fatal(err)
	}

	// 80 bytes past the reader's offset remain unread. Probe MUST report an addition.
	r, err := p.Probe(f, 20)
	if err != nil {
		t.Fatal(err)
	}
	if r != ProbeAddition {
		t.Fatalf("probe with unread tail (offset=20, size=100) = %v; want ProbeAddition (the tailer must not wedge)", r)
	}

	// Fully consumed: offset == size -> no change.
	if r, err := p.Probe(f, 100); err != nil || r != ProbeNoChange {
		t.Fatalf("probe fully-consumed = %v, %v; want ProbeNoChange", r, err)
	}

	// A genuine shrink (compaction/rotation) is still a reload.
	writeFileSize(t, f, 40)
	if r, err := p.Probe(f, 100); err != nil || r != ProbeCompressed {
		t.Fatalf("probe after shrink = %v, %v; want ProbeCompressed", r, err)
	}
}
