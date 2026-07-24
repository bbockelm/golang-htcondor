package classadlog

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// drainOpen reads every entry the parser can currently produce, returning them.
// It mirrors one poll cycle: Open (seek to the saved offset), read to EOF, Close
// (which finalizes the resume offset).
func drainOpen(t *testing.T, p *Parser) []*LogEntry {
	t.Helper()
	if err := p.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = p.Close() }()
	var out []*LogEntry
	for {
		e, err := p.ReadEntry()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("ReadEntry: %v", err)
		}
		out = append(out, e)
	}
}

// TestPartialTrailingLineNotConsumed reproduces a poll catching the schedd
// mid-write: a transaction whose final line has been partially written (no
// trailing newline yet). The parser must not error on it, must not consume it,
// and must read it in full once the newline arrives -- with nothing lost.
func TestPartialTrailingLineNotConsumed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job_queue.log")

	// A complete op, then a partial SetAttribute (op 103) with no value + no newline,
	// exactly like the reported "103 16257.1830 RecentB".
	complete := "103 1.0 Owner \"alice\"\n"
	if err := os.WriteFile(path, []byte(complete+"103 1.0 RecentB"), 0o600); err != nil {
		t.Fatal(err)
	}

	p := NewParser(path)
	got := drainOpen(t, p)
	if len(got) != 1 {
		t.Fatalf("first poll: got %d entries, want 1 (the partial line must be withheld)", len(got))
	}
	if got[0].OpType != OpSetAttribute || got[0].Key != "1.0" || got[0].Name != "Owner" {
		t.Fatalf("first entry = %+v, want SetAttribute 1.0 Owner", got[0])
	}
	if p.GetNextOffset() != int64(len(complete)) {
		t.Fatalf("offset after partial = %d, want %d (start of the partial line)", p.GetNextOffset(), len(complete))
	}

	// The schedd finishes the line (value + newline) and appends another op.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: test temp path
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("lockReads 42\n103 1.0 JobStatus 2\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	got = drainOpen(t, p)
	if len(got) != 2 {
		t.Fatalf("second poll: got %d entries, want 2 (the completed line + the new op)", len(got))
	}
	if got[0].Name != "RecentBlockReads" || got[0].Value != "42" {
		t.Errorf("completed line = %+v, want RecentBlockReads=42 (partial+rest joined)", got[0])
	}
	if got[1].Name != "JobStatus" {
		t.Errorf("second entry = %+v, want JobStatus", got[1])
	}
}
