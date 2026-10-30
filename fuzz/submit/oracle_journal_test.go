//go:build libcondor_utils

package fuzzsubmit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// TestOracleJournalIsClearedOnReturn: a call the oracle returns from must leave
// nothing behind, or every crash report would name the last input instead of
// the one that did not come back.
func TestOracleJournalIsClearedOnReturn(t *testing.T) {
	requireOracle(t)

	dir := t.TempDir()
	t.Setenv("SUBMIT_ORACLE_JOURNAL_DIR", dir)

	oracle.MakeAds("executable = /bin/true\nqueue\n", oracle.ModeAds, MaxProcs)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the journal directory: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("the oracle returned but left %d journal file(s) behind: %v", len(entries), entries)
	}
}

// TestOracleJournalNamesTheInputThatDidNotReturn is the case the journal exists
// for. It cannot crash the oracle on demand, so it drives the journal directly:
// after an entry is recorded and before it is cleared, the file must hold the
// input. A process that dies in between leaves exactly this.
func TestOracleJournalNamesTheInputThatDidNotReturn(t *testing.T) {
	requireOracle(t)

	dir := t.TempDir()
	t.Setenv("SUBMIT_ORACLE_JOURNAL_DIR", dir)

	const src = "executable = /bin/true\ncontainer_image = docker://busybox\nqueue 3\n"
	oracle.JournalEnter("MakeAds", src)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the journal directory: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d journal files, want exactly 1", len(entries))
	}
	b, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatalf("reading the journal: %v", err)
	}
	got := string(b)
	if !strings.Contains(got, src) {
		t.Errorf("the journal does not carry the input:\n%s", got)
	}
	if !strings.Contains(got, "MakeAds") {
		t.Errorf("the journal does not name the entry point:\n%s", got)
	}

	oracle.JournalLeave()
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("the journal was not cleared: %v", entries)
	}
}
