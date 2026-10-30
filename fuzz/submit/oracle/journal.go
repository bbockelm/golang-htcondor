//go:build libcondor_utils

package oracle

import (
	"os"
	"path/filepath"
	"strconv"
)

// The oracle runs libcondor_utils in this process, so a segfault or abort
// inside it takes the whole fuzz worker down. Go's fuzzing engine reports that
// as "fuzzing process hung or terminated unexpectedly" and writes out the input
// it happened to be working on -- which, when the worker was minimizing, is not
// the input that killed it. Three such crashes have been seen (two in CI, one
// locally) and none could be attributed, because the only record was that
// misleading file.
//
// So every call records its input before entering C++. A plain write(2) reaches
// the kernel, so the file survives the process dying immediately afterwards
// without an fsync on the hot path. The entry is cleared on the way out, which
// means a journal left behind names an input the oracle did not return from.
//
// One file per process, since a crash ends the process: concurrent workers are
// separate processes and do not share it.

// journalDirEnv overrides where the journal is written. The default is the
// system temp directory, which is where a fuzz worker can always write.
const journalDirEnv = "SUBMIT_ORACLE_JOURNAL_DIR"

// journalPath returns this process's journal file, or "" when journaling is
// switched off (SUBMIT_ORACLE_JOURNAL_DIR set to "off").
//
// Resolved on every call rather than cached. Caching it behind a sync.Once
// reads the environment once per process, which is right for a fuzz worker and
// wrong for anything that changes the variable afterwards -- a test that sets
// it, for instance, would silently keep writing to the first directory it ever
// saw. An environment lookup costs nothing next to running SubmitHash.
func journalPath() string {
	dir := os.Getenv(journalDirEnv)
	if dir == "off" {
		return ""
	}
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "submit-oracle-crash-"+strconv.Itoa(os.Getpid())+".txt")
}

// journalEnter records the input about to be handed to the C++ oracle. A
// failure to write is ignored: journaling is a debugging aid, and losing it
// must not change what the differential comparison reports.
func journalEnter(kind, text string) {
	p := journalPath()
	if p == "" {
		return
	}
	_ = os.WriteFile(p, []byte("oracle entry point: "+kind+"\n"+
		"this file exists because the oracle did not return from the input below\n"+
		"----- input -----\n"+text), 0o600)
}

// journalLeave clears the entry after the oracle returns, so only a call that
// never came back leaves a file behind.
func journalLeave() {
	p := journalPath()
	if p == "" {
		return
	}
	_ = os.Remove(p)
}

// JournalEnter and JournalLeave let a driver bracket work of its own the same
// way the oracle calls bracket theirs.
//
// The oracle's own calls are not the only thing that can end the process: the
// generator and the Go parser run in the same worker, and a death in either
// leaves no journal if only the C++ side is bracketed. A fuzz target that
// brackets the whole iteration records the input whatever kills the worker,
// which is the only way a crash gets attributed at all -- Go writes out the
// input the worker happened to hold, and while minimizing that is not the one
// that killed it.
func JournalEnter(kind, text string) { journalEnter(kind, text) }

// JournalLeave clears the entry, as a returning call does.
func JournalLeave() { journalLeave() }
