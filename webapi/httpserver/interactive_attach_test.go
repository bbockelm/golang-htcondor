package httpserver

import (
	"sync"
	"testing"
)

// TestLastTerminalOutTearsDownTheJob is the bug this exists to fix: a
// terminal that ends drops a .shutdown sentinel and condor_rm's the
// job, and both used to run on every disconnect -- so with two
// terminals open on one session, closing either removed the job and
// killed the other.
func TestLastTerminalOutTearsDownTheJob(t *testing.T) {
	term := newInteractiveTerminals()
	const job = "12.0"

	term.attach(job)
	term.attach(job)
	if got := term.count(job); got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}

	if term.detach(job) {
		t.Fatal("the first of two terminals to leave claimed the job was finished")
	}
	if got := term.count(job); got != 1 {
		t.Errorf("count = %d after one detach, want 1", got)
	}

	if !term.detach(job) {
		t.Fatal("the last terminal to leave did not claim the job was finished")
	}
	if got := term.count(job); got != 0 {
		t.Errorf("count = %d after the last detach, want 0", got)
	}
}

// TestTerminalsAreCountedPerJob: one job's terminals must not keep
// another job's alive.
func TestTerminalsAreCountedPerJob(t *testing.T) {
	term := newInteractiveTerminals()
	term.attach("12.0")
	term.attach("13.0")

	if !term.detach("12.0") {
		t.Error("the only terminal on 12.0 did not report itself last")
	}
	if !term.detach("13.0") {
		t.Error("the only terminal on 13.0 did not report itself last")
	}
}

// TestDetachWithNothingAttachedTearsDown: the count is advisory and
// lost across a restart, so a detach it never saw an attach for has to
// fall back to tearing down. Reclaiming a slot that may already be
// free is recoverable; leaking one forever is not.
func TestDetachWithNothingAttachedTearsDown(t *testing.T) {
	term := newInteractiveTerminals()
	if !term.detach("99.0") {
		t.Error("a detach with no attach did not tear down")
	}
	if got := term.count("99.0"); got != 0 {
		t.Errorf("count = %d, want the entry dropped", got)
	}
}

// TestTerminalCountIsConcurrencySafe: terminals attach and detach from
// their own WebSocket goroutines, and exactly one of them must be told
// it was last.
func TestTerminalCountIsConcurrencySafe(t *testing.T) {
	term := newInteractiveTerminals()
	const job = "12.0"
	const n = 50

	for i := 0; i < n; i++ {
		term.attach(job)
	}

	var wg sync.WaitGroup
	var lastMu sync.Mutex
	lasts := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if term.detach(job) {
				lastMu.Lock()
				lasts++
				lastMu.Unlock()
			}
		}()
	}
	wg.Wait()

	if lasts != 1 {
		t.Errorf("%d terminals believed they were last; exactly one must tear the job down", lasts)
	}
	if got := term.count(job); got != 0 {
		t.Errorf("count = %d after all detached, want 0", got)
	}
}
