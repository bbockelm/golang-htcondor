package httpserver

import "sync"

// Live browser terminals, counted per job.
//
// A terminal that ends tears its job down: it drops a .shutdown
// sentinel for the watchdog and condor_rm's the job, so that closing a
// tab frees the slot immediately rather than after the watchdog's
// staleness window. That is right for the last terminal on a job and
// wrong for any earlier one -- with two terminals open on the same
// session, closing either removed the job and killed the other. The
// count decides which case a disconnect is.
//
// This lives in the handler rather than on the job because it is about
// this server's own clients. It is therefore lost across a restart: a
// job with two terminals attached before a restart has a count of zero
// after it, and the first disconnect afterwards will tear the job
// down. That is the behaviour every disconnect had before this
// existed, so a restart degrades to the old bug rather than to
// something new -- and the alternative, a counter on the job ad,
// would have to be correct under a server that died without
// decrementing it.
type interactiveTerminals struct {
	mu     sync.Mutex
	perJob map[string]int
}

func newInteractiveTerminals() *interactiveTerminals {
	return &interactiveTerminals{perJob: make(map[string]int)}
}

// attach records a terminal on jobID.
func (t *interactiveTerminals) attach(jobID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.perJob[jobID]++
}

// detach records a terminal leaving jobID and reports whether it was
// the last one, which is when the caller should tear the job down.
//
// A detach with nothing attached reports true: the count is advisory
// and lost across restarts, and the safe failure is to reclaim a slot
// that may already be free rather than to leak one forever.
func (t *interactiveTerminals) detach(jobID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.perJob[jobID] - 1
	if n <= 0 {
		delete(t.perJob, jobID)
		return true
	}
	t.perJob[jobID] = n
	return false
}

// count reports the terminals attached to jobID. For tests.
func (t *interactiveTerminals) count(jobID string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.perJob[jobID]
}
