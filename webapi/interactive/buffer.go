package interactive

import (
	"strings"
	"sync"
)

// cappedBuffer collects command output up to a byte limit and then
// stops, remembering that it did.
//
// The limit is a context-window limit, not a memory one: whatever a
// command prints lands in a model's next prompt, so a command that
// dumps a log file should come back as "here is the start of it, and
// it was cut off" rather than as an answer nothing can read. Writes
// past the cap are discarded rather than erroring — a command whose
// output is long should still run to completion and report its exit
// status.
// It is mutex-guarded because x/crypto/ssh copies a session's output in
// goroutines that finish only when Wait() drains them. On a command
// timeout the manager stops waiting and reads what it has, so a copy
// goroutine may still be writing here while the caller reads -- a data
// race on strings.Builder, which can hand back a string built from a
// stale slice header. The lock costs nothing next to an SSH round trip.
type cappedBuffer struct {
	mu      sync.Mutex
	sb      strings.Builder
	limit   int
	written int
	cut     bool
}

func newCappedBuffer(limit int) *cappedBuffer {
	return &cappedBuffer{limit: limit}
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.limit - b.written; room > 0 {
		if len(p) <= room {
			b.sb.Write(p)
			b.written += len(p)
		} else {
			b.sb.Write(p[:room])
			b.written = b.limit
			b.cut = true
		}
	} else if len(p) > 0 {
		b.cut = true
	}
	// Always report the full write: the caller is an SSH session
	// copying a stream, and a short write would tear it down.
	return len(p), nil
}

func (b *cappedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.String()
}

func (b *cappedBuffer) truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cut
}

func (b *cappedBuffer) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sb.Reset()
	b.written = 0
	b.cut = false
}

// discard is an io.Writer for commands whose output nobody reads --
// the heartbeat and the shutdown sentinel.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
