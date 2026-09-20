package httpserver

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
)

// A write deadline that moves while the request is making progress.
//
// HTTP_API_WRITE_TIMEOUT is one number applied to every response the server
// writes, and net/http treats it as an absolute deadline rather than an idle
// timer -- a response is cut off that long after it began, however busy it has
// been. That is the right shape for an ordinary reply and the wrong shape for
// an MCP call that is deliberately waiting: watch_jobs blocks until something
// happens to a job, and the flat deadline decided how long it was allowed to,
// which is why its advertised cap was tuned down to fit inside the timeout
// rather than to fit what an agent actually wants to wait for.
//
// Writing progress does not help on its own; the deadline does not care how
// much has been written. What works is moving it: http.ResponseController
// grants another window per call, so the ceiling becomes "this response may
// continue while it is still making progress" instead of a fixed budget. A
// handler that stops extending is still cut off on its last window, so the
// slow-client protection the timeout exists for is kept.
//
// Extension is not unbounded: mcpMaxRequestDuration is a hard stop, so a tool
// that hangs ends the request instead of holding a connection for as long as
// its bug lasts.

const (
	// DefaultMCPMaxRequestDuration is how long an MCP request may run while
	// it keeps making progress. Deliberately generous -- the point is to let
	// a watch wait for a job rather than for a timeout -- but finite, so a
	// stuck tool is bounded by something.
	DefaultMCPMaxRequestDuration = 15 * time.Minute

	// mcpWriteWindow is how far ahead each extension moves the deadline, and
	// so how long a stalled response survives after its last sign of life.
	mcpWriteWindow = 30 * time.Second

	// mcpWatchWaitMargin is reserved for writing the response once a tool
	// returns. The watch cap derived from the request cap leaves this much
	// room, so a watch that waits the maximum still has time to answer.
	mcpWatchWaitMargin = 30 * time.Second

	// DefaultDeliverableWatchWait is how long a block can be expected to
	// SURVIVE, as against how long this server is willing to run it.
	//
	// The two are different numbers and only one of them is ours. The
	// deadline extension above settles what this daemon will hold a request
	// open for -- 14m30s once the reply margin is taken off the default hard
	// stop -- and says nothing about the MCP client at the other end, which
	// abandons a tool call on a timer of its own that this server cannot
	// see, cannot extend and is not told about. Measured against a live
	// deployment: a 45s and a 50s block both came back with their answer,
	// while 120s and 600s returned nothing at all -- not a timeout result, no
	// payload, just the client giving up. Reports of that timer put it near
	// 60s, and it varies by client: the CLI honours a per-server override,
	// the desktop app reportedly ignores it, and a progress notification
	// does not reset it.
	//
	// So a cap derived from our own deadline is a number no one can deliver,
	// and advertising it is worse than advertising a small one. The tool
	// description is what an agent plans against; told it may wait 14m30s it
	// asks for minutes, and every such call returns nothing -- which an agent
	// cannot tell apart from a lost answer, where a wait that runs out and
	// says "not yet" is unambiguous and costs one more turn. 45s is the
	// longest block observed to arrive, with the rest of the minute left for
	// the evaluation pass and the reply.
	//
	// This bounds the DEFAULT only. HTTP_API_MCP_WATCH_MAX_WAIT still wins
	// outright, in both directions: an operator who knows their clients are
	// configured for longer, or who has a gateway tighter than this, is the
	// only one who knows, and setting it is how they say so.
	DefaultDeliverableWatchWait = 45 * time.Second
)

// writeWindow is how far ahead each extension moves the deadline. Overridable
// so a test can exercise repeated extension without running for minutes; the
// shipped value is mcpWriteWindow.
func (h *Handler) writeWindow() time.Duration {
	if h.mcpWriteWindow > 0 {
		return h.mcpWriteWindow
	}
	return mcpWriteWindow
}

// mcpMaxRequestDuration is the configured hard stop, or the default.
func (h *Handler) mcpMaxRequestDuration() time.Duration {
	if h.mcpMaxRequest > 0 {
		return h.mcpMaxRequest
	}
	return DefaultMCPMaxRequestDuration
}

// derivedWatchMaxWait is how long watch_jobs may block, given the hard stop:
// long enough to be worth using, short enough to leave room to reply. Returns
// 0 when the cap is too small to be worth deriving from, which leaves the
// mcpserver default in place.
func derivedWatchMaxWait(maxRequest time.Duration) time.Duration {
	if maxRequest <= mcpWatchWaitMargin {
		return 0
	}
	return maxRequest - mcpWatchWaitMargin
}

// progressiveWriteDeadline keeps the response's write deadline ahead of a
// request that is still running, up to a hard stop.
//
// It returns a context that is cancelled at the hard stop -- so a tool blocked
// on it gives up rather than being severed mid-write -- and a stop function the
// caller must call once the response has been written. Extension continues
// through the write itself, which is why stopping is the caller's job rather
// than something tied to the dispatch returning.
func (h *Handler) progressiveWriteDeadline(parent context.Context, w http.ResponseWriter) (context.Context, func()) {
	maxRequest := h.mcpMaxRequestDuration()
	ctx, cancel := context.WithTimeout(parent, maxRequest)

	window := h.writeWindow()
	rc := http.NewResponseController(w)
	// Prove the deadline can be moved before relying on it. A
	// ResponseWriter that does not support it (a wrapper that does not
	// unwrap, say) leaves the server-wide timeout in force, which is what
	// happened before this existed -- worth a log line, not a failure.
	if err := rc.SetWriteDeadline(time.Now().Add(window)); err != nil {
		if !errors.Is(err, http.ErrNotSupported) {
			h.logger.Warn(logging.DestinationHTTP, "could not set the MCP write deadline; the server-wide timeout applies",
				"error", err)
		} else {
			h.logger.Debug(logging.DestinationHTTP, "write deadlines are not supported on this response; the server-wide timeout applies")
		}
		return ctx, cancel
	}

	done := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() { close(done) })
		cancel()
	}

	go func() {
		// Half a window, so a tick is missed only if the whole goroutine
		// is starved for longer than the window itself.
		ticker := time.NewTicker(window / 2)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				// The hard stop. Deliberately stop extending: the request
				// is over, and the last window is what remains for
				// whatever is still trying to write.
				return
			case <-ticker.C:
				if err := rc.SetWriteDeadline(time.Now().Add(window)); err != nil {
					return
				}
			}
		}
	}()

	return ctx, stop
}

// watchMaxWait is how long watch_jobs may block in-call: the operator's
// setting when there is one, else the smaller of what this server will run
// and what the client is expected to wait for.
//
// Only the operator knows what sits in front of this daemon, so an explicit
// HTTP_API_MCP_WATCH_MAX_WAIT is never overridden -- a gateway with a shorter
// timeout than ours is still the real ceiling, and the deadline extension here
// does nothing about it. Unset, the default is deliberately the pessimistic
// one of the two: the derived cap where the request deadline is the tighter
// constraint, DefaultDeliverableWatchWait where it is not. A cap nobody can
// deliver is not a generous default, it is a trap, and the number here is
// what the tool schema advertises to the agent.
func watchMaxWait(cfg HandlerConfig) time.Duration {
	if cfg.MCPWatchMaxWait > 0 {
		return cfg.MCPWatchMaxWait
	}
	maxRequest := cfg.MCPMaxRequestDuration
	if maxRequest <= 0 {
		maxRequest = DefaultMCPMaxRequestDuration
	}
	derived := derivedWatchMaxWait(maxRequest)
	// Zero means "nothing sensible to derive"; leave the mcpserver default
	// in place rather than raising it to the deliverable ceiling.
	if derived == 0 || derived < DefaultDeliverableWatchWait {
		return derived
	}
	return DefaultDeliverableWatchWait
}
