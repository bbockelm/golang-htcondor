// Package watchpoll holds the wire contract for a watch URL: the answer
// a poll returns, and how long one may block.
//
// It is its own package because both servers need it and neither can
// import the other. The REST daemon serves the endpoint; the MCP server
// mints the URLs and has to tell the agent what the endpoint will do,
// including from a standalone stdio process with no listener of its own.
// A second copy of these numbers would drift, and the number that
// matters most -- how long a call can block -- is the one a poller sizes
// its own client timeout from.
package watchpoll

import (
	"strconv"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
)

// Blocking policy for one poll of a watch URL.
//
// These are deliberately far longer than the MCP in-call cap. That cap
// is short because an MCP call crosses somebody else's gateway, whose
// timeout this server does not know. A watch URL is dialled directly by
// a poller that chose its own client timeout, and holding the connection
// open is the entire point: every second spent blocked here is a request
// the poller did not have to make, and a wake-up that is not late.
const (
	// DefaultWait is the block when the caller names none.
	DefaultWait = 60 * time.Second
	// MaxWait bounds one call. Past a few minutes idle proxies and load
	// balancers close connections regardless of the heartbeat, so a
	// longer block buys nothing and costs a reconnect.
	MaxWait = 5 * time.Minute
	// HeartbeatInterval is how often a streaming poll emits a liveness
	// frame while the answer is pending.
	HeartbeatInterval = 15 * time.Second
	// Refresh is how often a blocked call re-evaluates the watch.
	Refresh = 2 * time.Second
)

// Poll states. A caller only has to look at PollAgain; the state is for
// a human reading the log, and for dispatching on the SSE event name.
const (
	StateFired   = "fired"   // the watch has its answer
	StateWaiting = "waiting" // nothing yet; call again
	StateGone    = "gone"    // expired, cancelled, or never existed
)

// Answer is one answer from a watch URL: the long-poll body, and the
// terminal frame of the streaming form.
//
// WaitedSeconds is how long THIS call blocked. It is here rather than
// left for the caller to measure because the party that eventually reads
// this is often an LLM, and an agent that has to count heartbeat frames
// to learn how long it waited pays for every one of them. One number on
// the last frame is the whole answer.
type Answer struct {
	WatchID string `json:"watch_id"`
	State   string `json:"state"`
	// PollAgain is false once the answer cannot change. It is the one
	// field a dumb poller needs: keep calling while it is true, stop
	// when it is not.
	PollAgain     bool   `json:"poll_again"`
	WaitedSeconds int    `json:"waited_seconds"`
	Label         string `json:"label,omitempty"`
	Event         string `json:"event,omitempty"`
	// OpenSeconds is how long the watch itself has been open -- its age
	// while waiting, its time-to-answer once fired. Distinct from
	// WaitedSeconds, which is only about this call.
	OpenSeconds   int               `json:"open_seconds,omitempty"`
	MatchedTotal  int               `json:"matched_total,omitempty"`
	Matched       []jobwatch.JobRef `json:"matched,omitempty"`
	Unsatisfiable bool              `json:"unsatisfiable,omitempty"`
	Undetermined  bool              `json:"undetermined,omitempty"`
	Incomplete    bool              `json:"incomplete,omitempty"`
}

// Waiting builds the answer for a watch that has not fired.
func Waiting(id string, waited int) Answer {
	return Answer{WatchID: id, State: StateWaiting, PollAgain: true, WaitedSeconds: waited}
}

// Gone builds the answer for a watch that is no longer there. It is
// terminal: the watch expired, was cancelled, or never existed, and a
// poller that kept calling would wait forever on a dead URL.
func Gone(id string, waited int) Answer {
	return Answer{WatchID: id, State: StateGone, PollAgain: false, WaitedSeconds: waited}
}

// From renders a watch as an answer.
func From(w *jobwatch.Watch, waited int, now time.Time) Answer {
	a := Answer{
		WatchID:       w.ID,
		WaitedSeconds: waited,
		Label:         w.Label,
		Event:         string(w.Event),
		MatchedTotal:  w.MatchedTotal,
		Incomplete:    w.Incomplete,
	}
	if w.FiredAt.IsZero() {
		a.State, a.PollAgain = StateWaiting, true
		a.OpenSeconds = int(now.Sub(w.CreatedAt).Round(time.Second).Seconds())
		return a
	}
	a.State, a.PollAgain = StateFired, false
	a.OpenSeconds = int(w.FiredAt.Sub(w.CreatedAt).Round(time.Second).Seconds())
	a.Matched = w.Matched
	a.Unsatisfiable = w.Unsatisfiable
	a.Undetermined = w.Undetermined
	return a
}

// ClampWait reads a ?wait=<seconds> value. Absent, negative or
// unparseable means the default: a malformed optional knob is a worse
// reason to refuse a poll than to answer it at the usual length.
func ClampWait(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultWait
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return DefaultWait
	}
	if d := time.Duration(n) * time.Second; d <= MaxWait {
		return d
	}
	return MaxWait
}
