package mcpserver

import (
	"fmt"
	"time"
)

// What the agent is told about blocking, derived from how long it is actually
// allowed to block.
//
// The cap is deployment configuration: it follows the request deadline and,
// where there is one, the gateway in front of the daemon. The advice around it
// was not -- it was prose written when the cap was twenty seconds, and at that
// size "block only if you expect it imminently, otherwise register and collect
// later" is right. Raise the cap to minutes and the same sentence is wrong:
// blocking becomes the simple thing to do for most waits, and an agent that
// keeps returning immediately is doing extra turns for no reason.
//
// So the advice is rendered from the cap rather than written beside it. One
// value decides both the number the agent is given and what it is told to do
// with it, which is the only way they cannot disagree.

// blockingIsPrimaryAbove is where the advice flips. Below it, blocking is worth
// doing only for something already imminent; above it, a wait long enough to
// cover a job starting, or a short job finishing, is inside the cap, and
// telling an agent to return immediately just buys it another round trip.
const blockingIsPrimaryAbove = 2 * time.Minute

// blockingIsPrimary reports whether this deployment's cap makes blocking
// the endorsed way to wait, which decides more than the wording.
//
// Re-registering a watch resolves to the one already there. Below the
// threshold that is an agent using watch_jobs to poll -- it was told to
// block only for something imminent, it did, the event did not happen,
// and calling again just stalls the next turn too; it should be handed
// the current state and pointed at check_watches. Above it, blocking IS
// the advice, so a caller asking to wait again (a retry after a
// transport timeout, say) is doing what the tool told it to, and its
// wait must be honoured.
func blockingIsPrimary(maxWait int) bool {
	return time.Duration(maxWait)*time.Second >= blockingIsPrimaryAbove
}

// watchWaitAdvice is the cap-dependent text for the watch_jobs tool.
type watchWaitAdvice struct {
	// Strategy opens the tool description: what to do with this tool given
	// how long it may block.
	Strategy string
	// WaitParam describes the wait_seconds parameter.
	WaitParam string
}

// waitAdvice renders the advice for a cap of maxWait seconds.
func waitAdvice(maxWait int) watchWaitAdvice {
	human := humanizeSeconds(maxWait)

	if !blockingIsPrimary(maxWait) {
		return watchWaitAdvice{
			Strategy: "Registers a durable watch and returns immediately; " +
				"call check_watches later (any time, even in a different session) to collect the answer. " +
				fmt.Sprintf("This deployment allows blocking in-call for at most %s, so blocking is worth it only for something you expect imminently.", human),
			WaitParam: fmt.Sprintf("Optionally block up to this many seconds (max %d) waiting for the event before returning. "+
				"Use a small value only when you expect it imminently; otherwise return at once and use check_watches.", maxWait),
		}
	}

	return watchWaitAdvice{
		Strategy: "Registers a durable watch. " +
			fmt.Sprintf("You can block on it for up to %s, which is usually the simplest thing to do: pass wait_seconds and the answer comes back in this response. ", human) +
			"Or return immediately and call check_watches later (any time, even in a different session) to collect the answer — " +
			"which is what you want for a wait longer than that, or when you would rather not hold the call open.",
		WaitParam: fmt.Sprintf("Optionally block up to this many seconds (max %d, about %s) waiting for the event before returning. "+
			"Blocking is fine for anything you expect within that window; for a longer wait return at once and use check_watches.", maxWait, human),
	}
}

// humanizeSeconds renders a cap the way the advice reads it out: seconds while
// they are still easy to hold in mind, then minutes.
func humanizeSeconds(secs int) string {
	switch {
	case secs <= 0:
		return "no time at all"
	case secs < 90:
		return fmt.Sprintf("%d seconds", secs)
	case secs%60 == 0:
		return fmt.Sprintf("%d %s", secs/60, plural(secs/60, "minute"))
	default:
		return fmt.Sprintf("%d %s %d seconds", secs/60, plural(secs/60, "minute"), secs%60)
	}
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}
