package mcpserver

import (
	"fmt"
)

// What the agent is told about blocking, derived from how long it is actually
// allowed to block.
//
// The cap is deployment configuration: it follows the request deadline and,
// where there is one, the gateway in front of the daemon. The advice around it
// was not -- it was prose written beside a particular cap, and prose written
// for twenty seconds is wrong at fifteen minutes and vice versa. So the advice
// is rendered from the cap instead. One value decides both the number the
// agent is given and what it is told to do with it, which is the only way they
// cannot disagree.
//
// The division of labour the advice describes: watch_jobs registers a question
// once, check_watches is called as often as the agent likes AND is the tool
// that waits. Blocking used to be offered on watch_jobs alone, which put the
// only waiting knob on the one tool an agent is told to call once -- so an
// agent that wanted to wait had no correct move and fell back to the polling
// loop these tools exist to replace.

// RecommendedWaitSeconds is the block to ask for when nothing more specific is
// known. It is not the cap and it is deliberately far below it: the cap is
// what this server will honour, while the MCP client or gateway in front of it
// has a timeout of its own -- observed around a minute -- that this server
// cannot see. A block the client cuts off returns nothing at all, which is
// strictly worse than returning "not yet" and being called again.
const RecommendedWaitSeconds = 30

// recommendedWait is RecommendedWaitSeconds, or the cap where the cap is
// tighter -- never advice to ask for more than the server will give.
func recommendedWait(maxWait int) int {
	if maxWait < RecommendedWaitSeconds {
		return maxWait
	}
	return RecommendedWaitSeconds
}

// transportHazard is the warning attached to every blocking knob: the number
// this server honours is not the number the path in front of it honours.
const transportHazard = "Longer blocks are a gamble: the MCP client (or a gateway) between you and this " +
	"server has a timeout of its own, often around a minute, and if it fires first the call returns nothing at all."

// watchWaitAdvice is the cap-dependent text for the watch_jobs tool.
type watchWaitAdvice struct {
	// Strategy opens the tool description: what this tool is for, given
	// that check_watches is where waiting happens.
	Strategy string
	// WaitParam describes the wait_seconds parameter.
	WaitParam string
}

// waitAdvice renders the watch_jobs advice for a cap of maxWait seconds.
func waitAdvice(maxWait int) watchWaitAdvice {
	return watchWaitAdvice{
		Strategy: "Registers a durable watch and returns; " +
			fmt.Sprintf("to WAIT for it, call check_watches with wait_seconds (%d is a good value, %s the most this deployment allows). ", recommendedWait(maxWait), humanizeSeconds(maxWait)) +
			"check_watches can be called as often as you like, from any later turn or session, and is where waiting belongs.",
		WaitParam: fmt.Sprintf("Optionally block up to this many seconds (max %d) before returning, for something you expect within a few seconds of registering. ", maxWait) +
			"For any longer wait, return at once and block in check_watches instead: re-calling watch_jobs resolves back to this same watch and does not check it. " +
			transportHazard,
	}
}

// checkWaitAdvice is the cap-dependent text for the check_watches tool.
type checkWaitAdvice struct {
	// Waiting is appended to the tool description: that this is the tool
	// that blocks, and for how long.
	Waiting string
	// WaitParam describes the wait_seconds parameter.
	WaitParam string
}

// checkAdvice renders the check_watches advice for a cap of maxWait seconds.
func checkAdvice(maxWait int) checkWaitAdvice {
	rec := recommendedWait(maxWait)
	return checkWaitAdvice{
		Waiting: fmt.Sprintf("It is also the tool that WAITS: pass wait_seconds (try %d) and it blocks until one of these watches fires, "+
			"up to %s in this deployment. ", rec, humanizeSeconds(maxWait)) +
			"A watch that has already fired comes back straight away, and a wait that runs out comes back with the progress so " +
			"far — never an error — so the answer to \"is it done yet\" is always this call again.",
		WaitParam: fmt.Sprintf("Block up to this many seconds (max %d) waiting for a watch to fire. Omit it for an immediate snapshot. "+
			"Use %d unless you have a reason not to, and call again if it comes back with nothing: repeating a %d-second wait gets you "+
			"the answer sooner than one long block that may never be delivered. ", maxWait, rec, rec) +
			transportHazard,
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
