package mcpserver

import (
	"fmt"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
)

// The renderers below write for a language model, which means the first
// line has to carry the answer. A model that has to parse a table to
// learn whether its jobs finished will sometimes get it wrong; one that
// reads "FIRED: all 200 jobs are done" will not.

func renderWatchRegistration(got *jobwatch.Watch, registered *jobwatch.Watch) string {
	w := got
	if w == nil {
		w = registered
	}
	// Coalesced describes what this CALL did, and `got` is a fresh read
	// from the store, which cannot know that. Carry it across.
	if registered != nil && registered.Coalesced {
		w.Coalesced = true
	}
	var b strings.Builder
	if !w.FiredAt.IsZero() {
		fmt.Fprintf(&b, "FIRED already — %s\n\n", describeFired(w))
		fmt.Fprintf(&b, "Watch %s (%s) has already been answered; you do not need to check it again.\n", w.ID, describeQuestion(w))
		b.WriteString(renderMatched(w))
		return b.String()
	}

	// Re-registering an identical question returns the watch that
	// already exists. An agent reading watch_jobs as "tell me the state
	// now" otherwise calls it again every turn, waiting each time on a
	// question it has already arranged to have answered.
	if w.Coalesced {
		fmt.Fprintf(&b, "ALREADY WATCHING — %s, registered %s ago: %s\n\n",
			w.ID, shortDuration(time.Since(w.CreatedAt)), describeQuestion(w))
		b.WriteString(renderWatchProgress(w))
		fmt.Fprintf(&b, "\nTo check it, call check_watches with {\"watch_id\": %q}. Calling watch_jobs "+
			"again only returns here.\n", w.ID)
		return b.String()
	}

	fmt.Fprintf(&b, "WAITING — watch %s registered: %s\n\n", w.ID, describeQuestion(w))
	if w.Incomplete {
		b.WriteString("WARNING: this watch selects more jobs than one read of the queue covers, so it is " +
			"looking at a sample rather than the whole set. An \"all\" watch will never fire in this state, " +
			"because \"all\" cannot be claimed about jobs nobody looked at.\n" +
			"Narrow the constraint — naming a cluster (ClusterId == N) is almost always what was meant — " +
			"or use aggregate_jobs to follow bulk progress instead.\n\n")
	}
	b.WriteString(renderWatchProgress(w))
	fmt.Fprintf(&b, "\nDo not poll. When you next need to know, call check_watches with {\"watch_id\": %q}, "+
		"or with no arguments to collect every answer at once.\n", w.ID)
	return b.String()
}

// renderWatchProgress says what the watch currently selects.
//
// The zero case earns its own wording. A constraint that matches
// nothing is registered rather than refused, because the tracked set
// grows as jobs appear and watching for work not yet submitted is a
// real use -- but it is far more often a wrong cluster id or a typo,
// and a watch that silently selects nothing looks exactly like one
// waiting patiently on jobs that are still running. It would sit there
// until its TTL ran out, having never been able to fire.
func renderWatchProgress(w *jobwatch.Watch) string {
	if len(w.Tracked) > 0 {
		return fmt.Sprintf("Watching %d job(s). Nothing to report yet.\n", len(w.Tracked))
	}
	return "MATCHES NOTHING: no such job in your queue or in the last 24h of history. The watch stays " +
		"registered and fires if matching jobs appear, which is right if you have not submitted them " +
		"yet. Otherwise the constraint is wrong -- check it with query_jobs.\n"
}

func renderWatchReport(news, waiting []*jobwatch.Watch, includeDelivered bool) string {
	var b strings.Builder
	switch {
	case len(news) == 1:
		fmt.Fprintf(&b, "1 watch fired: %s\n\n", describeFired(news[0]))
	case len(news) > 1:
		fmt.Fprintf(&b, "%d watches fired.\n\n", len(news))
	case len(waiting) == 0:
		return "No watches registered. Use watch_jobs to be told when something happens instead of polling.\n"
	default:
		fmt.Fprintf(&b, "Nothing new. %d watch(es) still waiting.\n\n", len(waiting))
	}

	for _, w := range news {
		fmt.Fprintf(&b, "--- %s (%s) ---\n", w.ID, describeQuestion(w))
		fmt.Fprintf(&b, "fired %s (%s ago)\n", w.FiredAt.UTC().Format(time.RFC3339), shortDuration(time.Since(w.FiredAt)))
		b.WriteString(renderMatched(w))
		b.WriteString("\n")
	}
	if len(waiting) > 0 {
		b.WriteString("Still waiting:\n")
		for _, w := range waiting {
			fmt.Fprintf(&b, "- %s (%s), registered %s ago", w.ID, describeQuestion(w), shortDuration(time.Since(w.CreatedAt)))
			switch {
			case w.Incomplete:
				b.WriteString("  [selects more jobs than one read covers; narrow the constraint]")
			case len(w.Tracked) == 0:
				// This one has never selected a job, so it has never had
				// anything to wait on -- otherwise indistinguishable
				// from a watch waiting patiently.
				b.WriteString("  [MATCHES NOTHING -- check the constraint with query_jobs]")
			default:
				fmt.Fprintf(&b, "  [%d job(s)]", len(w.Tracked))
			}
			b.WriteString("\n")
		}
	}
	if !includeDelivered && len(news) > 0 {
		b.WriteString("\n(Answers already shown to you are omitted; pass include_delivered to see them again.)\n")
	}
	return b.String()
}

// describeQuestion restates the watch in the words the caller used, so a
// model holding several can tell which one an answer belongs to without
// having tracked the ids itself.
func describeQuestion(w *jobwatch.Watch) string {
	q := fmt.Sprintf("%s %s of %s", w.Mode, w.Event, w.Constraint)
	if w.Event == jobwatch.EventCustom {
		q = fmt.Sprintf("%s of [%s] among %s", w.Mode, w.Condition, w.Constraint)
	}
	if w.Label != "" {
		q = w.Label + ": " + q
	}
	return q
}

func describeFired(w *jobwatch.Watch) string {
	noun := "job"
	if w.MatchedTotal != 1 {
		noun = "jobs"
	}
	if w.Undetermined {
		// Deliberately not phrased as the event: nothing established
		// that these succeeded or failed, and saying so would be a
		// guess. What is known is that they ended.
		return fmt.Sprintf("%d %s ended, but their outcome could not be determined", w.MatchedTotal, noun)
	}
	switch w.Event {
	case jobwatch.EventDone:
		return fmt.Sprintf("%d %s finished", w.MatchedTotal, noun)
	case jobwatch.EventSucceeded:
		return fmt.Sprintf("%d %s succeeded", w.MatchedTotal, noun)
	case jobwatch.EventFailed:
		return fmt.Sprintf("%d %s FAILED", w.MatchedTotal, noun)
	case jobwatch.EventHeld:
		return fmt.Sprintf("%d %s went on HOLD", w.MatchedTotal, noun)
	case jobwatch.EventRunning:
		return fmt.Sprintf("%d %s started running", w.MatchedTotal, noun)
	default:
		return fmt.Sprintf("%d %s matched", w.MatchedTotal, noun)
	}
}

// renderMatched lists the jobs, with the attributes that make the answer
// actionable. Being told a job is held without the reason costs another
// round trip for the only fact that matters.
func renderMatched(w *jobwatch.Watch) string {
	if len(w.Matched) == 0 {
		return ""
	}
	var b strings.Builder
	if w.Undetermined {
		b.WriteString("  These jobs left the queue, but no history record was available to say how they\n" +
			"  finished -- the history mirror is unreachable or behind. Check them directly with\n" +
			"  query_history_db or get_job.\n")
	}
	for _, m := range w.Matched {
		fmt.Fprintf(&b, "  %d.%d", m.Cluster, m.Proc)
		for _, attr := range []string{"JobStatus", "ExitCode", "HoldReason", "RemoveReason"} {
			if v := m.Attrs[attr]; v != "" {
				fmt.Fprintf(&b, "  %s=%s", attr, v)
			}
		}
		b.WriteString("\n")
	}
	if w.MatchedTotal > len(w.Matched) {
		fmt.Fprintf(&b, "  ... and %d more (%d in total)\n", w.MatchedTotal-len(w.Matched), w.MatchedTotal)
	}
	return b.String()
}

func shortDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
}
