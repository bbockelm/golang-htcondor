package httpserver

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/PelicanPlatform/classad/dbrpc"
)

// Goodput: of the work this access point actually ran, how much of it
// was worth running.
//
// The status tiles say what is happening now and the activity lists say
// what changed recently. Neither answers the question an operator
// actually has after a bad afternoon -- did any of that work survive? A
// thousand jobs that ran for an hour each and then exited non-zero look
// exactly like a thousand successful ones from the queue's point of
// view, because by then they are gone from it entirely.
//
// It is deliberately about WALL CLOCK as well as counts. Ten thousand
// jobs failing in two seconds apiece is a bad submission and costs
// nothing; ten failing after twelve hours each is most of a day of a
// machine thrown away. The counts alone cannot tell those apart, and the
// second one is the one worth waking up for.

// goodputWindow is how far back the summary looks.
//
// A day rather than the hour the activity lists use: this is a rate, and
// an hour of a quiet access point is mostly noise. It is also the
// horizon an operator asks about ("how did last night go").
const goodputWindow = 24 * time.Hour

// GoodputSummary is the outcome of everything that finished in the
// window.
type GoodputSummary struct {
	WindowHours int `json:"window_hours"`

	// Succeeded is jobs that ran to completion and said so: exit 0, not
	// killed by a signal.
	Succeeded int `json:"succeeded"`
	// Failed is jobs that ran to completion and reported a problem --
	// a non-zero exit or a fatal signal.
	Failed int `json:"failed"`
	// Unfinished is jobs that left without an outcome, which is what a
	// removal looks like from here. Counted separately rather than
	// folded into failures: a job its owner cancelled is not the access
	// point going wrong.
	Unfinished int `json:"unfinished"`

	// GoodSeconds and BadSeconds are wall-clock time on the execute
	// node, split the same way. This is the half that makes the panel
	// worth having.
	GoodSeconds int64 `json:"good_seconds"`
	BadSeconds  int64 `json:"bad_seconds"`

	// TopFailures ranks the exit codes behind Failed, because "412 jobs
	// failed" and "412 jobs failed with exit 127" are different amounts
	// of information.
	TopFailures []ExitCodeCount `json:"top_failures,omitempty"`
}

// ExitCodeCount is one way jobs finished badly.
type ExitCodeCount struct {
	// Code is the exit status. Signal is set instead when the job was
	// killed, in which case Code has no meaning.
	Code   int64 `json:"code"`
	Signal bool  `json:"signal"`
	Count  int   `json:"count"`
	// Seconds is the wall clock spent on jobs that ended this way.
	Seconds int64 `json:"seconds"`
}

// goodputTopFailures bounds the failure list the same way the hold
// breakdown is bounded.
const goodputTopFailures = 5

// mirrorGoodput summarizes the history table over the window.
//
// One grouped aggregate does all of it: group by how the job ended,
// count and sum wall clock per group, classify here. Deliberately not
// per-aggregate filters, which would be the obvious way to write this --
// those need the extended opcodes, so a mirror a few versions old would
// fail the whole query rather than answer it.
func mirrorGoodput(ctx context.Context, dbc *dbrpc.Client, scope string, since int64) (*GoodputSummary, error) {
	constraint := fmt.Sprintf("(%s) && CompletionDate >= %d", scope, since)
	rows, err := dbc.AggregateTable(ctx, "history", constraint,
		[]string{"ExitCode", "ExitBySignal"},
		[]dbrpc.AggSpec{
			{Func: dbrpc.AggCount, Arg: "*"},
			{Func: dbrpc.AggSum, Arg: "RemoteWallClockTime"},
		})
	if err != nil {
		return nil, err
	}

	sum := &GoodputSummary{WindowHours: int(goodputWindow / time.Hour)}
	var failures []ExitCodeCount
	for _, r := range rows {
		if len(r.Group) < 2 || len(r.Values) < 2 {
			continue
		}
		n, cerr := strconv.Atoi(r.Values[0])
		if cerr != nil || n == 0 {
			continue
		}
		// SUM comes back as a ClassAd number, which is a float when any
		// input was one. Seconds do not need the fraction.
		secs := int64(parseAggFloat(r.Values[1]))

		code, hasCode := parseAggInt(r.Group[0])
		signal := r.Group[1] == "true"

		switch {
		case signal:
			sum.Failed += n
			sum.BadSeconds += secs
			failures = append(failures, ExitCodeCount{Signal: true, Count: n, Seconds: secs})
		case !hasCode:
			// No exit code and no signal: the job never reached the
			// point of having an outcome. A removal, almost always.
			sum.Unfinished += n
			sum.BadSeconds += secs
		case code == 0:
			sum.Succeeded += n
			sum.GoodSeconds += secs
		default:
			sum.Failed += n
			sum.BadSeconds += secs
			failures = append(failures, ExitCodeCount{Code: code, Count: n, Seconds: secs})
		}
	}
	sum.TopFailures = topExitCodes(failures, goodputTopFailures)
	return sum, nil
}

// topExitCodes ranks failures by wall clock rather than by count.
//
// Ranking by count answers "what failed most often", which a broken
// submission dominates and which is usually obvious anyway. Ranking by
// time answers "what cost the most", and the expensive failure is
// frequently the rare one -- a handful of jobs that each ran most of a
// day before dying.
func topExitCodes(in []ExitCodeCount, limit int) []ExitCodeCount {
	if len(in) == 0 {
		return nil
	}
	// Merge duplicates: signalled jobs arrive once per exit code the
	// source happened to record alongside the signal, and they are all
	// the same thing to a reader.
	merged := make([]ExitCodeCount, 0, len(in))
	for _, e := range in {
		found := false
		for i := range merged {
			if merged[i].Signal == e.Signal && (e.Signal || merged[i].Code == e.Code) {
				merged[i].Count += e.Count
				merged[i].Seconds += e.Seconds
				found = true
				break
			}
		}
		if !found {
			merged = append(merged, e)
		}
	}
	for i := 1; i < len(merged); i++ {
		for j := i; j > 0 && less(merged[j-1], merged[j]); j-- {
			merged[j-1], merged[j] = merged[j], merged[j-1]
		}
	}
	if len(merged) > limit {
		merged = merged[:limit]
	}
	return merged
}

// less reports whether a should sort after b: more wasted time first,
// then more jobs, so the order is stable for equal times.
func less(a, b ExitCodeCount) bool {
	if a.Seconds != b.Seconds {
		return a.Seconds < b.Seconds
	}
	return a.Count < b.Count
}

// parseAggInt reads a group value that should be an integer attribute.
// ok is false when the attribute was absent from every row in the group,
// which is a distinct answer from zero: exit 0 is a success and no exit
// code at all is a job that never finished.
func parseAggInt(s string) (int64, bool) {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// parseAggFloat reads a numeric aggregate, which may come back as an
// integer or a float depending on the inputs.
func parseAggFloat(s string) float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return v
}
