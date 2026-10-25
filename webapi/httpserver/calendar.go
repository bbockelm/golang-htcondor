package httpserver

// The calendar view: per-day counts of jobs submitted, completed,
// removed and in queue, over months rather than hours, so an access
// point's owner can see long-term progress rather than this minute's.
//
// Everything here is shaped around three properties of the mirror's
// aggregate engine. Each one is an invisible performance cliff: break it
// and the query still returns the right answer, just by a full record
// scan instead of out of the columnar blocks, which on a production
// history archive is two orders of magnitude. None of them are visible
// in the result, which is why calendarQueries builds the queries as
// values a test can assert on.
//
//  1. Bucket and window on EnteredHistoryTime, NEVER CompletionDate. A
//     removed job has no CompletionDate at all, so bucketing on it does
//     not merely mis-sort removals, it drops every one of them --
//     measured over seven days of production history as ~15 removals
//     against a true 26,798.
//
//     EnteredHistoryTime is the mirror's own "when did this leave the
//     queue" stamp, written on every record it archives: the job's
//     terminal-status transition (EnteredCurrentStatus), falling back to
//     CompletionDate and then to the ingest clock. A removed job has the
//     first of those even though it has none of the second, which is
//     what makes it the one attribute both halves of the chart can be
//     cut on. htcondordb zone-maps it precisely so a windowed read
//     prunes whole segments instead of scanning.
//
//  2. One query per status, narrowed by a constraint -- never one
//     aggregate carrying a per-aggregate FILTER. COUNT(*) FILTER (WHERE
//     JobStatus == 4) declines the columnar path outright (the columnar
//     pass knows nothing about a filter, so answering from it would
//     report an unfiltered count as a filtered one) and falls to a
//     record scan. Two separately constrained queries both stay on the
//     fast path.
//
//  3. One group column. The grouped columnar path serves exactly one,
//     so a second dimension declines it the same way. Each series is
//     therefore its own single-column bucketed aggregate.
//
// Queue depth is the one series that is not read at all: see
// deriveQueueDepth.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/bbockelm/golang-htcondor/logging"
)

// calendarBucket is one day, in seconds: the bucket width every series
// is grouped by, and the step between rows.
//
// The engine floors a bucketed group column to floor(v/width)*width, so
// the buckets are epoch-aligned -- which is to say UTC midnight. The
// response says so; a viewer in another zone sees days that straddle
// theirs, and inventing a local-midnight offset here would cost the
// alignment the zone maps prune on.
const calendarBucket = int64(24 * time.Hour / time.Second)

// Window bounds. The default is a quarter, which is the span the view
// exists to show.
//
// The cap is measured, not guessed. On history archives of realistic ad
// width spanning 400 days, with the columnar accelerator on (which
// htcondordb turns on by default), one owner-scoped day-series costs:
//
//	window     1M records     3M records
//	   7d      9-15ms         ~78ms
//	  30d      20-35ms        ~113ms
//	  90d      51-95ms        ~200ms
//	 180d      94-161ms       ~345ms
//	 365d      183-335ms      1.0-2.0s
//
// So the three archive series of a year-long calendar are about a second
// at 1M and three to four at 3M -- scaling with the records the window
// covers rather than with the number of days -- and a 5M-record archive
// extrapolates to under ten. That is paid once per calendarRefresh per
// scope and sits inside calendarComputeTimeout with room to spare. Past
// a year the window also stops buying a reader anything a day-wide
// column can show, so cost and usefulness run out at about the same
// place, and this is it.
//
// Without the accelerator the same work is a full record scan: 1.3-1.6s
// at 90 days and 5.3-6.1s at 365 on the 1M archive, 19-20s at 365 on the
// 3M one. That is a property of the mirror rather than of this code, and
// it is why the cost is bounded by a cache and a cap rather than assumed
// small.
const (
	calendarDefaultDays = 90
	calendarMaxDays     = 400
)

// calendarRefresh is how long one computed calendar is shared for.
//
// Generous on purpose. Every bucket but the last is settled -- a day
// that has ended does not gain jobs -- so all that moves within a
// refresh is today's row and the live anchor the queue depth is walked
// back from. Fifteen minutes bounds the archive aggregates to four per
// scope per hour on a view whose whole subject is months, and the
// response carries computed_at so a reader can see how stale it is
// rather than having to assume.
const calendarRefresh = 15 * time.Minute

// calendarComputeTimeout bounds one computation. Longer than the refresh
// interval because the computation is worth finishing into the cache
// even once the viewer who triggered it has gone -- the same bargain
// dashboardWalkTimeout makes.
const calendarComputeTimeout = 2 * time.Minute

// calendarProbeRows bounds the archive-reach probe: it only has to find
// one record, so it reads one.
const calendarProbeRows = 1

// CalendarDay is one day's row. Every day in the window gets one, zeros
// included: a day with no jobs and a day the archive cannot answer for
// are different facts, and omitting the empty ones would leave the panel
// unable to tell them apart (that is what partial and note are for).
type CalendarDay struct {
	// Day is the bucket start, unix seconds, UTC midnight.
	Day       int64 `json:"day"`
	Submitted int   `json:"submitted"`
	Completed int   `json:"completed"`
	Removed   int   `json:"removed"`
	InQueue   int   `json:"in_queue"`
}

// CalendarQueueDepth describes where the in_queue series came from.
//
// Both fields are reported rather than assumed, because the series is
// not measured. It is walked backwards from Anchor -- the live count --
// through the flows, so every day's depth carries the accumulated error
// of every job that left the queue without entering history. Saying
// "derived, from this anchor" is what lets a reader distinguish a drift
// from a real backlog.
//
// Anchor and the LAST day's in_queue are guaranteed equal whenever this
// block is present: deriveQueueDepth assigns the anchor to that day and
// walks backwards from it, so they are one number reported twice rather
// than two that could drift. A panel may render either -- as the figure
// beside the chart or as the last plotted point -- without the two
// disagreeing. (When the live count could not be read this block is
// absent and every in_queue is zero; partial and note say so.)
type CalendarQueueDepth struct {
	Derived bool `json:"derived"`
	Anchor  int  `json:"anchor"`
}

// CalendarBucketing names the attribute each series was bucketed on.
//
// Reported rather than left implicit because a drill-down has to ask the
// same question the figure answered, and the obvious guesses are wrong.
// The finished and removed series are bucketed on EnteredHistoryTime --
// the stamp described in the file header -- NOT on CompletionDate, which
// a removed job does not have at all, and not on EnteredCurrentStatus,
// which EnteredHistoryTime only usually equals. The two normally agree
// to the second and occasionally do not: a job whose terminal transition
// and completion straddle midnight, or one stamped from the ingest clock
// after a backlog drain, lands on a different day here than a constraint
// on CompletionDate would put it, and the drill-down then shows a total
// that disagrees with the number it was reached from.
//
// The submitted series is the one place the attribute is not the whole
// story: it is a union of the history archive and the live queue, both
// bucketed on QDate, so a drill-down must read BOTH or it undercounts by
// exactly the jobs that are still running. A QDate day-range alone is
// enough to reproduce it on each -- the archive half's window on
// EnteredHistoryTime is implied, since a job submitted inside the window
// cannot have entered history before it.
type CalendarBucketing struct {
	Submitted string `json:"submitted"`
	Completed string `json:"completed"`
	Removed   string `json:"removed"`
}

// CalendarResponse is the whole panel.
type CalendarResponse struct {
	// Enabled is false where nothing can answer -- no mirror -- in which
	// case there are no days. Reported rather than errored, the same way
	// handlers_metrics.go reports an absent sampler: a page hides a
	// feature it cannot have, it does not show an error for one.
	Enabled    bool          `json:"enabled"`
	Days       []CalendarDay `json:"days,omitempty"`
	WindowDays int           `json:"window_days,omitempty"`
	// Step is the bucket width in seconds, which is also the spacing
	// between consecutive Day values. Reported rather than left at an
	// assumed 86400 so a reader laying out weeks or looking for gaps is
	// not silently wrong if a coarser bucket is ever offered.
	Step       int64               `json:"step,omitempty"`
	QueueDepth *CalendarQueueDepth `json:"queue_depth,omitempty"`
	// BucketedOn says which attribute each series was bucketed on, so a
	// drill-down can ask the same question the figure answered.
	BucketedOn *CalendarBucketing `json:"bucketed_on,omitempty"`
	Source     string             `json:"source,omitempty"`
	ComputedAt int64              `json:"computed_at,omitempty"`
	// Partial says some of this is missing or approximate, and Note says
	// which: the archive does not reach back over the whole window, or
	// the mirror answered only part of it.
	Partial bool   `json:"partial"`
	Note    string `json:"note"`
}

// calendarSeries names one of the day-series, for a note and for a test
// to assert the right query was built for the right thing.
type calendarSeries string

const (
	seriesCompleted        calendarSeries = "completed"
	seriesRemoved          calendarSeries = "removed"
	seriesSubmittedHistory calendarSeries = "submitted (finished)"
	seriesSubmittedLive    calendarSeries = "submitted (in queue)"
)

// calendarQuery is one aggregate as constructed, before it is sent.
//
// Built as a value rather than passed straight to the client so a test
// can assert on the SHAPE -- one group column, no per-aggregate filter,
// the window and the bucket on the right attribute. Those are exactly
// the properties that regress silently: every one of them still returns
// the right numbers when broken, only slowly, so a test on the result
// cannot see it and only a test on the query can.
type calendarQuery struct {
	Series calendarSeries
	Table  string
	// Archive says this goes to the archive API rather than the table
	// one. The two are not interchangeable and the difference is
	// invisible from outside: htcondordb makes "history" an append-only
	// archive, and AggregateTable on that name answers "no such table".
	Archive    bool
	Constraint string
	Groups     []dbrpc.GroupCol
	Aggs       []dbrpc.AggSpec
}

// calendarCountStar is the one aggregate every series asks for. No
// Filter, deliberately and load-bearingly: see the file header.
func calendarCountStar() []dbrpc.AggSpec {
	return []dbrpc.AggSpec{{Func: dbrpc.AggCount, Arg: "*"}}
}

// calendarQueries builds the day-series queries for one window.
//
// start and end are bucket-aligned unix seconds, end exclusive. scope is
// the owner clause from mirrorScope; it is already a complete ClassAd
// expression, parenthesised here so a clause of its own cannot reach
// past the AND.
func calendarQueries(scope string, start, end int64) []calendarQuery {
	// The window, on the attribute the mirror stamps and zone-maps.
	// Bounded at both ends, not just below: an "everything since" read
	// has no upper segment to prune against, and a clock skewed forward
	// on one ingest would otherwise drag a bucket past the last day.
	hist := fmt.Sprintf("(%s) && EnteredHistoryTime >= %d && EnteredHistoryTime < %d", scope, start, end)
	byHistoryDay := []dbrpc.GroupCol{{Attr: "EnteredHistoryTime", BucketWidth: calendarBucket}}
	bySubmitDay := []dbrpc.GroupCol{{Attr: "QDate", BucketWidth: calendarBucket}}

	return []calendarQuery{
		// Finished and removed, one constrained query each rather than
		// one aggregate with two filters.
		{
			Series: seriesCompleted, Table: "history", Archive: true,
			Constraint: hist + " && JobStatus == 4",
			Groups:     byHistoryDay, Aggs: calendarCountStar(),
		},
		{
			Series: seriesRemoved, Table: "history", Archive: true,
			Constraint: hist + " && JobStatus == 3",
			Groups:     byHistoryDay, Aggs: calendarCountStar(),
		},
		// Submitted, from the archive: windowed on EnteredHistoryTime
		// but BUCKETED on QDate -- the day a job was submitted, not the
		// day it finished. Windowing on QDate instead would be the
		// obvious way to write it and is the wrong one: QDate is not
		// zone-mapped, so the window would prune nothing and the same
		// answer cost 677ms against 83ms. The window is on the mapped
		// attribute and the bucket on the asked-for one, and these are
		// different attributes precisely because they are allowed to be.
		//
		// Rows whose QDate bucket lands before the window are dropped by
		// the assembler: a job submitted in March and finished in June
		// belongs to March, which this window does not cover.
		{
			Series: seriesSubmittedHistory, Table: "history", Archive: true,
			Constraint: hist,
			Groups:     bySubmitDay, Aggs: calendarCountStar(),
		},
		// Submitted, from the live queue: the other half of the union --
		// work submitted inside the window that has not finished, and so
		// has no history record to be counted by the query above.
		//
		// The union is complete, and that is an arithmetic fact rather
		// than an approximation: a job submitted inside the window that
		// has already finished satisfies EnteredHistoryTime >= QDate >=
		// start, so the archive query's window necessarily contains it.
		// The live table carries no EnteredHistoryTime, so here the
		// window goes on QDate; it is a mutable table with no zone maps
		// to prune anyway.
		//
		// Complete, but not quite disjoint: the schedd writes history at
		// the terminal event and the reaper destroys the job a moment
		// later, so a job caught between the two is in both tables and
		// is counted twice. That is seconds of overlap on today's row
		// only -- except where LeaveJobInQueue holds finished jobs in
		// the queue, which widens it. Deduplicating would mean reading
		// job ids instead of counts, which is the whole scan this exists
		// to avoid, so the overlap is accepted rather than paid for.
		{
			Series: seriesSubmittedLive, Table: "jobs",
			Constraint: fmt.Sprintf("(%s) && QDate >= %d && QDate < %d", scope, start, end),
			Groups:     bySubmitDay, Aggs: calendarCountStar(),
		},
	}
}

// calendarBucketedOn reports, per series, the attribute its query
// grouped by. Derived from the constructed queries so the response
// cannot claim one attribute while the query uses another -- which is
// the failure it exists to prevent, since the only consumer is a
// drill-down that has to select the same set.
func calendarBucketedOn(queries []calendarQuery) *CalendarBucketing {
	out := &CalendarBucketing{}
	for _, q := range queries {
		if len(q.Groups) == 0 {
			continue
		}
		switch q.Series {
		case seriesCompleted:
			out.Completed = q.Groups[0].Attr
		case seriesRemoved:
			out.Removed = q.Groups[0].Attr
		case seriesSubmittedHistory, seriesSubmittedLive:
			// Both halves of the union bucket on the same attribute, by
			// construction; saying so once is the useful answer.
			out.Submitted = q.Groups[0].Attr
		}
	}
	return out
}

// calendarWindow is the bucket-aligned window for days ending with
// today: start inclusive, end exclusive, both at UTC midnight.
func calendarWindow(now time.Time, days int) (start, end int64) {
	end = (now.Unix()/calendarBucket)*calendarBucket + calendarBucket
	return end - int64(days)*calendarBucket, end
}

// calendarFromMirror computes one calendar.
//
// Serial, like activityFromMirror and for the same measured reason:
// these are scans, the database is the bottleneck, and asking it four
// things at once over the one multiplexed connection adds contention
// rather than saving anything worth having.
func (s *Handler) calendarFromMirror(ctx context.Context, owner string, ownedByMe bool, days int) (*CalendarResponse, error) {
	dbc, closer, scope, err := s.mirrorScope(ctx, owner, ownedByMe)
	if err != nil {
		return nil, err
	}
	defer closer()

	now := time.Now()
	start, end := calendarWindow(now, days)
	resp := &CalendarResponse{
		Enabled:    true,
		WindowDays: days,
		Step:       calendarBucket,
		Source:     "htcondordb mirror",
		ComputedAt: now.Unix(),
		Days:       calendarDays(start, days),
		// Read off the queries rather than written out again here, so
		// the two cannot drift: a change to what a series buckets on
		// changes what the response says it buckets on.
		BucketedOn: calendarBucketedOn(calendarQueries(scope, start, end)),
	}

	// index finds a day's row by its bucket; a bucket outside the window
	// has none, which is how the submitted-by-QDate rows from before the
	// window are dropped.
	index := func(bucket int64) *CalendarDay {
		i := (bucket - start) / calendarBucket
		if bucket < start || i < 0 || int(i) >= len(resp.Days) {
			return nil
		}
		return &resp.Days[i]
	}

	var missing []string
	// earliest is the first day in the window any history row landed on,
	// which the reach probe below needs to say anything useful.
	earliest := int64(-1)
	answered := 0
	for _, q := range calendarQueries(scope, start, end) {
		rows, qerr := runCalendarQuery(ctx, dbc, q)
		if qerr != nil {
			// One series failing costs that series, not the panel. A
			// deployment with no history archive loses three of the four
			// and still gets a live submitted series, which is a real if
			// short answer; losing all four is reported as a failure by
			// the caller below.
			missing = append(missing, fmt.Sprintf("the %s series could not be read", q.Series))
			s.logger.Debug(logging.DestinationHTTP, "calendar: the mirror could not answer a series",
				"series", string(q.Series), "error", qerr)
			continue
		}
		answered++
		for _, r := range rows {
			bucket, ok := parseAggInt(firstGroup(r))
			if !ok {
				continue
			}
			n, ok := parseAggInt(firstValue(r))
			if !ok {
				continue
			}
			// Only the EnteredHistoryTime-bucketed series say when the
			// archive's coverage starts. A QDate bucket is a submit day,
			// which can predate the record holding it by months, so
			// reading coverage off one would claim the archive reaches
			// further back than it does.
			if q.Groups[0].Attr == "EnteredHistoryTime" && (earliest < 0 || bucket < earliest) {
				earliest = bucket
			}
			day := index(bucket)
			if day == nil {
				continue
			}
			switch q.Series {
			case seriesCompleted:
				day.Completed += int(n)
			case seriesRemoved:
				day.Removed += int(n)
			case seriesSubmittedHistory, seriesSubmittedLive:
				day.Submitted += int(n)
			}
		}
	}
	if answered == 0 {
		return nil, fmt.Errorf("the mirror answered none of the calendar's queries")
	}

	// The anchor, and with it the whole in_queue series: one plain
	// ungrouped aggregate over the live table. Bounded by the scope
	// alone because that IS the bound -- it is the count of what is in
	// the queue, and there is no narrower question to ask.
	if anchor, aerr := mirrorQueueDepth(ctx, dbc, scope); aerr != nil {
		missing = append(missing, "the live queue count the depth is anchored to")
		s.logger.Debug(logging.DestinationHTTP, "calendar: the mirror could not count the live queue", "error", aerr)
	} else {
		resp.QueueDepth = &CalendarQueueDepth{Derived: true, Anchor: anchor}
		if clamped := deriveQueueDepth(resp.Days, anchor); clamped {
			missing = append(missing,
				"the derived queue depth ran below zero on some days, so jobs left the queue without entering history")
		}
	}

	// Does the archive cover the whole window? Only worth asking when
	// its first answer lands later than the window starts; otherwise it
	// demonstrably does.
	if earliest > start {
		reaches, rerr := calendarReachesBack(ctx, dbc, scope, start)
		switch {
		case rerr != nil:
			s.logger.Debug(logging.DestinationHTTP, "calendar: could not probe how far the archive reaches", "error", rerr)
		case !reaches:
			missing = append(missing, fmt.Sprintf(
				"the history archive holds no record from before %s, so earlier days are unknown rather than empty",
				time.Unix(earliest, 0).UTC().Format("2006-01-02")))
		}
	}

	if len(missing) > 0 {
		resp.Partial = true
		resp.Note = calendarNote(missing)
	}
	return resp, nil
}

// calendarNote renders what is missing as one sentence for the panel.
// Every shortfall is listed rather than only the first: "no history
// archive" and "the depth ran negative" are different problems with
// different fixes, and a reader shown one of them will act on it.
func calendarNote(missing []string) string {
	if len(missing) == 1 {
		return "This is incomplete: " + missing[0] + "."
	}
	return "This is incomplete: " + strings.Join(missing, "; ") + "."
}

// runCalendarQuery sends one constructed query down whichever API its
// table needs.
func runCalendarQuery(ctx context.Context, dbc *dbrpc.Client, q calendarQuery) ([]dbrpc.AggRow, error) {
	if q.Archive {
		return dbc.ArchiveAggregateBucketed(ctx, q.Table, q.Constraint, q.Groups, q.Aggs)
	}
	return dbc.AggregateBucketedTable(ctx, q.Table, q.Constraint, q.Groups, q.Aggs)
}

// mirrorQueueDepth counts what is in the queue right now: the anchor the
// in_queue series is walked backwards from.
func mirrorQueueDepth(ctx context.Context, dbc *dbrpc.Client, scope string) (int, error) {
	rows, err := dbc.AggregateTable(ctx, "jobs", scope, nil, calendarCountStar())
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		// An ungrouped aggregate over an empty match: no rows rather
		// than a zero row, on some paths. An empty queue is zero.
		return 0, nil
	}
	n, ok := parseAggInt(firstValue(rows[0]))
	if !ok {
		return 0, fmt.Errorf("the live queue count came back as %q", firstValue(rows[0]))
	}
	return int(n), nil
}

// calendarReachesBack reports whether the archive holds anything from
// before the window starts.
//
// One row is all the answer needs, and the two bounds are what keep it
// cheap in both directions. When there is nothing older -- the case this
// exists to detect -- every segment's zone map proves it holds no
// candidate and the whole archive is pruned without a record being read.
// When there is, the limit stops the read at the first one.
func calendarReachesBack(ctx context.Context, dbc *dbrpc.Client, scope string, start int64) (bool, error) {
	rows, err := dbc.QueryRawProject(ctx, "history",
		fmt.Sprintf("(%s) && EnteredHistoryTime < %d", scope, start),
		[]string{"EnteredHistoryTime"}, calendarProbeRows)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// calendarDays lays out the window, zero-filled. A gap and a zero are
// different facts, so the panel is given every day and told separately
// (partial, note) when some of them are unknown.
func calendarDays(start int64, days int) []CalendarDay {
	out := make([]CalendarDay, days)
	for i := range out {
		out[i].Day = start + int64(i)*calendarBucket
	}
	return out
}

// deriveQueueDepth fills in in_queue by walking the flows backwards from
// the live count.
//
//	depth(D) = depth(D+1) - submitted(D+1) + completed(D+1) + removed(D+1)
//
// The queue is not sampled per day and cannot be: the mirror holds what
// is in the queue NOW, and nothing records what was in it last Tuesday.
// What it does hold is every job that left, so the depth is reconstructed
// from the flows -- which makes the last day's value the only measured
// one and every earlier day a running total of differences from it.
//
// The error therefore accumulates backwards, and it accumulates from one
// specific thing: a job that left the queue without entering history
// (removed before the schedd wrote a history record, or lost to
// rotation) is a departure the walk never adds back, so the depth drifts
// upward the further back it goes. There is no fixing that here, so it
// is reported instead -- CalendarQueueDepth says derived, and a walk
// that goes negative says so too.
//
// Returns whether any day had to be clamped at zero. A negative count is
// not a plottable number, but silently flooring one would hide exactly
// the drift above, so the caller turns it into a note.
func deriveQueueDepth(days []CalendarDay, anchor int) (clamped bool) {
	if len(days) == 0 {
		return false
	}
	// The last bucket is today, and today's depth is the live count as
	// of now rather than at the end of the day -- the only row in the
	// series that is measured rather than derived.
	days[len(days)-1].InQueue = anchor
	for i := len(days) - 2; i >= 0; i-- {
		next := days[i+1]
		depth := next.InQueue - next.Submitted + next.Completed + next.Removed
		if depth < 0 {
			depth = 0
			clamped = true
		}
		days[i].InQueue = depth
	}
	return clamped
}

// firstGroup and firstValue read the one group column and the one
// aggregate every calendar query asks for, tolerating a row shaped
// otherwise rather than indexing into it.
func firstGroup(r dbrpc.AggRow) string {
	if len(r.Group) == 0 {
		return ""
	}
	return r.Group[0]
}

func firstValue(r dbrpc.AggRow) string {
	if len(r.Values) == 0 {
		return ""
	}
	return r.Values[0]
}
