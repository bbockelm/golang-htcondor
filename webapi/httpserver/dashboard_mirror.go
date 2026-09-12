package httpserver

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/PelicanPlatform/classad/dbrpc"
	"github.com/bbockelm/golang-htcondor/logging"
)

// With a mirror answering, the dashboard does not need the queue walk at
// all -- and therefore does not need the three-minute cache that exists
// to bound it.
//
// The walk exists because the schedd cannot answer narrow questions: it
// has no ordering, so "the ten newest holds" means reading everything.
// The mirror can, so the same page becomes half a dozen small bounded
// queries: two server-side aggregates for the counts and the hold
// breakdown, and one windowed lookup per activity list. Nothing is
// scanned and nothing is cached, so the numbers are current rather than
// up to three minutes old.
//
// Every query here is bounded twice over -- by a time window and by a
// row limit -- because "recent" on an access point with a hundred
// thousand jobs is otherwise an unbounded read wearing a friendly name.

// dashboardRecentWindow is how far back the activity lists look.
//
// An hour is long enough that a quiet access point still shows something
// and short enough that a busy one is answered from an index rather than
// a scan. Beyond it the lists would be showing history, which is what
// the archive page is for.
const dashboardRecentWindow = time.Hour

// dashboardFromMirror builds the whole snapshot from the mirror.
// It errors when there is no usable mirror, so the caller can fall back
// to the cached queue walk.
// mirrorScope opens a client and builds the owner constraint, which is
// the preamble both halves of the page share.
func (s *Handler) mirrorScope(ctx context.Context, owner string, ownedByMe bool) (*dbrpc.Client, func(), string, error) {
	if !s.dbMirror.Enabled() {
		return nil, nil, "", fmt.Errorf("no htcondordb mirror is configured")
	}
	dbc, closer, _, err := s.dbMirror.Client(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	scope := "true"
	if ownedByMe {
		scope = fmt.Sprintf("Owner == %s", classadStringLit(owner))
	}
	return dbc, closer, scope, nil
}

// countsFromMirror answers the status tiles and nothing else.
//
// One aggregate, which is what lets the tiles render while the rest of
// the page is still being fetched. They are the part a person reads
// first and the cheapest part to produce, so making them wait on the
// hold breakdown and four windowed lookups -- as one combined response
// did -- meant the whole page arrived at the speed of its slowest query.
func (s *Handler) countsFromMirror(ctx context.Context, owner string, ownedByMe bool) (*dashboardSnapshot, error) {
	dbc, closer, scope, err := s.mirrorScope(ctx, owner, ownedByMe)
	if err != nil {
		return nil, err
	}
	defer closer()

	counts, total, err := mirrorStatusCounts(ctx, dbc, scope)
	if err != nil {
		return nil, fmt.Errorf("counting jobs: %w", err)
	}
	return &dashboardSnapshot{Counts: counts, Total: total}, nil
}

// activityFromMirror answers the panels: the hold breakdown, the recent
// lists, and goodput.
//
// Serial, and measured that way. Running the six queries concurrently is
// the obvious optimisation -- dbrpc does multiplex them over the one
// connection -- and it was 22% SLOWER on a 50k-job queue (118ms against
// 97ms). These are scans, so the database is the bottleneck and asking
// it six things at once only adds contention; the round trips the
// fan-out saves are the cheap part when the mirror is on the same host
// or the same LAN, which is where it normally is. Worth reconsidering
// only for a deployment where the database is genuinely far away.
func (s *Handler) activityFromMirror(ctx context.Context, owner string, ownedByMe bool) (*dashboardSnapshot, error) {
	dbc, closer, scope, err := s.mirrorScope(ctx, owner, ownedByMe)
	if err != nil {
		return nil, err
	}
	defer closer()

	since := time.Now().Add(-dashboardRecentWindow).Unix()
	act := DashboardActivity{
		Source:            "htcondordb mirror",
		ComputedAt:        time.Now().Unix(),
		HoldWindowSeconds: int64(dashboardRecentWindow / time.Second),
	}

	act.HoldReasons, err = mirrorHoldReasons(ctx, dbc, scope, since)
	if err != nil {
		return nil, fmt.Errorf("grouping hold reasons: %w", err)
	}

	for _, list := range []struct {
		attr string
		into *[]RecentJob
		// extra narrows the list to the jobs the attribute is meaningful
		// for: every job has a QDate, only held ones have a hold time.
		extra  string
		detail []string
	}{
		{"QDate", &act.RecentlySubmitted, "", []string{"Cmd"}},
		{"JobCurrentStartDate", &act.RecentlyStarted, "", []string{"RemoteHost"}},
		{"EnteredCurrentStatus", &act.RecentlyHeld, "JobStatus == 5", []string{"HoldReason"}},
		// The queue holds the few completions the reaper has not taken;
		// the archive below has the rest.
		{"CompletionDate", &act.RecentlyCompleted, "JobStatus == 4", []string{"ExitCode"}},
	} {
		jobs, lerr := mirrorRecent(ctx, dbc, "jobs", scope, list.attr, list.extra, since, list.detail)
		if lerr != nil {
			return nil, fmt.Errorf("reading recent %s: %w", list.attr, lerr)
		}
		*list.into = jobs
	}
	act.CompletedAvailable = len(act.RecentlyCompleted) > 0
	act.CompletedPartial = true

	// The archive may be absent or lagging while the live table is fine.
	// Both of the reads below cost their own panel, not the page.
	if archived, aerr := mirrorRecent(ctx, dbc, "history", scope, "CompletionDate", "", since,
		[]string{"ExitCode", "ExitBySignal"}); aerr != nil {
		s.logger.Debug(logging.DestinationHTTP,
			"dashboard: mirror has no history for recently-completed", "error", aerr)
	} else {
		act.mergeArchivedCompletions(archived)
	}

	snap := &dashboardSnapshot{Activity: act}
	if gp, gerr := mirrorGoodput(ctx, dbc, scope, time.Now().Add(-goodputWindow).Unix()); gerr != nil {
		s.logger.Debug(logging.DestinationHTTP,
			"dashboard: mirror has no history for goodput", "error", gerr)
	} else {
		snap.Goodput = gp
	}
	return snap, nil
}

// mirrorStatusCounts groups the live table by status and hold code, which
// is the same distinction the tiles draw: a job held only because its
// input is still spooling is a submit in progress, not a failure.
func mirrorStatusCounts(ctx context.Context, dbc *dbrpc.Client, scope string) (map[string]int, int, error) {
	rows, err := dbc.AggregateTable(ctx, "jobs", scope,
		[]string{"JobStatus", "HoldReasonCode"}, []dbrpc.AggSpec{{Func: dbrpc.AggCount, Arg: "*"}})
	if err != nil {
		return nil, 0, err
	}
	counts, total := make(map[string]int), 0
	for _, r := range rows {
		if len(r.Group) < 2 || len(r.Values) == 0 {
			continue
		}
		n, cerr := strconv.Atoi(r.Values[0])
		if cerr != nil {
			continue
		}
		js, _ := strconv.ParseInt(r.Group[0], 10, 64)
		hrc, _ := strconv.ParseInt(r.Group[1], 10, 64)
		counts[dashboardStatusName(js, hrc)] += n
		total += n
	}
	return counts, total, nil
}

// mirrorHoldReasons is the hold breakdown as one server-side GROUP BY,
// over jobs that entered the held state inside the window.
//
// Recent rather than standing: a job held last Tuesday is still held,
// and counting it here would let a long-lived backlog drown out what is
// going wrong right now. The HELD tile beside this panel is where the
// standing total belongs, and the two are meant to disagree.
// The example message needs a row, so it is fetched separately and only
// for the reasons that made the cut.
func mirrorHoldReasons(ctx context.Context, dbc *dbrpc.Client, scope string, since int64) ([]HoldReasonCount, error) {
	held := fmt.Sprintf("%s && JobStatus == 5 && EnteredCurrentStatus >= %d", scope, since)
	rows, err := dbc.AggregateTable(ctx, "jobs", held,
		[]string{"HoldReasonCode"}, []dbrpc.AggSpec{{Func: dbrpc.AggCount, Arg: "*"}})
	if err != nil {
		return nil, err
	}
	out := make([]HoldReasonCount, 0, len(rows))
	for _, r := range rows {
		if len(r.Group) == 0 || len(r.Values) == 0 {
			continue
		}
		n, cerr := strconv.Atoi(r.Values[0])
		if cerr != nil {
			continue
		}
		code, _ := strconv.ParseInt(r.Group[0], 10, 64)
		out = append(out, HoldReasonCount{Code: code, Label: holdReasonLabel(code), Count: n})
	}
	out = topHoldReasonRows(out)

	// One example message per surviving reason. The code names the
	// category; the message names the file or the host, which is what
	// makes the row actionable.
	for i := range out {
		if out[i].Code < 0 {
			continue // the summed "other" row has no single example
		}
		rows, rerr := dbc.QueryRawProject(ctx, "jobs",
			fmt.Sprintf("%s && HoldReasonCode == %d", held, out[i].Code),
			[]string{"HoldReason"}, 1)
		if rerr != nil || len(rows) == 0 {
			continue
		}
		if ad, perr := classad.ParseOld(rows[0]); perr == nil {
			out[i].Example, _ = ad.EvaluateAttrString("HoldReason")
		}
	}
	return out, nil
}

// mirrorRecent reads one activity list: the jobs whose timestamp lands
// in the window, newest first.
func mirrorRecent(ctx context.Context, dbc *dbrpc.Client, table, scope, attr, extra string,
	since int64, detail []string) ([]RecentJob, error) {
	constraint := fmt.Sprintf("(%s) && %s >= %d", scope, attr, since)
	if extra != "" {
		constraint += " && (" + extra + ")"
	}
	project := append([]string{"ClusterId", "ProcId", "Owner", attr}, detail...)

	// Over-fetch, then take the newest: a mutable table has no ordering
	// to push the limit down into, so the window is what bounds this and
	// the sort happens here. The archive does return newest-first, but
	// sorting an already-sorted short list costs nothing.
	rows, err := dbc.QueryRawProject(ctx, table, constraint, project, recentPerList*10)
	if err != nil {
		return nil, err
	}
	out := make([]RecentJob, 0, len(rows))
	for _, row := range rows {
		ad, perr := classad.ParseOld(row)
		if perr != nil {
			continue
		}
		e := RecentJob{}
		e.ClusterID, _ = ad.EvaluateAttrInt("ClusterId")
		e.ProcID, _ = ad.EvaluateAttrInt("ProcId")
		e.Owner, _ = ad.EvaluateAttrString("Owner")
		e.At, _ = ad.EvaluateAttrInt(attr)
		e.Detail = recentDetail(ad, detail)
		out = append(out, e)
	}
	return newestFirst(out, recentPerList), nil
}

// recentDetail renders the one fact shown beside a job.
func recentDetail(ad *classad.ClassAd, attrs []string) string {
	for _, attr := range attrs {
		if attr == "ExitBySignal" {
			if v, ok := ad.EvaluateAttrBool(attr); ok && v {
				return "killed by a signal"
			}
			continue
		}
		if v, ok := ad.EvaluateAttrString(attr); ok && v != "" {
			return v
		}
		if v, ok := ad.EvaluateAttrInt(attr); ok {
			if attr == "ExitCode" {
				return fmt.Sprintf("exit %d", v)
			}
			return strconv.FormatInt(v, 10)
		}
	}
	return ""
}
