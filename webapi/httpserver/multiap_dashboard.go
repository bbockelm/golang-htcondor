package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// The dashboard in multi-AP mode: the caller's jobs on every AP, from
// the federation hub, in total and per AP, with the sources block.
//
// Counts are the caller's own: hub reads have no cross-user view (the
// superuser exemption is per AP and applies to routed reads), so
// owned_by_me=false is not honoured here.
//
// "Finished recently" per AP counts jobs with evidence that they
// finished: a history record in the window, or a job the hub's jobs
// stream saw leave whose last ad said it had completed or been removed.
// A delete alone is not counted: it is also what retiring (.retire) or
// reconciling an AP looks like, and a job that leaves held or idle has
// not been shown to have finished (jobwatch.Feed.Departures).

// DashboardAP is one AP's counts.
type DashboardAP struct {
	Schedd string `json:"schedd"`
	// State is the hub's view of the AP: fresh, or the state it is
	// degraded in.
	State        string         `json:"state"`
	JobsByStatus map[string]int `json:"jobs_by_status"`
	JobsTotal    int            `json:"jobs_total"`
}

// DashboardAPActivity is one AP's line in the activity answer.
type DashboardAPActivity struct {
	Schedd string `json:"schedd"`
	State  string `json:"state"`
	// FinishedRecently is how many of the caller's jobs on the AP are
	// known to have finished in the window: history records, and
	// departures the hub's jobs stream saw with evidence.
	FinishedRecently int `json:"finished_recently"`
	// FinishedPartial says the count may be low: the AP is not fresh on
	// the hub (its history may lag, and its departures are not counted),
	// or the history read hit its limit.
	FinishedPartial bool `json:"finished_partial,omitempty"`
}

// maxFinishedScan bounds the history read behind the per-AP finished
// counts.
const maxFinishedScan = 20000

// handleMultiDashboard serves GET /api/v1/dashboard in multi-AP mode.
func (s *Handler) handleMultiDashboard(w http.ResponseWriter, r *http.Request) {
	ctx, user, ok := s.multiAPCaller(w, r)
	if !ok {
		return
	}
	svc := s.multi.svc
	scope, names, sources, err := svc.Scope(user, "", r.URL.Query().Get("schedd"))
	if err != nil {
		s.multiAPError(w, err)
		return
	}
	sources = svc.TableSources(sources, multiap.TableJobs)
	resp := DashboardResponse{
		Username:     htcondor.GetAuthenticatedUserFromContext(ctx),
		JobsByStatus: map[string]int{},
		APs:          make([]DashboardAP, 0, len(names)),
		Sources:      &sources,
	}
	per := map[string]*DashboardAP{}
	for _, n := range names {
		resp.APs = append(resp.APs, DashboardAP{Schedd: n, State: sources.StateOf(n), JobsByStatus: map[string]int{}})
	}
	for i := range resp.APs {
		per[strings.ToLower(resp.APs[i].Schedd)] = &resp.APs[i]
	}
	if len(names) > 0 {
		dbc, closer, err := svc.HubClient(ctx)
		if err != nil {
			s.multiAPError(w, err)
			return
		}
		defer closer()
		rows, err := dbc.AggregateTable(ctx, multiap.TableJobs, scope,
			[]string{multiap.AttrScheddName, "JobStatus", "HoldReasonCode"}, []dbrpc.AggSpec{{Func: dbrpc.AggCount, Arg: "*"}})
		if err != nil {
			s.writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("counting jobs on the federation hub: %v", err))
			return
		}
		for _, row := range rows {
			if len(row.Group) < 3 || len(row.Values) == 0 {
				continue
			}
			n, cerr := strconv.Atoi(row.Values[0])
			if cerr != nil {
				continue
			}
			js, _ := strconv.ParseInt(row.Group[1], 10, 64)
			hrc, _ := strconv.ParseInt(row.Group[2], 10, 64)
			status := dashboardStatusName(js, hrc)
			resp.JobsByStatus[status] += n
			resp.JobsTotal += n
			if ap := per[strings.ToLower(strings.Trim(row.Group[0], `"`))]; ap != nil {
				ap.JobsByStatus[status] += n
				ap.JobsTotal += n
			}
		}
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handleMultiDashboardActivity serves GET /api/v1/dashboard/activity in
// multi-AP mode.
func (s *Handler) handleMultiDashboardActivity(w http.ResponseWriter, r *http.Request) {
	ctx, user, ok := s.multiAPCaller(w, r)
	if !ok {
		return
	}
	svc := s.multi.svc
	scope, names, sources, err := svc.Scope(user, "", r.URL.Query().Get("schedd"))
	if err != nil {
		s.multiAPError(w, err)
		return
	}
	// The lists read jobs, the finished counts and goodput history: an AP
	// whose stream of either is not usable is reported, not silently short.
	sources = svc.TableSources(svc.TableSources(sources, multiap.TableJobs), multiap.TableHistory)
	now := time.Now()
	since := now.Add(-dashboardRecentWindow).Unix()
	resp := DashboardActivityResponse{
		Activity: DashboardActivity{
			Source:            "federation hub",
			ComputedAt:        now.Unix(),
			HoldWindowSeconds: int64(dashboardRecentWindow / time.Second),
		},
		APs:     make([]DashboardAPActivity, 0, len(names)),
		Sources: &sources,
	}
	if len(names) == 0 {
		s.writeJSON(w, http.StatusOK, resp)
		return
	}
	dbc, closer, err := svc.HubClient(ctx)
	if err != nil {
		s.multiAPError(w, err)
		return
	}
	defer closer()

	act := &resp.Activity
	if act.HoldReasons, err = mirrorHoldReasons(ctx, dbc, scope, since); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("grouping hold reasons on the federation hub: %v", err))
		return
	}
	for _, list := range []struct {
		attr   string
		into   *[]RecentJob
		extra  string
		detail []string
	}{
		{"QDate", &act.RecentlySubmitted, "", []string{"Cmd"}},
		{"JobCurrentStartDate", &act.RecentlyStarted, "", []string{"RemoteHost"}},
		{"EnteredCurrentStatus", &act.RecentlyHeld, "JobStatus == 5", []string{"HoldReason"}},
		{"CompletionDate", &act.RecentlyCompleted, "JobStatus == 4", []string{"ExitCode"}},
	} {
		jobs, lerr := mirrorRecent(ctx, dbc, multiap.TableJobs, scope, list.attr, list.extra, since, list.detail)
		if lerr != nil {
			s.writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("reading recent %s on the federation hub: %v", list.attr, lerr))
			return
		}
		*list.into = jobs
	}
	act.CompletedAvailable = len(act.RecentlyCompleted) > 0
	act.CompletedPartial = true
	if archived, aerr := mirrorRecent(ctx, dbc, multiap.TableHistory, scope, "CompletionDate", "", since,
		[]string{"ExitCode", "ExitBySignal"}); aerr != nil {
		s.logger.Debug(logging.DestinationHTTP, "dashboard: the hub's history did not answer", "error", aerr)
	} else {
		act.mergeArchivedCompletions(archived)
	}
	for _, list := range [][]RecentJob{act.RecentlySubmitted, act.RecentlyStarted, act.RecentlyHeld, act.RecentlyCompleted} {
		for i := range list {
			list[i].JobID = s.multi.codec.Format(jobid.ID{Schedd: list[i].Schedd, Cluster: list[i].ClusterID, Proc: list[i].ProcID})
		}
	}
	if gp, gerr := mirrorGoodput(ctx, dbc, scope, now.Add(-goodputWindow).Unix()); gerr != nil {
		s.logger.Debug(logging.DestinationHTTP, "dashboard: no goodput from the hub's history", "error", gerr)
	} else {
		resp.Goodput = gp
	}

	finished, truncated, ferr := s.finishedPerAP(ctx, dbc, scope, user, since)
	if ferr != nil {
		s.logger.Debug(logging.DestinationHTTP, "dashboard: per-AP finished counts unavailable", "error", ferr)
	}
	for _, n := range names {
		state := sources.StateOf(n)
		resp.APs = append(resp.APs, DashboardAPActivity{
			Schedd:           n,
			State:            state,
			FinishedRecently: len(finished[strings.ToLower(n)]),
			FinishedPartial:  state != multiap.StateFresh || truncated || ferr != nil,
		})
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// finishedPerAP collects, per lower-cased AP, the caller's jobs known to
// have finished since: history records, and departures the feed saw with
// evidence. Departures on an AP the feed did not vouch for at the time
// -- a stale, retiring or disconnected one -- are not among them; see
// the file comment.
func (s *Handler) finishedPerAP(ctx context.Context, dbc *dbrpc.Client, scope, user string, since int64) (map[string]map[[2]int64]bool, bool, error) {
	out := map[string]map[[2]int64]bool{}
	add := func(schedd string, c, p int64) {
		k := strings.ToLower(schedd)
		if out[k] == nil {
			out[k] = map[[2]int64]bool{}
		}
		out[k][[2]int64{c, p}] = true
	}
	n := 0
	var perr error
	err := dbc.QueryRawProjectStream(ctx, multiap.TableHistory,
		fmt.Sprintf("(%s) && (CompletionDate >= %d || EnteredHistoryTime >= %d)", scope, since, since),
		[]string{multiap.AttrScheddName, "ClusterId", "ProcId"}, maxFinishedScan+1, func(text string) bool {
			ad, e := classad.ParseOld(text)
			if e != nil {
				perr = e
				return false
			}
			n++
			if n > maxFinishedScan {
				return false
			}
			sch, _ := ad.EvaluateAttrString(multiap.AttrScheddName)
			c, _ := ad.EvaluateAttrInt("ClusterId")
			p, _ := ad.EvaluateAttrInt("ProcId")
			add(sch, c, p)
			return true
		})
	if err == nil {
		err = perr
	}
	owner := user
	if i := strings.LastIndex(user, "@"); i > 0 {
		owner = user[:i]
	}
	if s.jobWatchFeed != nil {
		for _, d := range s.jobWatchFeed.Departures(owner, time.Unix(since, 0)) {
			if d.Schedd != "" {
				add(d.Schedd, d.Cluster, d.Proc)
			}
		}
	}
	return out, n > maxFinishedScan, err
}
