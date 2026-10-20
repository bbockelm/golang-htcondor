package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/utilization"
)

// analyze_utilization: how well a person's finished jobs used what they
// reserved, and what to request next time.
//
// The same analysis the web UI's Utilization page shows, through the same
// package, so an agent asked "should I lower request_memory?" gives the
// answer a person would read on that page -- with its submit lines and
// its confidence -- rather than an estimate of its own from a listing of
// ads it had to summarize.
//
// The read is this package's rather than the REST handler's. That
// handler's helpers hang off its own type, and a standalone MCP server
// has none; what is shared is everything that decides the answer: the
// projection, the per-ad reader, the window, and the analysis.

// Bounds on what one call reads. The default and ceiling are the page's:
// most recent first, so a busy user's answer covers their latest work, and
// the answer says when the cap was hit.
const (
	utilizationToolDefaultLimit = 50000
	utilizationToolMaxLimit     = 1000000
)

// utilizationDaysAllowed are the windows offered, as on the page.
var utilizationDaysAllowed = map[int]bool{1: true, 7: true, 30: true}

// utilizationMachinesTTL is how long the pool's machine shapes, read for
// the throughput estimate, are reused. Machines come and go far more
// slowly than an agent asks.
const utilizationMachinesTTL = 10 * time.Minute

func analyzeUtilizationTool() Tool {
	return Tool{
		Name: "analyze_utilization",
		Description: "How well finished jobs used the CPU, memory, disk and GPUs they requested, and what to request next time. " +
			"Covers jobs that finished (completed or removed) in the last 1, 7 or 30 days, grouped into workflows -- " +
			"what you would submit again: a DAG, or one executable under one batch name. " +
			"Answers with the share of each reserved resource that was used, the workflows that ran longest, and every " +
			"concrete suggestion: the submit-file lines to change, what the change would have saved, how confident the " +
			"suggestion is, and how many more jobs could run at once with it. Pass workflow to see one workflow in detail, " +
			"with percentiles of its run time, memory, CPU and disk use. Prefer this over reading job history yourself to " +
			"size a request. Covers YOUR OWN jobs; MCP admins get every user's and may name owners.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"days": map[string]interface{}{
					"type":        "integer",
					"enum":        []int{1, 7, 30},
					"description": "How far back to look: 1, 7 or 30 days (default 7). A job counts on the day it finished.",
				},
				"constraint": map[string]interface{}{
					"type":        "string",
					"description": "Optional ClassAd expression over job attributes, ANDed onto the jobs analysed, e.g. JobBatchName == \"sweep\" or RequestGpus > 0.",
				},
				"workflow": map[string]interface{}{
					"type": "string",
					"description": "Show one workflow in detail: its key from an earlier answer, its name, or part of its name or executable. " +
						"The analysis still covers every job in the window; this picks which workflow to detail.",
				},
				"owners": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "MCP admins only: narrow to these users' jobs. For anyone else it can only narrow their own jobs, so another user's name matches nothing.",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": fmt.Sprintf("Most recent finished jobs to analyse (default %d, at most %d). The answer says when the window held more.", utilizationToolDefaultLimit, utilizationToolMaxLimit),
				},
			},
		},
	}
}

// utilizationArgs is the tool's arguments, validated.
type utilizationArgs struct {
	days     int
	filter   string // re-serialized by the parser, or ""
	workflow string
	owners   []string // sorted, distinct
	limit    int
}

// parseUtilizationArgs reads and validates the arguments. maxLimit is the
// ceiling a limit is clamped to.
func parseUtilizationArgs(args map[string]interface{}, maxLimit int) (utilizationArgs, error) {
	a := utilizationArgs{days: 7, limit: utilizationToolDefaultLimit}
	if v, ok := args["days"]; ok && v != nil {
		n, ok := v.(float64)
		if !ok || n != float64(int(n)) || !utilizationDaysAllowed[int(n)] {
			return a, errors.New("days must be 1, 7 or 30")
		}
		a.days = int(n)
	}
	if v, ok := args["constraint"].(string); ok && strings.TrimSpace(v) != "" {
		// Re-serialized so it cannot reach past the parentheses it is
		// spliced into (see classadBalanced).
		safe, err := classadBalanced(strings.TrimSpace(v))
		if err != nil {
			return a, fmt.Errorf("constraint is not a valid ClassAd expression: %w", err)
		}
		a.filter = safe
	}
	if v, ok := args["workflow"].(string); ok {
		a.workflow = strings.TrimSpace(v)
	}
	switch v := args["owners"].(type) {
	case nil:
	case []interface{}:
		for _, o := range v {
			s, ok := o.(string)
			if !ok {
				return a, errors.New("owners must be a list of user names")
			}
			a.owners = append(a.owners, s)
		}
	case string:
		a.owners = strings.Split(v, ",")
	default:
		return a, errors.New("owners must be a list of user names")
	}
	a.owners = cleanOwners(a.owners)
	if v, ok := args["limit"]; ok && v != nil {
		n, ok := v.(float64)
		if !ok || n < 1 || n != float64(int(n)) {
			return a, errors.New("limit must be a positive whole number of jobs")
		}
		a.limit = int(n)
	}
	a.limit = min(a.limit, maxLimit)
	return a, nil
}

func cleanOwners(in []string) []string {
	var out []string
	for _, o := range in {
		if o = strings.TrimSpace(o); o != "" && !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	slices.Sort(out)
	return out
}

// utilizationSelection is which jobs the analysis may read: the caller's
// scope, narrowed by the owners and the constraint.
//
// scope is "true" for a call that may see every user's jobs, and the
// caller's own owner clause otherwise. Everything is ANDed onto it, so an
// argument can only remove jobs from the scope, never add any: a
// non-administrator naming another user's account gets the intersection
// of "mine" and "theirs", which is nothing.
func utilizationSelection(scope string, a utilizationArgs) string {
	out := "(" + scope + ")"
	if len(a.owners) > 0 {
		parts := make([]string, len(a.owners))
		for i, o := range a.owners {
			parts[i] = "Owner == " + classadStringLit(o)
		}
		out += " && (" + strings.Join(parts, " || ") + ")"
	}
	if a.filter != "" {
		out += " && (" + a.filter + ")"
	}
	return out
}

func (s *Server) utilizationMaxLimit() int {
	if s.utilizationMaxJobs > 0 {
		return s.utilizationMaxJobs
	}
	return utilizationToolMaxLimit
}

func (s *Server) toolAnalyzeUtilization(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	a, err := parseUtilizationArgs(args, s.utilizationMaxLimit())
	if err != nil {
		return nil, err
	}
	scope, ok := s.ownerScope(ctx, tierRead)
	if !ok {
		return nil, errScopeUnauthenticated
	}
	scopeClause := "true"
	var notes []string
	if !scope.AllUsers {
		scopeClause = scope.clause
		for _, o := range a.owners {
			if !strings.EqualFold(o, ownerFromActor(scope.Owner)) {
				notes = append(notes, fmt.Sprintf("You can analyse only your own jobs, so the owner %q matches nothing.", o))
			}
		}
	}

	now := time.Now().Unix()
	since := now - int64(a.days)*24*3600
	jobs, truncated, err := s.utilizationJobs(ctx, utilizationSelection(scopeClause, a), since, a.limit)
	if err != nil {
		return nil, fmt.Errorf("reading finished jobs: %w", err)
	}
	resp := utilization.Analyze(jobs, utilization.Options{
		Since: since, Until: now, Days: a.days, Truncated: truncated,
		ShowOwner: scope.AllUsers,
		Limit:     a.limit, MaxLimit: s.utilizationMaxLimit(),
		Machines: s.utilizationMachines(ctx),
	})

	text, structured := RenderUtilization(utilization.Summarize(resp), DetailFromResponse(resp),
		UtilizationView{Workflow: a.workflow, Notes: notes})
	return structuredTextResult(text+"\n"+scope.Note(), structured), nil
}

// scheddEnteredHistory is when a schedd history record entered history:
// EnteredHistoryTime where the schedd writes it, else the transition to
// completed or removed, else CompletionDate. The window is on the time a
// job left the queue rather than CompletionDate, because a removed job's
// CompletionDate is 0 and removed jobs are part of the answer. The same
// expression the REST handler uses.
const scheddEnteredHistory = `ifThenElse(isUndefined(EnteredHistoryTime), ` +
	`ifThenElse(isUndefined(EnteredCurrentStatus) || EnteredCurrentStatus <= 0, CompletionDate, EnteredCurrentStatus), ` +
	`EnteredHistoryTime)`

// utilizationJobs reads up to limit of selection's jobs that finished at
// or after since, most recent first, from the job history database when
// it may answer and the schedd's history otherwise. truncated says the
// window held more.
func (s *Server) utilizationJobs(ctx context.Context, selection string, since int64, limit int) ([]utilization.Job, bool, error) {
	jobs, truncated, d := s.utilizationFromMirror(ctx, selection, since, limit)
	if d.Use {
		return jobs, truncated, nil
	}
	if err := s.mirrorRequiredError(d); err != nil {
		return nil, false, err
	}
	return s.utilizationFromSchedd(ctx, selection, since, limit)
}

// utilizationFromMirror reads from the mirror's history archive, under
// the same gates as every other history read (see tryHistoryFromDB). A
// decision with Use false means the schedd must answer instead.
//
// The plain "EnteredHistoryTime >= since" is what the archive can skip
// whole segments by; the mirror stamps that attribute on every record it
// archives, so it needs no fallback.
func (s *Server) utilizationFromMirror(ctx context.Context, selection string, since int64, limit int) ([]utilization.Job, bool, dbmirror.Decision) {
	if !s.htcondordbEnabled() {
		return nil, false, decline(dbmirror.ReasonNotConfigured, "htcondordb routing is not configured")
	}
	if s.delegated && htcondor.GetAuthenticatedUserFromContext(ctx) == "" {
		return nil, false, decline(dbmirror.ReasonNoOwnerScope,
			"the schedd has not identified this caller, so the mirror must not answer on its behalf")
	}
	info, err := s.discoverHTCondorDB(ctx)
	if err != nil {
		return nil, false, decline(dbmirror.ReasonNoMirror, err.Error())
	}
	d := dbmirror.HistoryDecision(info, &htcondor.HistoryQueryOptions{Backwards: true})
	if !d.Use {
		return nil, false, d
	}
	dbc, closer, _, err := s.dbClient(ctx)
	if err != nil {
		return nil, false, decline(dbmirror.ReasonDialFailed, err.Error())
	}
	defer closer()

	constraint := fmt.Sprintf("(%s) && EnteredHistoryTime >= %d", selection, since)
	var jobs []utilization.Job
	var reader utilization.JobReader
	truncated := false
	yield := func(row string) bool {
		if len(jobs) >= limit {
			truncated = true
			return false
		}
		if ad, perr := classad.ParseOld(row); perr == nil {
			jobs = append(jobs, reader.FromAd(ad, ""))
		}
		return true
	}
	proj := utilization.Projection()
	// The reference-chasing projection evaluates a request written as an
	// expression over another attribute; a mirror too old for it gets
	// the plain one.
	err = dbc.QueryRawProjectRefsStream(ctx, historyArchiveTable, constraint, proj, limit+1, yield)
	if errors.Is(err, dbrpc.ErrProjectRefsUnsupported) {
		jobs, truncated = nil, false
		err = dbc.QueryRawProjectStream(ctx, historyArchiveTable, constraint, proj, limit+1, yield)
	}
	if err != nil {
		return nil, false, decline(dbmirror.ReasonQueryFailed, err.Error())
	}
	return jobs, truncated, d
}

// utilizationScanLimit is the schedd's backwards-walk budget: the walk
// normally stops at the window's start, and this is the backstop for a
// history file whose records are out of order.
func utilizationScanLimit(limit int) int {
	return max(3000000, 3*limit)
}

// utilizationFromSchedd reads the schedd's history file, newest first,
// stopping at the first record older than the window.
func (s *Server) utilizationFromSchedd(ctx context.Context, selection string, since int64, limit int) ([]utilization.Job, bool, error) {
	constraint := fmt.Sprintf("(%s) && %s >= %d", selection, scheddEnteredHistory, since)
	results, err := s.getSchedd().QueryHistoryStream(ctx, constraint, &htcondor.HistoryQueryOptions{
		Source:        htcondor.HistorySourceJobHistory,
		Limit:         limit + 1,
		ScanLimit:     utilizationScanLimit(limit),
		Projection:    utilization.Projection(),
		Backwards:     true,
		StreamResults: true,
		Since:         fmt.Sprintf("%s < %d", scheddEnteredHistory, since),
	}, &htcondor.StreamOptions{})
	if err != nil {
		return nil, false, err
	}
	var jobs []utilization.Job
	var reader utilization.JobReader
	truncated := false
	var streamErr error
	// Drained to the end even past the cap, so the reader is never left
	// blocked on a channel nobody reads; Limit keeps that tail to one.
	for res := range results {
		switch {
		case res.Err != nil:
			streamErr = res.Err
		case len(jobs) >= limit:
			truncated = true
		case res.Ad != nil:
			jobs = append(jobs, reader.FromAd(res.Ad, ""))
		}
	}
	if streamErr != nil {
		return nil, false, streamErr
	}
	return jobs, truncated, nil
}

// utilizationMachines is the pool's execute capacity for the throughput
// estimate, or nil when it cannot be had -- never an error, because the
// estimate is an extra and the rest of the answer stands without it.
// Every caller shares one read: the shapes of the pool's machines are not
// anyone's in particular.
func (s *Server) utilizationMachines(ctx context.Context) []utilization.Machine {
	src := s.poolSource()
	if src == nil {
		return nil
	}
	s.utilMachinesMu.Lock()
	defer s.utilMachinesMu.Unlock()
	if s.utilMachines != nil && time.Since(s.utilMachinesAt) < utilizationMachinesTTL {
		return s.utilMachines
	}
	readCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	// Dynamic slots are carved from partitionable ones counted at full
	// size; MachineFromAd drops anything else that adds no capacity.
	results, err := src.QueryAdsStream(readCtx, "StartdAd", `SlotType =!= "Dynamic"`,
		utilization.MachineProjection(), 0, &htcondor.StreamOptions{})
	if err != nil {
		return s.utilMachines
	}
	var machines []utilization.Machine
	failed := false
	for res := range results {
		if res.Err != nil {
			failed = true
			continue
		}
		if m, ok := utilization.MachineFromAd(res.Ad); ok {
			machines = append(machines, m)
		}
	}
	if failed || len(machines) == 0 {
		return s.utilMachines
	}
	s.utilMachines, s.utilMachinesAt = machines, time.Now()
	return machines
}
