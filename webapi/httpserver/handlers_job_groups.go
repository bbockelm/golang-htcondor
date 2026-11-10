package httpserver

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/runtimeest"
	"github.com/bbockelm/golang-htcondor/webapi/utilization"
)

// From one job to the groups it belongs to: the finished jobs a runtime
// estimate was built from, and the Utilization workflow.
//
// Both resolve the job with the same read scope as GET /api/v1/jobs/{id}
// -- someone else's job is "not found" -- and both decide group
// membership with the owning package's own functions (runtimeest's
// features and keys, utilization's identity and hash), so a link from a
// job lands on the group the number on its page came from.

// Paging and read bounds for the similar-jobs listing.
const (
	similarPageDefault = 50
	similarPageMax     = 200
	// similarScanLimit bounds the owner's history records read to find a
	// group's members, newest first.
	similarScanLimit = 50000
	// workflowScanLimit is the same for "has this workflow any history".
	workflowScanLimit = 20000
	// workflowHistoryDays is the window the Utilization link opens with.
	workflowHistoryDays = 30
)

// jobLookupAttrs is what both endpoints read of the job itself.
var jobLookupAttrs = slices.Concat(runtimeest.FinishedQueryAttrs, []string{"Args"})

// lookupJob reads one job the caller may see: from the queue, else from
// history. found is false for a job that is not there or not theirs.
func (s *Handler) lookupJob(ctx context.Context, r *http.Request, cluster, proc int, projection []string) (*classad.ClassAd, bool, error) {
	constraint, err := s.jobReadScope(ctx, r, cluster, proc)
	if err != nil {
		return nil, false, err
	}
	ads, _, err := s.getSchedd().QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{Projection: projection, Limit: 1})
	if err != nil {
		return nil, false, err
	}
	if len(ads) > 0 {
		return ads[0], true, nil
	}
	return s.lookupFinishedJob(ctx, r, constraint, projection)
}

// lookupFinishedJob is lookupJob's history half: the job constraint
// selects, already scoped to the caller, from the mirror when it may
// answer, else the schedd's history.
func (s *Handler) lookupFinishedJob(ctx context.Context, r *http.Request, constraint string, projection []string) (*classad.ClassAd, bool, error) {
	if s.mirrorAllowed(ctx, r) == nil {
		if ads, err := s.mirrorRows(ctx, "history", constraint, projection, 1); err == nil && len(ads) > 0 {
			return ads[0], true, nil
		}
	}
	ads, err := s.getSchedd().QueryHistoryWithOptions(ctx, constraint, &htcondor.HistoryQueryOptions{
		Source: htcondor.HistorySourceJobHistory, Limit: 1, ScanLimit: 200000, Projection: projection, Backwards: true,
	})
	if err != nil {
		return nil, false, err
	}
	if len(ads) > 0 {
		return ads[0], true, nil
	}
	return nil, false, nil
}

// streamHistory reads history records matching scope that entered
// history at or after since, newest first, at most limit of them, until
// yield returns false. The mirror answers when it may (the window a
// top-level conjunct it prunes on); else the schedd, with the window
// written for a history file that may not record EnteredHistoryTime
// (see scheddEnteredHistory).
func (s *Handler) streamHistory(ctx context.Context, r *http.Request, scope string, since int64, projection []string, limit int, reset func(), yield func(*classad.ClassAd) bool) error {
	if s.mirrorAllowed(ctx, r) == nil {
		yielded := 0
		stopped := false
		// Undo a partial mirror read, for both the caller's accumulator and
		// this function's own record of what it handed over. Only the mirror's
		// opcode retry uses it; the schedd fallback below still refuses to
		// start again once a row has gone out, since it cannot take them back.
		mirrorReset := func() {
			yielded, stopped = 0, false
			if reset != nil {
				reset()
			}
		}
		err := s.streamMirrorHistory(ctx, fmt.Sprintf("(%s) && EnteredHistoryTime >= %d", scope, since), projection, limit, mirrorReset,
			func(ad *classad.ClassAd) bool {
				yielded++
				if !yield(ad) {
					stopped = true
					return false
				}
				return true
			})
		if err == nil || stopped || yielded > 0 {
			// A read that failed part way has already handed rows over;
			// starting again on the schedd would hand them over twice.
			return err
		}
		s.logger.Debug(logging.DestinationHTTP, "history read: the mirror could not answer", "error", err)
	}
	results, err := s.getSchedd().QueryHistoryStream(ctx, fmt.Sprintf("(%s) && %s >= %d", scope, scheddEnteredHistory, since),
		&htcondor.HistoryQueryOptions{
			Source: htcondor.HistorySourceJobHistory, Limit: limit, ScanLimit: utilizationScanLimit(limit),
			Projection: projection, Backwards: true, StreamResults: true,
			Since: fmt.Sprintf("%s < %d", scheddEnteredHistory, since),
		},
		&htcondor.StreamOptions{BufferSize: s.streamBufferSize, WriteTimeout: s.streamWriteTimeout})
	if err != nil {
		return err
	}
	open := true
	var streamErr error
	for res := range results {
		switch {
		case res.Err != nil:
			streamErr = res.Err
		case open && res.Ad != nil:
			open = yield(res.Ad)
		}
	}
	return streamErr
}

// streamMirrorHistory reads the mirror's history archive, newest first.
func (s *Handler) streamMirrorHistory(ctx context.Context, constraint string, projection []string, limit int, reset func(), yield func(*classad.ClassAd) bool) error {
	info, err := s.dbMirror.Discover(ctx)
	if err != nil {
		return err
	}
	if d := dbmirror.HistoryDecision(info, &htcondor.HistoryQueryOptions{Backwards: true}); !d.Use {
		return errors.New(d.Note)
	}
	dbc, closer, _, err := s.dbMirror.Client(ctx)
	if err != nil {
		return err
	}
	defer closer()
	// Callers evaluate what comes back -- runtimeest.HistoryRecord and
	// utilization.FromAd -- so the projection needs its closure.
	return streamEvaluatedRows(ctx, dbc, "history", constraint, projection, limit, reset, func(row string) bool {
		ad, perr := classad.ParseOld(row)
		if perr != nil {
			return true
		}
		return yield(ad)
	})
}

// SimilarJobsResponse is GET /api/v1/jobs/{id}/similar.
type SimilarJobsResponse struct {
	JobID         string                     `json:"job_id"`
	Level         string                     `json:"level"`
	Description   string                     `json:"description"`
	EstimateLevel *string                    `json:"estimate_level"`
	Levels        []SimilarLevel             `json:"levels"`
	Window        SimilarWindow              `json:"window"`
	Runtimes      *runtimeest.RuntimeSummary `json:"runtimes"`
	Memory        *runtimeest.MemorySummary  `json:"memory"`
	Total         int                        `json:"total"`
	Offset        int                        `json:"offset"`
	NextOffset    *int                       `json:"next_offset"`
	Jobs          []SimilarJob               `json:"jobs"`
}

// SimilarLevel is one level a job can be grouped at.
type SimilarLevel struct {
	Level       string `json:"level"`
	Description string `json:"description"`
	Applies     bool   `json:"applies"`
	Count       *int   `json:"count"`
}

// SimilarWindow is the estimator's recency window and sample bound.
type SimilarWindow struct {
	Days    float64 `json:"days"`
	MaxJobs int     `json:"max_jobs"`
}

// SimilarJob is one finished job in the group.
type SimilarJob struct {
	ID        string  `json:"id"`
	Cluster   int64   `json:"cluster"`
	Proc      int64   `json:"proc"`
	Submitted *int64  `json:"submitted"`
	Completed int64   `json:"completed"`
	Runtime   float64 `json:"runtime"`
	ExitCode  int     `json:"exit_code"`
	// PeakMemoryMiB is the most memory it used, as the estimator reads
	// it (runtimeest.PeakMemoryMiB); null when the record has none.
	PeakMemoryMiB *float64 `json:"peak_memory_mib"`
}

// handleJobSimilar handles GET /api/v1/jobs/{id}/similar: the finished
// jobs in the job's group at one level of the runtime estimator.
//
// The list is what the estimator holds for the group, reconstructed from
// history with the estimator's own pieces: runtimeest.HistoryRecord for
// which records it reads and what it reads from them, runtimeest.InGroup
// for which group each falls in, the same recency window (the backfill)
// and the same bound on how many recent runtimes a group answers from
// (WindowSize). It can still differ from the estimator's own window, and
// the runtimes and memory blocks -- read from the estimator itself -- are
// the ones an estimate used:
//   - the estimator keeps a group's newest runtimes while the group stays
//     active, so a long-running server can hold runs older than the
//     backfill that this read does not reach; a group that went quiet
//     for the whole backfill has been evicted from it but may still have
//     records here;
//   - the estimator reads history every refresh interval, so the newest
//     completions may be listed before it has them;
//   - its read is capped (runtimeEstimateMaxRows) and this one reads at
//     most similarScanLimit of the owner's records.
func (s *Handler) handleJobSimilar(w http.ResponseWriter, r *http.Request, cluster, proc int) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	q := r.URL.Query()
	offset, size := 0, similarPageDefault
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			s.writeError(w, http.StatusBadRequest, "invalid offset: must be a non-negative number")
			return
		}
		offset = n
	}
	if v := q.Get("page_size"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			s.writeError(w, http.StatusBadRequest, "invalid page_size: must be a positive number")
			return
		}
		size = min(n, similarPageMax)
	}
	var asked *runtimeest.Level
	if v := q.Get("level"); v != "" {
		l, ok := runtimeest.ParseLevel(v)
		if !ok {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid level %q", v))
			return
		}
		asked = &l
	}
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	jobID := fmt.Sprintf("%d.%d", cluster, proc)
	ad, found, err := s.lookupJob(ctx, r, cluster, proc, jobLookupAttrs)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("Could not read the job: %v", err))
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Job not found: %s", jobID))
		return
	}
	features := runtimeest.FeaturesFromAd(ad)
	keys := runtimeest.DeriveKeys(features)

	resp := SimilarJobsResponse{JobID: jobID, Jobs: []SimilarJob{}, Levels: []SimilarLevel{}}
	if s.runtimeEst != nil {
		if res := s.runtimeEst.Estimate(runtimeest.QueryFromAd(ad, time.Now())); res.Basis != nil {
			resp.EstimateLevel = &res.Basis.Level
		}
	}
	level, ok := s.similarLevel(asked, resp.EstimateLevel, keys)
	if !ok {
		msg := "this job has nothing to group on"
		if asked != nil {
			msg = fmt.Sprintf("this job has nothing to group on at level %q", asked.String())
		}
		s.writeError(w, http.StatusBadRequest, msg)
		return
	}
	for _, l := range runtimeest.Levels() {
		lv := SimilarLevel{Level: l.String(), Description: l.Description(), Applies: keys.Key(l) != ""}
		if s.runtimeEst != nil && lv.Applies {
			n := len(s.runtimeEst.GroupRuntimes(keys, l))
			lv.Count = &n
		}
		resp.Levels = append(resp.Levels, lv)
	}
	resp.Level, resp.Description = level.String(), level.Description()
	backfill := defaultRuntimeEstimateBackfill
	if s.runtimeRefresher != nil {
		backfill = s.runtimeRefresher.backfill
	}
	maxJobs := runtimeest.DefaultWindow
	if s.runtimeEst != nil {
		maxJobs = s.runtimeEst.WindowSize()
		resp.Runtimes = runtimeest.Summarize(s.runtimeEst.GroupRuntimes(keys, level))
		resp.Memory = runtimeest.Summarize(s.runtimeEst.GroupMemory(keys, level))
	}
	resp.Window = SimilarWindow{Days: backfill.Hours() / 24, MaxJobs: maxJobs}

	members, err := s.similarMembers(ctx, r, ad, keys, level, time.Now().Add(-backfill).Unix(), maxJobs)
	if err != nil {
		s.writeUtilizationError(w, err)
		return
	}
	resp.Total = len(members)
	resp.Offset = offset
	if offset < len(members) {
		resp.Jobs = members[offset:min(offset+size, len(members))]
	}
	if next := offset + len(resp.Jobs); next < len(members) {
		resp.NextOffset = &next
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// similarLevel is the level to list: the one asked for, which must apply
// to the job; else the one that answered its estimate; else the most
// specific that applies. ok is false when that level does not apply, or
// no level does (a job with no owner).
func (s *Handler) similarLevel(asked *runtimeest.Level, estimate *string, keys runtimeest.Keys) (runtimeest.Level, bool) {
	if asked != nil {
		return *asked, keys.Key(*asked) != ""
	}
	if estimate != nil {
		if l, ok := runtimeest.ParseLevel(*estimate); ok {
			return l, true
		}
	}
	for _, l := range runtimeest.Levels() {
		if keys.Key(l) != "" {
			return l, true
		}
	}
	return 0, false
}

// similarMembers reads the owner's finished jobs in the window, newest
// first, and keeps those in the job's group at level until the group's
// bound. Confined, beyond the group's own owner, to what the caller may
// read at all (jobsReadScope), so the list can never show a job the
// caller could not open.
func (s *Handler) similarMembers(ctx context.Context, r *http.Request, ad *classad.ClassAd, keys runtimeest.Keys, level runtimeest.Level, since int64, maxJobs int) ([]SimilarJob, error) {
	base := "Owner == " + classadStringLit(keys.Owner()) + " && JobStatus == 4"
	if level == runtimeest.LevelCluster {
		if c, ok := ad.EvaluateAttrInt("ClusterId"); ok {
			base += " && ClusterId == " + strconv.FormatInt(c, 10)
		}
	}
	scope, err := s.jobsReadScope(ctx, r, base)
	if err != nil {
		return nil, err
	}
	var members []SimilarJob
	err = s.streamHistory(ctx, r, scope, since, runtimeest.HistoryAttrs, similarScanLimit,
		func() { members = nil },
		func(h *classad.ClassAd) bool {
			runtime, completed, ok := runtimeest.HistoryRecord(h)
			if !ok || !runtimeest.InGroup(h, keys, level) {
				return true
			}
			c, _ := h.EvaluateAttrInt("ClusterId")
			p, _ := h.EvaluateAttrInt("ProcId")
			job := SimilarJob{ID: fmt.Sprintf("%d.%d", c, p), Cluster: c, Proc: p, Completed: completed, Runtime: runtime}
			if q, ok := h.EvaluateAttrInt("QDate"); ok && q > 0 {
				job.Submitted = &q
			}
			if mib, ok := runtimeest.PeakMemoryMiB(h); ok {
				mib = math.Round(mib)
				job.PeakMemoryMiB = &mib
			}
			members = append(members, job)
			return len(members) < maxJobs
		})
	if err != nil {
		return nil, err
	}
	// Newest first by completion: the order the estimator's window keeps
	// them in, which history order only approximates.
	slices.SortStableFunc(members, func(a, b SimilarJob) int {
		return cmp.Or(cmp.Compare(b.Completed, a.Completed), cmp.Compare(a.Cluster, b.Cluster), cmp.Compare(a.Proc, b.Proc))
	})
	if members == nil {
		members = []SimilarJob{}
	}
	return members, nil
}

// UtilizationForJob is GET /api/v1/utilization/for-job/{id}.
type UtilizationForJob struct {
	JobID      string `json:"job_id"`
	Key        string `json:"key"`
	Name       string `json:"name"`
	Executable string `json:"executable"`
	Owner      string `json:"owner"`
	// HasHistory says whether the workflow has finished jobs in the
	// window the link opens with; nil when that could not be told within
	// the read's bound.
	HasHistory *bool `json:"has_history"`
}

// workflowIdentityAttrs is what deciding a job's workflow reads.
var workflowIdentityAttrs = []string{
	"ClusterId", "ProcId", "Owner", "JobStatus", "JobUniverse", "Cmd", "Args", "Arguments", "JobBatchName", "DAGManJobId",
}

// handleUtilizationForJob handles GET /api/v1/utilization/for-job/{id}:
// the Utilization workflow a job belongs to, by the analysis's own
// identity and hash, whether the job is waiting, running or finished.
func (s *Handler) handleUtilizationForJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	idText := r.URL.Path[len("/api/v1/utilization/for-job/"):]
	cluster, proc, err := parseJobID(idText)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	jobID := fmt.Sprintf("%d.%d", cluster, proc)
	ad, found, err := s.lookupJob(ctx, r, cluster, proc, workflowIdentityAttrs)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("Could not read the job: %v", err))
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Job not found: %s", jobID))
		return
	}
	j := utilization.FromAd(ad, "")
	key, name, program := utilization.WorkflowOf(&j)
	resp := UtilizationForJob{JobID: jobID, Key: key, Name: name, Executable: program, Owner: j.Owner}
	cacheKey := htcondor.GetAuthenticatedUserFromContext(ctx) + "|" + j.Owner + "|" + key
	has, err := s.workflowHistory().get(ctx, cacheKey, func(computeCtx context.Context) (*bool, error) {
		return s.workflowHasHistory(computeCtx, r, j.Owner, key)
	})
	if err == nil {
		resp.HasHistory = has
	} else {
		s.logger.Info(logging.DestinationHTTP, "utilization for-job: could not read the workflow's history", "error", err)
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// workflowHasHistory looks for one finished job of the workflow in the
// link's window, newest first, stopping at the first. Nil when the read's
// bound ran out first: the workflow may have history further back in a
// busy owner's records, and "no" would hide a link that works.
func (s *Handler) workflowHasHistory(ctx context.Context, r *http.Request, owner, key string) (*bool, error) {
	scope, err := s.jobsReadScope(ctx, r, "Owner == "+classadStringLit(owner)+" && (JobStatus == 3 || JobStatus == 4)")
	if err != nil {
		return nil, err
	}
	since := time.Now().Add(-workflowHistoryDays * 24 * time.Hour).Unix()
	found, read := false, 0
	err = s.streamHistory(ctx, r, scope, since, workflowIdentityAttrs, workflowScanLimit,
		func() { found, read = false, 0 },
		func(ad *classad.ClassAd) bool {
			read++
			j := utilization.FromAd(ad, "")
			if utilization.Finished(&j) && utilization.InWorkflow(&j, key) {
				found = true
				return false
			}
			return true
		})
	if err != nil {
		return nil, err
	}
	if !found && read >= workflowScanLimit {
		return nil, nil
	}
	return &found, nil
}

// workflowHistoryRefresh is how long a has-history answer is reused.
const workflowHistoryRefresh = 5 * time.Minute

func (s *Handler) workflowHistory() *sharedCache[*bool] {
	s.workflowHistoryOnce.Do(func() {
		s.workflowHistoryVal = newSharedCache[*bool](workflowHistoryRefresh, time.Minute)
	})
	return s.workflowHistoryVal
}
