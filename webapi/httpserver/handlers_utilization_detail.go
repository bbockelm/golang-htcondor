package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/utilization"
)

// One workflow's full detail, and applying its advice to the jobs of it
// still waiting in the queue.

// UtilizationWorkflowDetail is GET /api/v1/utilization/workflow.
type UtilizationWorkflowDetail struct {
	Since     int64           `json:"since"`
	Until     int64           `json:"until"`
	Days      int             `json:"days"`
	Truncated bool            `json:"truncated"`
	Limit     int             `json:"limit"`
	Workflow  json.RawMessage `json:"workflow"`
	// WaitingJobs is the caller's idle jobs of this workflow in the queue
	// now; nil in multi-AP mode or when the queue could not be read.
	WaitingJobs *int `json:"waiting_jobs"`
}

// handleUtilizationWorkflow handles GET /api/v1/utilization/workflow.
func (s *Handler) handleUtilizationWorkflow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	uq, err := s.parseUtilizationQuery(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	key := r.URL.Query().Get("w")
	if key == "" {
		s.writeError(w, http.StatusBadRequest, "missing w: the workflow key from /api/v1/utilization")
		return
	}
	c, ok := s.utilizationCall(w, r, uq)
	if !ok {
		return
	}
	res, err := s.utilizationAnalysis(c, uq)
	if err != nil {
		s.writeUtilizationAnalysisError(w, err)
		return
	}
	raw, found, err := res.workflow(key)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "No workflow with that key in this analysis")
		return
	}
	detail := UtilizationWorkflowDetail{
		Since: res.summary.Since, Until: res.summary.Until, Days: res.summary.Days,
		Truncated: res.summary.Truncated, Limit: res.summary.Limit, Workflow: raw,
	}
	if s.multi == nil {
		wf, _ := res.workflowSummary(key)
		if n, err := s.waitingJobCount(c, r, key, wf.Owner); err == nil {
			detail.WaitingJobs = &n
		} else {
			s.logger.Info(logging.DestinationHTTP, "utilization: could not count a workflow's waiting jobs", "error", err)
		}
	}
	s.writeJSON(w, http.StatusOK, detail)
}

// waitingJobsRefresh is how long a waiting-jobs count is reused: long
// enough that paging through a workflow's charts does not query the
// queue each time, short enough that the count after an apply is not
// stale for long.
const waitingJobsRefresh = 30 * time.Second

// waitingJobsProjection is what deciding a queued job's workflow and its
// requests needs.
var waitingJobsProjection = []string{
	"ClusterId", "ProcId", "Owner", "JobStatus", "JobUniverse", "Cmd", "Args", "Arguments",
	"JobBatchName", "DAGManJobId", "RequestMemory", "RequestCpus", "RequestDisk", "RequestGPUs",
}

// waitingJobs is the caller's idle jobs whose workflow is key, as ads.
//
// One narrow queue query: idle jobs, of the workflow's owner when it is
// known, confined to what the caller may edit (jobsOwnerScope at the
// mutate tier -- the same rule the job-edit endpoints apply), and then
// matched to the workflow by utilization.InWorkflow, the analysis's own
// grouping.
func (s *Handler) waitingJobs(c *utilizationCaller, r *http.Request, key, owner string) ([]*classad.ClassAd, error) {
	base := "JobStatus == 1"
	if owner != "" {
		base += " && Owner == " + classadStringLit(owner)
	}
	constraint, err := s.jobsOwnerScope(c.ctx, r, base, jobScopeMutate)
	if err != nil {
		return nil, err
	}
	ads, _, err := s.scheddFor(c.ctx).QueryWithOptions(c.ctx, constraint, &htcondor.QueryOptions{
		Projection: waitingJobsProjection,
		Limit:      -1,
	})
	if err != nil {
		return nil, err
	}
	var out []*classad.ClassAd
	for _, ad := range ads {
		j := utilization.FromAd(ad, "")
		if utilization.InWorkflow(&j, key) {
			out = append(out, ad)
		}
	}
	return out, nil
}

// waitingJobCount is how many waiting jobs a workflow has, cached briefly
// per caller and workflow.
func (s *Handler) waitingJobCount(c *utilizationCaller, r *http.Request, key, owner string) (int, error) {
	cacheKey := c.key + "|w=" + key + "|actor=" + htcondor.GetAuthenticatedUserFromContext(c.ctx)
	return s.waitingCounts().get(c.ctx, cacheKey, func(context.Context) (int, error) {
		ads, err := s.waitingJobs(c, r, key, owner)
		return len(ads), err
	})
}

func (s *Handler) waitingCounts() *sharedCache[int] {
	s.waitingCacheOnce.Do(func() {
		s.waitingCacheVal = newSharedCache[int](waitingJobsRefresh, time.Minute)
	})
	return s.waitingCacheVal
}

// UtilizationApplyRequest is POST /api/v1/utilization/apply.
type UtilizationApplyRequest struct {
	W          string   `json:"w"`
	Advice     []string `json:"advice"`
	Days       *int     `json:"days,omitempty"`
	OwnedByMe  *bool    `json:"owned_by_me,omitempty"`
	Constraint string   `json:"constraint,omitempty"`
	Owners     string   `json:"owners,omitempty"`
	Limit      *int     `json:"limit,omitempty"`
	Schedd     string   `json:"schedd,omitempty"`
}

// UtilizationApplyResponse is what an apply did.
type UtilizationApplyResponse struct {
	Edited   int                `json:"edited"`
	Set      map[string]float64 `json:"set"`
	Declined []AdviceDeclined   `json:"declined"`
	Skipped  []JobOutcome       `json:"skipped"`
	Failed   []JobOutcome       `json:"failed"`
}

// AdviceDeclined is advice that cannot be applied to queued jobs.
type AdviceDeclined struct {
	Advice string `json:"advice"`
	Reason string `json:"reason"`
}

// JobOutcome is one job left alone, and why.
type JobOutcome struct {
	Job    string `json:"job"`
	Reason string `json:"reason"`
}

// values turns the body's analysis parameters into the query string the
// GET endpoints take, so they are parsed -- and validated -- one way.
func (req UtilizationApplyRequest) values() url.Values {
	v := url.Values{}
	if req.Days != nil {
		v.Set("days", strconv.Itoa(*req.Days))
	}
	if req.OwnedByMe != nil {
		v.Set("owned_by_me", strconv.FormatBool(*req.OwnedByMe))
	}
	if req.Constraint != "" {
		v.Set("constraint", req.Constraint)
	}
	if req.Owners != "" {
		v.Set("owners", req.Owners)
	}
	if req.Limit != nil {
		v.Set("limit", strconv.Itoa(*req.Limit))
	}
	if req.Schedd != "" {
		v.Set("schedd", req.Schedd)
	}
	return v
}

// handleUtilizationApply handles POST /api/v1/utilization/apply: set the
// requests a workflow's advice names on that workflow's jobs still
// waiting to run.
//
// The values come from the server's own current advice for the
// workflow, never from the request, which only names which advice to
// apply. Only the four Request* attributes are written, only on idle
// jobs, and only on jobs the caller may edit -- the same owner scope,
// and the same administrator rule, as the job-edit endpoints. A request
// the job wrote as a formula over its own usage is left as written: it
// is the user's policy for growing the request, and a number in its
// place would quietly end it.
func (s *Handler) handleUtilizationApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.multi != nil {
		s.writeError(w, http.StatusNotImplemented, "Applying suggestions is not available in multi-AP mode")
		return
	}
	var req UtilizationApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	if req.W == "" || len(req.Advice) == 0 {
		s.writeError(w, http.StatusBadRequest, "w and advice are required")
		return
	}
	uq, err := s.parseUtilizationValues(req.values())
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	c, ok := s.utilizationCall(w, r, uq)
	if !ok {
		return
	}
	res, err := s.utilizationAnalysis(c, uq)
	if err != nil {
		s.writeUtilizationAnalysisError(w, err)
		return
	}
	raw, found, err := res.workflow(req.W)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "No workflow with that key in this analysis")
		return
	}
	var wf utilization.Workflow
	if err := json.Unmarshal(raw, &wf); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	out := UtilizationApplyResponse{Set: map[string]float64{}, Declined: []AdviceDeclined{}, Skipped: []JobOutcome{}, Failed: []JobOutcome{}}
	for _, id := range req.Advice {
		i := slices.IndexFunc(wf.Advice, func(a utilization.Advice) bool { return a.ID == id })
		if i < 0 {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("%q is not among this workflow's current suggestions", id))
			return
		}
		a := wf.Advice[i]
		switch {
		case a.Applies && a.Change != nil:
			out.Set[a.Change.Attribute] = a.Change.Value
		case a.ID == "memory-retry":
			out.Declined = append(out.Declined, AdviceDeclined{Advice: id, Reason: "it needs retry_request_memory, which condor_submit sets up as an on-evict transform (TransformOnEvict and TransformBody_RequestMemory) that cannot be added to a job already in the queue; use the submit lines for the next submission"})
		default:
			out.Declined = append(out.Declined, AdviceDeclined{Advice: id, Reason: "it does not change a request"})
		}
	}
	if len(out.Set) == 0 {
		s.writeJSON(w, http.StatusOK, out)
		return
	}

	wfSummary, _ := res.workflowSummary(req.W)
	ads, err := s.waitingJobs(c, r, req.W, wfSummary.Owner)
	if err != nil {
		s.writeUtilizationError(w, err)
		return
	}
	s.applyRequests(c, r, ads, out.Set, &out)
	s.logger.Info(logging.DestinationHTTP, "utilization suggestions applied",
		"workflow", req.W, "advice", strings.Join(req.Advice, ","), "edited", out.Edited,
		"skipped", len(out.Skipped), "failed", len(out.Failed))
	s.writeJSON(w, http.StatusOK, out)
}

// applyRequests edits the waiting jobs, a cluster at a time: one edit
// per cluster and set of attributes, with the procs named in the
// constraint, so a thousand waiting jobs in one cluster are one edit.
func (s *Handler) applyRequests(c *utilizationCaller, r *http.Request, ads []*classad.ClassAd, set map[string]float64, out *UtilizationApplyResponse) {
	type group struct {
		cluster int64
		attrs   map[string]string
		procs   []int64
	}
	groups := map[string]*group{}
	var order []string
	for _, ad := range ads {
		cluster, _ := ad.EvaluateAttrInt("ClusterId")
		proc, _ := ad.EvaluateAttrInt("ProcId")
		attrs := map[string]string{}
		var formulas []string
		for attr, value := range set {
			if expr, ok := ad.Lookup(attr); ok && expr != nil && utilization.IsAdaptive(expr.String()) {
				formulas = append(formulas, attr)
				continue
			}
			attrs[attr] = strconv.FormatFloat(value, 'f', -1, 64)
		}
		job := fmt.Sprintf("%d.%d", cluster, proc)
		if len(formulas) > 0 {
			slices.Sort(formulas)
			out.Skipped = append(out.Skipped, JobOutcome{Job: job,
				Reason: strings.Join(formulas, ", ") + " is a formula over the job's own usage; left as written"})
		}
		if len(attrs) == 0 {
			continue
		}
		names := make([]string, 0, len(attrs))
		for a := range attrs {
			names = append(names, a)
		}
		slices.Sort(names)
		gk := fmt.Sprintf("%d|%s", cluster, strings.Join(names, ","))
		g := groups[gk]
		if g == nil {
			g = &group{cluster: cluster, attrs: attrs}
			groups[gk] = g
			order = append(order, gk)
		}
		g.procs = append(g.procs, proc)
	}
	for _, gk := range order {
		g := groups[gk]
		procs := make([]string, len(g.procs))
		for i, p := range g.procs {
			procs[i] = strconv.FormatInt(p, 10)
		}
		// Still idle, still the caller's to edit: a job that started
		// between the read and the edit is left alone.
		base := fmt.Sprintf("ClusterId == %d && JobStatus == 1 && member(ProcId, {%s})", g.cluster, strings.Join(procs, ", "))
		fail := func(reason string) {
			for _, p := range g.procs {
				out.Failed = append(out.Failed, JobOutcome{Job: fmt.Sprintf("%d.%d", g.cluster, p), Reason: reason})
			}
		}
		constraint, err := s.jobsOwnerScope(c.ctx, r, base, jobScopeMutate)
		if err != nil {
			fail(err.Error())
			continue
		}
		n, err := s.utilizationEditJobs(c.ctx, constraint, g.attrs)
		if err != nil {
			fail(err.Error())
			continue
		}
		out.Edited += n
		if missed := len(g.procs) - n; missed > 0 {
			out.Failed = append(out.Failed, JobOutcome{Job: fmt.Sprintf("%d.*", g.cluster),
				Reason: fmt.Sprintf("%d of the cluster's waiting jobs started or left the queue before the edit", missed)})
		}
	}
}

// utilizationEditJobs is the edit apply makes: the job-edit endpoints'
// own path, with protected attributes refused. A variable on the handler
// so tests can see the edits without a schedd that implements them.
func (s *Handler) utilizationEditJobs(ctx context.Context, constraint string, attrs map[string]string) (int, error) {
	if s.utilizationEditHook != nil {
		return s.utilizationEditHook(ctx, constraint, attrs)
	}
	return s.scheddFor(ctx).EditJobs(ctx, constraint, attrs, &htcondor.EditJobOptions{})
}
