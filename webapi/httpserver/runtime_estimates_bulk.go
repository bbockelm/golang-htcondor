package httpserver

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/runtimeest"
)

// POST /api/v1/jobs/runtime-estimates: the runtime estimates for a list
// of jobs in one request, so the jobs listing asks once per refresh
// rather than once per job.
//
// The request names job ids rather than repeating the listing's
// constraint: the listing knows exactly which jobs it is showing, a
// handful of batches out of a queue that may hold tens of thousands, and
// an id list bounds the work here by what is on screen rather than by
// what the constraint happens to match. It is a POST only because a few
// thousand ids do not fit in a URL; it reads, and is authorized as a
// read (see condorScopeForRequest).

// maxBulkRuntimeEstimates caps the ids in one request. The listing asks
// about the jobs it shows, which is far fewer.
const maxBulkRuntimeEstimates = 5000

// bulkRuntimeEstimateClusters is how many clusters one schedd query
// names, so the constraint stays a reasonable size.
const bulkRuntimeEstimateClusters = 500

// bulkRuntimeEstimate is one job's estimate in the bulk response: a
// runtimeest.Result without its model, which the response carries once.
// The outer Model, nil and omitted, hides the embedded one.
type bulkRuntimeEstimate struct {
	runtimeest.Result
	Model *runtimeest.Model `json:"model,omitempty"`
}

// bulkRuntimeEstimatesResponse is the body when the estimator can
// answer. Estimates is keyed by job id and holds only the jobs the
// caller may read that are waiting or running.
type bulkRuntimeEstimatesResponse struct {
	Available bool                           `json:"available"`
	Estimates map[string]bulkRuntimeEstimate `json:"estimates"`
	Model     runtimeest.Model               `json:"model"`
}

// bulkRuntimeEstimatesUnavailable is the body when the estimator cannot
// answer for anyone: off, or not yet loaded.
type bulkRuntimeEstimatesUnavailable struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
}

// bulkJobID is one requested job.
type bulkJobID struct{ cluster, proc int }

// parseBulkJobIDs reads the request's ids: each "cluster.proc", at most
// maxBulkRuntimeEstimates of them, duplicates dropped.
func parseBulkJobIDs(ids []string) (map[bulkJobID]string, error) {
	if len(ids) > maxBulkRuntimeEstimates {
		return nil, errTooManyJobs
	}
	out := make(map[bulkJobID]string, len(ids))
	for _, id := range ids {
		c, p, err := parseJobID(id)
		if err != nil || c <= 0 || p < 0 {
			return nil, fmt.Errorf("invalid job ID %q: expected cluster.proc", id)
		}
		out[bulkJobID{c, p}] = fmt.Sprintf("%d.%d", c, p)
	}
	return out, nil
}

var errTooManyJobs = fmt.Errorf("at most %d jobs per request", maxBulkRuntimeEstimates)

// sortedClusters is the distinct clusters of ids, ascending.
func sortedClusters(ids map[bulkJobID]string) []int {
	set := make(map[int]struct{})
	for k := range ids {
		set[k.cluster] = struct{}{}
	}
	out := make([]int, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	slices.Sort(out)
	return out
}

// handleBulkRuntimeEstimates handles POST /api/v1/jobs/runtime-estimates.
//
// Body: {"jobs": ["123.0", "123.1", ...]}. Answer: 200 with
// {"available": true, "estimates": {"123.0": {...}, ...}, "model": {...}},
// each estimate shaped like the single-job endpoint's without the job id
// and model. A job the caller may not read, that does not exist, or that
// is neither waiting nor running is simply absent. A server without the
// feature answers {"available": false, "reason": "disabled"}, and one
// that has not read its history yet "model_warming_up", the same reasons
// the single-job endpoint gives; neither looks anything up.
func (h *Handler) handleBulkRuntimeEstimates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	ctx, needsRedirect, err := h.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			h.redirectToLogin(w, r)
			return
		}
		h.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	var req struct {
		Jobs []string `json:"jobs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	ids, err := parseBulkJobIDs(req.Jobs)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errTooManyJobs) {
			status = http.StatusRequestEntityTooLarge
		}
		h.writeError(w, status, err.Error())
		return
	}
	if h.runtimeEst == nil {
		h.writeJSON(w, http.StatusOK, bulkRuntimeEstimatesUnavailable{Reason: runtimeest.ReasonDisabled})
		return
	}
	model, loaded := h.runtimeEst.Model()
	if !loaded {
		h.writeJSON(w, http.StatusOK, bulkRuntimeEstimatesUnavailable{Reason: runtimeest.ReasonWarmingUp})
		return
	}

	constraints, err := h.bulkEstimateConstraints(ctx, r, sortedClusters(ids))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ads, err := h.bulkEstimateAds(ctx, constraints, ids)
	if err != nil {
		h.logger.Error(logging.DestinationHTTP, "runtime-estimates: query jobs", "error", err, "jobs", len(ids))
		h.writeError(w, http.StatusInternalServerError, "Failed to query jobs")
		return
	}

	now := time.Now()
	queries := make([]runtimeest.Query, len(ads))
	for i, a := range ads {
		queries[i] = runtimeest.QueryFromAd(a.ad, now)
	}
	results := h.runtimeEst.EstimateMany(queries)
	resp := bulkRuntimeEstimatesResponse{
		Available: true,
		Estimates: make(map[string]bulkRuntimeEstimate, len(ads)),
		Model:     model,
	}
	if len(results) > 0 {
		// The snapshot the estimates came from.
		resp.Model = results[0].Model
	}
	for i, a := range ads {
		resp.Estimates[a.id] = bulkRuntimeEstimate{Result: results[i]}
	}
	h.writeJSON(w, http.StatusOK, resp)
}

// bulkEstimateConstraints is the schedd constraints that read the
// requested clusters' waiting and running jobs, some hundreds of
// clusters to each, scoped exactly as the single-job endpoint scopes
// its read: so a job that endpoint would call "not found" is absent
// here.
//
// The schedd is asked by cluster -- member(ClusterId, {...}) -- and the
// procs nobody asked about are dropped afterwards (bulkEstimateAds): a
// clause per proc would be far longer for the common case of many procs
// of a few clusters.
func (h *Handler) bulkEstimateConstraints(ctx context.Context, r *http.Request, clusters []int) ([]string, error) {
	var out []string
	for chunk := range slices.Chunk(clusters, bulkRuntimeEstimateClusters) {
		var b strings.Builder
		b.WriteString("member(ClusterId, {")
		for i, c := range chunk {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(strconv.Itoa(c))
		}
		b.WriteString("}) && (JobStatus == 1 || JobStatus == 2)")
		constraint, err := h.jobsReadScope(ctx, r, b.String())
		if err != nil {
			return nil, err
		}
		out = append(out, constraint)
	}
	return out, nil
}

// estimateAd is a requested job's live ad.
type estimateAd struct {
	key bulkJobID
	id  string
	ad  *classad.ClassAd
}

// bulkEstimateAds runs constraints and keeps the requested jobs' ads,
// in job id order, which lets EstimateMany share work between a
// cluster's procs.
func (h *Handler) bulkEstimateAds(ctx context.Context, constraints []string, ids map[bulkJobID]string) ([]estimateAd, error) {
	var out []estimateAd
	for _, constraint := range constraints {
		ads, _, err := h.getSchedd().QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
			Projection: runtimeest.QueryAttrs,
			Limit:      -1,
		})
		if err != nil {
			return nil, err
		}
		for _, ad := range ads {
			c, cok := ad.EvaluateAttrInt("ClusterId")
			p, pok := ad.EvaluateAttrInt("ProcId")
			if !cok || !pok {
				continue
			}
			k := bulkJobID{int(c), int(p)}
			if id, ok := ids[k]; ok {
				out = append(out, estimateAd{key: k, id: id, ad: ad})
			}
		}
	}
	slices.SortFunc(out, func(a, b estimateAd) int {
		return cmp.Or(cmp.Compare(a.key.cluster, b.key.cluster), cmp.Compare(a.key.proc, b.key.proc))
	})
	return out, nil
}
