package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/matchanalyzer"
)

// matchAnalysisProvider memoizes the per-handler CollectorSlotProvider so
// the slot cache survives across HTTP calls. Without this, each
// /match-analysis hit would build a fresh provider and burn a fresh
// collector query — defeating the whole point of the cache.
//
// We lazily allocate on first use because the analyzer isn't always
// reachable (no collector configured) and we don't want the handler init
// path to depend on the matchanalyzer package.
func (s *Handler) matchAnalysisProvider() *matchanalyzer.CollectorSlotProvider {
	s.matchAnalysisOnce.Do(func() {
		if s.collector == nil {
			return
		}
		s.matchAnalysisSlots = matchanalyzer.NewCollectorSlotProvider(
			s.collector,
			// 30 seconds is the matchanalyzer default; spelled out
			// here so the choice is reviewable in the handler context
			// where this provider's lifetime matters.
			matchanalyzer.WithSlotCacheTTL(30*time.Second),
		)
	})
	return s.matchAnalysisSlots
}

// handleJobMatchAnalysis handles GET /api/v1/jobs/{id}/match-analysis.
// Runs matchanalyzer over the job's Requirements expression against the
// current slot pool and returns the structured Result as JSON.
//
// This is an explicit-request endpoint — there is no auto-poll. The
// frontend MUST gate it behind a user gesture because each call can
// trigger a multi-thousand-ad collector query (cached for 30s, but the
// first uncached call is heavy).
func (s *Handler) handleJobMatchAnalysis(w http.ResponseWriter, r *http.Request, cluster, proc int) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	provider := s.matchAnalysisProvider()
	if provider == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Match analysis requires a configured collector")
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

	// Fetch the job ad. We project Requirements specifically (plus the
	// identifying triple) — the analyzer only reads Requirements off the
	// job ad and we don't want to drag the entire JobAd over the wire.
	//
	// `?source=archive` redirects the lookup to HTCondor's history
	// database (completed / removed jobs) so the archive-detail page
	// can run "would this job have matched the current pool?" — the
	// Requirements expression is preserved on archived ads and the
	// analyzer doesn't care that the job no longer exists in the
	// queue. Default behavior (no source param, or "live") still hits
	// the live schedd query.
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	source := r.URL.Query().Get("source")
	projection := []string{"ClusterId", "ProcId", "Requirements", "Owner"}
	var jobAds []*classad.ClassAd
	switch source {
	case "", "live":
		jobAds, _, err = s.schedd.QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
			Projection: projection,
			Limit:      1,
		})
	case "archive":
		jobAds, err = s.schedd.QueryHistoryWithOptions(ctx, constraint, &htcondor.HistoryQueryOptions{
			Source:     htcondor.HistorySourceJobHistory,
			Projection: projection,
			Limit:      1,
			Backwards:  true,
		})
	default:
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid source %q (want \"live\" or \"archive\")", source))
		return
	}
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "match-analysis: query job", "error", err, "job", fmt.Sprintf("%d.%d", cluster, proc), "source", source)
		s.writeError(w, http.StatusInternalServerError, "Failed to query job")
		return
	}
	if len(jobAds) == 0 {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Job not found: %d.%d", cluster, proc))
		return
	}

	// Cap the analysis at 30s. The slot query and per-slot evaluation
	// loop are bounded by pool size, but a misconfigured collector or a
	// huge pool shouldn't be able to wedge the HTTP handler indefinitely.
	analysisCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	a := matchanalyzer.New(provider)
	res, err := a.Analyze(analysisCtx, jobAds[0])
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "match-analysis: analyze", "error", err, "job", fmt.Sprintf("%d.%d", cluster, proc))
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Analysis failed: %v", err))
		return
	}

	// Wrap in an envelope so we can attach metadata (the cache status,
	// the analyzed requirements text) without changing the inner Result
	// shape. Frontend reads result.* and renders the panel; a future
	// debug page can also surface the cache status.
	type response struct {
		JobID        string                    `json:"job_id"`
		Requirements string                    `json:"requirements"`
		Result       *matchanalyzer.Result     `json:"result"`
		SlotCache    matchanalyzer.CacheStatus `json:"slot_cache"`
	}

	requirementsText := ""
	if reqExpr, ok := jobAds[0].Lookup("Requirements"); ok && reqExpr != nil {
		requirementsText = reqExpr.String()
	}

	s.writeJSON(w, http.StatusOK, response{
		JobID:        fmt.Sprintf("%d.%d", cluster, proc),
		Requirements: requirementsText,
		Result:       res,
		SlotCache:    provider.CacheStatus(),
	})
}
