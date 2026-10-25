package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/ratelimit"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// HistoryListResponse represents a history listing response. Source and
// SourceNote name the backend that answered ("htcondordb" when a
// synchronized mirror served it, absent for the schedd) so a caller can
// tell how fresh the records are.
//
// ScanLimitReached is set when the schedd stopped at its scan limit
// before finding as many records as asked for: it examined only the
// RecordsScanned most recent history records, so older matches are not
// in the answer -- even an empty one.
type HistoryListResponse struct {
	Ads              []*classad.ClassAd `json:"ads"`
	Source           string             `json:"source,omitempty"`
	SourceNote       string             `json:"source_note,omitempty"`
	ScanLimitReached bool               `json:"scan_limit_reached,omitempty"`
	RecordsScanned   int                `json:"records_scanned,omitempty"`
}

// handleJobHistory handles GET /api/v1/jobs/archive
// Queries job history (completed jobs)
func (s *Handler) handleJobHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.multi != nil {
		s.handleMultiHistory(w, r)
		return
	}
	opts := &htcondor.HistoryQueryOptions{
		Source: htcondor.HistorySourceJobHistory,
	}
	s.handleHistoryQuery(w, r, opts)
}

// handleJobEpochs handles GET /api/v1/jobs/epochs
// Queries job epoch history (per job run instance)
func (s *Handler) handleJobEpochs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	opts := &htcondor.HistoryQueryOptions{
		Source: htcondor.HistorySourceJobEpoch,
	}
	if s.multi != nil {
		s.handleMultiEpochs(w, r, opts)
		return
	}
	s.handleHistoryQuery(w, r, opts)
}

// handleJobTransfers handles GET /api/v1/jobs/transfers
// Queries transfer history from job epochs
func (s *Handler) handleJobTransfers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	opts := &htcondor.HistoryQueryOptions{
		Source: htcondor.HistorySourceTransfer,
	}
	if s.multi != nil {
		s.handleMultiEpochs(w, r, opts)
		return
	}
	s.handleHistoryQuery(w, r, opts)
}

// historyCursorPredicate selects the records strictly before
// (cluster, proc) in (ClusterId, ProcId) order.
//
// It is the textbook keyset predicate
//
//	ClusterId < C || (ClusterId == C && ProcId < P)
//
// with "ClusterId <= C" hoisted out as a conjunct of its own. The two
// evaluate to the same value for every ClusterId and ProcId -- undefined,
// error, a string, a real, absent -- because ClusterId <= C is the
// disjunction of the other two comparisons and each of the three is
// undefined or an error exactly when the others are. The hoisted form is
// the one the htcondordb archive can use: its planner turns a top-level
// "ClusterId <= C" into an index or zone-map probe, and gets nothing from
// a top-level ||, so the textbook form reads the whole archive to find
// each page. The schedd evaluates either form the same way.
func historyCursorPredicate(cluster, proc int) string {
	return fmt.Sprintf("ClusterId <= %d && (ClusterId < %d || ProcId < %d)", cluster, cluster, proc)
}

// handleHistoryQuery is the common handler for all history query types
//
//nolint:gocyclo // Complex function for handling history streaming with error cases
func (s *Handler) handleHistoryQuery(w http.ResponseWriter, r *http.Request, baseOpts *htcondor.HistoryQueryOptions) {
	// Create authenticated context
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	// Parse query parameters
	constraint := r.URL.Query().Get("constraint")
	if constraint == "" {
		constraint = "true" // Default: all records
	}

	// Keyset-pagination cursor. With the archive scanning backwards
	// (newest first) and a per-page limit, we paginate deeper into
	// history by ANDing in a "strictly older than the last record I
	// saw" predicate. The (ClusterId, ProcId) tuple is the natural
	// sort key — schedd-assigned, monotonically increasing per
	// cluster, and each cluster/proc is unique. See
	// historyCursorPredicate for its form.
	//
	// HistoryQueryOptions.Since is NOT what we want here — that's
	// "stop scanning when matched" (newer-than semantics). For
	// "give me records older than N.M" we have to extend the
	// constraint. ScanLimit still applies and bounds the work per
	// page.
	beforeClusterStr := r.URL.Query().Get("before_cluster")
	beforeProcStr := r.URL.Query().Get("before_proc")
	if beforeClusterStr != "" {
		beforeCluster, err := strconv.Atoi(beforeClusterStr)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid before_cluster: %v", err))
			return
		}
		beforeProc := 0
		if beforeProcStr != "" {
			beforeProc, err = strconv.Atoi(beforeProcStr)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid before_proc: %v", err))
				return
			}
		}
		cursorPredicate := historyCursorPredicate(beforeCluster, beforeProc)
		// AND the cursor with the user-supplied constraint. Wrap
		// both in parens so operator precedence in the user's
		// expression doesn't accidentally break the cursor predicate.
		if constraint == "true" {
			constraint = cursorPredicate
		} else {
			constraint = fmt.Sprintf("(%s) && %s", constraint, cursorPredicate)
		}
	}

	// Parse limit parameter
	limit := 50 // default limit
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limitStr == "*" {
			limit = -1 // unlimited
		} else {
			parsedLimit, err := strconv.Atoi(limitStr)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid limit parameter: %v", err))
				return
			}
			limit = parsedLimit
		}
	}

	// Parse scan_limit parameter
	// Default to 10k to prevent timeouts on large pools
	scanLimit := 10000
	scanLimitExplicit := false
	if scanLimitStr := r.URL.Query().Get("scan_limit"); scanLimitStr != "" {
		scanLimitExplicit = true
		if scanLimitStr == "*" {
			scanLimit = -1 // unlimited
		} else {
			parsedScanLimit, err := strconv.Atoi(scanLimitStr)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid scan_limit parameter: %v", err))
				return
			}
			scanLimit = parsedScanLimit
		}
	}

	// Parse projection parameter
	// Default to source-specific projections if not specified
	// This prevents transferring all attributes which can be large
	projectionStr := r.URL.Query().Get("projection")
	var projection []string
	if projectionStr != "" {
		if projectionStr == "*" {
			projection = []string{"*"} // all attributes
		} else {
			projection = strings.Split(projectionStr, ",")
			for i := range projection {
				projection[i] = strings.TrimSpace(projection[i])
			}
		}
	} else {
		// Apply default projection based on source type
		// This reduces data transfer and prevents timeouts
		switch baseOpts.Source {
		case htcondor.HistorySourceJobEpoch:
			projection = htcondor.DefaultEpochProjection()
		case htcondor.HistorySourceTransfer:
			projection = htcondor.DefaultTransferProjection()
		default:
			projection = htcondor.DefaultHistoryProjection()
		}
	}

	// Parse backwards parameter (default: true)
	backwards := true
	if backwardsStr := r.URL.Query().Get("backwards"); backwardsStr != "" {
		backwards = backwardsStr == "true" || backwardsStr == "1"
	}

	// Parse stream_results parameter (default: true)
	streamResults := true
	if streamResultsStr := r.URL.Query().Get("stream_results"); streamResultsStr != "" {
		streamResults = streamResultsStr == "true" || streamResultsStr == "1"
	}

	// Parse since parameter
	since := r.URL.Query().Get("since")

	// Parse transfer_types parameter (only for transfer history)
	var transferTypes []htcondor.TransferType
	if baseOpts.Source == htcondor.HistorySourceTransfer {
		if transferTypesStr := r.URL.Query().Get("transfer_types"); transferTypesStr != "" {
			types := strings.Split(transferTypesStr, ",")
			for _, t := range types {
				t = strings.TrimSpace(strings.ToUpper(t))
				switch t {
				case "INPUT":
					transferTypes = append(transferTypes, htcondor.TransferTypeInput)
				case "OUTPUT":
					transferTypes = append(transferTypes, htcondor.TransferTypeOutput)
				case "CHECKPOINT":
					transferTypes = append(transferTypes, htcondor.TransferTypeCheckpoint)
				default:
					s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid transfer type: %s", t))
					return
				}
			}
		}
	}

	// Build query options
	opts := &htcondor.HistoryQueryOptions{
		Source:        baseOpts.Source,
		Limit:         limit,
		ScanLimit:     scanLimit,
		Projection:    projection,
		Backwards:     backwards,
		StreamResults: streamResults,
		Since:         since,
		TransferTypes: transferTypes,
	}

	scopedConstraint, _, serr := s.historyOwnerScope(ctx, r, constraint)
	if serr != nil {
		s.writeError(w, http.StatusBadRequest, serr.Error())
		return
	}
	constraint = scopedConstraint

	// Offload the history-file scan to a synchronized htcondordb mirror
	// when one is current. Completed-job history is append-only, so a
	// mirror a few minutes behind still answers correctly, and only the
	// job-history source is mirrored. An unscoped read routes as readily
	// as a scoped one -- QUERY_SCHEDD_HISTORY is READ-level on the schedd
	// and applies no owner filter of its own -- but only for a caller the
	// schedd has accepted at READ, since routing is what skips asking it.
	// Any miss falls through to the schedd.
	if baseOpts.Source == htcondor.HistorySourceJobHistory {
		// scan_limit is a budget for the schedd's backwards scan of the
		// history FILE; the archive prunes by zone map and has no
		// equivalent, so HistoryDecision treats it as a reason to stay
		// on the schedd. Only an explicit one should count: this
		// endpoint defaults it to 10k, and passing that default through
		// would mean the mirror never served an archive request at all.
		mirrorOpts := *opts
		if !scanLimitExplicit {
			mirrorOpts.ScanLimit = 0
		}
		served, decision := s.historyFromMirror(ctx, w, r, constraint, &mirrorOpts,
			htcondor.GetAuthenticatedUserFromContext(ctx))
		if served {
			return
		}
		if s.mirrorRequiredError(w, decision) {
			return
		}
	}

	// Decide whether to use streaming based on stream_results parameter
	useStreaming := streamResults

	if useStreaming {
		s.streamHistoryQuery(ctx, w, r, constraint, opts)
	} else {
		s.bufferHistoryQuery(ctx, w, r, constraint, opts)
	}
}

// streamHistoryQuery performs a streaming history query
func (s *Handler) streamHistoryQuery(ctx context.Context, w http.ResponseWriter, _ *http.Request, constraint string, opts *htcondor.HistoryQueryOptions) {
	// Start streaming query
	streamOpts := &htcondor.StreamOptions{
		BufferSize:   s.streamBufferSize,
		WriteTimeout: s.streamWriteTimeout,
	}
	// The stats are written before the channel closes, so they are read
	// only after the loop below has drained it.
	var stats htcondor.HistoryScanStats
	streamQueryOpts := *opts
	streamQueryOpts.Stats = &stats
	// The routed AP's schedd in multi-AP mode (multiap_epochs.go).
	resultCh, err := s.scheddFor(ctx).QueryHistoryStream(ctx, constraint, &streamQueryOpts, streamOpts)
	// A whole ad's requests can be evaluated; a projected one's cannot.
	wholeAd := isWholeAdProjection(opts.Projection)
	if err != nil {
		// Pre-request error - check type and set appropriate status
		switch {
		case ratelimit.IsRateLimitError(err):
			s.writeError(w, http.StatusTooManyRequests, err.Error())
		case isAuthenticationError(err):
			s.writeError(w, http.StatusUnauthorized, "Authentication failed")
		default:
			s.writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	// Set up streaming JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Start JSON array
	if _, err := w.Write([]byte(`{"ads":[`)); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to write response header", "error", err)
		return
	}

	// Stream history ads as they arrive
	adCount := 0
	var errorMsg string
	// stoppedEarly: the loop quit with the channel still open, so the
	// query may still be running and its stats are not ready to read.
	stoppedEarly := false
	for result := range resultCh {
		if result.Err != nil {
			// Check if it's a rate limit error
			if ratelimit.IsRateLimitError(result.Err) {
				s.logger.Error(logging.DestinationHTTP, "Rate limit exceeded", "error", result.Err)
				errorMsg = "Rate limit exceeded"
				break
			}
			// Check if it's an authentication error
			if isAuthenticationError(result.Err) {
				s.logger.Error(logging.DestinationHTTP, "Authentication failed", "error", result.Err)
				errorMsg = "Authentication failed"
				break
			}
			// Error occurred - log it and close the response
			s.logger.Error(logging.DestinationHTTP, "Query streaming error", "error", result.Err)
			errorMsg = streamErrorMessage(result.Err)
			break
		}

		// Check limit
		if opts.Limit > 0 && adCount >= opts.Limit {
			stoppedEarly = true
			break
		}

		// Usage attributes go out as numbers, as on the live paths.
		evaluateUsageAttrs(result.Ad)
		if wholeAd {
			annotateEvaluatedRequests(result.Ad)
		}
		if sch := routedSchedd(ctx); sch != "" && result.Ad != nil {
			// The access point it came from: the same cluster.proc on
			// another AP is another job.
			_ = result.Ad.Set(multiap.AttrScheddName, sch)
		}
		// Marshal the ad
		adJSON, err := json.Marshal(result.Ad)
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to marshal history ad", "error", err)
			continue
		}

		// Add comma if not first item
		if adCount > 0 {
			if _, err := w.Write([]byte(",")); err != nil {
				s.logger.Error(logging.DestinationHTTP, "Failed to write comma", "error", err)
				return
			}
		}

		// Write the ad
		if _, err := w.Write(adJSON); err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to write history ad", "error", err)
			return
		}

		adCount++
	}

	// Close JSON array and object
	if errorMsg != "" {
		// Include error in response
		errorJSON, _ := json.Marshal(errorMsg)
		if _, err := fmt.Fprintf(w, `],"error":%s}`, errorJSON); err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to write response footer with error", "error", err)
		}
	} else {
		footer := ""
		if !stoppedEarly {
			footer = scanLimitFooter(stats)
		}
		if _, err := w.Write([]byte(`]` + footer + `}`)); err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to write response footer", "error", err)
		}
	}
}

// scanLimitFooter renders a cut-off scan's fields for the end of a streamed
// response object (see HistoryListResponse), or "" when the scan was not cut
// off.
func scanLimitFooter(stats htcondor.HistoryScanStats) string {
	if !stats.ScanLimitReached {
		return ""
	}
	return fmt.Sprintf(`,"scan_limit_reached":true,"records_scanned":%d`, stats.RecordsScanned)
}

// bufferHistoryQuery performs a buffered history query
func (s *Handler) bufferHistoryQuery(ctx context.Context, w http.ResponseWriter, _ *http.Request, constraint string, opts *htcondor.HistoryQueryOptions) {
	// Query history with buffering
	var stats htcondor.HistoryScanStats
	bufferedOpts := *opts
	bufferedOpts.Stats = &stats
	ads, err := s.scheddFor(ctx).QueryHistoryWithOptions(ctx, constraint, &bufferedOpts)
	if err != nil {
		// Check error type and set appropriate status
		switch {
		case ratelimit.IsRateLimitError(err):
			s.writeError(w, http.StatusTooManyRequests, err.Error())
		case isAuthenticationError(err):
			s.writeError(w, http.StatusUnauthorized, "Authentication failed")
		default:
			s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Query failed: %v", err))
		}
		return
	}

	wholeAd := isWholeAdProjection(opts.Projection)
	sch := routedSchedd(ctx)
	for _, ad := range ads {
		evaluateUsageAttrs(ad)
		if wholeAd {
			annotateEvaluatedRequests(ad)
		}
		if sch != "" {
			_ = ad.Set(multiap.AttrScheddName, sch)
		}
	}
	// Return results as JSON
	response := HistoryListResponse{
		Ads:              ads,
		Source:           "schedd",
		ScanLimitReached: stats.ScanLimitReached,
	}
	if stats.ScanLimitReached {
		response.RecordsScanned = stats.RecordsScanned
	}
	s.writeJSON(w, http.StatusOK, response)
}

// historyOwnerScope confines a history query to the caller's own records
// when it must be, returning the constraint to use and whether it ended
// up scoped.
//
// A caller that is not an administrator (seesAllJobs), bearer or browser
// session, must not be able to read every user's history — the same
// enforcement /api/v1/jobs applies to the live queue. It is scoped
// regardless of the parameter. An administrator is unscoped by default
// and can opt in with owned_by_me=true.
//
// Whether the result may come from the htcondordb mirror is a separate
// question, decided on the caller's identity rather than on scoping;
// see handlers_dbroute.go.
func (s *Handler) historyOwnerScope(ctx context.Context, r *http.Request, constraint string) (string, bool, error) {
	ownedByMe := false
	if v := r.URL.Query().Get("owned_by_me"); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return "", false, fmt.Errorf("invalid owned_by_me parameter: %w", err)
		}
		ownedByMe = parsed
	}
	if s.multi != nil {
		// The caller's User on the AP the read was routed to, unless the
		// caller is a queue superuser there.
		scoped, err := s.jobsOwnerScope(ctx, r, constraint, jobScopeRead)
		return scoped, true, err
	}
	if !s.resolveOwnerScope(ctx, r, ownedByMe) {
		return constraint, false, nil
	}

	actor := htcondor.GetAuthenticatedUserFromContext(ctx)
	if actor == "" {
		return "", false, fmt.Errorf("authentication required for an owner-scoped history query")
	}
	// scopeToOwner re-serializes the caller's constraint so it cannot
	// escape the enclosing AND; an unparseable one is rejected rather
	// than widened.
	scoped, err := scopeToActor(ctx, actor, constraint)
	if err != nil {
		return "", false, fmt.Errorf("invalid constraint: %w", err)
	}
	return scoped, true, nil
}
