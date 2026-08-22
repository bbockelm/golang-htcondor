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
)

// HistoryListResponse represents a history listing response. Source and
// SourceNote name the backend that answered ("htcondordb" when a
// synchronized mirror served it, absent for the schedd) so a caller can
// tell how fresh the records are.
type HistoryListResponse struct {
	Ads        []*classad.ClassAd `json:"ads"`
	Source     string             `json:"source,omitempty"`
	SourceNote string             `json:"source_note,omitempty"`
}

// handleJobHistory handles GET /api/v1/jobs/archive
// Queries job history (completed jobs)
func (s *Handler) handleJobHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
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
	s.handleHistoryQuery(w, r, opts)
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
	// cluster, and each cluster/proc is unique. The OR-of-pairs form
	// is the standard SQL keyset pagination idiom and is parseable
	// by the schedd's classad expression evaluator.
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
		cursorPredicate := fmt.Sprintf(
			"(ClusterId < %d || (ClusterId == %d && ProcId < %d))",
			beforeCluster, beforeCluster, beforeProc,
		)
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
	if scanLimitStr := r.URL.Query().Get("scan_limit"); scanLimitStr != "" {
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

	scopedConstraint, scoped, serr := s.historyOwnerScope(ctx, r, constraint)
	if serr != nil {
		s.writeError(w, http.StatusBadRequest, serr.Error())
		return
	}
	constraint = scopedConstraint

	// Offload the history-file scan to a synchronized htcondordb mirror
	// when one is current. Completed-job history is append-only, so a
	// mirror a few minutes behind still answers correctly; only the
	// job-history source is mirrored, and only an owner-scoped query is
	// routed. Any miss falls through to the schedd.
	if scoped && baseOpts.Source == htcondor.HistorySourceJobHistory {
		if ads, note, routed := s.historyFromMirror(ctx, constraint, opts); routed {
			s.writeJSON(w, http.StatusOK, HistoryListResponse{Ads: ads, Source: "htcondordb", SourceNote: note})
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
	resultCh, err := s.getSchedd().QueryHistoryStream(ctx, constraint, opts, streamOpts)
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
			errorMsg = result.Err.Error()
			break
		}

		// Check limit
		if opts.Limit > 0 && adCount >= opts.Limit {
			break
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
		if _, err := w.Write([]byte(`]}`)); err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to write response footer", "error", err)
		}
	}
}

// bufferHistoryQuery performs a buffered history query
func (s *Handler) bufferHistoryQuery(ctx context.Context, w http.ResponseWriter, _ *http.Request, constraint string, opts *htcondor.HistoryQueryOptions) {
	// Query history with buffering
	ads, err := s.getSchedd().QueryHistoryWithOptions(ctx, constraint, opts)
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

	// Return results as JSON
	response := HistoryListResponse{
		Ads:    ads,
		Source: "schedd",
	}
	s.writeJSON(w, http.StatusOK, response)
}

// historyOwnerScope confines a history query to the caller's own records
// when it must be, returning the constraint to use and whether it ended
// up scoped.
//
// Two reasons this exists. A browser session that is not in the admin
// group must not be able to read every user's history — the same
// enforcement /api/v1/jobs already applies to the live queue, which the
// archive endpoint was missing. And a confined query is the only kind
// that may be served from the htcondordb mirror: that connection
// authenticates as this daemon, so the schedd's per-caller ACL is not
// behind it.
//
// The default is unscoped, which preserves the behavior bearer-token API
// callers have today (the schedd's ACL is their boundary); they can opt
// in with owned_by_me=true, which is also what makes their reads
// eligible for the mirror. A non-admin browser session is scoped
// regardless of the parameter.
func (s *Handler) historyOwnerScope(ctx context.Context, r *http.Request, constraint string) (string, bool, error) {
	ownedByMe := false
	if v := r.URL.Query().Get("owned_by_me"); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return "", false, fmt.Errorf("invalid owned_by_me parameter: %w", err)
		}
		ownedByMe = parsed
	}
	if _, hasSession := s.getSessionFromRequest(r); hasSession && !s.isWebUIAdmin(r) {
		ownedByMe = true
	}
	if !ownedByMe {
		return constraint, false, nil
	}

	actor := htcondor.GetAuthenticatedUserFromContext(ctx)
	if actor == "" {
		return "", false, fmt.Errorf("authentication required for an owner-scoped history query")
	}
	// scopeToOwner re-serializes the caller's constraint so it cannot
	// escape the enclosing AND; an unparseable one is rejected rather
	// than widened.
	scoped, err := scopeToOwner(ownerFromActor(actor), constraint)
	if err != nil {
		return "", false, fmt.Errorf("invalid constraint: %w", err)
	}
	return scoped, true, nil
}
