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

// HistoryListResponse represents a history listing response
type HistoryListResponse struct {
	Ads []*classad.ClassAd `json:"ads"`
}

// handleJobHistory handles GET /api/v1/jobs/archive
// Queries job history (completed jobs)
func (s *Server) handleJobHistory(w http.ResponseWriter, r *http.Request) {
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
func (s *Server) handleJobEpochs(w http.ResponseWriter, r *http.Request) {
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
func (s *Server) handleJobTransfers(w http.ResponseWriter, r *http.Request) {
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
func (s *Server) handleHistoryQuery(w http.ResponseWriter, r *http.Request, baseOpts *htcondor.HistoryQueryOptions) {
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
	scanLimit := -1 // no limit by default
	if scanLimitStr := r.URL.Query().Get("scan_limit"); scanLimitStr != "" {
		parsedScanLimit, err := strconv.Atoi(scanLimitStr)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid scan_limit parameter: %v", err))
			return
		}
		scanLimit = parsedScanLimit
	}

	// Parse projection parameter
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

	// Decide whether to use streaming based on stream_results parameter
	useStreaming := streamResults

	if useStreaming {
		s.streamHistoryQuery(ctx, w, r, constraint, opts)
	} else {
		s.bufferHistoryQuery(ctx, w, r, constraint, opts)
	}
}

// streamHistoryQuery performs a streaming history query
func (s *Server) streamHistoryQuery(ctx context.Context, w http.ResponseWriter, _ *http.Request, constraint string, opts *htcondor.HistoryQueryOptions) {
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
func (s *Server) bufferHistoryQuery(ctx context.Context, w http.ResponseWriter, _ *http.Request, constraint string, opts *htcondor.HistoryQueryOptions) {
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
		Ads: ads,
	}
	s.writeJSON(w, http.StatusOK, response)
}
