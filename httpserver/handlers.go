package httpserver

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/ratelimit"
)

// isAuthenticationError checks if an error is a genuine authentication/authorization error
// vs a connection error that happens to mention "security" or "authentication"
func isAuthenticationError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	// Check for explicit authentication/authorization failures
	if strings.Contains(errMsg, "DENIED") ||
		strings.Contains(errMsg, "unauthorized") ||
		strings.Contains(errMsg, "forbidden") {
		return true
	}
	// Check for authentication errors that are not connection errors
	if strings.Contains(errMsg, "authentication") && !strings.Contains(errMsg, "connection") {
		return true
	}
	return false
}

// JobSubmitRequest represents a job submission request
type JobSubmitRequest struct {
	SubmitFile string `json:"submit_file"` // Submit file content
}

// JobSubmitResponse represents a job submission response
type JobSubmitResponse struct {
	ClusterID int      `json:"cluster_id"`
	JobIDs    []string `json:"job_ids"` // Array of "cluster.proc" strings
}

// JobListResponse represents a job listing response
type JobListResponse struct {
	Jobs []*classad.ClassAd `json:"jobs"`
}

// handleJobs handles /api/v1/jobs endpoint (GET for list, POST for submit, DELETE/PATCH for bulk operations)
func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListJobs(w, r)
	case http.MethodPost:
		s.handleSubmitJob(w, r)
	case http.MethodDelete:
		s.handleBulkDeleteJobs(w, r)
	case http.MethodPatch:
		s.handleBulkEditJobs(w, r)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleListJobs handles GET /api/v1/jobs
//
//nolint:gocyclo // Complex function for handling job streaming with error cases
func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	// Create authenticated context
	ctx, err := s.createAuthenticatedContext(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	// Get query parameters
	constraint := r.URL.Query().Get("constraint")
	if constraint == "" {
		constraint = "true" // Default: all jobs
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

	// Get page token
	pageToken := r.URL.Query().Get("page_token")

	// Build query options with limit
	opts := &htcondor.QueryOptions{
		Limit:      limit,
		Projection: projection,
		PageToken:  pageToken,
	}

	// Start streaming query
	streamOpts := &htcondor.StreamOptions{
		BufferSize:   s.streamBufferSize,
		WriteTimeout: s.streamWriteTimeout,
	}
	resultCh, err := s.getSchedd().QueryStreamWithOptions(ctx, constraint, opts, streamOpts)
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
	if _, err := w.Write([]byte(`{"jobs":[`)); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to write response header", "error", err)
		return
	}

	// Stream job ads as they arrive
	jobCount := 0
	var lastClusterID, lastProcID int64
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
		if limit > 0 && jobCount >= limit {
			// We've reached the limit, stop consuming but we need to track if there are more
			break
		}

		// Marshal the ad
		adJSON, err := json.Marshal(result.Ad)
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to marshal job ad", "error", err)
			continue
		}

		// Add comma if not first item
		if jobCount > 0 {
			if _, err := w.Write([]byte(",")); err != nil {
				s.logger.Error(logging.DestinationHTTP, "Failed to write comma", "error", err)
				return
			}
		}

		// Write the ad
		if _, err := w.Write(adJSON); err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to write job ad", "error", err)
			return
		}

		// Track last job for pagination
		if clusterID, ok := result.Ad.EvaluateAttrInt("ClusterId"); ok {
			lastClusterID = clusterID
		}
		if procID, ok := result.Ad.EvaluateAttrInt("ProcId"); ok {
			lastProcID = procID
		}

		jobCount++

		// Flush after each ad for true streaming
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}

	// Close JSON array and add metadata
	metadata := fmt.Sprintf(`],"total_returned":%d`, jobCount)

	// Add error if one occurred
	if errorMsg != "" {
		errJSON, _ := json.Marshal(errorMsg)
		metadata += fmt.Sprintf(`,"error":%s`, errJSON)
	}

	// Add pagination info if we hit the limit and no error occurred
	if errorMsg == "" && limit > 0 && jobCount >= limit {
		// Generate next page token
		nextPageToken := htcondor.EncodePageToken(lastClusterID, lastProcID)
		metadata += fmt.Sprintf(`,"has_more":true,"next_page_token":%q`, nextPageToken)
	} else {
		metadata += `,"has_more":false`
	}

	metadata += "}"

	if _, err := w.Write([]byte(metadata)); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to write response footer", "error", err)
	}
}

// handleSubmitJob handles POST /api/v1/jobs
func (s *Server) handleSubmitJob(w http.ResponseWriter, r *http.Request) {
	// Create authenticated context
	ctx, err := s.createAuthenticatedContext(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	// Parse request body
	var req JobSubmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}

	if req.SubmitFile == "" {
		s.writeError(w, http.StatusBadRequest, "submit_file is required")
		return
	}

	// Submit job using SubmitRemote
	clusterID, procAds, err := s.getSchedd().SubmitRemote(ctx, req.SubmitFile)
	if err != nil {
		// Check if it's an authentication error
		if isAuthenticationError(err) {
			s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Job submission failed: %v", err))
		return
	}

	// Build job IDs list
	jobIDs := make([]string, len(procAds))
	for i, ad := range procAds {
		cluster, _ := ad.EvaluateAttrInt("ClusterId")
		proc, _ := ad.EvaluateAttrInt("ProcId")
		jobIDs[i] = fmt.Sprintf("%d.%d", cluster, proc)
	}

	s.writeJSON(w, http.StatusCreated, JobSubmitResponse{
		ClusterID: clusterID,
		JobIDs:    jobIDs,
	})
}

// handleJobByID handles /api/v1/jobs/{id} endpoint
func (s *Server) handleJobByID(w http.ResponseWriter, r *http.Request) {
	// Extract job ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/jobs/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		s.writeError(w, http.StatusNotFound, "Job ID required")
		return
	}

	jobID := parts[0]

	// Check for bulk operations at /api/v1/jobs/hold or /api/v1/jobs/release
	if len(parts) == 1 {
		switch jobID {
		case "hold":
			if r.Method == http.MethodPost {
				s.handleBulkHoldJobs(w, r)
			} else {
				s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			}
			return
		case "release":
			if r.Method == http.MethodPost {
				s.handleBulkReleaseJobs(w, r)
			} else {
				s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			}
			return
		}
	}

	// Check if this is a sandbox operation or job action on a specific job
	if len(parts) == 2 {
		switch parts[1] {
		case "input":
			s.handleJobInput(w, r, jobID)
			return
		case "output":
			s.handleJobOutput(w, r, jobID)
			return
		case "stdout":
			// GET /api/v1/jobs/{id}/stdout
			cluster, proc, err := parseJobID(jobID)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
				return
			}
			s.handleJobStdout(w, r, cluster, proc)
			return
		case "stderr":
			// GET /api/v1/jobs/{id}/stderr
			cluster, proc, err := parseJobID(jobID)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
				return
			}
			s.handleJobStderr(w, r, cluster, proc)
			return
		case "hold":
			s.handleJobHold(w, r, jobID)
			return
		case "release":
			s.handleJobRelease(w, r, jobID)
			return
		}
	}

	// Handle job operations
	switch r.Method {
	case http.MethodGet:
		s.handleGetJob(w, r, jobID)
	case http.MethodDelete:
		s.handleDeleteJob(w, r, jobID)
	case http.MethodPatch:
		s.handleEditJob(w, r, jobID)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleGetJob handles GET /api/v1/jobs/{id}
func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request, jobID string) {
	// Create authenticated context
	ctx, err := s.createAuthenticatedContext(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	// Parse job ID
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}

	// Build constraint for specific job
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)

	// Query for the specific job with extended projection including hold reason
	// We need hold reason info for clients that check job status details
	projection := append(htcondor.DefaultJobProjection(),
		"HoldReason", "HoldReasonCode", "HoldReasonSubCode",
		"RemoteHost", "RemoteSlotID", "StartdAddr")
	jobAds, _, err := s.getSchedd().QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Projection: projection,
	})
	if err != nil {
		if ratelimit.IsRateLimitError(err) {
			s.writeError(w, http.StatusTooManyRequests, fmt.Sprintf("Rate limit exceeded: %v", err))
			return
		}
		if isAuthenticationError(err) {
			s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Query failed: %v", err))
		return
	}

	if len(jobAds) == 0 {
		s.writeError(w, http.StatusNotFound, "Job not found")
		return
	}

	// Return the job ClassAd as JSON - uses MarshalJSON method
	s.writeJSON(w, http.StatusOK, jobAds[0])
}

// handleDeleteJob handles DELETE /api/v1/jobs/{id}
func (s *Server) handleDeleteJob(w http.ResponseWriter, r *http.Request, jobID string) {
	// Create authenticated context
	ctx, err := s.createAuthenticatedContext(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	// Parse job ID
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}

	// Build constraint for specific job
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)

	// Remove the job using the schedd RemoveJobs method
	results, err := s.getSchedd().RemoveJobs(ctx, constraint, "Removed via HTTP API")
	if err != nil {
		// Check if it's an authentication error
		if isAuthenticationError(err) {
			s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Job removal failed: %v", err))
		return
	}

	// Check if job was found and removed
	if results.NotFound > 0 {
		s.writeError(w, http.StatusNotFound, "Job not found")
		return
	}

	if results.Success == 0 {
		// Job exists but couldn't be removed (permission denied, bad status, etc.)
		msg := "Failed to remove job"
		switch {
		case results.PermissionDenied > 0:
			msg = "Permission denied to remove job"
		case results.BadStatus > 0:
			msg = "Job in wrong status for removal"
		case results.Error > 0:
			msg = "Error removing job"
		}
		s.writeError(w, http.StatusBadRequest, msg)
		return
	}

	// Success
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Job removed successfully",
		"job_id":  jobID,
		"results": map[string]int{
			"total":   results.TotalJobs,
			"success": results.Success,
		},
	})
}

// handleEditJob handles PATCH /api/v1/jobs/{id}
func (s *Server) handleEditJob(w http.ResponseWriter, r *http.Request, jobID string) {
	// Create authenticated context
	ctx, err := s.createAuthenticatedContext(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	// Parse job ID
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}

	// Parse request body with attributes to edit
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}

	if len(updates) == 0 {
		s.writeError(w, http.StatusBadRequest, "No attributes to update")
		return
	}

	// Convert interface{} values to strings for SetAttribute
	attributes := make(map[string]string)
	for key, value := range updates {
		// Convert value to string representation
		switch v := value.(type) {
		case string:
			// Quote string values for ClassAd
			attributes[key] = fmt.Sprintf("%q", v)
		case float64:
			// JSON numbers are float64
			if v == float64(int64(v)) {
				// It's an integer
				attributes[key] = fmt.Sprintf("%d", int64(v))
			} else {
				attributes[key] = fmt.Sprintf("%f", v)
			}
		case bool:
			if v {
				attributes[key] = "true"
			} else {
				attributes[key] = "false"
			}
		case nil:
			// For null values, set to UNDEFINED
			attributes[key] = "UNDEFINED"
		default:
			// For complex types, convert to JSON string
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Cannot convert attribute %s to string: %v", key, err))
				return
			}
			attributes[key] = string(jsonBytes)
		}
	}

	// Edit the job attributes
	opts := &htcondor.EditJobOptions{
		// Don't allow protected attributes by default - user would need superuser privileges
		AllowProtectedAttrs: false,
		Force:               false,
	}

	if err := s.getSchedd().EditJob(ctx, cluster, proc, attributes, opts); err != nil {
		// Check if it's a validation error (immutable/protected attribute)
		if strings.Contains(err.Error(), "immutable") || strings.Contains(err.Error(), "protected") {
			s.writeError(w, http.StatusForbidden, fmt.Sprintf("Cannot edit job: %v", err))
			return
		}
		// Check if it's a permission error
		if strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "EACCES") {
			s.writeError(w, http.StatusForbidden, fmt.Sprintf("Permission denied: %v", err))
			return
		}
		// Check if job doesn't exist
		if strings.Contains(err.Error(), "ENOENT") || strings.Contains(err.Error(), "nonexistent") {
			s.writeError(w, http.StatusNotFound, fmt.Sprintf("Job not found: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to edit job: %v", err))
		return
	}

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Successfully edited job %s", jobID),
		"job_id":  jobID,
	}); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to encode response", "error", err, "job_id", jobID)
	}
}

// handleBulkDeleteJobs handles DELETE /api/v1/jobs with constraint-based bulk removal
func (s *Server) handleBulkDeleteJobs(w http.ResponseWriter, r *http.Request) {
	// Create authenticated context
	ctx, err := s.createAuthenticatedContext(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	// Parse request body
	var req struct {
		Constraint string `json:"constraint"`
		Reason     string `json:"reason,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}

	if req.Constraint == "" {
		s.writeError(w, http.StatusBadRequest, "Constraint is required for bulk delete")
		return
	}

	// Default reason if not provided
	if req.Reason == "" {
		req.Reason = "Removed via HTTP API bulk operation"
	}

	// Remove jobs by constraint
	results, err := s.getSchedd().RemoveJobs(ctx, req.Constraint, req.Reason)
	if err != nil {
		// Check if it's an authentication error
		if isAuthenticationError(err) {
			s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Bulk job removal failed: %v", err))
		return
	}

	// Check results
	if results.TotalJobs == 0 {
		s.writeError(w, http.StatusNotFound, "No jobs matched the constraint")
		return
	}

	// Return success with statistics
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":    "Bulk job removal completed",
		"constraint": req.Constraint,
		"results": map[string]int{
			"total":             results.TotalJobs,
			"success":           results.Success,
			"not_found":         results.NotFound,
			"permission_denied": results.PermissionDenied,
			"bad_status":        results.BadStatus,
			"error":             results.Error,
		},
	})
}

// handleBulkEditJobs handles PATCH /api/v1/jobs with constraint-based bulk editing
func (s *Server) handleBulkEditJobs(w http.ResponseWriter, r *http.Request) {
	// Create authenticated context
	ctx, err := s.createAuthenticatedContext(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	// Parse request body
	var req struct {
		Constraint string                 `json:"constraint"`
		Attributes map[string]interface{} `json:"attributes"`
		Options    *struct {
			AllowProtectedAttrs bool `json:"allow_protected_attrs,omitempty"`
			Force               bool `json:"force,omitempty"`
		} `json:"options,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}

	if req.Constraint == "" {
		s.writeError(w, http.StatusBadRequest, "Constraint is required for bulk edit")
		return
	}

	if len(req.Attributes) == 0 {
		s.writeError(w, http.StatusBadRequest, "No attributes to update")
		return
	}

	// Convert interface{} values to strings for SetAttribute
	attributes := make(map[string]string)
	for key, value := range req.Attributes {
		// Convert value to string representation
		switch v := value.(type) {
		case string:
			// Quote string values for ClassAd
			attributes[key] = fmt.Sprintf("%q", v)
		case float64:
			// JSON numbers are float64
			if v == float64(int64(v)) {
				// It's an integer
				attributes[key] = fmt.Sprintf("%d", int64(v))
			} else {
				attributes[key] = fmt.Sprintf("%f", v)
			}
		case bool:
			if v {
				attributes[key] = "true"
			} else {
				attributes[key] = "false"
			}
		case nil:
			// For null values, set to UNDEFINED
			attributes[key] = "UNDEFINED"
		default:
			// For complex types, convert to JSON string
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Cannot convert attribute %s to string: %v", key, err))
				return
			}
			attributes[key] = string(jsonBytes)
		}
	}

	// Set up options
	opts := &htcondor.EditJobOptions{
		AllowProtectedAttrs: false,
		Force:               false,
	}
	if req.Options != nil {
		opts.AllowProtectedAttrs = req.Options.AllowProtectedAttrs
		opts.Force = req.Options.Force
	}

	// Edit jobs matching constraint
	count, err := s.getSchedd().EditJobs(ctx, req.Constraint, attributes, opts)
	if err != nil {
		// Check if it's a validation error (immutable/protected attribute)
		if strings.Contains(err.Error(), "immutable") || strings.Contains(err.Error(), "protected") {
			s.writeError(w, http.StatusForbidden, fmt.Sprintf("Cannot edit jobs: %v", err))
			return
		}
		// Check if it's a permission error
		if strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "EACCES") {
			s.writeError(w, http.StatusForbidden, fmt.Sprintf("Permission denied: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to edit jobs: %v", err))
		return
	}

	if count == 0 {
		s.writeError(w, http.StatusNotFound, "No jobs matched the constraint")
		return
	}

	// Return success response
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "success",
		"message":     fmt.Sprintf("Successfully edited %d job(s)", count),
		"constraint":  req.Constraint,
		"jobs_edited": count,
	})
}

// parseBulkActionRequest parses constraint and reason from request body for bulk operations
func (s *Server) parseBulkActionRequest(r *http.Request, actionName string) (constraint, reason string, err error) {
	var req struct {
		Constraint string `json:"constraint"`
		Reason     string `json:"reason,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return "", "", fmt.Errorf("invalid request body: %w", err)
	}

	if req.Constraint == "" {
		return "", "", fmt.Errorf("constraint is required for bulk %s", actionName)
	}

	// Default reason if not provided
	if req.Reason == "" {
		req.Reason = fmt.Sprintf("%s via HTTP API bulk operation", actionName)
	}

	return req.Constraint, req.Reason, nil
}

// handleBulkActionResults checks results and writes appropriate response for bulk operations
func (s *Server) handleBulkActionResults(w http.ResponseWriter, results *htcondor.JobActionResults, constraint, actionName string) {
	// Check results
	if results.TotalJobs == 0 {
		s.writeError(w, http.StatusNotFound, "No jobs matched the constraint")
		return
	}

	// Return success with statistics
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":    fmt.Sprintf("Bulk job %s completed", actionName),
		"constraint": constraint,
		"results": map[string]int{
			"total":             results.TotalJobs,
			"success":           results.Success,
			"not_found":         results.NotFound,
			"permission_denied": results.PermissionDenied,
			"bad_status":        results.BadStatus,
			"already_done":      results.AlreadyDone,
			"error":             results.Error,
		},
	})
}

// JobActionFunc is a function that performs a job action (hold, release, etc.)
type JobActionFunc func(ctx context.Context, constraint, reason string) (*htcondor.JobActionResults, error)

// handleBulkJobAction is a generic handler for bulk job actions (hold, release, etc.)
func (s *Server) handleBulkJobAction(w http.ResponseWriter, r *http.Request, actionName, actionVerb string, actionFunc JobActionFunc) {
	// Create authenticated context
	ctx, err := s.createAuthenticatedContext(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	// Parse request body
	constraint, reason, err := s.parseBulkActionRequest(r, actionName)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Perform action
	results, err := actionFunc(ctx, constraint, reason)
	if err != nil {
		// Check if it's an authentication error
		if isAuthenticationError(err) {
			s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Bulk job %s failed: %v", actionVerb, err))
		return
	}

	s.handleBulkActionResults(w, results, constraint, actionVerb)
}

// handleBulkHoldJobs handles POST /api/v1/jobs/hold with constraint-based bulk hold
func (s *Server) handleBulkHoldJobs(w http.ResponseWriter, r *http.Request) {
	s.handleBulkJobAction(w, r, "Held", "hold", s.getSchedd().HoldJobs)
}

// handleBulkReleaseJobs handles POST /api/v1/jobs/release with constraint-based bulk release
func (s *Server) handleBulkReleaseJobs(w http.ResponseWriter, r *http.Request) {
	s.handleBulkJobAction(w, r, "Released", "release", s.getSchedd().ReleaseJobs)
}

// handleJobInput handles PUT /api/v1/jobs/{id}/input
func (s *Server) handleJobInput(w http.ResponseWriter, r *http.Request, jobID string) {
	if r.Method != http.MethodPut {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Create authenticated context
	ctx, err := s.createAuthenticatedContext(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	// Parse job ID
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}

	// First, query for the job to get its proc ad with transfer attributes
	// We need transfer-related attributes for spooling to work
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	projection := []string{"ClusterId", "ProcId", "TransferInputFiles", "TransferInput"}
	jobAds, _, err := s.getSchedd().QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Projection: projection,
	})
	if err != nil {
		if ratelimit.IsRateLimitError(err) {
			s.writeError(w, http.StatusTooManyRequests, fmt.Sprintf("Rate limit exceeded: %v", err))
			return
		}
		if isAuthenticationError(err) {
			s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Query failed: %v", err))
		return
	}

	if len(jobAds) == 0 {
		s.writeError(w, http.StatusNotFound, "Job not found")
		return
	}

	// Read tarfile from request body
	// Note: We should limit the size to prevent abuse
	limitedReader := io.LimitReader(r.Body, 1024*1024*1024) // 1GB limit

	// Spool job files from tar
	err = s.getSchedd().SpoolJobFilesFromTar(ctx, jobAds, limitedReader)
	if err != nil {
		if isAuthenticationError(err) {
			s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to spool job files: %v", err))
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{
		"message": "Job input files uploaded successfully",
		"job_id":  jobID,
	})
}

// handleJobOutput handles GET /api/v1/jobs/{id}/output
func (s *Server) handleJobOutput(w http.ResponseWriter, r *http.Request, jobID string) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Create authenticated context
	ctx, err := s.createAuthenticatedContext(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	// Parse job ID
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}

	// Build constraint for specific job
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)

	// Set up response as tar stream
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"job-%s-output.tar\"", jobID))
	w.WriteHeader(http.StatusOK)

	// Start receiving job sandbox
	errChan := s.getSchedd().ReceiveJobSandbox(ctx, constraint, w)

	// Wait for transfer to complete
	if err := <-errChan; err != nil {
		// Error occurred, but we've already started writing the response
		// Log the error and the client will see an incomplete tar
		s.logger.Error(logging.DestinationSchedd, "Error receiving job sandbox", "job_id", jobID, "error", err)
		return
	}
}

// parseJobID parses a job ID string like "123.4" into cluster and proc
func parseJobID(jobID string) (cluster, proc int, err error) {
	parts := strings.Split(jobID, ".")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid job ID format, expected cluster.proc")
	}

	cluster, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid cluster ID: %w", err)
	}

	proc, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid proc ID: %w", err)
	}

	return cluster, proc, nil
}

// handleMetrics handles GET /metrics endpoint for Prometheus scraping
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.prometheusExporter == nil {
		s.writeError(w, http.StatusNotImplemented, "Metrics not enabled")
		return
	}

	ctx := r.Context()
	metricsText, err := s.prometheusExporter.Export(ctx)
	if err != nil {
		s.logger.Error(logging.DestinationMetrics, "Error exporting metrics", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to export metrics")
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(metricsText)); err != nil {
		s.logger.Error(logging.DestinationMetrics, "Error writing metrics response", "error", err)
	}
}

// handleHealthz handles GET /healthz endpoint for health checks
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Health check always returns OK if the server is running
	s.writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

// handleReadyz handles GET /readyz endpoint for readiness checks
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Readiness check returns OK if the server is ready to accept traffic
	// Currently just checks if the server is running, but could be extended
	// to check schedd connectivity or other dependencies
	s.writeJSON(w, http.StatusOK, map[string]string{
		"status": "ready",
	})
}

// parseJobActionRequest parses job ID and optional reason for single job actions
func (s *Server) parseJobActionRequest(r *http.Request, jobID, defaultAction string) (cluster, proc int, reason string, err error) {
	// Parse job ID
	cluster, proc, err = parseJobID(jobID)
	if err != nil {
		return 0, 0, "", fmt.Errorf("invalid job ID: %w", err)
	}

	// Parse optional reason from request body
	var req struct {
		Reason string `json:"reason,omitempty"`
	}
	if r.Body != nil && r.Body != http.NoBody {
		if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
			// If body can't be decoded, just use empty reason
			req.Reason = ""
		}
	}

	// Default reason if not provided
	if req.Reason == "" {
		req.Reason = fmt.Sprintf("%s via HTTP API", defaultAction)
	}

	return cluster, proc, req.Reason, nil
}

// handleJobActionResults checks results and writes response for single job actions
func (s *Server) handleJobActionResults(w http.ResponseWriter, results *htcondor.JobActionResults, jobID, actionName string) {
	// Check if job was found
	if results.NotFound > 0 {
		s.writeError(w, http.StatusNotFound, "Job not found")
		return
	}

	if results.Success == 0 {
		// Job exists but couldn't be acted upon
		msg := fmt.Sprintf("Failed to %s job", actionName)
		switch {
		case results.PermissionDenied > 0:
			msg = fmt.Sprintf("Permission denied to %s job", actionName)
		case results.BadStatus > 0:
			msg = fmt.Sprintf("Job in wrong status for %s", actionName)
		case results.AlreadyDone > 0:
			switch actionName {
			case "hold":
				msg = "Job is already held"
			case "release":
				msg = "Job is already released/not held"
			default:
				msg = fmt.Sprintf("Job action %s already done", actionName)
			}
		case results.Error > 0:
			msg = fmt.Sprintf("Error %s job", actionName+"ing")
		}
		s.writeError(w, http.StatusBadRequest, msg)
		return
	}

	// Success
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("Job %s successfully", actionName+"ed"),
		"job_id":  jobID,
		"results": map[string]int{
			"total":   results.TotalJobs,
			"success": results.Success,
		},
	})
}

// handleSingleJobAction is a generic handler for single job actions (hold, release, etc.)
func (s *Server) handleSingleJobAction(w http.ResponseWriter, r *http.Request, jobID, actionName, actionVerb string, actionFunc JobActionFunc) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Create authenticated context
	ctx, err := s.createAuthenticatedContext(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	// Parse job ID and reason
	cluster, proc, reason, err := s.parseJobActionRequest(r, jobID, actionName)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Build constraint for specific job
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)

	// Perform action
	results, err := actionFunc(ctx, constraint, reason)
	if err != nil {
		// Check if it's an authentication error
		if isAuthenticationError(err) {
			s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Job %s failed: %v", actionVerb, err))
		return
	}

	s.handleJobActionResults(w, results, jobID, actionVerb)
}

// handleJobHold handles POST /api/v1/jobs/{id}/hold
func (s *Server) handleJobHold(w http.ResponseWriter, r *http.Request, jobID string) {
	s.handleSingleJobAction(w, r, jobID, "Held", "hold", s.getSchedd().HoldJobs)
}

// handleJobRelease handles POST /api/v1/jobs/{id}/release
func (s *Server) handleJobRelease(w http.ResponseWriter, r *http.Request, jobID string) {
	s.handleSingleJobAction(w, r, jobID, "Released", "release", s.getSchedd().ReleaseJobs)
}

// CollectorAdsResponse represents collector ads listing response
type CollectorAdsResponse struct {
	Ads []*classad.ClassAd `json:"ads"`
}

// handleCollectorAds handles /api/v1/collector/ads endpoint
func (s *Server) handleCollectorAds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.collector == nil {
		s.writeError(w, http.StatusNotImplemented, "Collector not configured")
		return
	}

	ctx := r.Context()

	// Get query parameters
	constraint := r.URL.Query().Get("constraint")
	if constraint == "" {
		constraint = "true" // Default: all ads
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

	// Get effective projection if none specified
	if len(projection) == 0 {
		projection = htcondor.DefaultCollectorProjection()
	} else if len(projection) == 1 && projection[0] == "*" {
		projection = nil // nil means all attributes
	}

	// Start streaming query
	streamOpts := &htcondor.StreamOptions{
		BufferSize:   s.streamBufferSize,
		WriteTimeout: s.streamWriteTimeout,
	}
	resultCh, err := s.collector.QueryAdsStream(ctx, "StartdAd", constraint, projection, limit, streamOpts)
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

	// Stream ads as they arrive
	adCount := 0
	var errorMsg string
	for result := range resultCh {
		if result.Err != nil {
			// Error occurred - log it and close the response
			s.logger.Error(logging.DestinationHTTP, "Query streaming error", "error", result.Err)
			errorMsg = result.Err.Error()
			break
		}

		// Check limit
		if limit > 0 && adCount >= limit {
			break
		}

		// Marshal the ad
		adJSON, err := json.Marshal(result.Ad)
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to marshal ad", "error", err)
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
			s.logger.Error(logging.DestinationHTTP, "Failed to write ad", "error", err)
			return
		}

		adCount++

		// Flush after each ad for true streaming
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}

	// Close JSON array and add metadata
	metadata := fmt.Sprintf(`],"total_returned":%d`, adCount)

	// Add error if one occurred
	if errorMsg != "" {
		errJSON, _ := json.Marshal(errorMsg)
		metadata += fmt.Sprintf(`,"error":%s`, errJSON)
	}

	// Collector doesn't support pagination yet - hardcode has_more as false
	// TODO: When collector supports pagination, implement proper page token handling
	metadata += `,"has_more":false,"next_page_token":""`

	metadata += "}"

	if _, err := w.Write([]byte(metadata)); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to write response footer", "error", err)
	}
}

// handleCollectorAdsByType handles /api/v1/collector/ads/{adType} endpoint
//
//nolint:gocyclo // Complex function for handling collector ad streaming with multiple ad types and error cases
func (s *Server) handleCollectorAdsByType(w http.ResponseWriter, r *http.Request, adType string) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.collector == nil {
		s.writeError(w, http.StatusNotImplemented, "Collector not configured")
		return
	}

	ctx := r.Context()

	// Get query parameters
	constraint := r.URL.Query().Get("constraint")
	if constraint == "" {
		constraint = "true" // Default: all ads of this type
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

	// Get effective projection if none specified
	if len(projection) == 0 {
		projection = htcondor.DefaultCollectorProjection()
	} else if len(projection) == 1 && projection[0] == "*" {
		projection = nil // nil means all attributes
	}

	// Map common ad type names
	var queryAdType string
	switch strings.ToLower(adType) {
	case "all":
		// For "all", we'll query startd ads as a default
		// A more complete implementation would query all types and merge
		queryAdType = "StartdAd"
	case "startd", "machine", "machines":
		queryAdType = "StartdAd"
	case "schedd", "schedds":
		queryAdType = "ScheddAd"
	case "master", "masters":
		queryAdType = "MasterAd"
	case "submitter", "submitters":
		queryAdType = "SubmitterAd"
	case "negotiator", "negotiators":
		queryAdType = "NegotiatorAd"
	case "collector", "collectors":
		queryAdType = "CollectorAd"
	default:
		// Try to use the ad type as-is
		queryAdType = adType
	}

	// Start streaming query
	streamOpts := &htcondor.StreamOptions{
		BufferSize:   s.streamBufferSize,
		WriteTimeout: s.streamWriteTimeout,
	}
	resultCh, err := s.collector.QueryAdsStream(ctx, queryAdType, constraint, projection, limit, streamOpts)
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

	// Stream ads as they arrive
	adCount := 0
	var errorMsg string
	for result := range resultCh {
		if result.Err != nil {
			// Error occurred - log it and close the response
			s.logger.Error(logging.DestinationHTTP, "Query streaming error", "error", result.Err, "adType", adType)
			errorMsg = result.Err.Error()
			break
		}

		// Check limit
		if limit > 0 && adCount >= limit {
			break
		}

		// Marshal the ad
		adJSON, err := json.Marshal(result.Ad)
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to marshal ad", "error", err)
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
			s.logger.Error(logging.DestinationHTTP, "Failed to write ad", "error", err)
			return
		}

		adCount++

		// Flush after each ad for true streaming
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}

	// Close JSON array and add metadata
	metadata := fmt.Sprintf(`],"total_returned":%d`, adCount)

	// Add error if one occurred
	if errorMsg != "" {
		errJSON, _ := json.Marshal(errorMsg)
		metadata += fmt.Sprintf(`,"error":%s`, errJSON)
	}

	// Collector doesn't support pagination yet - hardcode has_more as false
	// TODO: When collector supports pagination, implement proper page token handling
	metadata += `,"has_more":false,"next_page_token":""`

	metadata += "}"

	if _, err := w.Write([]byte(metadata)); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to write response footer", "error", err)
	}
}

// handleCollectorAdByName handles /api/v1/collector/ads/{adType}/{name} endpoint
func (s *Server) handleCollectorAdByName(w http.ResponseWriter, r *http.Request, adType, name string) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.collector == nil {
		s.writeError(w, http.StatusNotImplemented, "Collector not configured")
		return
	}

	ctx := r.Context()

	// Map ad type
	var queryAdType string
	var nameAttr string
	switch strings.ToLower(adType) {
	case "startd", "machine", "machines":
		queryAdType = "StartdAd"
		nameAttr = "Name"
	case "schedd", "schedds":
		queryAdType = "ScheddAd"
		nameAttr = "Name"
	case "master", "masters":
		queryAdType = "MasterAd"
		nameAttr = "Name"
	case "submitter", "submitters":
		queryAdType = "SubmitterAd"
		nameAttr = "Name"
	case "negotiator", "negotiators":
		queryAdType = "NegotiatorAd"
		nameAttr = "Name"
	case "collector", "collectors":
		queryAdType = "CollectorAd"
		nameAttr = "Name"
	default:
		queryAdType = adType
		nameAttr = "Name"
	}

	// Get projection parameter
	projectionStr := r.URL.Query().Get("projection")
	var projection []string
	if projectionStr != "" {
		projection = strings.Split(projectionStr, ",")
		for i := range projection {
			projection[i] = strings.TrimSpace(projection[i])
		}
	}

	// Build constraint for specific ad by name
	constraint := fmt.Sprintf("%s == %q", nameAttr, name)

	// Query collector
	ads, _, err := s.collector.QueryAdsWithOptions(ctx, queryAdType, constraint, &htcondor.QueryOptions{Projection: projection})
	if err != nil {
		if ratelimit.IsRateLimitError(err) {
			s.writeError(w, http.StatusTooManyRequests, fmt.Sprintf("Rate limit exceeded: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Query failed: %v", err))
		return
	}

	if len(ads) == 0 {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Ad not found: %s/%s", adType, name))
		return
	}

	// Return the first matching ad
	s.writeJSON(w, http.StatusOK, ads[0])
}

// handleJobStdout handles GET /api/v1/jobs/{cluster}.{proc}/stdout
func (s *Server) handleJobStdout(w http.ResponseWriter, r *http.Request, cluster, proc int) {
	s.handleJobOutputFile(w, r, cluster, proc, "stdout", "Out")
}

// handleJobStderr handles GET /api/v1/jobs/{cluster}.{proc}/stderr
func (s *Server) handleJobStderr(w http.ResponseWriter, r *http.Request, cluster, proc int) {
	s.handleJobOutputFile(w, r, cluster, proc, "stderr", "Err")
}

// handleJobOutputFile is a helper function to retrieve stdout or stderr from a job
func (s *Server) handleJobOutputFile(w http.ResponseWriter, r *http.Request, cluster, proc int, outputType, attributeName string) {
	ctx := r.Context()

	// Query the job to get the output filename
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	projection := []string{"ClusterId", "ProcId", "JobStatus", attributeName}

	opts := &htcondor.QueryOptions{
		Projection: projection,
	}
	jobAds, _, err := s.schedd.QueryWithOptions(ctx, constraint, opts)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to query job", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to query job")
		return
	}

	if len(jobAds) == 0 {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Job not found: %d.%d", cluster, proc))
		return
	}

	jobAd := jobAds[0]

	// Get the output filename from the job ad
	outputFileExpr, ok := jobAd.Lookup(attributeName)
	if !ok {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Job does not have %s configured", outputType))
		return
	}

	outputFile, err := outputFileExpr.Eval(nil).StringValue()
	if err != nil || outputFile == "" {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Job %s attribute is empty or invalid", outputType))
		return
	}

	// Download the job sandbox
	sandboxCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var sandboxBuf bytes.Buffer
	errChan := s.schedd.ReceiveJobSandbox(sandboxCtx, constraint, &sandboxBuf)

	if err := <-errChan; err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to download job sandbox", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to download job sandbox")
		return
	}

	// Extract the output file from the tar archive
	tarReader := tar.NewReader(&sandboxBuf)
	var outputContent string

	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to read tar archive", "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to read tar archive")
			return
		}

		// Check if this is the output file we're looking for
		baseName := filepath.Base(header.Name)
		if baseName == outputFile {
			content, err := io.ReadAll(tarReader)
			if err != nil {
				s.logger.Error(logging.DestinationHTTP, "Failed to read output content", "error", err)
				s.writeError(w, http.StatusInternalServerError, "Failed to read output content")
				return
			}
			outputContent = string(content)
			break
		}
	}

	if outputContent == "" {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("%s file not found in job sandbox", outputType))
		return
	}

	// Return the output as plain text
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(outputContent))
}

// handleCollectorPath handles /api/v1/collector/* paths with routing
func (s *Server) handleCollectorPath(w http.ResponseWriter, r *http.Request) {
	// Strip /api/v1/collector/ prefix
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/collector/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		s.writeError(w, http.StatusNotFound, "Collector endpoint not found")
		return
	}

	// Route based on path structure
	switch {
	case parts[0] == "ads" && len(parts) == 1:
		// GET /api/v1/collector/ads
		s.handleCollectorAds(w, r)
	case parts[0] == "ads" && len(parts) == 2:
		// GET /api/v1/collector/ads/{adType}
		s.handleCollectorAdsByType(w, r, parts[1])
	case parts[0] == "ads" && len(parts) == 3:
		// GET /api/v1/collector/ads/{adType}/{name}
		s.handleCollectorAdByName(w, r, parts[1], parts[2])
	case parts[0] == "ads":
		s.writeError(w, http.StatusNotFound, "Invalid collector path")
	case parts[0] == "ping" && len(parts) == 1:
		// GET /api/v1/collector/ping
		s.handleCollectorPing(w, r)
	default:
		s.writeError(w, http.StatusNotFound, "Collector endpoint not found")
	}
}

// PingResponse represents a ping response for a daemon
type PingResponse struct {
	Daemon         string `json:"daemon"`               // "collector" or "schedd"
	AuthMethod     string `json:"auth_method"`          // Authentication method used
	User           string `json:"user"`                 // Authenticated username
	SessionID      string `json:"session_id"`           // Session identifier
	ValidCommands  string `json:"valid_commands"`       // Commands authorized
	Encryption     bool   `json:"encryption"`           // Whether encryption is enabled
	Authentication bool   `json:"authentication"`       // Whether authentication is enabled
	Authorized     bool   `json:"authorized,omitempty"` // Whether authorized for requested permission (if permission checked)
	Permission     string `json:"permission,omitempty"` // Permission level checked (if any)
}

// handleCollectorPing handles GET /api/v1/collector/ping
func (s *Server) handleCollectorPing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.collector == nil {
		s.writeError(w, http.StatusNotImplemented, "Collector not configured")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	result, err := s.collector.Ping(ctx)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Ping failed: %v", err))
		return
	}

	response := PingResponse{
		Daemon:         "collector",
		AuthMethod:     result.AuthMethod,
		User:           result.User,
		SessionID:      result.SessionID,
		ValidCommands:  result.ValidCommands,
		Encryption:     result.Encryption,
		Authentication: result.Authentication,
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleScheddPing handles GET /api/v1/schedd/ping
func (s *Server) handleScheddPing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	result, err := s.schedd.Ping(ctx)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Ping failed: %v", err))
		return
	}

	response := PingResponse{
		Daemon:         "schedd",
		AuthMethod:     result.AuthMethod,
		User:           result.User,
		SessionID:      result.SessionID,
		ValidCommands:  result.ValidCommands,
		Encryption:     result.Encryption,
		Authentication: result.Authentication,
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handlePing handles GET /api/v1/ping to ping both collector and schedd
func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	response := make(map[string]interface{})

	// Ping collector if configured
	if s.collector != nil {
		collectorResult, err := s.collector.Ping(ctx)
		if err != nil {
			response["collector"] = map[string]interface{}{
				"status": "error",
				"error":  err.Error(),
			}
		} else {
			response["collector"] = PingResponse{
				Daemon:         "collector",
				AuthMethod:     collectorResult.AuthMethod,
				User:           collectorResult.User,
				SessionID:      collectorResult.SessionID,
				ValidCommands:  collectorResult.ValidCommands,
				Encryption:     collectorResult.Encryption,
				Authentication: collectorResult.Authentication,
			}
		}
	}

	// Ping schedd
	scheddResult, err := s.schedd.Ping(ctx)
	if err != nil {
		response["schedd"] = map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		}
	} else {
		response["schedd"] = PingResponse{
			Daemon:         "schedd",
			AuthMethod:     scheddResult.AuthMethod,
			User:           scheddResult.User,
			SessionID:      scheddResult.SessionID,
			ValidCommands:  scheddResult.ValidCommands,
			Encryption:     scheddResult.Encryption,
			Authentication: scheddResult.Authentication,
		}
	}

	s.writeJSON(w, http.StatusOK, response)
}
