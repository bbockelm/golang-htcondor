package httpserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

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

	projectionStr := r.URL.Query().Get("projection")
	var projection []string
	if projectionStr != "" {
		projection = strings.Split(projectionStr, ",")
		for i := range projection {
			projection[i] = strings.TrimSpace(projection[i])
		}
	}

	// Query schedd
	jobAds, err := s.schedd.Query(ctx, constraint, projection)
	if err != nil {
		// Check if it's a rate limit error
		if strings.Contains(err.Error(), "rate limit") {
			s.writeError(w, http.StatusTooManyRequests, fmt.Sprintf("Rate limit exceeded: %v", err))
			return
		}
		// Check if it's an authentication error
		if strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "security") {
			s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Query failed: %v", err))
		return
	}

	// Return ClassAds directly - they have MarshalJSON method
	s.writeJSON(w, http.StatusOK, JobListResponse{Jobs: jobAds})
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
	clusterID, procAds, err := s.schedd.SubmitRemote(ctx, req.SubmitFile)
	if err != nil {
		// Check if it's an authentication error
		if strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "security") {
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

	// Check if this is a sandbox operation or job action
	if len(parts) == 2 {
		switch parts[1] {
		case "input":
			s.handleJobInput(w, r, jobID)
			return
		case "output":
			s.handleJobOutput(w, r, jobID)
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

	// Query for the specific job
	jobAds, err := s.schedd.Query(ctx, constraint, nil)
	if err != nil {
		if strings.Contains(err.Error(), "rate limit") {
			s.writeError(w, http.StatusTooManyRequests, fmt.Sprintf("Rate limit exceeded: %v", err))
			return
		}
		if strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "security") {
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
	results, err := s.schedd.RemoveJobs(ctx, constraint, "Removed via HTTP API")
	if err != nil {
		// Check if it's an authentication error
		if strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "security") {
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

	if err := s.schedd.EditJob(ctx, cluster, proc, attributes, opts); err != nil {
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
	results, err := s.schedd.RemoveJobs(ctx, req.Constraint, req.Reason)
	if err != nil {
		// Check if it's an authentication error
		if strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "security") {
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
	count, err := s.schedd.EditJobs(ctx, req.Constraint, attributes, opts)
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

// handleBulkHoldJobs handles POST /api/v1/jobs/hold with constraint-based bulk hold
func (s *Server) handleBulkHoldJobs(w http.ResponseWriter, r *http.Request) {
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
		s.writeError(w, http.StatusBadRequest, "Constraint is required for bulk hold")
		return
	}

	// Default reason if not provided
	if req.Reason == "" {
		req.Reason = "Held via HTTP API bulk operation"
	}

	// Hold jobs by constraint
	results, err := s.schedd.HoldJobs(ctx, req.Constraint, req.Reason)
	if err != nil {
		// Check if it's an authentication error
		if strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "security") {
			s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Bulk job hold failed: %v", err))
		return
	}

	// Check results
	if results.TotalJobs == 0 {
		s.writeError(w, http.StatusNotFound, "No jobs matched the constraint")
		return
	}

	// Return success with statistics
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":    "Bulk job hold completed",
		"constraint": req.Constraint,
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

// handleBulkReleaseJobs handles POST /api/v1/jobs/release with constraint-based bulk release
func (s *Server) handleBulkReleaseJobs(w http.ResponseWriter, r *http.Request) {
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
		s.writeError(w, http.StatusBadRequest, "Constraint is required for bulk release")
		return
	}

	// Default reason if not provided
	if req.Reason == "" {
		req.Reason = "Released via HTTP API bulk operation"
	}

	// Release jobs by constraint
	results, err := s.schedd.ReleaseJobs(ctx, req.Constraint, req.Reason)
	if err != nil {
		// Check if it's an authentication error
		if strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "security") {
			s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Bulk job release failed: %v", err))
		return
	}

	// Check results
	if results.TotalJobs == 0 {
		s.writeError(w, http.StatusNotFound, "No jobs matched the constraint")
		return
	}

	// Return success with statistics
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":    "Bulk job release completed",
		"constraint": req.Constraint,
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

	// First, query for the job to get its proc ad
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	jobAds, err := s.schedd.Query(ctx, constraint, nil)
	if err != nil {
		if strings.Contains(err.Error(), "rate limit") {
			s.writeError(w, http.StatusTooManyRequests, fmt.Sprintf("Rate limit exceeded: %v", err))
			return
		}
		if strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "security") {
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
	err = s.schedd.SpoolJobFilesFromTar(ctx, jobAds, limitedReader)
	if err != nil {
		if strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "security") {
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
	errChan := s.schedd.ReceiveJobSandbox(ctx, constraint, w)

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

// handleJobHold handles POST /api/v1/jobs/{id}/hold
func (s *Server) handleJobHold(w http.ResponseWriter, r *http.Request, jobID string) {
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

	// Parse job ID
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}

	// Parse optional reason from request body
	var req struct {
		Reason string `json:"reason,omitempty"`
	}
	if r.Body != nil && r.Body != http.NoBody {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// If body can't be decoded, just use empty reason
			req.Reason = ""
		}
	}

	// Default reason if not provided
	if req.Reason == "" {
		req.Reason = "Held via HTTP API"
	}

	// Build constraint for specific job
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)

	// Hold the job
	results, err := s.schedd.HoldJobs(ctx, constraint, req.Reason)
	if err != nil {
		// Check if it's an authentication error
		if strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "security") {
			s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Job hold failed: %v", err))
		return
	}

	// Check if job was found
	if results.NotFound > 0 {
		s.writeError(w, http.StatusNotFound, "Job not found")
		return
	}

	if results.Success == 0 {
		// Job exists but couldn't be held
		msg := "Failed to hold job"
		switch {
		case results.PermissionDenied > 0:
			msg = "Permission denied to hold job"
		case results.BadStatus > 0:
			msg = "Job in wrong status for hold"
		case results.AlreadyDone > 0:
			msg = "Job is already held"
		case results.Error > 0:
			msg = "Error holding job"
		}
		s.writeError(w, http.StatusBadRequest, msg)
		return
	}

	// Success
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Job held successfully",
		"job_id":  jobID,
		"results": map[string]int{
			"total":   results.TotalJobs,
			"success": results.Success,
		},
	})
}

// handleJobRelease handles POST /api/v1/jobs/{id}/release
func (s *Server) handleJobRelease(w http.ResponseWriter, r *http.Request, jobID string) {
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

	// Parse job ID
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}

	// Parse optional reason from request body
	var req struct {
		Reason string `json:"reason,omitempty"`
	}
	if r.Body != nil && r.Body != http.NoBody {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// If body can't be decoded, just use empty reason
			req.Reason = ""
		}
	}

	// Default reason if not provided
	if req.Reason == "" {
		req.Reason = "Released via HTTP API"
	}

	// Build constraint for specific job
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)

	// Release the job
	results, err := s.schedd.ReleaseJobs(ctx, constraint, req.Reason)
	if err != nil {
		// Check if it's an authentication error
		if strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "security") {
			s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Job release failed: %v", err))
		return
	}

	// Check if job was found
	if results.NotFound > 0 {
		s.writeError(w, http.StatusNotFound, "Job not found")
		return
	}

	if results.Success == 0 {
		// Job exists but couldn't be released
		msg := "Failed to release job"
		switch {
		case results.PermissionDenied > 0:
			msg = "Permission denied to release job"
		case results.BadStatus > 0:
			msg = "Job in wrong status for release"
		case results.AlreadyDone > 0:
			msg = "Job is already released/not held"
		case results.Error > 0:
			msg = "Error releasing job"
		}
		s.writeError(w, http.StatusBadRequest, msg)
		return
	}

	// Success
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Job released successfully",
		"job_id":  jobID,
		"results": map[string]int{
			"total":   results.TotalJobs,
			"success": results.Success,
		},
	})
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

	// Get projection parameter
	projectionStr := r.URL.Query().Get("projection")
	var projection []string
	if projectionStr != "" {
		projection = strings.Split(projectionStr, ",")
		for i := range projection {
			projection[i] = strings.TrimSpace(projection[i])
		}
	}

	// Query collector for all ads (using "Machine" which queries STARTD ads)
	// In a more complete implementation, we'd query all ad types
	ads, err := s.collector.QueryAdsWithProjection(ctx, "StartdAd", constraint, projection)
	if err != nil {
		if strings.Contains(err.Error(), "rate limit") {
			s.writeError(w, http.StatusTooManyRequests, fmt.Sprintf("Rate limit exceeded: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Query failed: %v", err))
		return
	}

	s.writeJSON(w, http.StatusOK, CollectorAdsResponse{Ads: ads})
}

// handleCollectorAdsByType handles /api/v1/collector/ads/{adType} endpoint
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

	// Get projection parameter
	projectionStr := r.URL.Query().Get("projection")
	var projection []string
	if projectionStr != "" {
		projection = strings.Split(projectionStr, ",")
		for i := range projection {
			projection[i] = strings.TrimSpace(projection[i])
		}
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

	// Query collector
	ads, err := s.collector.QueryAdsWithProjection(ctx, queryAdType, constraint, projection)
	if err != nil {
		if strings.Contains(err.Error(), "rate limit") {
			s.writeError(w, http.StatusTooManyRequests, fmt.Sprintf("Rate limit exceeded: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Query failed: %v", err))
		return
	}

	s.writeJSON(w, http.StatusOK, CollectorAdsResponse{Ads: ads})
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
	ads, err := s.collector.QueryAdsWithProjection(ctx, queryAdType, constraint, projection)
	if err != nil {
		if strings.Contains(err.Error(), "rate limit") {
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
	if parts[0] == "ads" {
		if len(parts) == 1 {
			// GET /api/v1/collector/ads
			s.handleCollectorAds(w, r)
		} else if len(parts) == 2 {
			// GET /api/v1/collector/ads/{adType}
			s.handleCollectorAdsByType(w, r, parts[1])
		} else if len(parts) == 3 {
			// GET /api/v1/collector/ads/{adType}/{name}
			s.handleCollectorAdByName(w, r, parts[1], parts[2])
		} else {
			s.writeError(w, http.StatusNotFound, "Invalid collector path")
		}
	} else {
		s.writeError(w, http.StatusNotFound, "Collector endpoint not found")
	}
}

// handleJobsPath handles /api/v1/jobs/* paths with routing for bulk operations
func (s *Server) handleJobsPath(w http.ResponseWriter, r *http.Request) {
	// Strip /api/v1/jobs/ prefix
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/jobs/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		s.writeError(w, http.StatusNotFound, "Jobs endpoint not found")
		return
	}

	// Check for bulk hold/release operations
	if parts[0] == "hold" && len(parts) == 1 {
		// POST /api/v1/jobs/hold
		if r.Method == http.MethodPost {
			s.handleBulkHoldJobs(w, r)
		} else {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
		return
	}

	if parts[0] == "release" && len(parts) == 1 {
		// POST /api/v1/jobs/release
		if r.Method == http.MethodPost {
			s.handleBulkReleaseJobs(w, r)
		} else {
			s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
		return
	}

	// Otherwise, treat as job ID path
	s.handleJobByID(w, r)
}
