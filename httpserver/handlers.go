package httpserver

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
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
	Jobs []map[string]interface{} `json:"jobs"`
}

// handleJobs handles /api/v1/jobs endpoint (GET for list, POST for submit)
func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListJobs(w, r)
	case http.MethodPost:
		s.handleSubmitJob(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleListJobs handles GET /api/v1/jobs
func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	// Extract bearer token or generate from user header
	token, err := s.extractOrGenerateToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Missing or invalid bearer token")
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

	// Create context with token for authentication
	// TODO: Properly integrate token into schedd authentication
	ctx := WithToken(r.Context(), token)

	// Query schedd
	jobAds, err := s.schedd.Query(ctx, constraint, projection)
	if err != nil {
		// Check if it's an authentication error
		if strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "security") {
			writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Query failed: %v", err))
		return
	}

	// Convert ClassAds to JSON-friendly format
	jobs := make([]map[string]interface{}, len(jobAds))
	for i, ad := range jobAds {
		jobs[i] = classAdToMap(ad)
	}

	writeJSON(w, http.StatusOK, JobListResponse{Jobs: jobs})
}

// handleSubmitJob handles POST /api/v1/jobs
func (s *Server) handleSubmitJob(w http.ResponseWriter, r *http.Request) {
	// Extract bearer token or generate from user header
	token, err := s.extractOrGenerateToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Missing or invalid bearer token")
		return
	}

	// Parse request body
	var req JobSubmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}

	if req.SubmitFile == "" {
		writeError(w, http.StatusBadRequest, "submit_file is required")
		return
	}

	// Create context with token for authentication
	// TODO: Properly integrate token into schedd authentication
	ctx := WithToken(r.Context(), token)

	// Submit job using SubmitRemote
	clusterID, procAds, err := s.schedd.SubmitRemote(ctx, req.SubmitFile)
	if err != nil {
		// Check if it's an authentication error
		if strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "security") {
			writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Job submission failed: %v", err))
		return
	}

	// Build job IDs list
	jobIDs := make([]string, len(procAds))
	for i, ad := range procAds {
		cluster, _ := ad.EvaluateAttrInt("ClusterId")
		proc, _ := ad.EvaluateAttrInt("ProcId")
		jobIDs[i] = fmt.Sprintf("%d.%d", cluster, proc)
	}

	writeJSON(w, http.StatusCreated, JobSubmitResponse{
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
		writeError(w, http.StatusNotFound, "Job ID required")
		return
	}

	jobID := parts[0]

	// Check if this is a sandbox operation
	if len(parts) == 2 {
		switch parts[1] {
		case "input":
			s.handleJobInput(w, r, jobID)
			return
		case "output":
			s.handleJobOutput(w, r, jobID)
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
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleGetJob handles GET /api/v1/jobs/{id}
func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request, jobID string) {
	// Extract bearer token or generate from user header
	token, err := s.extractOrGenerateToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Missing or invalid bearer token")
		return
	}

	// Parse job ID
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}

	// Build constraint for specific job
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)

	// Create context with token
	// TODO: Properly integrate token into schedd authentication
	ctx := WithToken(r.Context(), token)

	// Query for the specific job
	jobAds, err := s.schedd.Query(ctx, constraint, nil)
	if err != nil {
		if strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "security") {
			writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Query failed: %v", err))
		return
	}

	if len(jobAds) == 0 {
		writeError(w, http.StatusNotFound, "Job not found")
		return
	}

	// Return the job ClassAd as JSON
	writeJSON(w, http.StatusOK, classAdToMap(jobAds[0]))
}

// handleDeleteJob handles DELETE /api/v1/jobs/{id}
func (s *Server) handleDeleteJob(w http.ResponseWriter, r *http.Request, jobID string) {
	// Extract bearer token or generate from user header
	token, err := s.extractOrGenerateToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Missing or invalid bearer token")
		return
	}

	// Parse job ID
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}

	// Create context with token
	// TODO: Properly integrate token into schedd authentication
	ctx := WithToken(r.Context(), token)

	// TODO: Implement job removal using schedd.Act() or similar API
	// This requires implementing the job action API in the base library
	_ = ctx
	_ = cluster
	_ = proc

	writeError(w, http.StatusNotImplemented, "Job removal not yet implemented - requires schedd.Act() API")
}

// handleEditJob handles PATCH /api/v1/jobs/{id}
func (s *Server) handleEditJob(w http.ResponseWriter, r *http.Request, jobID string) {
	// Extract bearer token or generate from user header
	token, err := s.extractOrGenerateToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Missing or invalid bearer token")
		return
	}

	// Parse job ID
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}

	// Parse request body with attributes to edit
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}

	// Create context with token
	// TODO: Properly integrate token into schedd authentication
	ctx := WithToken(r.Context(), token)

	// TODO: Implement job editing using schedd QMGMT API
	// This requires implementing the job edit API in the base library
	_ = ctx
	_ = cluster
	_ = proc
	_ = updates

	writeError(w, http.StatusNotImplemented, "Job editing not yet implemented - requires QMGMT edit API")
}

// handleJobInput handles PUT /api/v1/jobs/{id}/input
func (s *Server) handleJobInput(w http.ResponseWriter, r *http.Request, jobID string) {
	if r.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract bearer token or generate from user header
	token, err := s.extractOrGenerateToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Missing or invalid bearer token")
		return
	} // Parse job ID
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}

	// First, query for the job to get its proc ad
	// TODO: Properly integrate token into schedd authentication
	ctx := WithToken(r.Context(), token)
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	jobAds, err := s.schedd.Query(ctx, constraint, nil)
	if err != nil {
		if strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "security") {
			writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Query failed: %v", err))
		return
	}

	if len(jobAds) == 0 {
		writeError(w, http.StatusNotFound, "Job not found")
		return
	}

	// Read tarfile from request body
	// Note: We should limit the size to prevent abuse
	limitedReader := io.LimitReader(r.Body, 1024*1024*1024) // 1GB limit

	// Spool job files from tar
	err = s.schedd.SpoolJobFilesFromTar(ctx, jobAds, limitedReader)
	if err != nil {
		if strings.Contains(err.Error(), "authentication") || strings.Contains(err.Error(), "security") {
			writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to spool job files: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Job input files uploaded successfully",
		"job_id":  jobID,
	})
}

// handleJobOutput handles GET /api/v1/jobs/{id}/output
func (s *Server) handleJobOutput(w http.ResponseWriter, r *http.Request, jobID string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract bearer token or generate from user header
	token, err := s.extractOrGenerateToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Missing or invalid bearer token")
		return
	} // Parse job ID
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}

	// Build constraint for specific job
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)

	// Create context with token
	// TODO: Properly integrate token into schedd authentication
	ctx := WithToken(r.Context(), token)

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
		log.Printf("Error receiving job sandbox for %s: %v", jobID, err)
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
		return 0, 0, fmt.Errorf("invalid cluster ID: %v", err)
	}

	proc, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid proc ID: %v", err)
	}

	return cluster, proc, nil
}

// classAdToMap converts a ClassAd to a map for JSON serialization
func classAdToMap(ad *classad.ClassAd) map[string]interface{} {
	result := make(map[string]interface{})

	// Iterate through all attributes in the ClassAd using GetAttributes()
	for _, attr := range ad.GetAttributes() {
		// Use EvaluateAttr to get the evaluated value directly
		val := ad.EvaluateAttr(attr)
		result[attr] = convertClassAdValue(val)
	}

	return result
}

// convertClassAdValue converts a ClassAd value to a JSON-friendly type
func convertClassAdValue(val interface{}) interface{} {
	switch v := val.(type) {
	case *classad.ClassAd:
		return classAdToMap(v)
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = convertClassAdValue(item)
		}
		return result
	default:
		return v
	}
}
