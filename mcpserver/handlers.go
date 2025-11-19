// Package mcpserver implements the Model Context Protocol (MCP) server for HTCondor.
package mcpserver

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/golang-jwt/jwt/v5"
)

// Tool represents an MCP tool definition
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// Resource represents an MCP resource
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType,omitempty"`
}

// handleListTools returns the list of available tools
func (s *Server) handleListTools(_ context.Context, _ json.RawMessage) interface{} {
	tools := []Tool{
		{
			Name:        "submit_job",
			Description: "Submit an HTCondor job using a submit file",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"submit_file": map[string]interface{}{
						"type":        "string",
						"description": "HTCondor submit file content",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Authentication token (optional)",
					},
				},
				"required": []string{"submit_file"},
			},
		},
		{
			Name:        "query_jobs",
			Description: "Query HTCondor jobs with optional constraints, projections, and pagination",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"constraint": map[string]interface{}{
						"type":        "string",
						"description": "ClassAd constraint expression (default: 'true' for all jobs)",
					},
					"projection": map[string]interface{}{
						"type":        "array",
						"description": "List of attributes to include in results. Use ['*'] for all attributes. Default is a limited set of common attributes.",
						"items": map[string]interface{}{
							"type": "string",
						},
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of results to return (default: 50). Use -1 for unlimited.",
					},
					"page_token": map[string]interface{}{
						"type":        "string",
						"description": "Page token for pagination. When a query returns 'has_more': true, use the 'next_page_token' value from the response to fetch the next page of results. The token encodes the position (ClusterId.ProcId) of the last job in the current page, and subsequent queries will return jobs that come after this position. Leave empty for the first page.",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Authentication token (optional)",
					},
				},
			},
		},
		{
			Name:        "get_job",
			Description: "Get details of a specific HTCondor job by ID",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"job_id": map[string]interface{}{
						"type":        "string",
						"description": "Job ID in format 'cluster.proc' (e.g., '123.0')",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Authentication token (optional)",
					},
				},
				"required": []string{"job_id"},
			},
		},
		{
			Name:        "remove_job",
			Description: "Remove (delete) a specific HTCondor job",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"job_id": map[string]interface{}{
						"type":        "string",
						"description": "Job ID in format 'cluster.proc' (e.g., '123.0')",
					},
					"reason": map[string]interface{}{
						"type":        "string",
						"description": "Reason for removal (optional)",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Authentication token (optional)",
					},
				},
				"required": []string{"job_id"},
			},
		},
		{
			Name:        "remove_jobs",
			Description: "Remove multiple HTCondor jobs matching a constraint",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"constraint": map[string]interface{}{
						"type":        "string",
						"description": "ClassAd constraint to select jobs to remove",
					},
					"reason": map[string]interface{}{
						"type":        "string",
						"description": "Reason for removal (optional)",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Authentication token (optional)",
					},
				},
				"required": []string{"constraint"},
			},
		},
		{
			Name:        "edit_job",
			Description: "Edit attributes of a specific HTCondor job",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"job_id": map[string]interface{}{
						"type":        "string",
						"description": "Job ID in format 'cluster.proc' (e.g., '123.0')",
					},
					"attributes": map[string]interface{}{
						"type":        "object",
						"description": "Attributes to update as key-value pairs",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Authentication token (optional)",
					},
				},
				"required": []string{"job_id", "attributes"},
			},
		},
		{
			Name:        "hold_job",
			Description: "Hold a specific HTCondor job",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"job_id": map[string]interface{}{
						"type":        "string",
						"description": "Job ID in format 'cluster.proc' (e.g., '123.0')",
					},
					"reason": map[string]interface{}{
						"type":        "string",
						"description": "Reason for holding (optional)",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Authentication token (optional)",
					},
				},
				"required": []string{"job_id"},
			},
		},
		{
			Name:        "release_job",
			Description: "Release a held HTCondor job",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"job_id": map[string]interface{}{
						"type":        "string",
						"description": "Job ID in format 'cluster.proc' (e.g., '123.0')",
					},
					"reason": map[string]interface{}{
						"type":        "string",
						"description": "Reason for release (optional)",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Authentication token (optional)",
					},
				},
				"required": []string{"job_id"},
			},
		},
		{
			Name:        "get_job_stdout",
			Description: "Get stdout (output) from a completed or running HTCondor job",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"job_id": map[string]interface{}{
						"type":        "string",
						"description": "Job ID in format 'cluster.proc' (e.g., '123.0')",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Authentication token (optional)",
					},
				},
				"required": []string{"job_id"},
			},
		},
		{
			Name:        "get_job_stderr",
			Description: "Get stderr (error output) from a completed or running HTCondor job",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"job_id": map[string]interface{}{
						"type":        "string",
						"description": "Job ID in format 'cluster.proc' (e.g., '123.0')",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Authentication token (optional)",
					},
				},
				"required": []string{"job_id"},
			},
		},
	}

	return map[string]interface{}{
		"tools": tools,
	}
}

// handleCallTool executes a tool call
func (s *Server) handleCallTool(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var request struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}

	if err := json.Unmarshal(params, &request); err != nil {
		return nil, fmt.Errorf("invalid tool call params: %w", err)
	}

	// Create context with security config if token provided
	token, _ := request.Arguments["token"].(string)
	var username string
	if token != "" {
		secConfig := &security.SecurityConfig{
			AuthMethods:    []security.AuthMethod{security.AuthToken},
			Authentication: security.SecurityRequired,
			CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
			Encryption:     security.SecurityOptional,
			Integrity:      security.SecurityOptional,
			Token:          token,
		}
		ctx = htcondor.WithSecurityConfig(ctx, secConfig)

		// Check if token is already validated
		username = s.getValidatedUsername(token)
		if username != "" {
			// Use cached validated username for rate limiting
			ctx = htcondor.WithAuthenticatedUser(ctx, username)
		}
		// If not validated, treat as unauthenticated for rate limiting
		// Token will be validated on first successful operation
	}

	// Route to appropriate handler
	var result interface{}
	var err error
	switch request.Name {
	case "submit_job":
		result, err = s.toolSubmitJob(ctx, request.Arguments)
	case "query_jobs":
		result, err = s.toolQueryJobs(ctx, request.Arguments)
	case "get_job":
		result, err = s.toolGetJob(ctx, request.Arguments)
	case "remove_job":
		result, err = s.toolRemoveJob(ctx, request.Arguments)
	case "remove_jobs":
		result, err = s.toolRemoveJobs(ctx, request.Arguments)
	case "edit_job":
		result, err = s.toolEditJob(ctx, request.Arguments)
	case "hold_job":
		result, err = s.toolHoldJob(ctx, request.Arguments)
	case "release_job":
		result, err = s.toolReleaseJob(ctx, request.Arguments)
	case "get_job_stdout":
		result, err = s.toolGetJobStdout(ctx, request.Arguments)
	case "get_job_stderr":
		result, err = s.toolGetJobStderr(ctx, request.Arguments)
	default:
		return nil, fmt.Errorf("unknown tool: %s", request.Name)
	}

	// If operation succeeded and token was provided but not yet validated, mark it as validated
	if err == nil && token != "" && username == "" {
		// Parse username and expiration from token in a single call
		if extractedUsername, expiration, parseErr := parseJWTClaims(token); parseErr == nil {
			s.markTokenValidated(token, extractedUsername, expiration)
		}
	}

	return result, err
}

// toolSubmitJob handles job submission
func (s *Server) toolSubmitJob(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	submitFile, ok := args["submit_file"].(string)
	if !ok || submitFile == "" {
		return nil, fmt.Errorf("submit_file is required")
	}

	clusterID, procAds, err := s.schedd.SubmitRemote(ctx, submitFile)
	if err != nil {
		return nil, fmt.Errorf("job submission failed: %w", err)
	}

	// Build job IDs list
	jobIDs := make([]string, len(procAds))
	for i, ad := range procAds {
		cluster, _ := ad.EvaluateAttrInt("ClusterId")
		proc, _ := ad.EvaluateAttrInt("ProcId")
		jobIDs[i] = fmt.Sprintf("%d.%d", cluster, proc)
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("Successfully submitted job cluster %d with %d proc(s): %s",
					clusterID, len(jobIDs), strings.Join(jobIDs, ", ")),
			},
		},
		"metadata": map[string]interface{}{
			"cluster_id": clusterID,
			"job_ids":    jobIDs,
		},
	}, nil
}

// toolQueryJobs handles job queries
func (s *Server) toolQueryJobs(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	constraint, _ := args["constraint"].(string)
	if constraint == "" {
		constraint = "true"
	}

	var projection []string
	if projArray, ok := args["projection"].([]interface{}); ok {
		projection = make([]string, len(projArray))
		for i, p := range projArray {
			projection[i], _ = p.(string)
		}
	}

	// Parse limit parameter (default 50)
	limit := 50
	if limitVal, ok := args["limit"].(float64); ok {
		limit = int(limitVal)
	}

	// Get page token
	pageToken, _ := args["page_token"].(string)

	// Build query options
	opts := &htcondor.QueryOptions{
		Limit:      limit,
		Projection: projection,
		PageToken:  pageToken,
	}

	// Use streaming query
	streamOpts := &htcondor.StreamOptions{
		BufferSize:   100,
		WriteTimeout: 5 * time.Second,
	}
	resultCh := s.schedd.QueryStreamWithOptions(ctx, constraint, opts, streamOpts)

	// Collect results from stream
	var jobAds []*classad.ClassAd
	for result := range resultCh {
		if result.Err != nil {
			return nil, fmt.Errorf("query failed: %w", result.Err)
		}
		// Check if this is an error ad (Owner is null)
		if owner, ok := result.Ad.EvaluateAttrInt("Owner"); !ok || owner == 0 {
			// This is an error ad - extract error message
			var errMsg string
			if errCode, ok := result.Ad.EvaluateAttrInt("ErrorCode"); ok && errCode != 0 {
				if errStr, ok := result.Ad.EvaluateAttrString("ErrorString"); ok {
					errMsg = errStr
				} else {
					errMsg = fmt.Sprintf("error code %d", errCode)
				}
			} else {
				errMsg = "unknown error"
			}
			return nil, fmt.Errorf("schedd query error: %s", errMsg)
		}
		jobAds = append(jobAds, result.Ad)
	}

	// Convert ClassAds to JSON
	jobsJSON, err := json.Marshal(jobAds)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize jobs: %w", err)
	}

	resultText := fmt.Sprintf("Found %d job(s) matching constraint '%s':\n%s",
		len(jobAds), constraint, string(jobsJSON))

	// Build metadata
	metadata := map[string]interface{}{
		"count":      len(jobAds),
		"constraint": constraint,
		"has_more":   false,
	}

	// Check if we might have more results (got exactly the limit)
	if limit > 0 && len(jobAds) >= limit {
		// Generate page token from last job
		if len(jobAds) > 0 {
			lastJob := jobAds[len(jobAds)-1]
			if clusterID, ok := lastJob.EvaluateAttrInt("ClusterId"); ok {
				if procID, ok := lastJob.EvaluateAttrInt("ProcId"); ok {
					metadata["has_more"] = true
					metadata["next_page_token"] = htcondor.EncodePageToken(clusterID, procID)
					resultText += fmt.Sprintf("\n\nMore results available. Use page_token: %s", metadata["next_page_token"])
				}
			}
		}
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": resultText,
			},
		},
		"metadata": metadata,
	}, nil
}

// toolGetJob handles getting a specific job
func (s *Server) toolGetJob(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	jobID, ok := args["job_id"].(string)
	if !ok || jobID == "" {
		return nil, fmt.Errorf("job_id is required")
	}

	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		return nil, fmt.Errorf("invalid job_id: %w", err)
	}

	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	jobAds, _, err := s.schedd.QueryWithOptions(ctx, constraint, nil)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	if len(jobAds) == 0 {
		return nil, fmt.Errorf("job %s not found", jobID)
	}

	jobJSON, err := json.MarshalIndent(jobAds[0], "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize job: %w", err)
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("Job %s:\n%s", jobID, string(jobJSON)),
			},
		},
	}, nil
}

// performJobAction is a helper function for single job actions (hold/release/remove)
func performJobAction(ctx context.Context, args map[string]interface{}, actionFunc func(context.Context, string, string) (*htcondor.JobActionResults, error), defaultReason, actionName string) (interface{}, error) {
	jobID, ok := args["job_id"].(string)
	if !ok || jobID == "" {
		return nil, fmt.Errorf("job_id is required")
	}

	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		return nil, fmt.Errorf("invalid job_id: %w", err)
	}

	reason, _ := args["reason"].(string)
	if reason == "" {
		reason = defaultReason
	}

	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	results, err := actionFunc(ctx, constraint, reason)
	if err != nil {
		return nil, fmt.Errorf("job %s failed: %w", actionName, err)
	}

	if results.NotFound > 0 {
		return nil, fmt.Errorf("job %s not found", jobID)
	}

	if results.Success == 0 {
		return nil, fmt.Errorf("failed to %s job %s", actionName, jobID)
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("Successfully %s job %s", actionName, jobID),
			},
		},
	}, nil
}

// toolRemoveJob handles removing a specific job
func (s *Server) toolRemoveJob(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return performJobAction(ctx, args, s.schedd.RemoveJobs, "Removed via MCP", "remove")
}

// toolRemoveJobs handles removing multiple jobs
func (s *Server) toolRemoveJobs(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	constraint, ok := args["constraint"].(string)
	if !ok || constraint == "" {
		return nil, fmt.Errorf("constraint is required")
	}

	reason, _ := args["reason"].(string)
	if reason == "" {
		reason = "Removed via MCP bulk operation"
	}

	results, err := s.schedd.RemoveJobs(ctx, constraint, reason)
	if err != nil {
		return nil, fmt.Errorf("bulk job removal failed: %w", err)
	}

	if results.TotalJobs == 0 {
		return nil, fmt.Errorf("no jobs matched constraint '%s'", constraint)
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("Removed %d of %d job(s) matching constraint '%s'",
					results.Success, results.TotalJobs, constraint),
			},
		},
		"metadata": map[string]interface{}{
			"total":             results.TotalJobs,
			"success":           results.Success,
			"permission_denied": results.PermissionDenied,
			"not_found":         results.NotFound,
		},
	}, nil
}

// toolEditJob handles editing a job
func (s *Server) toolEditJob(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	jobID, ok := args["job_id"].(string)
	if !ok || jobID == "" {
		return nil, fmt.Errorf("job_id is required")
	}

	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		return nil, fmt.Errorf("invalid job_id: %w", err)
	}

	updates, ok := args["attributes"].(map[string]interface{})
	if !ok || len(updates) == 0 {
		return nil, fmt.Errorf("attributes is required")
	}

	// Convert interface{} values to strings for SetAttribute
	attributes := make(map[string]string)
	for key, value := range updates {
		switch v := value.(type) {
		case string:
			attributes[key] = fmt.Sprintf("%q", v)
		case float64:
			if v == float64(int64(v)) {
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
			attributes[key] = "UNDEFINED"
		default:
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("cannot convert attribute %s to string: %w", key, err)
			}
			attributes[key] = string(jsonBytes)
		}
	}

	opts := &htcondor.EditJobOptions{
		AllowProtectedAttrs: false,
		Force:               false,
	}

	if err := s.schedd.EditJob(ctx, cluster, proc, attributes, opts); err != nil {
		return nil, fmt.Errorf("failed to edit job: %w", err)
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("Successfully edited job %s", jobID),
			},
		},
	}, nil
}

// toolHoldJob handles holding a job
func (s *Server) toolHoldJob(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return performJobAction(ctx, args, s.schedd.HoldJobs, "Held via MCP", "hold")
}

// toolReleaseJob handles releasing a job
func (s *Server) toolReleaseJob(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return performJobAction(ctx, args, s.schedd.ReleaseJobs, "Released via MCP", "release")
}

// handleListResources returns the list of available resources
func (s *Server) handleListResources(_ context.Context, _ json.RawMessage) interface{} {
	resources := []Resource{
		{
			URI:         "condor://schedd/status",
			Name:        "Schedd Status",
			Description: "Current status and information about the HTCondor schedd",
			MimeType:    "application/json",
		},
	}

	return map[string]interface{}{
		"resources": resources,
	}
}

// handleReadResource reads a specific resource
func (s *Server) handleReadResource(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var request struct {
		URI string `json:"uri"`
	}

	if err := json.Unmarshal(params, &request); err != nil {
		return nil, fmt.Errorf("invalid resource read params: %w", err)
	}

	switch request.URI {
	case "condor://schedd/status":
		return s.resourceScheddStatus(ctx)
	default:
		return nil, fmt.Errorf("unknown resource: %s", request.URI)
	}
}

// resourceScheddStatus returns schedd status information
func (s *Server) resourceScheddStatus(ctx context.Context) (interface{}, error) {
	// Query the collector for schedd ad
	if s.collector == nil {
		return map[string]interface{}{
			"contents": []map[string]interface{}{
				{
					"uri":      "condor://schedd/status",
					"mimeType": "text/plain",
					"text":     "Schedd status unavailable (no collector configured)",
				},
			},
		}, nil
	}

	// Try to get schedd ad from collector using QueryAds
	constraint := "true" // Get all schedds or filter later
	ads, _, err := s.collector.QueryAdsWithOptions(ctx, "ScheddAd", constraint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to query collector: %w", err)
	}

	if len(ads) == 0 {
		return map[string]interface{}{
			"contents": []map[string]interface{}{
				{
					"uri":      "condor://schedd/status",
					"mimeType": "text/plain",
					"text":     "No schedd ads found in collector",
				},
			},
		}, nil
	}

	// Serialize the schedd ad (use first one)
	adJSON, err := json.MarshalIndent(ads[0], "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize schedd ad: %w", err)
	}

	return map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"uri":      "condor://schedd/status",
				"mimeType": "application/json",
				"text":     string(adJSON),
			},
		},
	}, nil
}

// parseJobID parses a job ID string in format "cluster.proc"
func parseJobID(jobID string) (cluster int, proc int, err error) {
	parts := strings.Split(jobID, ".")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("job ID must be in format 'cluster.proc'")
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

// parseJWTClaims extracts username and expiration from a JWT token using the JWT library
// Returns the username, expiration time, or an error if parsing fails
func parseJWTClaims(token string) (username string, expiration time.Time, err error) {
	// Parse the token without verification (we just need to read claims)
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsedToken, _, parseErr := parser.ParseUnverified(token, &jwt.RegisteredClaims{})
	if parseErr != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse JWT: %w", parseErr)
	}

	// Extract standard claims
	claims, ok := parsedToken.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return "", time.Time{}, fmt.Errorf("failed to extract JWT claims")
	}

	// Check if subject is set
	if claims.Subject == "" {
		return "", time.Time{}, fmt.Errorf("JWT missing sub claim")
	}

	// Check if expiration is set
	if claims.ExpiresAt == nil {
		return "", time.Time{}, fmt.Errorf("JWT missing exp claim")
	}

	return claims.Subject, claims.ExpiresAt.Time, nil
}

// toolGetJobStdout handles retrieving stdout from a job
func (s *Server) toolGetJobStdout(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return s.toolGetJobOutput(ctx, args, "stdout", "Out")
}

// toolGetJobStderr handles retrieving stderr from a job
func (s *Server) toolGetJobStderr(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return s.toolGetJobOutput(ctx, args, "stderr", "Err")
}

// toolGetJobOutput is a helper function to retrieve stdout or stderr from a job
func (s *Server) toolGetJobOutput(ctx context.Context, args map[string]interface{}, outputType, attributeName string) (interface{}, error) {
	jobID, ok := args["job_id"].(string)
	if !ok || jobID == "" {
		return nil, fmt.Errorf("job_id is required")
	}

	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		return nil, fmt.Errorf("invalid job_id: %w", err)
	}

	// Query the job to get the output filename
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	projection := []string{"ClusterId", "ProcId", "JobStatus", attributeName}

	opts := &htcondor.QueryOptions{
		Projection: projection,
	}
	jobAds, _, err := s.schedd.QueryWithOptions(ctx, constraint, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to query job: %w", err)
	}

	if len(jobAds) == 0 {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}

	jobAd := jobAds[0]

	// Get the output filename from the job ad
	outputFileExpr, ok := jobAd.Lookup(attributeName)
	if !ok {
		return nil, fmt.Errorf("job does not have %s attribute configured", outputType)
	}

	outputFile, err := outputFileExpr.Eval(nil).StringValue()
	if err != nil || outputFile == "" {
		return nil, fmt.Errorf("job %s attribute is empty or invalid", outputType)
	}

	// Download the job sandbox
	sandboxCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var sandboxBuf bytes.Buffer
	errChan := s.schedd.ReceiveJobSandbox(sandboxCtx, constraint, &sandboxBuf)

	if err := <-errChan; err != nil {
		return nil, fmt.Errorf("failed to download job sandbox: %w", err)
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
			return nil, fmt.Errorf("failed to read tar archive: %w", err)
		}

		// Check if this is the output file we're looking for
		baseName := filepath.Base(header.Name)
		if baseName == outputFile {
			content, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, fmt.Errorf("failed to read %s content: %w", outputType, err)
			}
			outputContent = string(content)
			break
		}
	}

	if outputContent == "" {
		return nil, fmt.Errorf("%s file not found in job sandbox (expected: %s)", outputType, outputFile)
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("Job %s %s:\n%s", jobID, outputType, outputContent),
			},
		},
		"metadata": map[string]interface{}{
			"job_id":      jobID,
			"output_type": outputType,
			"filename":    outputFile,
			"size":        len(outputContent),
		},
	}, nil
}
