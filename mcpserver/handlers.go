// Package mcpserver implements the Model Context Protocol server for HTCondor.
package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
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
			Description: "Query HTCondor jobs with optional constraints and projections",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"constraint": map[string]interface{}{
						"type":        "string",
						"description": "ClassAd constraint expression (default: 'true' for all jobs)",
					},
					"projection": map[string]interface{}{
						"type":        "array",
						"description": "List of attributes to include in results",
						"items": map[string]interface{}{
							"type": "string",
						},
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
		
		// Extract username from token for rate limiting
		username, _ := parseJWTUsername(token)
		if username != "" {
			ctx = htcondor.WithAuthenticatedUser(ctx, username)
		}
	}

	// Route to appropriate handler
	switch request.Name {
	case "submit_job":
		return s.toolSubmitJob(ctx, request.Arguments)
	case "query_jobs":
		return s.toolQueryJobs(ctx, request.Arguments)
	case "get_job":
		return s.toolGetJob(ctx, request.Arguments)
	case "remove_job":
		return s.toolRemoveJob(ctx, request.Arguments)
	case "remove_jobs":
		return s.toolRemoveJobs(ctx, request.Arguments)
	case "edit_job":
		return s.toolEditJob(ctx, request.Arguments)
	case "hold_job":
		return s.toolHoldJob(ctx, request.Arguments)
	case "release_job":
		return s.toolReleaseJob(ctx, request.Arguments)
	default:
		return nil, fmt.Errorf("unknown tool: %s", request.Name)
	}
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

	jobAds, err := s.schedd.Query(ctx, constraint, projection)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	// Convert ClassAds to JSON
	jobsJSON, err := json.Marshal(jobAds)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize jobs: %w", err)
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("Found %d job(s) matching constraint '%s':\n%s",
					len(jobAds), constraint, string(jobsJSON)),
			},
		},
		"metadata": map[string]interface{}{
			"count":      len(jobAds),
			"constraint": constraint,
		},
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
	jobAds, err := s.schedd.Query(ctx, constraint, nil)
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
	ads, err := s.collector.QueryAds(ctx, "ScheddAd", constraint)
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

// parseJWTUsername extracts the username (sub claim) from a JWT token
// Returns the username or an error if parsing fails
func parseJWTUsername(token string) (string, error) {
	// JWT format: header.payload.signature
	parts := []byte(token)
	dotCount := 0
	payloadStart := 0
	payloadEnd := 0

	for i, b := range parts {
		if b == '.' {
			dotCount++
			if dotCount == 1 {
				payloadStart = i + 1
			} else if dotCount == 2 {
				payloadEnd = i
				break
			}
		}
	}

	if dotCount < 2 {
		return "", fmt.Errorf("invalid JWT format")
	}

	// Decode the payload (base64url)
	payloadB64 := string(parts[payloadStart:payloadEnd])
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse JSON to extract sub claim
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT payload: %w", err)
	}

	// Extract username from sub claim
	sub, ok := claims["sub"]
	if !ok {
		return "", fmt.Errorf("JWT missing sub claim")
	}

	username, ok := sub.(string)
	if !ok {
		return "", fmt.Errorf("JWT sub claim is not a string")
	}

	return username, nil
}
