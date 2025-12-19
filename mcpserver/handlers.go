// Package mcpserver implements the Model Context Protocol (MCP) server for HTCondor.
package mcpserver

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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
			Description: "Submit an HTCondor job using a submit file. After submission, use upload_job_input to upload the executable and any input files (<100KB total recommended). For large input files (>100KB), use HTTP/HTTPS URLs in transfer_input_files instead of uploading via upload_job_input.",
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
		{
			Name:        "advertise_to_collector",
			Description: "Advertise a ClassAd to the HTCondor collector. The UPDATE command is determined from the ad's MyType attribute if not explicitly specified.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"ad": map[string]interface{}{
						"type":        "object",
						"description": "ClassAd to advertise as a JSON object (e.g., {\"MyType\": \"Machine\", \"Name\": \"slot1@host\", \"State\": \"Unclaimed\"})",
					},
					"command": map[string]interface{}{
						"type":        "string",
						"description": "Optional UPDATE command (e.g., 'UPDATE_STARTD_AD'). If not specified, determined from ad's MyType",
					},
					"with_ack": map[string]interface{}{
						"type":        "boolean",
						"description": "Request acknowledgment from collector (default: false)",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Authentication token (optional)",
					},
				},
				"required": []string{"ad"},
			},
		},
		{
			Name:        "query_job_archive",
			Description: "Query archived job records from HTCondor (completed jobs)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"constraint": map[string]interface{}{
						"type":        "string",
						"description": "ClassAd constraint expression (default: 'true' for all archived jobs)",
					},
					"projection": map[string]interface{}{
						"type":        "array",
						"description": "List of attributes to include in results. Default: ClusterId, ProcId, Owner, JobStatus, EnteredCurrentStatus, CompletionDate, RemoveReason",
						"items": map[string]interface{}{
							"type": "string",
						},
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of archived records to return. Use -1 for unlimited.",
					},
					"scan_limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of archived records to scan before stopping",
					},
					"backwards": map[string]interface{}{
						"type":        "boolean",
						"description": "Scan archive backwards from most recent (default: true)",
					},
					"since": map[string]interface{}{
						"type":        "string",
						"description": "Only return records after this timestamp (ISO8601 format)",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Authentication token (optional)",
					},
				},
			},
		},
		{
			Name:        "query_job_epochs",
			Description: "Query job epoch history records (job restarts and execution attempts)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"constraint": map[string]interface{}{
						"type":        "string",
						"description": "ClassAd constraint expression (default: 'true' for all epochs)",
					},
					"projection": map[string]interface{}{
						"type":        "array",
						"description": "List of attributes to include in results. Default: ClusterId, ProcId, EpochNumber, Owner, JobStartDate, JobCurrentStartDate, RemoteHost",
						"items": map[string]interface{}{
							"type": "string",
						},
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of epoch records to return. Use -1 for unlimited.",
					},
					"scan_limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of epoch records to scan before stopping",
					},
					"backwards": map[string]interface{}{
						"type":        "boolean",
						"description": "Scan history backwards from most recent (default: true)",
					},
					"since": map[string]interface{}{
						"type":        "string",
						"description": "Only return records after this timestamp (ISO8601 format)",
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Authentication token (optional)",
					},
				},
			},
		},
		{
			Name:        "query_transfer_history",
			Description: "Query file transfer history records",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"constraint": map[string]interface{}{
						"type":        "string",
						"description": "ClassAd constraint expression (default: 'true' for all transfers)",
					},
					"projection": map[string]interface{}{
						"type":        "array",
						"description": "List of attributes to include in results. Default: ClusterId, ProcId, TransferType, TransferStartTime, TransferEndTime, TransferSuccess, TransferFileBytes",
						"items": map[string]interface{}{
							"type": "string",
						},
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of transfer records to return. Use -1 for unlimited.",
					},
					"scan_limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of transfer records to scan before stopping",
					},
					"backwards": map[string]interface{}{
						"type":        "boolean",
						"description": "Scan history backwards from most recent (default: true)",
					},
					"since": map[string]interface{}{
						"type":        "string",
						"description": "Only return records after this timestamp (ISO8601 format)",
					},
					"transfer_types": map[string]interface{}{
						"type":        "array",
						"description": "List of transfer types to include (INPUT_FILES, OUTPUT_FILES, CHECKPOINT_FILES)",
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
			Name:        "upload_job_input",
			Description: "Upload input files to a job's sandbox. Use this for small files (<100KB total). For larger files, use HTTP/HTTPS URLs in transfer_input_files instead.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"job_id": map[string]interface{}{
						"type":        "string",
						"description": "Job ID in format 'cluster.proc' (e.g., '123.0')",
					},
					"files": map[string]interface{}{
						"type":        "array",
						"description": "Array of files to upload",
						"items": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"filename": map[string]interface{}{
									"type":        "string",
									"description": "Name of the file (e.g., 'script.sh', 'data.txt')",
								},
								"data": map[string]interface{}{
									"type":        "string",
									"description": "File content. For text files, provide plain text. For binary files, provide base64-encoded data and set is_base64=true.",
								},
								"is_base64": map[string]interface{}{
									"type":        "boolean",
									"description": "If true, the data field is base64-encoded binary content (default: false, meaning plain text)",
								},
								"is_executable": map[string]interface{}{
									"type":        "boolean",
									"description": "If true, set executable permissions on the file (default: false)",
								},
							},
							"required": []string{"filename", "data"},
						},
					},
					"token": map[string]interface{}{
						"type":        "string",
						"description": "Authentication token (optional)",
					},
				},
				"required": []string{"job_id", "files"},
			},
		},
		{
			Name:        "get_job_output",
			Description: "Get all output files from a job's sandbox as structured data. Files are returned with their content (text or base64-encoded for binary), truncated if larger than 100KB per file.",
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
	case "advertise_to_collector":
		result, err = s.toolAdvertiseToCollector(ctx, request.Arguments)
	case "query_job_archive":
		result, err = s.toolQueryJobHistory(ctx, request.Arguments)
	case "query_job_epochs":
		result, err = s.toolQueryJobEpochs(ctx, request.Arguments)
	case "query_transfer_history":
		result, err = s.toolQueryTransferHistory(ctx, request.Arguments)
	case "upload_job_input":
		result, err = s.toolUploadJobInput(ctx, request.Arguments)
	case "get_job_output":
		result, err = s.toolGetJobOutputFiles(ctx, request.Arguments)
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

	// Determine if job likely needs input file spooling by parsing the submit file
	// and checking the generated ClassAd attributes directly
	needsSpooling := true // Default to true for safety
	if sf, err := htcondor.ParseSubmitFile(strings.NewReader(submitFile)); err == nil {
		// Generate a job ad to check transfer attributes
		jobID := htcondor.JobID{Cluster: clusterID, Proc: 0}
		if ad, err := sf.MakeJobAd(jobID, nil); err == nil {
			// Check TransferExecutable - defaults to true
			transferExec := true
			if val, ok := ad.EvaluateAttrBool("TransferExecutable"); ok {
				transferExec = val
			}

			// Check TransferInput - if set, files need to be spooled
			hasInputFiles := false
			if val, _ := ad.EvaluateAttrString("TransferInput"); val != "" {
				hasInputFiles = true
			}

			// Check Input (stdin redirection) - if set, the input file needs to be spooled
			hasStdinFile := false
			if val, _ := ad.EvaluateAttrString("Input"); val != "" {
				hasStdinFile = true
			}

			// Spooling is needed if executable will be transferred OR input files are specified
			needsSpooling = transferExec || hasInputFiles || hasStdinFile
		}
	}

	var nextSteps string
	if needsSpooling {
		nextSteps = fmt.Sprintf(`

NEXT STEPS:
1. The job is currently HELD (JobStatus=5) waiting for input files to be uploaded.
2. Upload input files (executable script, data files) using the HTTP PUT endpoint for job input.
3. After uploading, the job will be automatically released and transition to IDLE (JobStatus=1).
4. Poll job status using query_jobs to monitor progress. Poll no more than every 5 seconds.
5. When JobStatus=4 (Completed), retrieve output using get_job_stdout and get_job_stderr.

Job Status Values:
- 1 = Idle (waiting for resources)
- 2 = Running
- 3 = Removed
- 4 = Completed
- 5 = Held (waiting for input files or user action)

First job ID for status checks: %s`, jobIDs[0])
	} else {
		nextSteps = fmt.Sprintf(`

NEXT STEPS:
1. The job has been submitted and should transition to IDLE (JobStatus=1) shortly.
   (No input file upload needed since the executable is a system command.)
2. Poll job status using query_jobs to monitor progress. Poll no more than every 5 seconds.
3. When JobStatus=4 (Completed), retrieve output using get_job_stdout and get_job_stderr.

Job Status Values:
- 1 = Idle (waiting for resources)
- 2 = Running
- 3 = Removed
- 4 = Completed
- 5 = Held (waiting for input files or user action)

First job ID for status checks: %s`, jobIDs[0])
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("Successfully submitted job cluster %d with %d proc(s): %s%s",
					clusterID, len(jobIDs), strings.Join(jobIDs, ", "), nextSteps),
			},
		},
		"metadata": map[string]interface{}{
			"cluster_id": clusterID,
			"job_ids":    jobIDs,
		},
	}, nil
}

// toolQueryJobs handles job queries
// By default, only queries jobs owned by the authenticated user for security
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

	// Build query options - filter by owner by default for security
	opts := &htcondor.QueryOptions{
		Limit:      limit,
		Projection: projection,
		PageToken:  pageToken,
		FetchOpts:  htcondor.FetchMyJobs, // Only query jobs owned by the authenticated user
	}

	// Get authenticated user from context if available
	if user := htcondor.GetAuthenticatedUserFromContext(ctx); user != "" {
		opts.Owner = user
	}

	// Use streaming query
	streamOpts := &htcondor.StreamOptions{
		BufferSize:   100,
		WriteTimeout: 5 * time.Second,
	}
	resultCh, err := s.schedd.QueryStreamWithOptions(ctx, constraint, opts, streamOpts)
	if err != nil {
		// Pre-request error
		return nil, fmt.Errorf("failed to start query: %w", err)
	}

	// Collect results from stream
	var jobAds []*classad.ClassAd
	for result := range resultCh {
		if result.Err != nil {
			return nil, fmt.Errorf("query failed: %w", result.Err)
		}
		jobAds = append(jobAds, result.Ad)
	}

	// Convert ClassAds to JSON
	jobsJSON, err := json.Marshal(jobAds)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize jobs: %w", err)
	}

	// Build helpful status information
	statusGuide := `

JOB STATUS REFERENCE:
- JobStatus=1: Idle (waiting for resources)
- JobStatus=2: Running
- JobStatus=3: Removed
- JobStatus=4: Completed (retrieve output with get_job_stdout/get_job_stderr)
- JobStatus=5: Held (may need input files uploaded or user action)

TIPS:
- Poll job status no more frequently than every 5 seconds
- Use constraint queries instead of fetching many individual jobs (e.g., "ClusterId == 123")
- For completed jobs (JobStatus=4), use get_job_stdout to retrieve output`

	resultText := fmt.Sprintf("Found %d job(s) matching constraint '%s':\n%s%s",
		len(jobAds), constraint, string(jobsJSON), statusGuide)

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

// toolAdvertiseToCollector handles advertise_to_collector tool calls
func (s *Server) toolAdvertiseToCollector(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	// Check if collector is configured
	if s.collector == nil {
		return nil, fmt.Errorf("collector not configured")
	}

	// Parse arguments
	adData, ok := args["ad"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("ad must be a JSON object")
	}

	// Convert map to ClassAd
	adJSON, err := json.Marshal(adData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ad: %w", err)
	}

	ad := classad.New()
	if err := json.Unmarshal(adJSON, ad); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ad: %w", err)
	}

	// Build advertise options
	opts := &htcondor.AdvertiseOptions{
		UseTCP: true,
	}

	// Parse optional with_ack
	if withAck, ok := args["with_ack"].(bool); ok {
		opts.WithAck = withAck
	}

	// Parse optional command
	if cmdStr, ok := args["command"].(string); ok && cmdStr != "" {
		// Import commands package if needed
		cmd, valid := htcondor.ParseAdvertiseCommand(cmdStr)
		if !valid {
			return nil, fmt.Errorf("invalid command: %s", cmdStr)
		}
		opts.Command = cmd
	}

	// Advertise the ad
	if err := s.collector.Advertise(ctx, ad, opts); err != nil {
		return nil, fmt.Errorf("failed to advertise: %w", err)
	}

	// Get ad name for response
	adName := "unknown"
	if nameStr, ok := ad.EvaluateAttrString("Name"); ok {
		adName = nameStr
	}

	adType := "Generic"
	if typeStr, ok := ad.EvaluateAttrString("MyType"); ok {
		adType = typeStr
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("Successfully advertised %s ad '%s' to collector", adType, adName),
			},
		},
		"metadata": map[string]interface{}{
			"ad_name":  adName,
			"ad_type":  adType,
			"with_ack": opts.WithAck,
		},
	}, nil
}

// toolQueryJobHistory handles job history queries
func (s *Server) toolQueryJobHistory(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return s.toolQueryHistory(ctx, args, htcondor.HistorySourceJobHistory, "job history")
}

// toolQueryJobEpochs handles job epoch history queries
func (s *Server) toolQueryJobEpochs(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return s.toolQueryHistory(ctx, args, htcondor.HistorySourceJobEpoch, "job epochs")
}

// toolQueryTransferHistory handles transfer history queries
func (s *Server) toolQueryTransferHistory(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return s.toolQueryHistory(ctx, args, htcondor.HistorySourceTransfer, "transfer history")
}

// toolQueryHistory is a helper function for history queries
func (s *Server) toolQueryHistory(ctx context.Context, args map[string]interface{}, source htcondor.HistoryRecordSource, typeName string) (interface{}, error) {
	constraint, _ := args["constraint"].(string)
	if constraint == "" {
		constraint = "true"
	}

	// Parse projection
	var projection []string
	if projArray, ok := args["projection"].([]interface{}); ok {
		projection = make([]string, len(projArray))
		for i, p := range projArray {
			projection[i], _ = p.(string)
		}
	}

	// Build query options
	opts := &htcondor.HistoryQueryOptions{
		Source:     source,
		Projection: projection,
		Backwards:  true, // Default to backwards
	}

	// Parse limit (default: no limit for history queries)
	if limitVal, ok := args["limit"].(float64); ok {
		opts.Limit = int(limitVal)
	}

	// Parse scan_limit
	if scanLimitVal, ok := args["scan_limit"].(float64); ok {
		opts.ScanLimit = int(scanLimitVal)
	}

	// Parse backwards
	if backwardsVal, ok := args["backwards"].(bool); ok {
		opts.Backwards = backwardsVal
	}

	// Parse since timestamp
	if sinceVal, ok := args["since"].(string); ok && sinceVal != "" {
		// Store as constraint string
		opts.Since = sinceVal
	}

	// Parse transfer_types for transfer history
	if source == htcondor.HistorySourceTransfer {
		if typesArray, ok := args["transfer_types"].([]interface{}); ok && len(typesArray) > 0 {
			var transferTypes []htcondor.TransferType
			for _, t := range typesArray {
				typeStr, _ := t.(string)
				switch typeStr {
				case "INPUT_FILES", "INPUT":
					transferTypes = append(transferTypes, htcondor.TransferTypeInput)
				case "OUTPUT_FILES", "OUTPUT":
					transferTypes = append(transferTypes, htcondor.TransferTypeOutput)
				case "CHECKPOINT_FILES", "CHECKPOINT":
					transferTypes = append(transferTypes, htcondor.TransferTypeCheckpoint)
				}
			}
			if len(transferTypes) > 0 {
				opts.TransferTypes = transferTypes
			}
		}
	}

	// Execute query
	records, err := s.schedd.QueryHistoryWithOptions(ctx, constraint, opts)
	if err != nil {
		return nil, fmt.Errorf("history query failed: %w", err)
	}

	// Convert ClassAds to JSON
	recordsJSON, err := json.Marshal(records)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize records: %w", err)
	}

	resultText := fmt.Sprintf("Found %d %s record(s):\n%s",
		len(records), typeName, string(recordsJSON))

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": resultText,
			},
		},
		"metadata": map[string]interface{}{
			"total_records": len(records),
			"constraint":    constraint,
			"source":        string(source),
		},
	}, nil
}

// OutputFile represents a file from the job's output sandbox
type OutputFile struct {
	Filename    string `json:"filename"`
	Data        string `json:"data"`
	IsTruncated bool   `json:"is_truncated"`
	URL         string `json:"url,omitempty"`
	IsBase64    bool   `json:"is_base64"`
	Size        int64  `json:"size"`
}

// maxFileSize is the maximum size of file content to include in response (100KB)
const maxFileSize = 100 * 1024

// toolUploadJobInput handles uploading input files to a job's sandbox
func (s *Server) toolUploadJobInput(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	jobID, ok := args["job_id"].(string)
	if !ok || jobID == "" {
		return nil, fmt.Errorf("job_id is required")
	}

	filesRaw, ok := args["files"].([]interface{})
	if !ok || len(filesRaw) == 0 {
		return nil, fmt.Errorf("files array is required and must not be empty")
	}

	// Parse job ID
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		return nil, fmt.Errorf("invalid job_id: %w", err)
	}

	// Query for the job to get its proc ad with transfer attributes
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	projection := []string{"ClusterId", "ProcId", "TransferInput", "Cmd", "TransferExecutable"}
	jobAds, _, err := s.schedd.QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Projection: projection,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query job: %w", err)
	}

	if len(jobAds) == 0 {
		return nil, fmt.Errorf("job %s not found", jobID)
	}

	// Build a tarball from the input files
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)

	var uploadedFiles []string
	var totalSize int64

	for i, fileRaw := range filesRaw {
		fileMap, ok := fileRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("files[%d] must be an object", i)
		}

		filename, ok := fileMap["filename"].(string)
		if !ok || filename == "" {
			return nil, fmt.Errorf("files[%d].filename is required", i)
		}

		data, ok := fileMap["data"].(string)
		if !ok {
			return nil, fmt.Errorf("files[%d].data is required", i)
		}

		// Decode data if base64-encoded
		var fileData []byte
		isBase64, _ := fileMap["is_base64"].(bool)
		if isBase64 {
			decoded, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				return nil, fmt.Errorf("files[%d].data: invalid base64: %w", i, err)
			}
			fileData = decoded
		} else {
			fileData = []byte(data)
		}

		// Determine file mode
		var fileMode int64 = 0644
		isExecutable, _ := fileMap["is_executable"].(bool)
		if isExecutable {
			fileMode = 0755
		}

		// Write tar header
		header := &tar.Header{
			Name:    filename,
			Size:    int64(len(fileData)),
			Mode:    fileMode,
			ModTime: time.Now(),
		}
		if err := tw.WriteHeader(header); err != nil {
			return nil, fmt.Errorf("failed to write tar header for %s: %w", filename, err)
		}

		// Write file content
		if _, err := tw.Write(fileData); err != nil {
			return nil, fmt.Errorf("failed to write tar content for %s: %w", filename, err)
		}

		uploadedFiles = append(uploadedFiles, filename)
		totalSize += int64(len(fileData))
	}

	// Close the tar writer
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("failed to close tar writer: %w", err)
	}

	// Check total size and warn if large
	var sizeWarning string
	if totalSize > maxFileSize {
		sizeWarning = fmt.Sprintf("\n\nWARNING: Total upload size (%d bytes) exceeds recommended limit of 100KB. "+
			"For large files, consider using HTTP/HTTPS URLs in transfer_input_files instead.", totalSize)
	}

	// Spool the files to the schedd
	err = s.schedd.SpoolJobFilesFromTar(ctx, jobAds, &tarBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to spool job files: %w", err)
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("Successfully uploaded %d file(s) to job %s: %s%s\n\n"+
					"NEXT STEPS:\n"+
					"1. The job should now be released from HELD state and transition to IDLE (JobStatus=1).\n"+
					"2. Poll job status using query_jobs to monitor progress.\n"+
					"3. When JobStatus=4 (Completed), use get_job_output to retrieve all output files.",
					len(uploadedFiles), jobID, strings.Join(uploadedFiles, ", "), sizeWarning),
			},
		},
		"metadata": map[string]interface{}{
			"job_id":     jobID,
			"file_count": len(uploadedFiles),
			"files":      uploadedFiles,
			"total_size": totalSize,
		},
	}, nil
}

// toolGetJobOutputFiles handles retrieving all output files from a job's sandbox
func (s *Server) toolGetJobOutputFiles(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	jobID, ok := args["job_id"].(string)
	if !ok || jobID == "" {
		return nil, fmt.Errorf("job_id is required")
	}

	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		return nil, fmt.Errorf("invalid job_id: %w", err)
	}

	// Build constraint for specific job
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)

	// Download the job sandbox into a buffer
	sandboxCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var sandboxBuf bytes.Buffer
	errChan := s.schedd.ReceiveJobSandbox(sandboxCtx, constraint, &sandboxBuf)

	if err := <-errChan; err != nil {
		return nil, fmt.Errorf("failed to download job sandbox: %w", err)
	}

	// Parse the tar archive and extract files
	tarReader := tar.NewReader(&sandboxBuf)
	var outputFiles []OutputFile

	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar archive: %w", err)
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Read file content (up to maxFileSize + 1 to detect truncation)
		limitedReader := io.LimitReader(tarReader, maxFileSize+1)
		content, err := io.ReadAll(limitedReader)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", header.Name, err)
		}

		isTruncated := len(content) > maxFileSize
		if isTruncated {
			content = content[:maxFileSize]
		}

		// Determine if content is valid UTF-8 text or binary
		isText := utf8.Valid(content) && !containsNullBytes(content)

		file := OutputFile{
			Filename:    header.Name,
			IsTruncated: isTruncated,
			Size:        header.Size,
			IsBase64:    !isText,
		}

		if isText {
			file.Data = string(content)
		} else {
			file.Data = base64.StdEncoding.EncodeToString(content)
		}

		// Generate HTTP URL if base URL is configured
		if s.httpBaseURL != "" {
			file.URL = s.buildFileDownloadURL(jobID, header.Name)
		}

		outputFiles = append(outputFiles, file)
	}

	if len(outputFiles) == 0 {
		return map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("No output files found for job %s. The job may not have produced any output yet.", jobID),
				},
			},
			"metadata": map[string]interface{}{
				"job_id":     jobID,
				"file_count": 0,
			},
		}, nil
	}

	// Build summary text
	var summaryParts []string
	var truncatedFiles []string
	for _, f := range outputFiles {
		encoding := "text"
		if f.IsBase64 {
			encoding = "base64"
		}
		summaryParts = append(summaryParts, fmt.Sprintf("- %s (%d bytes, %s)", f.Filename, f.Size, encoding))
		if f.IsTruncated {
			truncatedFiles = append(truncatedFiles, f.Filename)
		}
	}

	summaryText := fmt.Sprintf("Retrieved %d output file(s) from job %s:\n%s",
		len(outputFiles), jobID, strings.Join(summaryParts, "\n"))

	if len(truncatedFiles) > 0 {
		summaryText += fmt.Sprintf("\n\nWARNING: The following files were truncated to 100KB: %s",
			strings.Join(truncatedFiles, ", "))
		if s.httpBaseURL != "" {
			summaryText += "\nUse the provided URLs to download the complete files."
		}
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": summaryText,
			},
		},
		"metadata": map[string]interface{}{
			"job_id":     jobID,
			"file_count": len(outputFiles),
			"files":      outputFiles,
		},
	}, nil
}

// buildFileDownloadURL constructs the HTTP URL for downloading a specific file from a job's output
func (s *Server) buildFileDownloadURL(jobID, filename string) string {
	if s.httpBaseURL == "" {
		return ""
	}
	// URL format: {baseURL}/api/v1/jobs/{jobID}/output/file/{filename}
	return fmt.Sprintf("%s/api/v1/jobs/%s/output/file/%s",
		strings.TrimSuffix(s.httpBaseURL, "/"),
		url.PathEscape(jobID),
		url.PathEscape(filename))
}

// containsNullBytes checks if the byte slice contains null bytes (common in binary files)
func containsNullBytes(data []byte) bool {
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	return false
}
