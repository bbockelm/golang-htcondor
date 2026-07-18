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
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/condordocs"
	"github.com/bbockelm/golang-htcondor/webapi/matchanalyzer"
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

// scopeContextKey carries the OAuth2 granted-scopes set into MCP
// request handling so handleListTools can filter the catalog. The
// HTTP transport populates this from fosite's
// AccessRequester.GetGrantedScopes(); the stdio transport leaves it
// nil, which is treated as "no filtering" — stdio is implicitly
// trusted (it's the local process boundary).
type scopeContextKey struct{}

// WithGrantedScopes attaches the OAuth2-granted scope set to a
// context. Used by the HTTP MCP transport to feed the scope filter
// in handleListTools.
func WithGrantedScopes(ctx context.Context, scopes []string) context.Context {
	if scopes == nil {
		return ctx
	}
	return context.WithValue(ctx, scopeContextKey{}, scopes)
}

// grantedScopesFromContext returns the scope set previously attached
// via WithGrantedScopes, or nil if the caller didn't set any. Callers
// must treat nil as "no scope info available" and decide their
// default policy — handleListTools defaults to "show everything"
// because stdio is the unguarded use case.
func grantedScopesFromContext(ctx context.Context) []string {
	if v, ok := ctx.Value(scopeContextKey{}).([]string); ok {
		return v
	}
	return nil
}

// scopesAllowTool reports whether the given scope set permits a tool
// with the given name. The classification uses the same allowlist
// the HTTP transport's methodRequiresWrite consults — adding a tool
// in one place without updating the other will cause the list to
// either over- or under-expose. The shared constant
// readOnlyMCPTools below is the single source of truth.
//
// Returns true when scopes is nil (no constraint info), so the stdio
// path keeps showing everything.
func scopesAllowTool(scopes []string, name string) bool {
	if scopes == nil {
		return true
	}
	hasRead := false
	hasWrite := false
	for _, s := range scopes {
		switch s {
		case "mcp:read":
			hasRead = true
		case "mcp:write":
			hasWrite = true
		}
	}
	if hasWrite {
		return true
	}
	if hasRead && readOnlyMCPTools[name] {
		return true
	}
	return false
}

// IsReadOnlyTool reports whether the named MCP tool is in the
// read-only allowlist. Used by both the in-package scope filter on
// tools/list and the httpserver-side OAuth2 scope check on
// tools/call. Putting the canonical list in this package keeps the
// two paths from drifting.
func IsReadOnlyTool(name string) bool {
	return readOnlyMCPTools[name]
}

// readOnlyMCPTools is the canonical list of MCP tools that are safe
// to call with only the mcp:read scope. The httpserver-side scope
// gate consumes this via IsReadOnlyTool. Adding a new MCP tool
// without updating this map silently classifies it as write-only.
var readOnlyMCPTools = map[string]bool{
	"query_jobs":                    true,
	"get_job":                       true,
	"analyze_job_match":             true,
	"query_job_archive":             true,
	"query_job_epochs":              true,
	"query_transfer_history":        true,
	"list_service_credentials":      true,
	"get_credential_status":         true,
	"condor_doc_job_attributes":     true,
	"condor_doc_machine_attributes": true,
	"condor_doc_submit_syntax":      true,
	"condor_doc_config_variables":   true,
	"condor_doc_search":             true,
}

// handleListTools returns the list of available tools, filtered by
// the caller's OAuth2 scope set if the HTTP transport provided one
// via WithGrantedScopes. Stdio callers (no scopes on context) see
// the full catalog.
func (s *Server) handleListTools(ctx context.Context, _ json.RawMessage) interface{} {
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
			Name:        "analyze_job_match",
			Description: "Explain why a job is or isn't matching slots in the pool. Decomposes the job's Requirements expression into independently-evaluable predicates, evaluates each against every slot in the collector's view, and reports per-predicate match counts plus the predicate most responsible for narrowing the match set. Useful for diagnosing 'job stuck idle' situations: if no slot fully matches, the response includes a 'narrowing_predicate_index' pointing at the predicate to investigate. The collector query is cached for ~30s, but the first call can be heavy for large pools.",
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

	// Add HTCondor documentation tools if the docs are embedded.
	// These are read-only, side-effect-free reference lookups; we
	// register them under the read-only OAuth2 allowlist.
	if condordocs.IsEmbedded() {
		tools = append(tools, condorDocTools()...)
	}

	// Add credential management tools if credd is available
	if s.credd != nil {
		tools = append(tools,
			Tool{
				Name:        "list_service_credentials",
				Description: "List all OAuth service credentials stored in the credential daemon. Use this to check which services have credentials configured.",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"token": map[string]interface{}{
							"type":        "string",
							"description": "Authentication token (optional)",
						},
					},
				},
			},
			Tool{
				Name:        "get_credential_status",
				Description: "Check whether an OAuth credential exists for a given service and optional handle. Use this to verify credentials are bootstrapped before or after job submission.",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"service": map[string]interface{}{
							"type":        "string",
							"description": "The OAuth service name (e.g., 'scitokens')",
						},
						"handle": map[string]interface{}{
							"type":        "string",
							"description": "Optional handle to distinguish multiple credentials for the same service",
						},
						"token": map[string]interface{}{
							"type":        "string",
							"description": "Authentication token (optional)",
						},
					},
					"required": []string{"service"},
				},
			},
			Tool{
				Name:        "store_service_credential",
				Description: "Store an OAuth credential (e.g., a refresh token) for a service. This is used to bootstrap credentials required by jobs that need OAuthServicesNeeded. The credential is stored in the HTCondor credential daemon.",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"service": map[string]interface{}{
							"type":        "string",
							"description": "The OAuth service name (e.g., 'scitokens')",
						},
						"handle": map[string]interface{}{
							"type":        "string",
							"description": "Optional handle to distinguish multiple credentials for the same service",
						},
						"credential": map[string]interface{}{
							"type":        "string",
							"description": "The credential value (e.g., a refresh token). Can be plain text or base64-encoded.",
						},
						"token": map[string]interface{}{
							"type":        "string",
							"description": "Authentication token (optional)",
						},
					},
					"required": []string{"service", "credential"},
				},
			},
			Tool{
				Name:        "delete_service_credential",
				Description: "Delete an OAuth service credential from the credential daemon.",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"service": map[string]interface{}{
							"type":        "string",
							"description": "The OAuth service name to delete",
						},
						"handle": map[string]interface{}{
							"type":        "string",
							"description": "Optional handle identifying a specific credential for the service",
						},
						"token": map[string]interface{}{
							"type":        "string",
							"description": "Authentication token (optional)",
						},
					},
					"required": []string{"service"},
				},
			},
		)
	}

	// Filter by caller's OAuth2 scopes if the HTTP transport
	// supplied them. Read-only-token clients see only the
	// read-safe subset; write-token and stdio (no scope info)
	// clients see the full catalog. Without this filter, a
	// read-only token client would see write tools in tools/list
	// and try to call them, getting confusing
	// insufficient_scope rejections — and a hostile relying
	// party could enumerate the full attack surface to
	// social-engineer a write upgrade.
	scopes := grantedScopesFromContext(ctx)
	filtered := tools[:0:0]
	for _, t := range tools {
		if scopesAllowTool(scopes, t.Name) {
			filtered = append(filtered, t)
		}
	}
	return map[string]interface{}{
		"tools": filtered,
	}
}

// handleCallTool executes a tool call.
//
// The flat per-tool switch below is intentional: a `grep "case \""`
// finds any tool's entry point. Refactoring to a handler map would
// hide the call graph and isn't worth the cyclomatic-score saving.
//
//nolint:gocyclo // dispatch table by design; each new tool adds one branch
func (s *Server) handleCallTool(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var request struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}

	if err := json.Unmarshal(params, &request); err != nil {
		return nil, fmt.Errorf("invalid tool call params: %w", err)
	}

	// Create context with security config if token provided. We use
	// the shared NewClientSecurityConfig builder so the AuthMethods
	// list comes from SEC_CLIENT_AUTHENTICATION_METHODS / the
	// configured fallback — locking this to TOKEN-only (the previous
	// behavior) broke pools whose collector also offers SSL but not
	// our token's iss/kid.
	token, _ := request.Arguments["token"].(string)
	var username string
	if token != "" {
		secConfig, err := htcondor.NewClientSecurityConfig(ctx, token, "", 0, "CLIENT", nil)
		if err != nil {
			return nil, fmt.Errorf("build security config: %w", err)
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
	case "analyze_job_match":
		result, err = s.toolAnalyzeJobMatch(ctx, request.Arguments)
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
	case "list_service_credentials":
		result, err = s.toolListServiceCredentials(ctx, request.Arguments)
	case "get_credential_status":
		result, err = s.toolGetCredentialStatus(ctx, request.Arguments)
	case "store_service_credential":
		result, err = s.toolStoreServiceCredential(ctx, request.Arguments)
	case "delete_service_credential":
		result, err = s.toolDeleteServiceCredential(ctx, request.Arguments)
	default:
		// Doc tools all share one handler — dispatching them here as
		// a single default-arm fallback means the switch's
		// cyclomatic-complexity score doesn't grow each time we add
		// a new condor_doc_* tool.
		if !isCondorDocTool(request.Name) {
			return nil, fmt.Errorf("unknown tool: %s", request.Name)
		}
		result, err = s.toolCondorDocSearch(ctx, request.Name, request.Arguments)
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
1. The job is currently HELD (JobStatus=5) waiting for input spooling.
2. You MUST call upload_job_input to complete the spooling step, even if the
   only file to upload is the executable (and there are no other input files).
   DO NOT use release_job — the job cannot run until spooling is complete.
   Releasing without spooling will cause the job to fail immediately.
3. After a successful upload_job_input, the job is automatically released to IDLE (JobStatus=1).
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

	// Check for OAuthServicesNeeded by re-querying the submitted job.
	// Job transforms may add this attribute after the job is committed.
	oauthNote := s.checkOAuthServicesNeeded(ctx, clusterID)

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("Successfully submitted job cluster %d with %d proc(s): %s%s%s",
					clusterID, len(jobIDs), strings.Join(jobIDs, ", "), nextSteps, oauthNote),
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

	// Owner-scope the query: a non-admin caller asking for cluster.proc
	// X.Y must own that job (or get a "not found" rather than a leak
	// of someone else's full ad). Admins skip the wrapper for
	// cross-user troubleshooting.
	idClause := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	constraint, ok := s.scopeToOwner(ctx, idClause)
	if !ok {
		return nil, fmt.Errorf("authentication required")
	}
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

// matchAnalysisProvider lazily allocates the slot provider used by the
// analyze_job_match tool. Returns nil if no collector is configured — the
// caller surfaces that as a "tool not available" error rather than crashing.
//
// The provider's slot cache is process-wide so an agent that runs the
// analysis tool a few times in quick succession (a common debugging
// pattern) only triggers one collector query within the cache window.
func (s *Server) matchAnalysisProvider() *matchanalyzer.CollectorSlotProvider {
	s.matchAnalysisOnce.Do(func() {
		if s.collector == nil {
			return
		}
		s.matchAnalysisSlots = matchanalyzer.NewCollectorSlotProvider(
			s.collector,
			matchanalyzer.WithSlotCacheTTL(30*time.Second),
		)
	})
	return s.matchAnalysisSlots
}

// toolAnalyzeJobMatch implements the analyze_job_match MCP tool.
//
// Output shape: a "text" content block containing the human-readable
// rendering (so agents that don't parse structured data still get
// something useful) plus a "data" key in the tool response carrying the
// full JSON Result for agents that want to drive their own UI off it.
func (s *Server) toolAnalyzeJobMatch(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	jobID, ok := args["job_id"].(string)
	if !ok || jobID == "" {
		return nil, fmt.Errorf("job_id is required")
	}
	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		return nil, fmt.Errorf("invalid job_id: %w", err)
	}

	provider := s.matchAnalysisProvider()
	if provider == nil {
		// No collector wired — the analyzer has nothing to query against.
		// Fail explicitly rather than silently returning an empty result;
		// the user invoking the tool needs to know the AP isn't set up
		// for this analysis.
		return nil, fmt.Errorf("analyze_job_match requires a configured collector on this MCP server")
	}

	// Pull the job ad. Only Requirements + identifying triple are needed
	// — the analyzer doesn't read other attributes off the job.
	// Owner-scope so a non-admin caller can't analyze another user's
	// job and harvest its Requirements expression.
	idClause := fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc)
	constraint, ok := s.scopeToOwner(ctx, idClause)
	if !ok {
		return nil, fmt.Errorf("authentication required")
	}
	jobAds, _, err := s.schedd.QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Projection: []string{"ClusterId", "ProcId", "Requirements", "Owner"},
		Limit:      1,
	})
	if err != nil {
		return nil, fmt.Errorf("query job: %w", err)
	}
	if len(jobAds) == 0 {
		return nil, fmt.Errorf("job %s not found", jobID)
	}

	// 30s analysis timeout — same rationale as the HTTP handler. Keeps
	// a misconfigured collector or oversized pool from wedging the agent.
	analysisCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	a := matchanalyzer.New(provider)
	res, err := a.Analyze(analysisCtx, jobAds[0])
	if err != nil {
		return nil, fmt.Errorf("analyze: %w", err)
	}

	requirementsText := ""
	if reqExpr, ok := jobAds[0].Lookup("Requirements"); ok && reqExpr != nil {
		requirementsText = reqExpr.String()
	}

	textBlock := matchanalyzer.RenderText(res)
	if requirementsText != "" {
		textBlock = fmt.Sprintf("Job %s\nRequirements: %s\n\n%s", jobID, requirementsText, textBlock)
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": textBlock,
			},
		},
		// Include the structured data alongside the text. Agents that
		// know about it can drive their own visualization; agents that
		// don't simply ignore the extra field.
		"data": map[string]interface{}{
			"job_id":       jobID,
			"requirements": requirementsText,
			"result":       res,
			"slot_cache":   provider.CacheStatus(),
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
	llmConstraint, ok := args["constraint"].(string)
	if !ok || llmConstraint == "" {
		return nil, fmt.Errorf("constraint is required")
	}

	reason, _ := args["reason"].(string)
	if reason == "" {
		reason = "Removed via MCP bulk operation"
	}

	// Owner-scope the constraint so a non-admin caller's "remove
	// everything" turns into "remove everything I own". Admins skip
	// the wrapper for cross-user cleanup. CRITICAL: without this
	// wrapper an LLM prompt-injection setting constraint = "true"
	// could mass-remove every user's jobs (modulo schedd ACL).
	constraint, ok := s.scopeToOwner(ctx, llmConstraint)
	if !ok {
		return nil, fmt.Errorf("authentication required")
	}
	results, err := s.schedd.RemoveJobs(ctx, constraint, reason)
	if err != nil {
		return nil, fmt.Errorf("bulk job removal failed: %w", err)
	}

	if results.TotalJobs == 0 {
		return nil, fmt.Errorf("no jobs matched constraint '%s'", llmConstraint)
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("Removed %d of %d job(s) matching constraint '%s'",
					results.Success, results.TotalJobs, llmConstraint),
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
	llmConstraint, _ := args["constraint"].(string)
	// Owner-scope the constraint so a non-admin caller's history
	// query never returns another user's records — the upstream
	// schedd ACL is broadly READ on most pools, so without this
	// wrapper a `mcp:write` token holder could dump every user's
	// historical job ads.
	constraint, ok := s.scopeToOwner(ctx, llmConstraint)
	if !ok {
		return nil, fmt.Errorf("authentication required")
	}
	if constraint == "" {
		// scopeToOwner returns "" only for admin callers who passed
		// an empty LLM constraint. Use "true" so HistoryQuery
		// matches every record (the admin explicitly asked for it).
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
		// Reject any filename that could escape the spool dir on
		// the receiving schedd. Go's archive/tar won't escape, but
		// the schedd's tar untar is C++ and may be permissive — and
		// even if it isn't, this is a cheap defense-in-depth check
		// that mirrors the policy on the file-DOWNLOAD path.
		if err := validateTarEntryName(filename); err != nil {
			return nil, fmt.Errorf("files[%d].filename: %w", i, err)
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

// checkOAuthServicesNeeded queries the first proc of a submitted cluster to see if
// a job transform added the OAuthServicesNeeded attribute. If found, it returns a
// message instructing the user to bootstrap the required credentials.
func (s *Server) checkOAuthServicesNeeded(ctx context.Context, clusterID int) string {
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == 0", clusterID)
	projection := []string{"OAuthServicesNeeded"}
	opts := &htcondor.QueryOptions{
		Limit:      1,
		Projection: projection,
		FetchOpts:  htcondor.FetchMyJobs,
	}
	ads, _, err := s.schedd.QueryWithOptions(ctx, constraint, opts)
	if err != nil || len(ads) == 0 {
		return ""
	}
	services, ok := ads[0].EvaluateAttrString("OAuthServicesNeeded")
	if !ok || services == "" {
		return ""
	}

	hasCredd := s.credd != nil
	var sb strings.Builder
	fmt.Fprintf(&sb, "\n\nOAUTH CREDENTIALS REQUIRED:\nThe job requires OAuth credentials for: %s\n", services)
	sb.WriteString("OAuth services added by server-side job transforms typically work with an empty credential.\n")
	if hasCredd {
		sb.WriteString("Use 'get_credential_status' to check if credentials exist for each service.\n")
		sb.WriteString("If missing, use 'store_service_credential' with an empty string as the credential value.\n")
		sb.WriteString("The job will remain held until the required credentials are available.")
	} else {
		sb.WriteString("Use the HTTP credential API to store the required credentials.\n")
		sb.WriteString("The job will remain held until the required credentials are available.")
	}
	return sb.String()
}

// toolListServiceCredentials lists all OAuth service credentials
func (s *Server) toolListServiceCredentials(ctx context.Context, _ map[string]interface{}) (interface{}, error) {
	if s.credd == nil {
		return nil, fmt.Errorf("credential service is not available")
	}

	creds, err := s.credd.ListServiceCreds(ctx, htcondor.CredTypeOAuth, "")
	if err != nil {
		return nil, fmt.Errorf("failed to list service credentials: %w", err)
	}

	if len(creds) == 0 {
		return map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": "No OAuth service credentials found.",
				},
			},
		}, nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Found %d service credential(s):\n\n", len(creds))
	for _, c := range creds {
		status := "present"
		if !c.Exists {
			status = "missing"
		}
		entry := fmt.Sprintf("- Service: %s", c.Service)
		if c.Handle != "" {
			entry += fmt.Sprintf(", Handle: %s", c.Handle)
		}
		entry += fmt.Sprintf(" [%s]", status)
		if c.UpdatedAt != nil {
			entry += fmt.Sprintf(" (updated: %s)", c.UpdatedAt.Format(time.RFC3339))
		}
		sb.WriteString(entry + "\n")
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": sb.String(),
			},
		},
	}, nil
}

// toolGetCredentialStatus checks whether an OAuth credential exists for a service
func (s *Server) toolGetCredentialStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if s.credd == nil {
		return nil, fmt.Errorf("credential service is not available")
	}

	service, ok := args["service"].(string)
	if !ok || service == "" {
		return nil, fmt.Errorf("service is required")
	}
	handle, _ := args["handle"].(string)

	status, err := s.credd.GetServiceCredStatus(ctx, htcondor.CredTypeOAuth, service, handle, "")
	if err != nil {
		if errors.Is(err, htcondor.ErrCredentialNotFound) {
			label := service
			if handle != "" {
				label += "/" + handle
			}
			return map[string]interface{}{
				"content": []map[string]interface{}{
					{
						"type": "text",
						"text": fmt.Sprintf("No credential found for service '%s'. You may need to store one using store_service_credential.", label),
					},
				},
			}, nil
		}
		return nil, fmt.Errorf("failed to query credential status: %w", err)
	}

	label := service
	if handle != "" {
		label += "/" + handle
	}
	text := fmt.Sprintf("Credential for service '%s': exists=%v", label, status.Exists)
	if status.UpdatedAt != nil {
		text += fmt.Sprintf(", updated_at=%s", status.UpdatedAt.Format(time.RFC3339))
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": text,
			},
		},
	}, nil
}

// toolStoreServiceCredential stores an OAuth credential for a service
func (s *Server) toolStoreServiceCredential(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if s.credd == nil {
		return nil, fmt.Errorf("credential service is not available")
	}

	service, ok := args["service"].(string)
	if !ok || service == "" {
		return nil, fmt.Errorf("service is required")
	}
	credential, ok := args["credential"].(string)
	if !ok || credential == "" {
		return nil, fmt.Errorf("credential is required")
	}
	handle, _ := args["handle"].(string)

	// Try base64 decode; fall back to raw bytes
	credBytes, err := base64.StdEncoding.DecodeString(credential)
	if err != nil {
		credBytes = []byte(credential)
	}

	if err := s.credd.PutServiceCred(ctx, htcondor.CredTypeOAuth, credBytes, service, handle, "", nil); err != nil {
		return nil, fmt.Errorf("failed to store credential: %w", err)
	}

	label := service
	if handle != "" {
		label += "/" + handle
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("Successfully stored OAuth credential for service '%s'.", label),
			},
		},
	}, nil
}

// toolDeleteServiceCredential removes an OAuth credential for a service
func (s *Server) toolDeleteServiceCredential(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if s.credd == nil {
		return nil, fmt.Errorf("credential service is not available")
	}

	service, ok := args["service"].(string)
	if !ok || service == "" {
		return nil, fmt.Errorf("service is required")
	}
	handle, _ := args["handle"].(string)

	if err := s.credd.DeleteServiceCred(ctx, htcondor.CredTypeOAuth, service, handle, ""); err != nil {
		if errors.Is(err, htcondor.ErrCredentialNotFound) {
			return nil, fmt.Errorf("credential not found for service '%s'", service)
		}
		return nil, fmt.Errorf("failed to delete credential: %w", err)
	}

	label := service
	if handle != "" {
		label += "/" + handle
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("Successfully deleted OAuth credential for service '%s'.", label),
			},
		},
	}, nil
}
