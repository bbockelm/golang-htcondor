package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/metricsd"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/matchanalyzer"
)

// Server represents the MCP server
type Server struct {
	schedd             *htcondor.Schedd
	collector          *htcondor.Collector
	credd              htcondor.CreddClient
	instructions       string // Server-level instructions surfaced to agents in the initialize response
	signingKeyPath     string
	trustDomain        string
	uidDomain          string
	httpBaseURL        string // Base URL for HTTP API (e.g., "http://localhost:8080") for file download links
	logger             *logging.Logger
	metricsRegistry    *metricsd.Registry
	prometheusExporter *metricsd.PrometheusExporter
	delegated          bool
	stdin              io.Reader
	stdout             io.Writer
	// matchAnalysisOnce / matchAnalysisSlots back the lazy-allocated
	// CollectorSlotProvider used by the analyze_job_match tool. Same
	// motivation as the httpserver Handler equivalent: keep the slot
	// cache alive across calls so a debug session that re-runs analysis
	// only triggers one collector query per cache window.
	matchAnalysisOnce  sync.Once
	matchAnalysisSlots *matchanalyzer.CollectorSlotProvider

	// adminUsers is the set of subjects (JWT `sub` values) treated
	// as administrators. Admin users skip the per-tool owner-scope
	// wrapper that otherwise forces every query / mutation to be
	// limited to the caller's own jobs. Configured via
	// Config.AdminUsers; nil/empty means no admin users (default —
	// every authenticated caller is treated as a normal user).
	adminUsers map[string]struct{}

	// htcondorConfig is the ambient HTCondor configuration, used to build the CLIENT security
	// config when dialing the htcondordb database for the DB-backed tools. nil disables them.
	htcondorConfig *config.Config
	// dbMirror discovers and dials the synchronized htcondordb mirror, and owns the
	// policy for when a read may be served from it (webapi/dbmirror). Shared with the
	// REST API so both surfaces route on the same freshness rules.
	dbMirror *dbmirror.Locator
}

// Config holds server configuration
type Config struct {
	ScheddName string // Schedd name
	ScheddAddr string // Schedd address (e.g., "127.0.0.1:9618"). If empty, discovered from collector.
	// ScheddHost is the SCHEDD_HOST setting: the host (optionally
	// "name@host", optionally with a port) whose schedd this server
	// should talk to. Consulted when neither ScheddAddr nor ScheddName
	// is set, and it selects that host's schedd rather than whichever
	// one the collector lists first.
	ScheddHost      string
	Schedd          *htcondor.Schedd     // Pre-configured Schedd instance (optional, if provided, ScheddName/ScheddAddr are ignored)
	SigningKeyPath  string               // Path to token signing key (optional, for token generation)
	TrustDomain     string               // Trust domain for token issuer (optional)
	UIDDomain       string               // UID domain for generated token username (optional)
	HTTPBaseURL     string               // Base URL for HTTP API (e.g., "http://localhost:8080") for file download links
	Collector       *htcondor.Collector  // Collector for metrics and discovery (optional)
	Credd           htcondor.CreddClient // Optional credd client for credential management
	Instructions    string               // Server-level instructions provided to all agents in the MCP initialize response
	EnableMetrics   bool                 // Enable metrics collection (default: true if Collector is set)
	MetricsCacheTTL time.Duration        // Metrics cache TTL (default: 10s)
	Logger          *logging.Logger      // Logger instance (optional, creates default if nil)
	Stdin           io.Reader            // Input stream (default: os.Stdin)
	Stdout          io.Writer            // Output stream (default: os.Stdout)
	// AdminUsers is the list of authenticated subjects (JWT `sub` /
	// authenticated username) who get admin treatment in tool
	// dispatch — most importantly, they are exempt from the
	// per-tool owner-scope wrapper that otherwise restricts queries
	// and mutations to the caller's own jobs. Match must be exact
	// against the value returned by
	// htcondor.GetAuthenticatedUserFromContext (typically
	// "user@uid.domain"). Empty list = no admin users (default).
	AdminUsers []string

	// HTCondorConfig is the ambient HTCondor configuration. When set (together with a
	// Collector), the htcondordb-backed tools are enabled: the server discovers the database
	// via the collector and authenticates to it using this config's SEC_* knobs. nil disables
	// those tools.
	HTCondorConfig *config.Config

	// Delegated marks a server that acts on behalf of remote callers
	// rather than running as the user, which is the case when webapi
	// embeds it behind HTTP. It changes what an unknown caller means:
	// a delegated server must refuse an owner-scoped tool it cannot
	// confine, while a server run from a user's shell over stdio is
	// already confined by being that user's process. Default false, so
	// the stdio CLI keeps working exactly as before.
	Delegated bool

	// htcondordb mirror routing, mirroring the REST handler's config of
	// the same name so one daemon routes both surfaces identically. See
	// dbmirror.Options.
	DBMirrorName     string // HTTP_API_DBMIRROR_NAME
	DBMirrorAddress  string // HTTP_API_DBMIRROR_ADDRESS
	DBMirrorRequired bool   // HTTP_API_DBMIRROR_REQUIRED
}

// NewServer creates a new MCP server
func NewServer(cfg Config) (*Server, error) {
	// Initialize logger if not provided
	logger := cfg.Logger
	if logger == nil {
		var err error
		logger, err = logging.New(&logging.Config{
			OutputPath: "stderr",
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create logger: %w", err)
		}
	}

	// Use provided schedd or create new one
	var schedd *htcondor.Schedd
	if cfg.Schedd != nil {
		// Reuse provided schedd instance
		logger.Debug(logging.DestinationSchedd, "Using provided schedd instance")
		schedd = cfg.Schedd
	} else {
		// Discover schedd address if not provided
		scheddAddr := cfg.ScheddAddr
		if scheddAddr == "" {
			if cfg.Collector == nil {
				return nil, fmt.Errorf("ScheddAddr not provided and Collector not configured for discovery")
			}

			logger.Infof(logging.DestinationSchedd, "ScheddAddr not provided, discovering schedd '%s' from collector...", cfg.ScheddName)
			var err error
			scheddAddr, err = discoverSchedd(cfg.Collector, cfg.ScheddName, cfg.ScheddHost, 10*time.Second, logger)
			if err != nil {
				return nil, fmt.Errorf("failed to discover schedd: %w", err)
			}
			logger.Info(logging.DestinationSchedd, "Discovered schedd", "address", scheddAddr)
		}

		// Create schedd with the address as-is (can be host:port or sinful string)
		schedd = htcondor.NewSchedd(cfg.ScheddName, scheddAddr)
	}

	// Default I/O streams
	stdin := cfg.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}
	stdout := cfg.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}

	adminUsers := make(map[string]struct{}, len(cfg.AdminUsers))
	for _, u := range cfg.AdminUsers {
		u = strings.TrimSpace(u)
		if u != "" {
			adminUsers[u] = struct{}{}
		}
	}

	s := &Server{
		schedd:         schedd,
		collector:      cfg.Collector,
		credd:          cfg.Credd,
		instructions:   buildInstructions(schedd.Name(), cfg.Instructions),
		trustDomain:    cfg.TrustDomain,
		uidDomain:      cfg.UIDDomain,
		signingKeyPath: cfg.SigningKeyPath,
		httpBaseURL:    cfg.HTTPBaseURL,
		logger:         logger,
		stdin:          stdin,
		stdout:         stdout,
		adminUsers:     adminUsers,
		htcondorConfig: cfg.HTCondorConfig,
		delegated:      cfg.Delegated,
		dbMirror: dbmirror.NewLocatorWithOptions(cfg.Collector, cfg.HTCondorConfig, dbmirror.Options{
			Name:     cfg.DBMirrorName,
			Address:  cfg.DBMirrorAddress,
			Required: cfg.DBMirrorRequired,
		}),
	}

	// Setup metrics if collector is provided
	enableMetrics := cfg.EnableMetrics
	if cfg.Collector != nil && !cfg.EnableMetrics {
		enableMetrics = true // Enable by default if collector is provided
	}

	if enableMetrics && cfg.Collector != nil {
		// Create metrics registry and Prometheus exporter
		s.metricsRegistry = metricsd.NewRegistry()
		s.prometheusExporter = metricsd.NewPrometheusExporter(s.metricsRegistry)

		// Note: In MCP server, metrics collection is passive
		// The HTTP server would start the collector, but here we just make it available
		// cacheTTL from cfg.MetricsCacheTTL would be used if we implement background collection
	}

	return s, nil
}

// discoverSchedd discovers a schedd from the collector
func discoverSchedd(collector *htcondor.Collector, scheddName, scheddHost string, timeout time.Duration, _ *logging.Logger) (string, error) {
	// A SCHEDD_HOST carrying a port is already an address; nothing to
	// look up.
	target := htcondor.ParseScheddHost(scheddHost)
	if scheddName == "" && target.Address() != "" {
		return target.Address(), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	constraint := "true"
	switch {
	case scheddName != "":
		constraint = fmt.Sprintf("Name == %q", scheddName)
	case target.IsSet():
		constraint = target.CollectorConstraint()
	}

	ads, _, err := collector.QueryAdsWithOptions(ctx, "ScheddAd", constraint, nil)
	if err != nil {
		return "", fmt.Errorf("collector query failed: %w", err)
	}

	if len(ads) == 0 {
		switch {
		case scheddName != "":
			return "", fmt.Errorf("schedd '%s' not found in collector", scheddName)
		case target.IsSet():
			return "", fmt.Errorf("no schedd for SCHEDD_HOST %q found in collector", scheddHost)
		}
		return "", fmt.Errorf("no schedds found in collector")
	}

	// Extract MyAddress from the first matching schedd
	myAddr, ok := ads[0].EvaluateAttrString("MyAddress")
	if !ok {
		return "", fmt.Errorf("schedd ad missing MyAddress attribute")
	}

	return myAddr, nil
}

// MCPMessage represents an MCP protocol message
type MCPMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *MCPError       `json:"error,omitempty"`
}

// MCPError represents an MCP error
type MCPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Run starts the MCP server and processes messages
func (s *Server) Run(ctx context.Context) error {
	s.logger.Info(logging.DestinationGeneral, "Starting MCP server")

	decoder := json.NewDecoder(s.stdin)
	encoder := json.NewEncoder(s.stdout)

	for {
		select {
		case <-ctx.Done():
			s.logger.Info(logging.DestinationGeneral, "MCP server shutting down")
			return nil
		default:
		}

		var msg MCPMessage
		if err := decoder.Decode(&msg); err != nil {
			if err == io.EOF {
				s.logger.Info(logging.DestinationGeneral, "MCP server: client disconnected")
				return nil
			}
			s.logger.Error(logging.DestinationGeneral, "Failed to decode message", "error", err)
			continue
		}

		s.logger.Debug(logging.DestinationGeneral, "Received MCP message", "method", msg.Method, "id", msg.ID)

		// Handle the message
		response := s.handleMessage(ctx, &msg)

		// Send response
		if err := encoder.Encode(response); err != nil {
			s.logger.Error(logging.DestinationGeneral, "Failed to encode response", "error", err)
			continue
		}
	}
}

// handleMessage processes an MCP message and returns a response
func (s *Server) handleMessage(ctx context.Context, msg *MCPMessage) *MCPMessage {
	// Always set JSONRPC version
	response := &MCPMessage{
		JSONRPC: "2.0",
		ID:      msg.ID,
	}

	// Handle different methods
	switch msg.Method {
	case "initialize":
		response.Result = s.handleInitialize(ctx, msg.Params)
	case "tools/list":
		response.Result = s.handleListTools(ctx, msg.Params)
	case "tools/call":
		// Minted here, not inside handleCallTool: the id has to be
		// readable on THIS scope so the error result can carry the same
		// value the log line does. A context derived inside the callee
		// does not come back.
		traceID := newTraceID()
		ctx = withTraceID(ctx, traceID)
		result, err := s.handleCallTool(ctx, msg.Params)
		switch {
		case err == nil:
			response.Result = result
		case isProtocolError(err):
			// A malformed request: no tool ran, so there is no tool
			// result to return.
			response.Error = &MCPError{
				Code:    -32000,
				Message: err.Error(),
			}
		default:
			// A tool ran and failed. MCP wants that as a normal result
			// carrying isError, because a JSON-RPC error is a protocol
			// fault that clients surface as an opaque failure -- the
			// model never sees the text, so the diagnosis is thrown
			// away exactly when it is needed.
			response.Result = toolErrorResult(toolNameFromParams(msg.Params), traceID, err)
		}
	case "resources/list":
		response.Result = s.handleListResources(ctx, msg.Params)
	case "resources/read":
		result, err := s.handleReadResource(ctx, msg.Params)
		if err != nil {
			response.Error = &MCPError{
				Code:    -32000,
				Message: err.Error(),
			}
		} else {
			response.Result = result
		}
	default:
		response.Error = &MCPError{
			Code:    -32601,
			Message: fmt.Sprintf("Method not found: %s", msg.Method),
		}
	}

	return response
}

// HandleMessage is the public interface for handling MCP messages (used by HTTP handler)
func (s *Server) HandleMessage(ctx context.Context, msg *MCPMessage) *MCPMessage {
	return s.handleMessage(ctx, msg)
}

// SetStdin sets the input stream for the MCP server and returns the previous stream
func (s *Server) SetStdin(stdin io.Reader) io.Reader {
	old := s.stdin
	s.stdin = stdin
	return old
}

// SetStdout sets the output stream for the MCP server and returns the previous stream
func (s *Server) SetStdout(stdout io.Writer) io.Writer {
	old := s.stdout
	s.stdout = stdout
	return old
}

// handleInitialize handles the initialize request
func (s *Server) handleInitialize(_ context.Context, _ json.RawMessage) interface{} {
	result := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools":     map[string]interface{}{},
			"resources": map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    "htcondor-mcp",
			"version": "0.1.0",
		},
	}
	if s.instructions != "" {
		s.logger.Info(logging.DestinationMCP, "Including instructions in initialize response", "length", len(s.instructions))
		result["instructions"] = s.instructions
	}
	return result
}

// toolNameFromParams re-reads just the tool name from a tools/call
// params blob, for error reporting. The dispatcher has already parsed
// and validated these params by the time we need this, so a failure here
// means the name is genuinely absent rather than malformed.
func toolNameFromParams(params json.RawMessage) string {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &req); err != nil || req.Name == "" {
		return "unknown"
	}
	return req.Name
}
