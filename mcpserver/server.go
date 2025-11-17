package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/metricsd"
)

// Server represents the MCP server
type Server struct {
	schedd             *htcondor.Schedd
	collector          *htcondor.Collector
	signingKeyPath     string
	trustDomain        string
	uidDomain          string
	logger             *logging.Logger
	metricsRegistry    *metricsd.Registry
	prometheusExporter *metricsd.PrometheusExporter
	stdin              io.Reader
	stdout             io.Writer
	validatedTokens    map[string]TokenInfo // Cache of validated tokens
	tokenMutex         sync.RWMutex
}

// TokenInfo stores information about a validated token
type TokenInfo struct {
	Username   string
	Expiration time.Time
}

// Config holds server configuration
type Config struct {
	ScheddName      string              // Schedd name
	ScheddAddr      string              // Schedd address (e.g., "127.0.0.1:9618"). If empty, discovered from collector.
	Schedd          *htcondor.Schedd    // Pre-configured Schedd instance (optional, if provided, ScheddName/ScheddAddr are ignored)
	SigningKeyPath  string              // Path to token signing key (optional, for token generation)
	TrustDomain     string              // Trust domain for token issuer (optional)
	UIDDomain       string              // UID domain for generated token username (optional)
	Collector       *htcondor.Collector // Collector for metrics and discovery (optional)
	EnableMetrics   bool                // Enable metrics collection (default: true if Collector is set)
	MetricsCacheTTL time.Duration       // Metrics cache TTL (default: 10s)
	Logger          *logging.Logger     // Logger instance (optional, creates default if nil)
	Stdin           io.Reader           // Input stream (default: os.Stdin)
	Stdout          io.Writer           // Output stream (default: os.Stdout)
}

// NewServer creates a new MCP server
func NewServer(cfg Config) (*Server, error) {
	// Initialize logger if not provided
	logger := cfg.Logger
	if logger == nil {
		var err error
		logger, err = logging.New(&logging.Config{
			OutputPath:   "stderr",
			MinVerbosity: logging.VerbosityInfo,
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
			scheddAddr, err = discoverSchedd(cfg.Collector, cfg.ScheddName, 10*time.Second, logger)
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

	s := &Server{
		schedd:          schedd,
		collector:       cfg.Collector,
		trustDomain:     cfg.TrustDomain,
		uidDomain:       cfg.UIDDomain,
		signingKeyPath:  cfg.SigningKeyPath,
		logger:          logger,
		stdin:           stdin,
		stdout:          stdout,
		validatedTokens: make(map[string]TokenInfo),
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
func discoverSchedd(collector *htcondor.Collector, scheddName string, timeout time.Duration, _ *logging.Logger) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	constraint := "true"
	if scheddName != "" {
		constraint = fmt.Sprintf("Name == %q", scheddName)
	}

	ads, err := collector.QueryAds(ctx, "ScheddAd", constraint)
	if err != nil {
		return "", fmt.Errorf("collector query failed: %w", err)
	}

	if len(ads) == 0 {
		if scheddName != "" {
			return "", fmt.Errorf("schedd '%s' not found in collector", scheddName)
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

	// Start token cleanup goroutine
	s.startTokenCleanup(ctx)

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
		result, err := s.handleCallTool(ctx, msg.Params)
		if err != nil {
			response.Error = &MCPError{
				Code:    -32000,
				Message: err.Error(),
			}
		} else {
			response.Result = result
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

// markTokenValidated adds a token to the validated cache after successful authentication
func (s *Server) markTokenValidated(token, username string, expiration time.Time) {
	s.tokenMutex.Lock()
	defer s.tokenMutex.Unlock()
	s.validatedTokens[token] = TokenInfo{
		Username:   username,
		Expiration: expiration,
	}
}

// getValidatedUsername returns the username if the token is in the validated cache and not expired
// Returns empty string if token is not validated or expired
func (s *Server) getValidatedUsername(token string) string {
	s.tokenMutex.RLock()
	defer s.tokenMutex.RUnlock()

	info, exists := s.validatedTokens[token]
	if !exists {
		return ""
	}

	// Check if token is expired
	if time.Now().After(info.Expiration) {
		return ""
	}

	return info.Username
}

// startTokenCleanup starts a goroutine that periodically removes expired tokens from cache
func (s *Server) startTokenCleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.cleanupExpiredTokens()
			}
		}
	}()
}

// cleanupExpiredTokens removes expired tokens from the cache
func (s *Server) cleanupExpiredTokens() {
	s.tokenMutex.Lock()
	defer s.tokenMutex.Unlock()

	now := time.Now()
	for token, info := range s.validatedTokens {
		if now.After(info.Expiration) {
			delete(s.validatedTokens, token)
		}
	}
}

// handleInitialize handles the initialize request
func (s *Server) handleInitialize(_ context.Context, _ json.RawMessage) interface{} {
	return map[string]interface{}{
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
}
