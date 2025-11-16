package httpserver

import (
	"net/http"

	"github.com/bbockelm/golang-htcondor/logging"
)

// setupRoutes sets up all HTTP routes
func (s *Server) setupRoutes(mux *http.ServeMux) {
	// OpenAPI schema
	mux.HandleFunc("/openapi.json", s.handleOpenAPISchema)

	// Job management endpoints
	mux.HandleFunc("/api/v1/jobs", s.handleJobs)
	mux.HandleFunc("/api/v1/jobs/", s.handleJobByID) // Pattern with trailing slash catches /api/v1/jobs/{id}

	// MCP endpoints (OAuth2 protected)
	if s.oauth2Provider != nil {
		// OAuth2 endpoints
		mux.HandleFunc("/mcp/oauth2/authorize", s.handleOAuth2Authorize)
		mux.HandleFunc("/mcp/oauth2/token", s.handleOAuth2Token)
		mux.HandleFunc("/mcp/oauth2/introspect", s.handleOAuth2Introspect)
		mux.HandleFunc("/mcp/oauth2/revoke", s.handleOAuth2Revoke)

		// MCP protocol endpoint
		mux.HandleFunc("/mcp/message", s.handleMCPMessage)

		s.logger.Info(logging.DestinationHTTP, "MCP endpoints enabled", "path_prefix", "/mcp")
	}

	// Metrics endpoint (if enabled)
	if s.prometheusExporter != nil {
		mux.HandleFunc("/metrics", s.handleMetrics)
	}
}
