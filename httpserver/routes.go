package httpserver

import (
	"net/http"

	"github.com/bbockelm/golang-htcondor/logging"
)

// setupRoutes sets up all HTTP routes
func (s *Server) setupRoutes(mux *http.ServeMux) {
	// CORS middleware: allow all origins
	cors := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			h.ServeHTTP(w, r)
		})
	}

	// Welcome page at root
	mux.HandleFunc("/", s.handleWelcome)

	// Login endpoint
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)

	// OpenAPI schema and Swagger UI
	mux.Handle("/openapi.json", cors(http.HandlerFunc(s.handleOpenAPISchema)))
	mux.HandleFunc("/docs", s.handleSwaggerUI)
	mux.HandleFunc("/docs/oauth2-redirect", s.handleSwaggerOAuth2Redirect)

	// Job management endpoints
	mux.Handle("/api/v1/jobs", cors(http.HandlerFunc(s.handleJobs)))
	mux.Handle("/api/v1/jobs/", cors(http.HandlerFunc(s.handleJobByID))) // Pattern with trailing slash catches /api/v1/jobs/{id}

	// Job history endpoints
	mux.Handle("/api/v1/jobs/archive", cors(http.HandlerFunc(s.handleJobHistory)))
	mux.Handle("/api/v1/jobs/epochs", cors(http.HandlerFunc(s.handleJobEpochs)))
	mux.Handle("/api/v1/jobs/transfers", cors(http.HandlerFunc(s.handleJobTransfers)))

	// Credential management endpoints (credd)
	mux.Handle("/api/v1/creds/user", cors(http.HandlerFunc(s.handleUserCredential)))
	mux.Handle("/api/v1/creds/service", cors(http.HandlerFunc(s.handleServiceCredentialCollection)))
	mux.Handle("/api/v1/creds/service/", cors(http.HandlerFunc(s.handleServiceCredentialItem)))

	// Authentication endpoint
	mux.Handle("/api/v1/whoami", cors(http.HandlerFunc(s.handleWhoAmI)))

	// Collector endpoints
	mux.HandleFunc("/api/v1/collector/", s.handleCollectorPath) // Pattern with trailing slash catches /api/v1/collector/* paths

	// Ping endpoints
	mux.HandleFunc("/api/v1/ping", s.handlePing)              // Ping both collector and schedd
	mux.HandleFunc("/api/v1/schedd/ping", s.handleScheddPing) // Ping schedd only
	// Collector ping is handled via /api/v1/collector/ping in handleCollectorPath

	// MCP endpoints (OAuth2 protected)
	if s.oauth2Provider != nil {
		// OAuth2 metadata discovery (RFC 8414 and RFC 9068)
		mux.HandleFunc("/.well-known/oauth-authorization-server", s.handleOAuth2Metadata)
		mux.HandleFunc("/.well-known/oauth-protected-resource", s.handleOAuth2ProtectedResourceMetadata)

		// OAuth2 endpoints
		mux.HandleFunc("/mcp/oauth2/authorize", s.handleOAuth2Authorize)
		mux.HandleFunc("/mcp/oauth2/consent", s.handleOAuth2Consent)   // Consent page
		mux.HandleFunc("/mcp/oauth2/callback", s.handleOAuth2Callback) // SSO callback
		mux.HandleFunc("/mcp/oauth2/token", s.handleOAuth2Token)
		mux.HandleFunc("/mcp/oauth2/introspect", s.handleOAuth2Introspect)
		mux.HandleFunc("/mcp/oauth2/revoke", s.handleOAuth2Revoke)
		mux.HandleFunc("/mcp/oauth2/register", s.handleOAuth2Register) // Dynamic client registration (RFC 7591)

		// Device code flow endpoints (RFC 8628)
		mux.HandleFunc("/mcp/oauth2/device/authorize", s.handleOAuth2DeviceAuthorize)
		mux.HandleFunc("/mcp/oauth2/device/verify", s.handleOAuth2DeviceVerify)

		// MCP protocol endpoint
		mux.HandleFunc("/mcp/message", s.handleMCPMessage)

		s.logger.Info(logging.DestinationHTTP, "MCP endpoints enabled", "path_prefix", "/mcp")
	}

	// IDP endpoints (if enabled)
	if s.idpProvider != nil {
		// OIDC discovery metadata (only under /idp prefix)
		mux.HandleFunc("/idp/.well-known/openid-configuration", s.handleIDPMetadata)

		// IDP OAuth2 endpoints
		mux.HandleFunc("/idp/login", s.handleIDPLogin)
		mux.HandleFunc("/idp/authorize", s.handleIDPAuthorize)
		mux.HandleFunc("/idp/token", s.handleIDPToken)
		mux.HandleFunc("/idp/userinfo", s.handleIDPUserInfo)
		mux.HandleFunc("/idp/.well-known/jwks.json", s.handleIDPJWKS)

		s.logger.Info(logging.DestinationHTTP, "IDP endpoints enabled", "path_prefix", "/idp")
	}

	// Metrics endpoint (if enabled)
	if s.prometheusExporter != nil {
		mux.HandleFunc("/metrics", s.handleMetrics)
	}

	// Health and readiness endpoints for Kubernetes
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
}
