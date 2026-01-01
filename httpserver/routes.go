package httpserver

import (
	"net/http"

	"github.com/bbockelm/golang-htcondor/logging"
)

// setupRoutes sets up all HTTP routes for the Handler
func (h *Handler) setupRoutes() {
	mux := h.mux
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
	mux.HandleFunc("/", h.handleWelcome)

	// Login endpoint
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/logout", h.handleLogout)

	// OpenAPI schema and Swagger UI
	mux.Handle("/openapi.json", cors(http.HandlerFunc(h.handleOpenAPISchema)))
	mux.HandleFunc("/docs", h.handleSwaggerUI)
	mux.HandleFunc("/docs/oauth2-redirect", h.handleSwaggerOAuth2Redirect)

	// Job management endpoints
	mux.Handle("/api/v1/jobs", cors(http.HandlerFunc(h.handleJobs)))
	mux.Handle("/api/v1/jobs/", cors(http.HandlerFunc(h.handleJobByID))) // Pattern with trailing slash catches /api/v1/jobs/{id}

	// Job history endpoints
	mux.Handle("/api/v1/jobs/archive", cors(http.HandlerFunc(h.handleJobHistory)))
	mux.Handle("/api/v1/jobs/epochs", cors(http.HandlerFunc(h.handleJobEpochs)))
	mux.Handle("/api/v1/jobs/transfers", cors(http.HandlerFunc(h.handleJobTransfers)))

	// Credential management endpoints (credd)
	mux.Handle("/api/v1/creds/user", cors(http.HandlerFunc(h.handleUserCredential)))
	mux.Handle("/api/v1/creds/service", cors(http.HandlerFunc(h.handleServiceCredentialCollection)))
	mux.Handle("/api/v1/creds/service/", cors(http.HandlerFunc(h.handleServiceCredentialItem)))

	// Authentication endpoint
	mux.Handle("/api/v1/whoami", cors(http.HandlerFunc(h.handleWhoAmI)))

	// Collector endpoints
	mux.HandleFunc("/api/v1/collector/", h.handleCollectorPath) // Pattern with trailing slash catches /api/v1/collector/* paths

	// Ping endpoints
	mux.HandleFunc("/api/v1/ping", h.handlePing)              // Ping both collector and schedd
	mux.HandleFunc("/api/v1/schedd/ping", h.handleScheddPing) // Ping schedd only
	// Collector ping is handled via /api/v1/collector/ping in handleCollectorPath

	// MCP endpoints (OAuth2 protected)
	if h.oauth2Provider != nil {
		// OAuth2 metadata discovery (RFC 8414 and RFC 9068)
		mux.HandleFunc("/.well-known/oauth-authorization-server", h.handleOAuth2Metadata)
		mux.HandleFunc("/.well-known/oauth-protected-resource", h.handleOAuth2ProtectedResourceMetadata)

		// OAuth2 endpoints
		mux.HandleFunc("/mcp/oauth2/authorize", h.handleOAuth2Authorize)
		mux.HandleFunc("/mcp/oauth2/consent", h.handleOAuth2Consent)   // Consent page
		mux.HandleFunc("/mcp/oauth2/callback", h.handleOAuth2Callback) // SSO callback
		mux.HandleFunc("/mcp/oauth2/token", h.handleOAuth2Token)
		mux.HandleFunc("/mcp/oauth2/introspect", h.handleOAuth2Introspect)
		mux.HandleFunc("/mcp/oauth2/revoke", h.handleOAuth2Revoke)
		mux.HandleFunc("/mcp/oauth2/register", h.handleOAuth2Register) // Dynamic client registration (RFC 7591)

		// Device code flow endpoints (RFC 8628)
		mux.HandleFunc("/mcp/oauth2/device/authorize", h.handleOAuth2DeviceAuthorize)
		mux.HandleFunc("/mcp/oauth2/device/verify", h.handleOAuth2DeviceVerify)

		// MCP protocol endpoint
		mux.HandleFunc("/mcp/message", h.handleMCPMessage)

		h.logger.Info(logging.DestinationHTTP, "MCP endpoints enabled", "path_prefix", "/mcp")
	}

	// IDP endpoints (if enabled)
	if h.idpProvider != nil {
		// OIDC discovery metadata (only under /idp prefix)
		mux.HandleFunc("/idp/.well-known/openid-configuration", h.handleIDPMetadata)

		// IDP OAuth2 endpoints
		mux.HandleFunc("/idp/login", h.handleIDPLogin)
		mux.HandleFunc("/idp/authorize", h.handleIDPAuthorize)
		mux.HandleFunc("/idp/token", h.handleIDPToken)
		mux.HandleFunc("/idp/userinfo", h.handleIDPUserInfo)
		mux.HandleFunc("/idp/.well-known/jwks.json", h.handleIDPJWKS)

		h.logger.Info(logging.DestinationHTTP, "IDP endpoints enabled", "path_prefix", "/idp")
	}

	// Metrics endpoint (if enabled)
	if h.prometheusExporter != nil {
		mux.HandleFunc("/metrics", h.handleMetrics)
	}

	// Health and readiness endpoints for Kubernetes
	mux.HandleFunc("/healthz", h.handleHealthz)
	mux.HandleFunc("/readyz", h.handleReadyz)
}
