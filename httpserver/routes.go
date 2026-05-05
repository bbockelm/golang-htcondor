package httpserver

import (
	"net/http"

	"github.com/bbockelm/golang-htcondor/httpserver/webui"
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

	// Root handler: serve the embedded SPA when the frontend is compiled in,
	// otherwise fall back to the legacy welcome page.
	if webui.IsEmbedded() {
		spa := webui.NewSPAHandler()
		mux.Handle("/", spa)
	} else {
		mux.HandleFunc("/", h.handleWelcome)
	}

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

	// Web UI session endpoints (browser-session aware; cookie-only)
	mux.Handle("/api/v1/auth/me", cors(http.HandlerFunc(h.handleAuthMe)))
	mux.Handle("/api/v1/auth/logout", cors(http.HandlerFunc(h.handleAuthLogout)))

	// Web UI dashboard summary
	mux.Handle("/api/v1/dashboard", cors(http.HandlerFunc(h.handleDashboard)))

	// Public sandbox download via short-lived signed URL. No session
	// required — the token in ?t=... is the authorization.
	mux.Handle("/api/v1/share/output", cors(http.HandlerFunc(h.handleSharedOutput)))

	// Admin endpoints (gated on WebUIAdminGroup membership). The
	// gating is enforced inside each handler via requireAdmin so we
	// can return appropriate status codes (503 when the admin UI is
	// not configured, 403 when the user lacks the group, 401 when
	// no session is present).
	mux.Handle("/api/v1/admin/oauth2/clients", cors(http.HandlerFunc(h.handleAdminListClients)))
	mux.Handle("/api/v1/admin/oauth2/clients/", cors(http.HandlerFunc(h.handleAdminDeleteClient)))
	mux.Handle("/api/v1/admin/oauth2/tokens", cors(http.HandlerFunc(h.handleAdminListTokens)))
	mux.Handle("/api/v1/admin/logs", cors(http.HandlerFunc(h.handleAdminLogs)))

	// Build/version info endpoint (authenticated)
	mux.Handle("/api/v1/version", cors(http.HandlerFunc(h.handleVersion)))

	// JupyterLab tunnel endpoints. Catch-all under /jupyter/ so the inner
	// dispatcher (handleJupyterPath) can route on the verb segment. Note:
	// no CORS wrapper — the proxy serves user-facing assets that often
	// embed in an iframe and don't want extra CORS headers from us.
	mux.HandleFunc("/api/v1/jupyter/", h.handleJupyterPath)

	// Interactive batch jobs (terminal sessions backed by a vanilla-universe
	// watchdog the SSH bridge heartbeats over the existing ssh.Client).
	// POST creates a session, GET lists the caller's sessions.
	mux.Handle("/api/v1/interactive/terminal", cors(http.HandlerFunc(h.handleInteractiveTerminal)))

	// Batch-submission templates: built-in + global + user-saved.
	// Catch-all so handleTemplates can split on the trailing /{id}.
	mux.Handle("/api/v1/templates", cors(http.HandlerFunc(h.handleTemplates)))
	mux.Handle("/api/v1/templates/", cors(http.HandlerFunc(h.handleTemplates)))

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

	// Metrics endpoint. Always registered: even without a
	// metricsdRegistry (no Collector configured), httpMetricsState
	// exposes the HTTP request counters and Go-runtime/process
	// collectors that prometheus/client_golang ships with by default.
	mux.HandleFunc("/metrics", h.handleMetrics)

	// Health and readiness endpoints for Kubernetes
	mux.HandleFunc("/healthz", h.handleHealthz)
	mux.HandleFunc("/readyz", h.handleReadyz)
}
