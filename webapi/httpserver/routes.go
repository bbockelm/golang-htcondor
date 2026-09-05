package httpserver

import (
	"net/http"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/webui"
)

// setupRoutes sets up all HTTP routes for the Handler.
//
// CORS: by default we don't emit Access-Control-Allow-Origin at all
// (the SPA is same-origin so browsers don't need it). When the
// operator wires up the API to a separate-origin SPA they should
// configure HTTP_API_BASE_URL; we then echo Origin back when it
// matches the configured base URL, with credentials enabled. This
// is stricter than the previous "Allow-Origin: *" policy, which
// the audit flagged as accidentally making the API broadly
// crawlable.
//
// Browsers refuse to send cookies on cross-origin XHR with
// Allow-Origin: * regardless, so the previous policy didn't expose
// authenticated data — but it did mean any third-party page could
// fetch unauthenticated endpoints (the welcome page, /healthz,
// version info) and read responses, including any that leaked
// upstream metadata.
const (
	// mcpMessagePath is the MCP protocol endpoint: the resource whose
	// identifier OAuth clients validate against.
	mcpMessagePath = "/mcp/message"
	// wellKnownProtectedResource is the RFC 9728 metadata path. The
	// resource-specific document lives at this plus the resource's own
	// path, so the two are written as one expression rather than as two
	// strings that can drift apart.
	wellKnownProtectedResource = "/.well-known/oauth-protected-resource"
)

func (h *Handler) setupRoutes() {
	mux := h.mux
	cors := func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && h.corsOriginAllowed(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Vary", "Origin")
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			handler.ServeHTTP(w, r)
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

	// /.well-known/ is discovery space, never SPA content. Without this
	// the root handler above answers every unregistered probe under it
	// with the SPA's index.html and a 200, so a client looking for JSON
	// reports a parse error on "<!DOCTYPE" and never learns that what it
	// asked for simply is not served here. A 404 says that plainly.
	//
	// Registered paths under /.well-known/ still win: this is a subtree
	// pattern, and ServeMux prefers the longer, more specific match.
	mux.HandleFunc("/.well-known/", func(w http.ResponseWriter, r *http.Request) {
		h.writeError(w, http.StatusNotFound, "No metadata document is served at "+r.URL.Path)
	})

	// Login endpoint
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/logout", h.handleLogout)

	// OpenAPI schema and Swagger UI
	mux.Handle("/openapi.json", cors(http.HandlerFunc(h.handleOpenAPISchema)))
	mux.HandleFunc("/docs", h.handleSwaggerUI)
	mux.HandleFunc("/docs/oauth2-redirect", h.handleSwaggerOAuth2Redirect)

	// Job management endpoints
	mux.Handle("/api/v1/jobs/watch", cors(h.requireCondorScope(http.HandlerFunc(h.handleJobsWatch)))) // SSE job-ad change stream (more specific than /api/v1/jobs/ below)
	mux.Handle("/api/v1/jobs", cors(h.requireCondorScope(http.HandlerFunc(h.handleJobs))))
	mux.Handle("/api/v1/jobs/", cors(h.requireCondorScope(http.HandlerFunc(h.handleJobByID)))) // Pattern with trailing slash catches /api/v1/jobs/{id}

	// Job history endpoints
	mux.Handle("/api/v1/jobs/archive", cors(h.requireCondorScope(http.HandlerFunc(h.handleJobHistory))))
	mux.Handle("/api/v1/jobs/epochs", cors(h.requireCondorScope(http.HandlerFunc(h.handleJobEpochs))))
	mux.Handle("/api/v1/jobs/transfers", cors(h.requireCondorScope(http.HandlerFunc(h.handleJobTransfers))))

	// Credential management endpoints (credd)
	mux.Handle("/api/v1/creds/user", cors(h.requireCondorScope(http.HandlerFunc(h.handleUserCredential))))
	mux.Handle("/api/v1/creds/service", cors(h.requireCondorScope(http.HandlerFunc(h.handleServiceCredentialCollection))))
	mux.Handle("/api/v1/creds/service/", cors(h.requireCondorScope(http.HandlerFunc(h.handleServiceCredentialItem))))

	// Placement endpoints (condor_placementd). Catch-all under the
	// prefix so handlePlacementPath can route on the last segment; all
	// of them are admin-gated inside the handlers.
	mux.Handle("/api/v1/placement/", cors(http.HandlerFunc(h.handlePlacementPath)))

	// Authentication endpoint
	mux.Handle("/api/v1/whoami", cors(http.HandlerFunc(h.handleWhoAmI)))

	// Web UI session endpoints (browser-session aware; cookie-only)
	mux.Handle("/api/v1/auth/me", cors(http.HandlerFunc(h.handleAuthMe)))
	mux.Handle("/api/v1/auth/logout", cors(http.HandlerFunc(h.handleAuthLogout)))
	// Superuser mode toggle. Gated inside the handler on the dedicated
	// superuser group -- NOT the admin-UI group.
	mux.Handle("/api/v1/admin/superuser", cors(http.HandlerFunc(h.handleSuperuserMode)))

	// Web UI dashboard summary
	mux.Handle("/api/v1/dashboard", cors(h.requireCondorScope(http.HandlerFunc(h.handleDashboard))))

	// Public sandbox download via short-lived signed URL. No session
	// required — the token in ?t=... is the authorization.
	mux.Handle("/api/v1/share/output", cors(http.HandlerFunc(h.handleSharedOutput)))

	// Admin endpoints (gated on WebUIAdminGroup membership). The
	// gating is enforced inside each handler via requireAdmin so we
	// can return appropriate status codes (503 when the admin UI is
	// not configured, 403 when the user lacks the group, 401 when
	// no session is present).
	mux.Handle("/api/v1/admin/oauth2/clients", cors(http.HandlerFunc(h.handleAdminListClients)))
	// The per-client path carries both the delete and the notes edit;
	// split here so each handler can stay about one verb.
	mux.Handle("/api/v1/admin/oauth2/clients/", cors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			h.handleAdminUpdateClient(w, r)
			return
		}
		h.handleAdminDeleteClient(w, r)
	})))
	mux.Handle("/api/v1/admin/oauth2/tokens", cors(http.HandlerFunc(h.handleAdminListTokens)))
	mux.Handle("/api/v1/admin/oauth2/revoke", cors(http.HandlerFunc(h.handleAdminRevokeTokens)))
	mux.Handle("/api/v1/admin/logs", cors(http.HandlerFunc(h.handleAdminLogs)))
	mux.Handle("/api/v1/admin/condor-config", cors(http.HandlerFunc(h.handleAdminCondorConfig)))
	// API key management (admin-only). The collection path covers
	// list (GET) and create (POST); the per-key path is for soft-
	// delete (DELETE /api/v1/admin/api-keys/{key_id}).
	mux.Handle("/api/v1/admin/api-keys", cors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			h.handleAdminCreateAPIKey(w, r)
			return
		}
		h.handleAdminListAPIKeys(w, r)
	})))
	mux.Handle("/api/v1/admin/api-keys/", cors(http.HandlerFunc(h.handleAdminDeleteAPIKey)))

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

	// Chat endpoint (LLM-backed assistant for the jobs view). The
	// handlers themselves return 503 when the chat engine isn't
	// configured; we always register so the SPA's /info probe
	// gets a sensible answer regardless of feature state.
	mux.Handle("/api/v1/chat", cors(http.HandlerFunc(h.handleChat)))
	mux.Handle("/api/v1/chat/info", cors(http.HandlerFunc(h.handleChatInfo)))

	// Collector endpoints
	mux.Handle("/api/v1/collector/watch", cors(h.requireCondorScope(http.HandlerFunc(h.handleCollectorWatch)))) // SSE ad-change stream (more specific than the dispatcher below)
	mux.Handle("/api/v1/collector/", h.requireCondorScope(http.HandlerFunc(h.handleCollectorPath)))             // Pattern with trailing slash catches /api/v1/collector/* paths

	// htcondordb mirror status (admin-gated inside the handler). The
	// data is on /readyz and /metrics too, but both of those answer a
	// monitoring system; this one answers the admin UI.
	mux.Handle("/api/v1/dbmirror/status", cors(http.HandlerFunc(h.handleDBMirrorStatus)))
	// An on-demand probe, so an operator debugging a mirror does not have
	// to leave the page or wait for the background poller's next tick to
	// see whether a change they just made worked.
	mux.Handle("/api/v1/dbmirror/test", cors(http.HandlerFunc(h.handleDBMirrorTest)))

	// Ping endpoints
	mux.HandleFunc("/api/v1/ping", h.handlePing)              // Ping both collector and schedd
	mux.HandleFunc("/api/v1/schedd/ping", h.handleScheddPing) // Ping schedd only
	// Collector ping is handled via /api/v1/collector/ping in handleCollectorPath

	// MCP endpoints (OAuth2 protected)
	if h.oauth2Provider != nil {
		// OAuth2 metadata discovery (RFC 8414 and RFC 9068)
		mux.HandleFunc("/.well-known/oauth-authorization-server", h.handleOAuth2Metadata)
		mux.HandleFunc(wellKnownProtectedResource, h.handleOAuth2ProtectedResourceMetadata)
		// RFC 9728 section 3.1: a resource with a path is described at
		// that path appended to the well-known one. MCP clients derive
		// this URL from the server URL they were configured with, so
		// without it they fetch a document that does not exist -- see
		// handleOAuth2ProtectedResourceMetadata.
		mux.HandleFunc(wellKnownProtectedResource+mcpMessagePath, h.handleOAuth2ProtectedResourceMetadata)

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
		mux.HandleFunc(mcpMessagePath, h.handleMCPMessage)

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
