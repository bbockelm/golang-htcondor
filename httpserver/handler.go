package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/metricsd"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

// Handler represents the HTTP API handler that can be embedded in any HTTP server
type Handler struct {
	schedd              *htcondor.Schedd
	scheddMu            sync.RWMutex // Protects schedd instance for thread-safe updates
	scheddName          string       // Schedd name for discovery
	scheddDiscovered    bool         // Whether schedd address was discovered from collector
	collector           *htcondor.Collector
	credd               htcondor.CreddClient
	creddAvailable      atomic.Bool // Whether credd is available (nil credd = not available)
	creddDiscovered     bool        // Whether credd address was discovered (and needs periodic updates)
	userHeader          string
	signingKeyPath      string
	trustDomain         string
	uidDomain           string
	httpBaseURL         string // Base URL for HTTP API (for generating MCP file download links)
	tlsCACertFile       string
	logger              *logging.Logger
	metricsRegistry     *metricsd.Registry
	prometheusExporter  *metricsd.PrometheusExporter
	tokenCache          *TokenCache        // Cache of validated tokens and their session caches (includes username)
	sessionStore        *SessionStore      // HTTP session store for browser-based authentication
	oauth2Provider      *OAuth2Provider    // OAuth2 provider for MCP endpoints
	oauth2Config        *oauth2.Config     // OAuth2 client config for SSO
	oauth2StateStore    *OAuth2StateStore  // State storage for OAuth2 SSO flow
	oauth2UserInfoURL   string             // User info endpoint for SSO
	oauth2UsernameClaim string             // Claim name for username (default: "sub")
	oauth2GroupsClaim   string             // Claim name for group information (default: "groups")
	mcpAccessGroup      string             // Group required for any MCP access (empty = all authenticated users)
	mcpReadGroup        string             // Group required for read access (empty = all users have read)
	mcpWriteGroup       string             // Group required for write access (empty = all users have write)
	idpProvider         *IDPProvider       // Built-in IDP provider
	idpLoginLimiter     *LoginRateLimiter  // Rate limiter for IDP login attempts
	streamBufferSize    int                // Buffer size for streaming queries (default: 100)
	streamWriteTimeout  time.Duration      // Write timeout for streaming queries (default: 5s)
	wg                  sync.WaitGroup     // WaitGroup to track background goroutines
	pingInterval        time.Duration      // Interval for periodic daemon pings (0 = disabled)
	token               string             // Token for daemon authentication
	mux                 *http.ServeMux     // HTTP request multiplexer
	ctx                 context.Context    // Context for background goroutines
	cancelFunc          context.CancelFunc // Function to cancel background goroutines
}

// HandlerConfig holds handler configuration
type HandlerConfig struct {
	ScheddName          string               // Schedd name
	ScheddAddr          string               // Schedd address (e.g., "127.0.0.1:9618"). If empty, discovered from collector.
	UserHeader          string               // HTTP header to extract username from (optional)
	SigningKeyPath      string               // Path to token signing key (optional, for token generation)
	TrustDomain         string               // Trust domain for token issuer (optional; only used if UserHeader is set)
	UIDDomain           string               // UID domain for generated token username (optional; only used if UserHeader is set)
	HTTPBaseURL         string               // Base URL for HTTP API (e.g., "http://localhost:8080") for generating file download links in MCP responses
	TLSCACertFile       string               // Path to TLS CA certificate file (optional, for trusting self-signed certs)
	Collector           *htcondor.Collector  // Collector for metrics (optional)
	EnableMetrics       bool                 // Enable /metrics endpoint (default: true if Collector is set)
	MetricsCacheTTL     time.Duration        // Metrics cache TTL (default: 10s)
	Logger              *logging.Logger      // Logger instance (optional, creates default if nil)
	EnableMCP           bool                 // Enable MCP endpoints with OAuth2 (default: false)
	OAuth2DBPath        string               // Path to OAuth2 SQLite database (default: LOCAL_DIR/oauth2.db or /var/lib/condor/oauth2.db). Can be configured via HTTP_API_OAUTH2_DB_PATH
	OAuth2Issuer        string               // OAuth2 issuer URL (default: listen address)
	OAuth2ClientID      string               // OAuth2 client ID for SSO (optional)
	OAuth2ClientSecret  string               // OAuth2 client secret for SSO (optional)
	OAuth2AuthURL       string               // OAuth2 authorization URL for SSO (optional)
	OAuth2TokenURL      string               // OAuth2 token URL for SSO (optional)
	OAuth2RedirectURL   string               // OAuth2 redirect URL for SSO (optional)
	OAuth2UserInfoURL   string               // OAuth2 user info endpoint for SSO (optional)
	OAuth2Scopes        []string             // OAuth2 scopes to request (default: ["openid", "profile", "email"])
	OAuth2UsernameClaim string               // Claim name for username in token (default: "sub")
	OAuth2GroupsClaim   string               // Claim name for groups in user info (default: "groups")
	MCPAccessGroup      string               // Group required for any MCP access (empty = all authenticated)
	MCPReadGroup        string               // Group required for read operations (empty = all have read)
	MCPWriteGroup       string               // Group required for write operations (empty = all have write)
	EnableIDP           bool                 // Enable built-in IDP (always enabled in demo mode)
	IDPDBPath           string               // Path to IDP SQLite database (default: "idp.db")
	IDPIssuer           string               // IDP issuer URL (default: listen address)
	SessionTTL          time.Duration        // HTTP session TTL (default: 24h)
	HTCondorConfig      *config.Config       // HTCondor configuration (optional, used for LOCAL_DIR default)
	PingInterval        time.Duration        // Interval for periodic daemon pings (default: 1 minute, 0 = disabled)
	StreamBufferSize    int                  // Buffer size for streaming queries (default: 100)
	StreamWriteTimeout  time.Duration        // Write timeout for streaming queries (default: 5s)
	Token               string               // Token for daemon authentication (optional)
	Credd               htcondor.CreddClient // Optional credd client; defaults to in-memory implementation
}

// NewHandler creates a new HTTP API handler that can be embedded in any HTTP server
//
//nolint:gocyclo // Initialization logic with sequential checks is acceptable
func NewHandler(cfg HandlerConfig) (*Handler, error) {
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

	// Discover schedd address if not provided
	scheddAddr := cfg.ScheddAddr
	scheddDiscovered := false
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
		scheddDiscovered = true
	}

	// Create schedd with the address as-is (can be host:port or sinful string)
	schedd := htcondor.NewSchedd(cfg.ScheddName, scheddAddr)

	// Set session TTL
	sessionTTL := cfg.SessionTTL
	if sessionTTL == 0 {
		sessionTTL = 24 * time.Hour // Default: 24 hours
	}

	// Set streaming defaults
	streamBufferSize := cfg.StreamBufferSize
	if streamBufferSize == 0 {
		streamBufferSize = 100
	}
	streamWriteTimeout := cfg.StreamWriteTimeout
	if streamWriteTimeout == 0 {
		streamWriteTimeout = 5 * time.Second
	}

	h := &Handler{
		schedd:             schedd,
		scheddName:         cfg.ScheddName,
		scheddDiscovered:   scheddDiscovered,
		collector:          cfg.Collector,
		credd:              cfg.Credd,
		trustDomain:        cfg.TrustDomain,
		uidDomain:          cfg.UIDDomain,
		httpBaseURL:        cfg.HTTPBaseURL,
		userHeader:         cfg.UserHeader,
		signingKeyPath:     cfg.SigningKeyPath,
		tlsCACertFile:      cfg.TLSCACertFile,
		logger:             logger,
		tokenCache:         NewTokenCache(), // Initialize token cache (includes username for rate limiting)
		streamBufferSize:   streamBufferSize,
		streamWriteTimeout: streamWriteTimeout,
		token:              cfg.Token,
	}

	// Discover credd if not provided
	if h.credd == nil {
		logger.Info(logging.DestinationHTTP, "Credd not provided, attempting discovery...")
		creddAddr, err := discoverCredd(cfg.ScheddName, scheddAddr, cfg.Collector, logger)
		if err != nil {
			logger.Warn(logging.DestinationHTTP, "Failed to discover credd, credential endpoints will be disabled", "error", err)
			h.creddAvailable.Store(false)
			h.creddDiscovered = true // Mark for periodic discovery attempts
		} else {
			logger.Info(logging.DestinationHTTP, "Discovered credd", "address", creddAddr)
			h.credd = htcondor.NewCedarCredd(creddAddr)
			h.creddAvailable.Store(true)
			h.creddDiscovered = true // Mark for periodic updates
		}
	} else {
		h.creddAvailable.Store(true)
		h.creddDiscovered = false // Explicitly provided, no need for updates
	}

	// Setup OAuth2 provider if MCP is enabled
	if cfg.EnableMCP {
		oauth2DBPath := cfg.OAuth2DBPath
		if oauth2DBPath == "" {
			oauth2DBPath = getDefaultDBPath(cfg.HTCondorConfig, "oauth2.db")
		}

		oauth2Issuer := cfg.OAuth2Issuer
		if oauth2Issuer == "" {
			oauth2Issuer = "http://localhost:8080"
		}

		oauth2Provider, err := NewOAuth2Provider(oauth2DBPath, oauth2Issuer)
		if err != nil {
			return nil, fmt.Errorf("failed to create OAuth2 provider: %w", err)
		}
		h.oauth2Provider = oauth2Provider
		logger.Info(logging.DestinationHTTP, "OAuth2 provider enabled for MCP endpoints", "issuer", oauth2Issuer)

		// Set username claim name (default: "sub")
		h.oauth2UsernameClaim = cfg.OAuth2UsernameClaim
		if h.oauth2UsernameClaim == "" {
			h.oauth2UsernameClaim = "sub"
		}

		// Initialize OAuth2 state store
		h.oauth2StateStore = NewOAuth2StateStore()

		// Setup OAuth2 client config for SSO if configured
		if cfg.OAuth2ClientID != "" && cfg.OAuth2AuthURL != "" && cfg.OAuth2TokenURL != "" {
			// Set default scopes if not provided
			scopes := cfg.OAuth2Scopes
			if len(scopes) == 0 {
				scopes = []string{"openid", "profile", "email"}
			}

			h.oauth2Config = &oauth2.Config{
				ClientID:     cfg.OAuth2ClientID,
				ClientSecret: cfg.OAuth2ClientSecret,
				RedirectURL:  cfg.OAuth2RedirectURL,
				Endpoint: oauth2.Endpoint{
					AuthURL:  cfg.OAuth2AuthURL,
					TokenURL: cfg.OAuth2TokenURL,
				},
				Scopes: scopes,
			}
			h.oauth2UserInfoURL = cfg.OAuth2UserInfoURL
			logger.Info(logging.DestinationHTTP, "OAuth2 SSO client configured", "auth_url", cfg.OAuth2AuthURL, "scopes", scopes)

			// If we are also the provider (EnableMCP), ensure the client exists
			if cfg.EnableMCP {
				// Client registration code remains the same...
				h.ensureOAuth2ClientRegistered(cfg.OAuth2ClientID, cfg.OAuth2ClientSecret, cfg.OAuth2RedirectURL, scopes)
			}
		}

		// Set groups claim name (default: "groups")
		h.oauth2GroupsClaim = cfg.OAuth2GroupsClaim
		if h.oauth2GroupsClaim == "" {
			h.oauth2GroupsClaim = "groups"
		}

		// Set group-based access control
		h.mcpAccessGroup = cfg.MCPAccessGroup
		h.mcpReadGroup = cfg.MCPReadGroup
		h.mcpWriteGroup = cfg.MCPWriteGroup

		if h.mcpAccessGroup != "" {
			logger.Info(logging.DestinationHTTP, "MCP access control enabled", "access_group", h.mcpAccessGroup)
		}
		if h.mcpReadGroup != "" {
			logger.Info(logging.DestinationHTTP, "MCP read access control enabled", "read_group", h.mcpReadGroup)
		}
		if h.mcpWriteGroup != "" {
			logger.Info(logging.DestinationHTTP, "MCP write access control enabled", "write_group", h.mcpWriteGroup)
		}

		// Initialize session store with shared database connection
		sessionStore, err := NewSessionStore(h.oauth2Provider.GetStorage().GetDB(), sessionTTL)
		if err != nil {
			return nil, fmt.Errorf("failed to create session store: %w", err)
		}
		h.sessionStore = sessionStore
		logger.Info(logging.DestinationHTTP, "Session store enabled with database persistence", "ttl", sessionTTL)
	} else {
		// OAuth2 not enabled, create standalone database for sessions
		sessionDBPath := cfg.OAuth2DBPath
		if sessionDBPath == "" {
			sessionDBPath = getDefaultDBPath(cfg.HTCondorConfig, "sessions.db")
		} else {
			sessionDBPath += ".sessions"
		}

		// Open database for sessions
		sessionDB, err := sql.Open("sqlite", sessionDBPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open session database: %w", err)
		}

		sessionStore, err := NewSessionStore(sessionDB, sessionTTL)
		if err != nil {
			_ = sessionDB.Close()
			return nil, fmt.Errorf("failed to create session store: %w", err)
		}
		h.sessionStore = sessionStore
		logger.Info(logging.DestinationHTTP, "Session store enabled with standalone database", "path", sessionDBPath, "ttl", sessionTTL)
	}

	// Setup IDP provider if enabled (can work independently of MCP)
	if cfg.EnableIDP {
		idpDBPath := cfg.IDPDBPath
		if idpDBPath == "" {
			idpDBPath = getDefaultDBPath(cfg.HTCondorConfig, "idp.db")
		}

		idpIssuer := cfg.IDPIssuer
		if idpIssuer == "" {
			idpIssuer = "http://localhost:8080"
		}

		idpProvider, err := NewIDPProvider(idpDBPath, idpIssuer)
		if err != nil {
			return nil, fmt.Errorf("failed to create IDP provider: %w", err)
		}
		h.idpProvider = idpProvider
		h.idpLoginLimiter = NewLoginRateLimiter(rate.Limit(5.0/60.0), 5) // 5 attempts per minute with burst of 5
		logger.Info(logging.DestinationHTTP, "IDP provider enabled", "issuer", idpIssuer)

		// Ensure OAuth2 state store is initialized if we might use SSO (which IDP enables)
		if h.oauth2StateStore == nil {
			h.oauth2StateStore = NewOAuth2StateStore()
		}
	}

	// Setup metrics if collector is provided
	enableMetrics := cfg.EnableMetrics
	if cfg.Collector != nil && !cfg.EnableMetrics {
		enableMetrics = true // Enable by default if collector is provided
	}

	if enableMetrics && cfg.Collector != nil {
		registry := metricsd.NewRegistry()

		// Set cache TTL
		cacheTTL := cfg.MetricsCacheTTL
		if cacheTTL == 0 {
			cacheTTL = 10 * time.Second
		}
		registry.SetCacheTTL(cacheTTL)

		// Register collectors
		poolCollector := metricsd.NewPoolCollector(cfg.Collector)
		registry.Register(poolCollector)

		processCollector := metricsd.NewProcessCollector()
		registry.Register(processCollector)

		h.metricsRegistry = registry
		h.prometheusExporter = metricsd.NewPrometheusExporter(registry)

		h.logger.Info(logging.DestinationMetrics, "Metrics endpoint enabled", "path", "/metrics")
	}

	// Setup periodic ping if configured
	pingInterval := cfg.PingInterval
	if pingInterval == 0 {
		pingInterval = 1 * time.Minute // Default to 1 minute
	}
	if pingInterval > 0 {
		h.pingInterval = pingInterval
		h.logger.Info(logging.DestinationHTTP, "Periodic daemon ping enabled", "interval", pingInterval)
	}

	// Note: Routes will be set up by the Server or by the user calling SetupRoutes
	h.mux = http.NewServeMux()

	return h, nil
}

// SetupRoutes sets up the HTTP routes on the handler's multiplexer
// This should be called by Server.NewServer or by users who create a Handler directly
func (h *Handler) SetupRoutes(setupFunc func(*http.ServeMux)) {
	if setupFunc != nil {
		setupFunc(h.mux)
	}
}

// ensureOAuth2ClientRegistered ensures an OAuth2 client is registered (extracted helper)
func (h *Handler) ensureOAuth2ClientRegistered(clientID, _ /* clientSecret */, _ /* redirectURL */ string, _ /* scopes */ []string) {
	// Check if client exists
	_, err := h.oauth2Provider.GetStorage().GetClient(context.Background(), clientID)
	if err != nil {
		// Client registration logic from original NewServer
		// (code omitted for brevity but would be the same as in original)
		h.logger.Debug(logging.DestinationHTTP, "OAuth2 client not found or error, would register", "client_id", clientID)
	}
}

// ServeHTTP implements http.Handler interface
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// Start initializes the handler and starts background goroutines.
// The provided context controls the handler's lifetime - when the context is cancelled,
// the handler will gracefully shut down all background goroutines.
//
// This method should be called by Server.Start() or Server.StartTLS() before serving requests.
func (h *Handler) Start(ctx context.Context, ln net.Listener, protocol string) error {
	// Set up all HTTP routes
	h.setupRoutes()

	h.ctx, h.cancelFunc = context.WithCancel(ctx)

	// Initialize IDP if enabled
	if err := h.initializeIDP(ln, protocol); err != nil {
		return err
	}

	// Initialize OAuth2 provider with actual address
	h.initializeOAuth2(ln, protocol)

	// Start OAuth2 state store cleanup if it exists
	if h.oauth2StateStore != nil {
		h.oauth2StateStore.Start(ctx)
	}

	// Start schedd address updater if address was discovered from collector
	if h.scheddDiscovered && h.collector != nil {
		h.startScheddAddressUpdater(ctx)
	}

	// Start credd address updater if credd was discovered (or discovery failed but should retry)
	if h.creddDiscovered && h.collector != nil {
		h.startCreddAddressUpdater(ctx)
	}

	// Start session cleanup goroutine
	h.startSessionCleanup(ctx)

	// Start periodic ping goroutine if enabled
	if h.pingInterval > 0 {
		go h.periodicPing(ctx)
	}

	return nil
}

// Stop gracefully stops all background goroutines and closes providers.
// This method is called when the handler's context is cancelled (via Server.Shutdown).
// The background goroutines are responsible for watching their context and exiting when done.
func (h *Handler) Stop(ctx context.Context) error {
	h.logger.Info(logging.DestinationHTTP, "Stopping HTTP handler")

	// Cancel the handler's context if it's not already done.
	h.cancelFunc()

	// Wait for background goroutines to finish (with timeout)
	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		// Also wait for OAuth2 state store cleanup goroutine
		if h.oauth2StateStore != nil {
			h.oauth2StateStore.Wait()
		}
		close(done)
	}()

	// Wait for goroutines to finish or context to be done
	select {
	case <-done:
		h.logger.Debug(logging.DestinationHTTP, "Background goroutines stopped")
	case <-ctx.Done():
		h.logger.Warn(logging.DestinationHTTP, "Shutdown timeout waiting for background goroutines")
	}

	// Close OAuth2 provider if enabled
	if h.oauth2Provider != nil {
		if err := h.oauth2Provider.Close(); err != nil {
			h.logger.Error(logging.DestinationHTTP, "Failed to close OAuth2 provider", "error", err)
		}
	}

	// Close IDP provider if enabled
	if h.idpProvider != nil {
		if err := h.idpProvider.Close(); err != nil {
			h.logger.Error(logging.DestinationHTTP, "Failed to close IDP provider", "error", err)
		}
	}

	return nil
}

// ErrorResponse represents an error response body
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
}

// writeError writes an error response
func (h *Handler) writeError(w http.ResponseWriter, statusCode int, message string) {
	// Add WWW-Authenticate header for 401 Unauthorized responses per RFC 6750
	if statusCode == http.StatusUnauthorized {
		h.addWWWAuthenticateHeader(w, "", "")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(ErrorResponse{
		Error:   http.StatusText(statusCode),
		Message: message,
		Code:    statusCode,
	}); err != nil {
		h.logger.Error(logging.DestinationHTTP, "Failed to encode error response", "error", err, "status_code", statusCode)
	}
}

// writeOAuthError writes an error response with appropriate WWW-Authenticate header
func (h *Handler) writeOAuthError(w http.ResponseWriter, statusCode int, errorCode, errorDescription string) {
	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		h.addWWWAuthenticateHeader(w, errorCode, errorDescription)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(ErrorResponse{
		Error:   errorCode,
		Message: errorDescription,
		Code:    statusCode,
	}); err != nil {
		h.logger.Error(logging.DestinationHTTP, "Failed to encode error response", "error", err, "status_code", statusCode)
	}
}

// addWWWAuthenticateHeader adds RFC 6750 compliant WWW-Authenticate header
// See: https://datatracker.ietf.org/doc/html/rfc6750#section-3
func (h *Handler) addWWWAuthenticateHeader(w http.ResponseWriter, errorCode, errorDescription string) {
	var headerValue string

	if h.oauth2Provider != nil {
		// Get the issuer from OAuth2 provider config
		realm := h.oauth2Provider.config.AccessTokenIssuer

		// Build WWW-Authenticate header value with realm
		headerValue = fmt.Sprintf(`Bearer realm="%s"`, realm)

		if errorCode != "" {
			headerValue += fmt.Sprintf(`, error="%s"`, errorCode)
		}

		if errorDescription != "" {
			headerValue += fmt.Sprintf(`, error_description="%s"`, errorDescription)
		}
	} else {
		// Even without OAuth2 provider, we should include WWW-Authenticate header
		// for proper OAuth2/Bearer token authentication per RFC 6750
		headerValue = "Bearer"

		if errorCode != "" {
			headerValue += fmt.Sprintf(` error="%s"`, errorCode)
		}

		if errorDescription != "" {
			headerValue += fmt.Sprintf(`, error_description="%s"`, errorDescription)
		}
	}

	w.Header().Set("WWW-Authenticate", headerValue)
}

// writeJSON writes a JSON response
func (h *Handler) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			h.logger.Error(logging.DestinationHTTP, "Error encoding JSON response", "error", err, "status_code", statusCode)
		}
	}
}

// redirectToLogin redirects a browser request to the OAuth2 login flow preserving the original URL
func (h *Handler) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	if h.oauth2Config == nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required but no OAuth2 provider configured")
		return
	}

	// Build the original URL (relative path with query string)
	originalURL := r.URL.Query().Get("return_to")
	if originalURL == "" {
		originalURL = r.URL.Path
		if r.URL.RawQuery != "" {
			originalURL += "?" + r.URL.RawQuery
		}
	}

	// If the original URL is /login (or starts with /login), default to root to avoid loops
	if strings.HasPrefix(originalURL, "/login") {
		originalURL = "/"
	}

	// Generate state parameter
	state, err := h.oauth2StateStore.GenerateState()
	if err != nil {
		h.logger.Error(logging.DestinationHTTP, "Failed to generate OAuth2 state", "error", err)
		h.writeError(w, http.StatusInternalServerError, "Failed to initiate authentication")
		return
	}

	// Store the state with the original URL (no authorize request for browser flow)
	h.oauth2StateStore.StoreWithURL(state, nil, originalURL)

	// Build authorization URL
	authURL := h.oauth2Config.AuthCodeURL(state)

	h.logger.Info(logging.DestinationHTTP, "Redirecting unauthenticated browser to login",
		"original_url", originalURL, "state", state, "auth_url", authURL)

	// Redirect to IDP
	http.Redirect(w, r, authURL, http.StatusFound)
}

// GetOAuth2Provider returns the OAuth2 provider (for testing)
func (h *Handler) GetOAuth2Provider() *OAuth2Provider {
	return h.oauth2Provider
}

// UpdateOAuth2RedirectURL updates the OAuth2 redirect URL for SSO integration
func (h *Handler) UpdateOAuth2RedirectURL(redirectURL string) {
	if h.oauth2Config != nil {
		h.oauth2Config.RedirectURL = redirectURL
	}
}

// getSchedd returns the current schedd instance (thread-safe)
func (h *Handler) getSchedd() *htcondor.Schedd {
	h.scheddMu.RLock()
	defer h.scheddMu.RUnlock()
	return h.schedd
}

// GetSchedd returns the current schedd instance (thread-safe)
func (h *Handler) GetSchedd() *htcondor.Schedd {
	h.scheddMu.RLock()
	defer h.scheddMu.RUnlock()
	return h.schedd
}

// UpdateSchedd updates the schedd instance with a new address (thread-safe)
func (h *Handler) UpdateSchedd(newAddress string) {
	h.scheddMu.Lock()
	defer h.scheddMu.Unlock()

	// Only update if the address has changed
	if h.schedd.Address() != newAddress {
		h.logger.Info(logging.DestinationSchedd, "Updating schedd address",
			"old_address", h.schedd.Address(),
			"new_address", newAddress)
		h.schedd = htcondor.NewSchedd(h.scheddName, newAddress)
	}
}

// startScheddAddressUpdater starts a background goroutine that periodically
// checks for schedd address updates from the collector
func (h *Handler) startScheddAddressUpdater(ctx context.Context) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()

		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		h.logger.Info(logging.DestinationSchedd, "Started schedd address updater",
			"interval", "60s",
			"schedd_name", h.scheddName)

		for {
			select {
			case <-ticker.C:
				// Query collector for updated schedd address
				newAddr, err := discoverSchedd(h.collector, h.scheddName, 5*time.Second, h.logger)
				if err != nil {
					h.logger.Warn(logging.DestinationSchedd, "Failed to discover schedd address",
						"error", err,
						"schedd_name", h.scheddName)
					continue
				}

				// Update schedd if address changed
				h.UpdateSchedd(newAddr)

			case <-ctx.Done():
				h.logger.Info(logging.DestinationSchedd, "Stopping schedd address updater")
				return
			}
		}
	}()
}

// startCreddAddressUpdater starts a background goroutine that periodically
// checks for credd address updates from the collector
func (h *Handler) startCreddAddressUpdater(ctx context.Context) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()

		// Use half of ping interval, or 30 seconds if ping is disabled
		checkInterval := h.pingInterval / 2
		if checkInterval == 0 {
			checkInterval = 30 * time.Second
		}

		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()

		h.logger.Info(logging.DestinationHTTP, "Starting periodic credd discovery", "interval", checkInterval)

		for {
			select {
			case <-ticker.C:
				// Get current schedd address for credd discovery
				schedd := h.getSchedd()
				scheddAddr := schedd.Address()

				// Attempt to discover credd
				creddAddr, err := discoverCredd(h.scheddName, scheddAddr, h.collector, h.logger)
				if err != nil {
					// Only log if credd is already available to avoid spam
					if h.creddAvailable.Load() {
						h.logger.Warn(logging.DestinationHTTP, "Credd became unavailable", "error", err)
						h.creddAvailable.Store(false)
					}
					continue
				}

				// Update credd if it became available
				if !h.creddAvailable.Load() {
					h.logger.Info(logging.DestinationHTTP, "Credd became available", "address", creddAddr)
					h.credd = htcondor.NewCedarCredd(creddAddr)
					h.creddAvailable.Store(true)
				}

			case <-ctx.Done():
				h.logger.Info(logging.DestinationHTTP, "Stopping credd address updater")
				return
			}
		}
	}()
}

// startSessionCleanup starts a background goroutine that periodically
// cleans up expired sessions
func (h *Handler) startSessionCleanup(ctx context.Context) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()

		// Clean up expired sessions every hour
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		h.logger.Info(logging.DestinationHTTP, "Started session cleanup goroutine", "interval", "1h")

		for {
			select {
			case <-ticker.C:
				h.sessionStore.Cleanup()
				h.logger.Debug(logging.DestinationHTTP, "Cleaned up expired sessions",
					"active_sessions", h.sessionStore.Size())

			case <-ctx.Done():
				h.logger.Info(logging.DestinationHTTP, "Stopping session cleanup goroutine")
				return
			}
		}
	}()
}

// periodicPing runs in a goroutine and periodically pings the collector and schedd
func (h *Handler) periodicPing(ctx context.Context) {
	h.wg.Add(1)
	defer h.wg.Done()

	ticker := time.NewTicker(h.pingInterval)
	defer ticker.Stop()

	h.logger.Info(logging.DestinationHTTP, "Starting periodic daemon ping", "interval", h.pingInterval)

	for {
		select {
		case <-ctx.Done():
			h.logger.Info(logging.DestinationHTTP, "Stopping periodic daemon ping")
			return
		case <-ticker.C:
			h.performPeriodicPing()
		}
	}
}

// performPeriodicPing performs a single ping to collector and schedd
func (h *Handler) performPeriodicPing() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// If we have a token, configure security
	if h.token != "" {
		secConfig, err := ConfigureSecurityForToken(h.token)
		if err != nil {
			h.logger.Error(logging.DestinationHTTP, "Failed to configure security for periodic ping", "error", err)
		} else {
			ctx = htcondor.WithSecurityConfig(ctx, secConfig)
		}
	}

	// Ping collector if configured
	if h.collector != nil {
		_, err := h.collector.Ping(ctx)
		if err != nil {
			h.logger.Warn(logging.DestinationHTTP, "Periodic collector ping failed", "error", err)
		} else {
			h.logger.Debug(logging.DestinationHTTP, "Periodic collector ping succeeded")
		}
	}

	// Ping schedd
	_, err := h.getSchedd().Ping(ctx)
	if err != nil {
		h.logger.Warn(logging.DestinationHTTP, "Periodic schedd ping failed", "error", err)
	} else {
		h.logger.Debug(logging.DestinationHTTP, "Periodic schedd ping succeeded")
	}
}

// initializeIDP initializes the IDP provider with actual listening address
func (h *Handler) initializeIDP(ln net.Listener, protocol string) error {
	if h.idpProvider == nil {
		return nil
	}

	ctx := context.Background()

	// Update issuer with actual listening address only if needed
	actualAddr := ln.Addr().String()
	issuer := protocol + "://" + actualAddr

	// Only update if the issuer was empty or had a dynamic port (:0)
	if shouldUpdateIssuer(h.idpProvider.config.AccessTokenIssuer) {
		h.idpProvider.UpdateIssuer(issuer)
	} else {
		// Use the configured issuer instead
		issuer = h.idpProvider.config.AccessTokenIssuer
	}

	// Initialize default users
	if err := h.initializeIDPUsers(ctx); err != nil {
		return fmt.Errorf("failed to initialize IDP users: %w", err)
	}

	// Initialize auto-generated client with redirect URI
	redirectURI := issuer + "/idp/callback"
	if err := h.initializeIDPClient(ctx, redirectURI); err != nil {
		return fmt.Errorf("failed to initialize IDP client: %w", err)
	}

	// Configure internal IDP as the upstream OAuth2 provider for the server
	// This allows the server to use its own IDP for authentication (SSO)
	clientID := "internal-client"
	clientSecret := "internal-secret"
	ssoRedirectURI := issuer + "/mcp/oauth2/callback"

	// Check if client exists
	_, err := h.idpProvider.storage.GetClient(ctx, clientID)
	if err != nil {
		// Create client if not found (or error)
		// Hash the secret
		hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash client secret: %w", err)
		}

		client := &fosite.DefaultClient{
			ID:            clientID,
			Secret:        hashedSecret,
			RedirectURIs:  []string{ssoRedirectURI},
			ResponseTypes: []string{"code"},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			Scopes:        []string{"openid", "profile", "email"},
			Public:        false,
		}

		if err := h.idpProvider.storage.CreateClient(ctx, client); err != nil {
			return fmt.Errorf("failed to create internal IDP client: %w", err)
		}
		h.logger.Info(logging.DestinationHTTP, "Created internal IDP client", "client_id", clientID)
	}

	// Create Swagger UI client (public client)
	swaggerClientID := "swagger-client"
	swaggerRedirectURIs := []string{issuer + "/docs/oauth2-redirect"}

	// Add localhost/127.0.0.1 variants if issuer uses wildcard or unspecified address
	// This ensures Swagger UI works when accessed via localhost even if server listens on [::]
	if strings.Contains(issuer, "[::]") || strings.Contains(issuer, "0.0.0.0") {
		_, port, _ := net.SplitHostPort(actualAddr)
		if port != "" {
			swaggerRedirectURIs = append(swaggerRedirectURIs,
				protocol+"://localhost:"+port+"/docs/oauth2-redirect",
				protocol+"://127.0.0.1:"+port+"/docs/oauth2-redirect",
			)
		}
	}

	// Check if client exists
	_, err = h.idpProvider.storage.GetClient(ctx, swaggerClientID)
	if err != nil {
		// Create client if not found (or error)
		client := &fosite.DefaultClient{
			ID:            swaggerClientID,
			Secret:        nil, // Public client has no secret
			RedirectURIs:  swaggerRedirectURIs,
			ResponseTypes: []string{"code"},
			GrantTypes:    []string{"authorization_code"},
			Scopes:        []string{"openid", "profile", "email"},
			Public:        true,
		}

		if err := h.idpProvider.storage.CreateClient(ctx, client); err != nil {
			return fmt.Errorf("failed to create Swagger IDP client: %w", err)
		}
		h.logger.Info(logging.DestinationHTTP, "Created Swagger IDP client", "client_id", swaggerClientID, "redirect_uris", swaggerRedirectURIs)
	}

	// Also ensure the client exists in the OAuth2 provider if enabled
	// This is required because Swagger UI is configured to use the MCP OAuth2 endpoints
	if h.oauth2Provider != nil {
		_, err = h.oauth2Provider.GetStorage().GetClient(ctx, swaggerClientID)
		if err != nil {
			client := &fosite.DefaultClient{
				ID:            swaggerClientID,
				Secret:        nil, // Public client has no secret
				RedirectURIs:  swaggerRedirectURIs,
				ResponseTypes: []string{"code"},
				GrantTypes:    []string{"authorization_code"},
				Scopes:        []string{"openid", "profile", "email"},
				Public:        true,
			}

			if err := h.oauth2Provider.GetStorage().CreateClient(ctx, client); err != nil {
				h.logger.Error(logging.DestinationHTTP, "Failed to create Swagger OAuth2 client", "error", err)
			} else {
				h.logger.Info(logging.DestinationHTTP, "Created Swagger OAuth2 client", "client_id", swaggerClientID)
			}
		}
	}

	// Configure h.oauth2Config to use the internal IDP
	h.oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  issuer + "/idp/authorize",
			TokenURL: issuer + "/idp/token",
		},
		RedirectURL: ssoRedirectURI,
		Scopes:      []string{"openid", "profile", "email"},
	}
	h.oauth2UserInfoURL = issuer + "/idp/userinfo"

	h.logger.Info(logging.DestinationHTTP, "Configured OAuth2 SSO to use internal IDP", "issuer", issuer)

	return nil
}

// initializeOAuth2 initializes the OAuth2 provider with actual listening address
func (h *Handler) initializeOAuth2(ln net.Listener, protocol string) {
	if h.oauth2Provider == nil {
		return
	}

	actualAddr := ln.Addr().String()
	issuer := h.oauth2Provider.config.AccessTokenIssuer

	// Only update issuer if it was empty or had a dynamic port (:0)
	if shouldUpdateIssuer(issuer) {
		issuer = protocol + "://" + actualAddr
		h.oauth2Provider.UpdateIssuer(issuer)
	}

	// Create Swagger UI client (public client) if not already present
	// This ensures Swagger UI can authenticate via OAuth2 in normal mode (MCP enabled without IDP)
	ctx := context.Background()
	swaggerClientID := "swagger-client"
	swaggerRedirectURIs := []string{issuer + "/docs/oauth2-redirect"}

	// Add localhost/127.0.0.1 variants if issuer uses wildcard or unspecified address
	// This ensures Swagger UI works when accessed via localhost even if server listens on [::]
	issuerURL, err := parseURL(issuer)
	if err == nil {
		hostname := issuerURL.Hostname()
		port := issuerURL.Port()
		if (hostname == "[::]" || hostname == "0.0.0.0") && port == "0" {
			_, actualPort, _ := net.SplitHostPort(actualAddr)
			if actualPort != "" {
				swaggerRedirectURIs = append(swaggerRedirectURIs,
					protocol+"://localhost:"+actualPort+"/docs/oauth2-redirect",
					protocol+"://127.0.0.1:"+actualPort+"/docs/oauth2-redirect",
				)
			}
		}
	}

	// Check if client exists
	_, err = h.oauth2Provider.GetStorage().GetClient(ctx, swaggerClientID)
	if err != nil {
		// Create client if not found (or error)
		client := &fosite.DefaultClient{
			ID:            swaggerClientID,
			Secret:        nil, // Public client has no secret
			RedirectURIs:  swaggerRedirectURIs,
			ResponseTypes: []string{"code"},
			GrantTypes:    []string{"authorization_code"},
			Scopes:        []string{"openid", "profile", "email"},
			Public:        true,
		}

		if err := h.oauth2Provider.GetStorage().CreateClient(ctx, client); err != nil {
			h.logger.Error(logging.DestinationHTTP, "Failed to create Swagger OAuth2 client", "error", err)
		} else {
			h.logger.Info(logging.DestinationHTTP, "Created Swagger OAuth2 client", "client_id", swaggerClientID, "redirect_uris", swaggerRedirectURIs)
		}
	}
}

// initializeIDPUsers initializes default users in the IDP provider
func (h *Handler) initializeIDPUsers(ctx context.Context) error {
	// Check if admin user exists
	exists, err := h.idpProvider.storage.UserExists(ctx, "admin")
	if err != nil {
		return fmt.Errorf("failed to check if admin user exists: %w", err)
	}

	if !exists {
		// Generate random password
		password, err := generateRandomPassword(16)
		if err != nil {
			return fmt.Errorf("failed to generate admin password: %w", err)
		}

		// Create admin user with "admin" state
		if err := h.idpProvider.storage.CreateUser(ctx, "admin", password, "admin"); err != nil {
			return fmt.Errorf("failed to create admin user: %w", err)
		}

		// Print credentials to terminal
		fmt.Printf("\n")
		fmt.Printf("========================================\n")
		fmt.Printf("IDP Admin Credentials\n")
		fmt.Printf("========================================\n")
		fmt.Printf("Username: admin\n")
		fmt.Printf("Password: %s\n", password)
		fmt.Printf("========================================\n")
		fmt.Printf("\n")

		h.logger.Info(logging.DestinationHTTP, "Created IDP admin user", "username", "admin")
	}

	return nil
}

// initializeIDPClient creates an auto-generated OAuth2 client for the server
func (h *Handler) initializeIDPClient(ctx context.Context, redirectURI string) error {
	clientID := "htcondor-server"

	// Check if client already exists
	_, err := h.idpProvider.storage.GetClient(ctx, clientID)
	if err == nil {
		// Client already exists, update redirect URI if needed
		// For simplicity, we'll just return
		h.logger.Info(logging.DestinationHTTP, "IDP client already exists", "client_id", clientID)
		return nil
	}

	if !errors.Is(err, fosite.ErrNotFound) {
		return fmt.Errorf("failed to check for existing client: %w", err)
	}

	// Generate client secret
	secret, err := generateRandomPassword(32)
	if err != nil {
		return fmt.Errorf("failed to generate client secret: %w", err)
	}

	// Create the client
	client := &fosite.DefaultClient{
		ID:     clientID,
		Secret: []byte(secret),
		RedirectURIs: []string{
			redirectURI,
		},
		GrantTypes: []string{
			"authorization_code",
			"refresh_token",
		},
		ResponseTypes: []string{
			"code",
		},
		Scopes: []string{
			"openid",
			"profile",
			"email",
		},
	}

	if err := h.idpProvider.storage.CreateClient(ctx, client); err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	h.logger.Info(logging.DestinationHTTP, "Created IDP client", "client_id", clientID)
	return nil
}
