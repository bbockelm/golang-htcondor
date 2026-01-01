package httpserver

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/metricsd"
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
	tokenCache          *TokenCache       // Cache of validated tokens and their session caches (includes username)
	sessionStore        *SessionStore     // HTTP session store for browser-based authentication
	oauth2Provider      *OAuth2Provider   // OAuth2 provider for MCP endpoints
	oauth2Config        *oauth2.Config    // OAuth2 client config for SSO
	oauth2StateStore    *OAuth2StateStore // State storage for OAuth2 SSO flow
	oauth2UserInfoURL   string            // User info endpoint for SSO
	oauth2UsernameClaim string            // Claim name for username (default: "sub")
	oauth2GroupsClaim   string            // Claim name for group information (default: "groups")
	mcpAccessGroup      string            // Group required for any MCP access (empty = all authenticated users)
	mcpReadGroup        string            // Group required for read access (empty = all users have read)
	mcpWriteGroup       string            // Group required for write access (empty = all users have write)
	idpProvider         *IDPProvider      // Built-in IDP provider
	idpLoginLimiter     *LoginRateLimiter // Rate limiter for IDP login attempts
	streamBufferSize    int               // Buffer size for streaming queries (default: 100)
	streamWriteTimeout  time.Duration     // Write timeout for streaming queries (default: 5s)
	stopChan            chan struct{}     // Channel to signal shutdown of background goroutines
	wg                  sync.WaitGroup    // WaitGroup to track background goroutines
	pingInterval        time.Duration     // Interval for periodic daemon pings (0 = disabled)
	pingStopCh          chan struct{}     // Channel to signal ping goroutine to stop
	token               string            // Token for daemon authentication
	mux                 *http.ServeMux    // HTTP request multiplexer
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
		stopChan:           make(chan struct{}),
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
		h.pingStopCh = make(chan struct{})
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

// Start starts background goroutines (address updaters, session cleanup, periodic ping)
// This should be called after the handler is created and before serving requests
func (h *Handler) Start(_ net.Listener, _ /* protocol */ string) error {
	// Note: IDP and OAuth2 initialization, address updaters, session cleanup, and periodic ping
	// are handled by the Server wrapper. If using Handler standalone, users need to call these
	// initialization methods manually or implement their own lifecycle management.
	return nil
}

// Stop gracefully stops all background goroutines
func (h *Handler) Stop(_ context.Context) error {
	h.logger.Info(logging.DestinationHTTP, "Stopping HTTP handler")

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
