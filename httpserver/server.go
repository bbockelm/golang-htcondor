package httpserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/metricsd"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

// Server represents the HTTP API server
type Server struct {
	httpServer          *http.Server
	listener            net.Listener // Explicit listener to get actual address
	schedd              *htcondor.Schedd
	scheddMu            sync.RWMutex // Protects schedd instance for thread-safe updates
	scheddName          string       // Schedd name for discovery
	scheddDiscovered    bool         // Whether schedd address was discovered from collector
	collector           *htcondor.Collector
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
}

// Config holds server configuration
type Config struct {
	ListenAddr          string              // Address to listen on (e.g., ":8080")
	ScheddName          string              // Schedd name
	ScheddAddr          string              // Schedd address (e.g., "127.0.0.1:9618"). If empty, discovered from collector.
	UserHeader          string              // HTTP header to extract username from (optional)
	SigningKeyPath      string              // Path to token signing key (optional, for token generation)
	TrustDomain         string              // Trust domain for token issuer (optional; only used if UserHeader is set)
	UIDDomain           string              // UID domain for generated token username (optional; only used if UserHeader is set)
	HTTPBaseURL         string              // Base URL for HTTP API (e.g., "http://localhost:8080") for generating file download links in MCP responses
	TLSCertFile         string              // Path to TLS certificate file (optional, enables HTTPS)
	TLSKeyFile          string              // Path to TLS key file (optional, enables HTTPS)
	TLSCACertFile       string              // Path to TLS CA certificate file (optional, for trusting self-signed certs)
	ReadTimeout         time.Duration       // HTTP read timeout (default: 30s)
	WriteTimeout        time.Duration       // HTTP write timeout (default: 30s)
	IdleTimeout         time.Duration       // HTTP idle timeout (default: 120s)
	Collector           *htcondor.Collector // Collector for metrics (optional)
	EnableMetrics       bool                // Enable /metrics endpoint (default: true if Collector is set)
	MetricsCacheTTL     time.Duration       // Metrics cache TTL (default: 10s)
	Logger              *logging.Logger     // Logger instance (optional, creates default if nil)
	EnableMCP           bool                // Enable MCP endpoints with OAuth2 (default: false)
	OAuth2DBPath        string              // Path to OAuth2 SQLite database (default: LOCAL_DIR/oauth2.db or /var/lib/condor/oauth2.db). Can be configured via HTTP_API_OAUTH2_DB_PATH
	OAuth2Issuer        string              // OAuth2 issuer URL (default: listen address)
	OAuth2ClientID      string              // OAuth2 client ID for SSO (optional)
	OAuth2ClientSecret  string              // OAuth2 client secret for SSO (optional)
	OAuth2AuthURL       string              // OAuth2 authorization URL for SSO (optional)
	OAuth2TokenURL      string              // OAuth2 token URL for SSO (optional)
	OAuth2RedirectURL   string              // OAuth2 redirect URL for SSO (optional)
	OAuth2UserInfoURL   string              // OAuth2 user info endpoint for SSO (optional)
	OAuth2Scopes        []string            // OAuth2 scopes to request (default: ["openid", "profile", "email"])
	OAuth2UsernameClaim string              // Claim name for username in token (default: "sub")
	OAuth2GroupsClaim   string              // Claim name for groups in user info (default: "groups")
	MCPAccessGroup      string              // Group required for any MCP access (empty = all authenticated)
	MCPReadGroup        string              // Group required for read operations (empty = all have read)
	MCPWriteGroup       string              // Group required for write operations (empty = all have write)
	EnableIDP           bool                // Enable built-in IDP (always enabled in demo mode)
	IDPDBPath           string              // Path to IDP SQLite database (default: "idp.db")
	IDPIssuer           string              // IDP issuer URL (default: listen address)
	SessionTTL          time.Duration       // HTTP session TTL (default: 24h)
	HTCondorConfig      *config.Config      // HTCondor configuration (optional, used for LOCAL_DIR default)
	PingInterval        time.Duration       // Interval for periodic daemon pings (default: 1 minute, 0 = disabled)
	StreamBufferSize    int                 // Buffer size for streaming queries (default: 100)
	StreamWriteTimeout  time.Duration       // Write timeout for streaming queries (default: 5s)
	Token               string              // Token for daemon authentication (optional)
}

// NewServer creates a new HTTP API server
//
//nolint:gocyclo // Initialization logic with sequential checks is acceptable
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

	s := &Server{
		schedd:             schedd,
		scheddName:         cfg.ScheddName,
		scheddDiscovered:   scheddDiscovered,
		collector:          cfg.Collector,
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

	// Setup OAuth2 provider if MCP is enabled
	if cfg.EnableMCP {
		oauth2DBPath := cfg.OAuth2DBPath
		if oauth2DBPath == "" {
			oauth2DBPath = getDefaultDBPath(cfg.HTCondorConfig, "oauth2.db")
		}

		oauth2Issuer := cfg.OAuth2Issuer
		if oauth2Issuer == "" {
			oauth2Issuer = "http://" + cfg.ListenAddr
		}

		oauth2Provider, err := NewOAuth2Provider(oauth2DBPath, oauth2Issuer)
		if err != nil {
			return nil, fmt.Errorf("failed to create OAuth2 provider: %w", err)
		}
		s.oauth2Provider = oauth2Provider
		logger.Info(logging.DestinationHTTP, "OAuth2 provider enabled for MCP endpoints", "issuer", oauth2Issuer)

		// Set username claim name (default: "sub")
		s.oauth2UsernameClaim = cfg.OAuth2UsernameClaim
		if s.oauth2UsernameClaim == "" {
			s.oauth2UsernameClaim = "sub"
		}

		// Initialize OAuth2 state store
		s.oauth2StateStore = NewOAuth2StateStore()

		// Setup OAuth2 client config for SSO if configured
		if cfg.OAuth2ClientID != "" && cfg.OAuth2AuthURL != "" && cfg.OAuth2TokenURL != "" {
			// Set default scopes if not provided
			scopes := cfg.OAuth2Scopes
			if len(scopes) == 0 {
				scopes = []string{"openid", "profile", "email"}
			}

			s.oauth2Config = &oauth2.Config{
				ClientID:     cfg.OAuth2ClientID,
				ClientSecret: cfg.OAuth2ClientSecret,
				RedirectURL:  cfg.OAuth2RedirectURL,
				Endpoint: oauth2.Endpoint{
					AuthURL:  cfg.OAuth2AuthURL,
					TokenURL: cfg.OAuth2TokenURL,
				},
				Scopes: scopes,
			}
			s.oauth2UserInfoURL = cfg.OAuth2UserInfoURL
			logger.Info(logging.DestinationHTTP, "OAuth2 SSO client configured", "auth_url", cfg.OAuth2AuthURL, "scopes", scopes)

			// If we are also the provider (EnableMCP), ensure the client exists
			if cfg.EnableMCP {
				// Check if client exists
				_, err := s.oauth2Provider.GetStorage().GetClient(context.Background(), cfg.OAuth2ClientID)
				if err != nil {
					// Assume it doesn't exist or error, try to create it
					// Hash the secret
					hashedSecret, err := bcrypt.GenerateFromPassword([]byte(cfg.OAuth2ClientSecret), bcrypt.DefaultCost)
					if err != nil {
						logger.Error(logging.DestinationHTTP, "Failed to hash OAuth2 client secret", "error", err)
					} else {
						client := &fosite.DefaultClient{
							ID:            cfg.OAuth2ClientID,
							Secret:        hashedSecret,
							RedirectURIs:  []string{cfg.OAuth2RedirectURL},
							ResponseTypes: []string{"code"},
							GrantTypes:    []string{"authorization_code", "refresh_token"},
							Scopes:        scopes,
							Public:        false,
						}
						if err := s.oauth2Provider.GetStorage().CreateClient(context.Background(), client); err != nil {
							logger.Error(logging.DestinationHTTP, "Failed to auto-register OAuth2 client", "error", err)
						} else {
							logger.Info(logging.DestinationHTTP, "Auto-registered OAuth2 client", "client_id", cfg.OAuth2ClientID)
						}
					}
				}
			}
		}

		// Set groups claim name (default: "groups")
		s.oauth2GroupsClaim = cfg.OAuth2GroupsClaim
		if s.oauth2GroupsClaim == "" {
			s.oauth2GroupsClaim = "groups"
		}

		// Set group-based access control
		s.mcpAccessGroup = cfg.MCPAccessGroup
		s.mcpReadGroup = cfg.MCPReadGroup
		s.mcpWriteGroup = cfg.MCPWriteGroup

		if s.mcpAccessGroup != "" {
			logger.Info(logging.DestinationHTTP, "MCP access control enabled", "access_group", s.mcpAccessGroup)
		}
		if s.mcpReadGroup != "" {
			logger.Info(logging.DestinationHTTP, "MCP read access control enabled", "read_group", s.mcpReadGroup)
		}
		if s.mcpWriteGroup != "" {
			logger.Info(logging.DestinationHTTP, "MCP write access control enabled", "write_group", s.mcpWriteGroup)
		}

		// Initialize session store with shared database connection
		sessionStore, err := NewSessionStore(s.oauth2Provider.GetStorage().GetDB(), sessionTTL)
		if err != nil {
			return nil, fmt.Errorf("failed to create session store: %w", err)
		}
		s.sessionStore = sessionStore
		logger.Info(logging.DestinationHTTP, "Session store enabled with database persistence", "ttl", sessionTTL)
	} else {
		// OAuth2 not enabled, create standalone database for sessions
		// Use a separate database file for sessions
		sessionDBPath := cfg.OAuth2DBPath
		if sessionDBPath == "" {
			sessionDBPath = getDefaultDBPath(cfg.HTCondorConfig, "sessions.db")
		} else {
			// Use same path but different file name if OAuth2 DB is configured
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
		s.sessionStore = sessionStore
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
			idpIssuer = "http://" + cfg.ListenAddr
		}

		idpProvider, err := NewIDPProvider(idpDBPath, idpIssuer)
		if err != nil {
			return nil, fmt.Errorf("failed to create IDP provider: %w", err)
		}
		s.idpProvider = idpProvider
		s.idpLoginLimiter = NewLoginRateLimiter(rate.Limit(5.0/60.0), 5) // 5 attempts per minute with burst of 5
		logger.Info(logging.DestinationHTTP, "IDP provider enabled", "issuer", idpIssuer)

		// Ensure OAuth2 state store is initialized if we might use SSO (which IDP enables)
		if s.oauth2StateStore == nil {
			s.oauth2StateStore = NewOAuth2StateStore()
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

		s.metricsRegistry = registry
		s.prometheusExporter = metricsd.NewPrometheusExporter(registry)

		s.logger.Info(logging.DestinationMetrics, "Metrics endpoint enabled", "path", "/metrics")
	}

	mux := http.NewServeMux()
	s.setupRoutes(mux)

	// Wrap with access logging middleware
	handler := s.accessLogMiddleware(mux)

	// Set default timeouts if not specified
	readTimeout := cfg.ReadTimeout
	if readTimeout == 0 {
		readTimeout = 30 * time.Second
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout == 0 {
		writeTimeout = 30 * time.Second
	}
	idleTimeout := cfg.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = 120 * time.Second
	}

	s.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	// Setup periodic ping if configured
	pingInterval := cfg.PingInterval
	if pingInterval == 0 {
		pingInterval = 1 * time.Minute // Default to 1 minute
	}
	if pingInterval > 0 {
		s.pingInterval = pingInterval
		s.pingStopCh = make(chan struct{})
		s.logger.Info(logging.DestinationHTTP, "Periodic daemon ping enabled", "interval", pingInterval)
	}

	return s, nil
}

// shouldUpdateIssuer checks if an issuer URL needs to be updated with the actual listening address.
// Returns true if the issuer is empty or if the host ends with :0 (indicating a dynamic port).
func shouldUpdateIssuer(issuer string) bool {
	if issuer == "" {
		return true
	}
	// Parse the issuer URL to check if port is 0
	u, err := parseURL(issuer)
	if err != nil {
		// If we can't parse it, assume it needs updating
		return true
	}

	// Check if the port is "0" (dynamic port)
	port := u.Port()
	return port == "0"
}

// parseURL is a helper to parse URLs that may or may not include a scheme
func parseURL(urlStr string) (*url.URL, error) {
	// Try parsing as-is first
	u, err := url.Parse(urlStr)
	if err == nil && u.Scheme != "" {
		return u, nil
	}

	// If no scheme, try adding http://
	if !strings.Contains(urlStr, "://") {
		urlStr = "http://" + urlStr
	}

	return url.Parse(urlStr)
}

// initializeIDP initializes the IDP provider with actual listening address
func (s *Server) initializeIDP(ln net.Listener, protocol string) error {
	if s.idpProvider == nil {
		return nil
	}

	ctx := context.Background()

	// Update issuer with actual listening address only if needed
	actualAddr := ln.Addr().String()
	issuer := protocol + "://" + actualAddr

	// Only update if the issuer was empty or had a dynamic port (:0)
	if shouldUpdateIssuer(s.idpProvider.config.AccessTokenIssuer) {
		s.idpProvider.UpdateIssuer(issuer)
	} else {
		// Use the configured issuer instead
		issuer = s.idpProvider.config.AccessTokenIssuer
	}

	// Initialize default users
	if err := s.initializeIDPUsers(ctx); err != nil {
		return fmt.Errorf("failed to initialize IDP users: %w", err)
	}

	// Initialize auto-generated client with redirect URI
	redirectURI := issuer + "/idp/callback"
	if err := s.initializeIDPClient(ctx, redirectURI); err != nil {
		return fmt.Errorf("failed to initialize IDP client: %w", err)
	}

	// Configure internal IDP as the upstream OAuth2 provider for the server
	// This allows the server to use its own IDP for authentication (SSO)
	clientID := "internal-client"
	clientSecret := "internal-secret"
	ssoRedirectURI := issuer + "/mcp/oauth2/callback"

	// Check if client exists
	_, err := s.idpProvider.storage.GetClient(ctx, clientID)
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

		if err := s.idpProvider.storage.CreateClient(ctx, client); err != nil {
			return fmt.Errorf("failed to create internal IDP client: %w", err)
		}
		s.logger.Info(logging.DestinationHTTP, "Created internal IDP client", "client_id", clientID)
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
	_, err = s.idpProvider.storage.GetClient(ctx, swaggerClientID)
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

		if err := s.idpProvider.storage.CreateClient(ctx, client); err != nil {
			return fmt.Errorf("failed to create Swagger IDP client: %w", err)
		}
		s.logger.Info(logging.DestinationHTTP, "Created Swagger IDP client", "client_id", swaggerClientID, "redirect_uris", swaggerRedirectURIs)
	}

	// Also ensure the client exists in the OAuth2 provider if enabled
	// This is required because Swagger UI is configured to use the MCP OAuth2 endpoints
	if s.oauth2Provider != nil {
		_, err = s.oauth2Provider.GetStorage().GetClient(ctx, swaggerClientID)
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

			if err := s.oauth2Provider.GetStorage().CreateClient(ctx, client); err != nil {
				s.logger.Error(logging.DestinationHTTP, "Failed to create Swagger OAuth2 client", "error", err)
			} else {
				s.logger.Info(logging.DestinationHTTP, "Created Swagger OAuth2 client", "client_id", swaggerClientID)
			}
		}
	}

	// Configure s.oauth2Config to use the internal IDP
	s.oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  issuer + "/idp/authorize",
			TokenURL: issuer + "/idp/token",
		},
		RedirectURL: ssoRedirectURI,
		Scopes:      []string{"openid", "profile", "email"},
	}
	s.oauth2UserInfoURL = issuer + "/idp/userinfo"

	s.logger.Info(logging.DestinationHTTP, "Configured OAuth2 SSO to use internal IDP", "issuer", issuer)

	return nil
}

// initializeOAuth2 initializes the OAuth2 provider with actual listening address
func (s *Server) initializeOAuth2(ln net.Listener, protocol string) {
	if s.oauth2Provider == nil {
		return
	}

	actualAddr := ln.Addr().String()
	issuer := s.oauth2Provider.config.AccessTokenIssuer

	// Only update issuer if it was empty or had a dynamic port (:0)
	if shouldUpdateIssuer(issuer) {
		issuer = protocol + "://" + actualAddr
		s.oauth2Provider.UpdateIssuer(issuer)
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
	_, err = s.oauth2Provider.GetStorage().GetClient(ctx, swaggerClientID)
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

		if err := s.oauth2Provider.GetStorage().CreateClient(ctx, client); err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to create Swagger OAuth2 client", "error", err)
		} else {
			s.logger.Info(logging.DestinationHTTP, "Created Swagger OAuth2 client", "client_id", swaggerClientID, "redirect_uris", swaggerRedirectURIs)
		}
	}
}

// getDefaultDBPath returns a default database path using LOCAL_DIR from HTCondor config
func getDefaultDBPath(cfg *config.Config, filename string) string {
	if cfg != nil {
		if localDir, ok := cfg.Get("LOCAL_DIR"); ok && localDir != "" {
			return filepath.Join(localDir, filename)
		}
	}
	// Fallback to standard HTCondor location
	return filepath.Join("/var/lib/condor", filename)
}

// Start starts the HTTP server
func (s *Server) Start() error {
	s.logger.Info(logging.DestinationHTTP, "Starting HTCondor API server", "address", s.httpServer.Addr)

	// Create listener explicitly to get actual address
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	s.listener = ln

	// Initialize IDP if enabled
	if err := s.initializeIDP(ln, "http"); err != nil {
		return err
	}

	// Initialize OAuth2 provider with actual address
	s.initializeOAuth2(ln, "http")

	// Start schedd address updater if address was discovered from collector
	if s.scheddDiscovered && s.collector != nil {
		s.startScheddAddressUpdater()
	}

	// Start session cleanup goroutine
	s.startSessionCleanup()

	// Start periodic ping goroutine if enabled
	if s.pingInterval > 0 {
		go s.periodicPing()
	}

	s.logger.Info(logging.DestinationHTTP, "Listening on", "address", ln.Addr().String())
	// Print to stdout for integration tests to detect start up
	fmt.Printf("Server started on http://%s\n", ln.Addr().String())
	return s.httpServer.Serve(ln)
}

// StartTLS starts the HTTPS server with TLS
func (s *Server) StartTLS(certFile, keyFile string) error {
	s.logger.Info(logging.DestinationHTTP, "Starting HTCondor API server with TLS", "address", s.httpServer.Addr)

	// Create listener explicitly to get actual address
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	s.listener = ln

	// Initialize IDP if enabled
	if err := s.initializeIDP(ln, "https"); err != nil {
		return err
	}

	// Initialize OAuth2 provider with actual address
	s.initializeOAuth2(ln, "https")

	// Start schedd address updater if address was discovered from collector
	if s.scheddDiscovered && s.collector != nil {
		s.startScheddAddressUpdater()
	}

	// Start session cleanup goroutine
	s.startSessionCleanup()

	// Start periodic ping goroutine if enabled
	if s.pingInterval > 0 {
		go s.periodicPing()
	}

	s.logger.Info(logging.DestinationHTTP, "Listening on", "address", ln.Addr().String())
	// Print to stdout for integration tests to detect start up
	fmt.Printf("Server started on https://%s\n", ln.Addr().String())
	return s.httpServer.ServeTLS(ln, certFile, keyFile)
}

// Shutdown gracefully shuts down the HTTP server
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info(logging.DestinationHTTP, "Shutting down HTTP server")

	// Stop periodic ping goroutine if enabled
	if s.pingStopCh != nil {
		close(s.pingStopCh)
	}

	// Signal background goroutines to stop
	close(s.stopChan)

	// Wait for background goroutines to finish (with timeout)
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	// Wait for goroutines to finish or context to be done
	select {
	case <-done:
		s.logger.Debug(logging.DestinationHTTP, "Background goroutines stopped")
	case <-ctx.Done():
		s.logger.Warn(logging.DestinationHTTP, "Shutdown timeout waiting for background goroutines")
	}

	// Close OAuth2 provider if enabled
	if s.oauth2Provider != nil {
		if err := s.oauth2Provider.Close(); err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to close OAuth2 provider", "error", err)
		}
	}

	// Close IDP provider if enabled
	if s.idpProvider != nil {
		if err := s.idpProvider.Close(); err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to close IDP provider", "error", err)
		}
	}

	return s.httpServer.Shutdown(ctx)
}

// getSchedd returns the current schedd instance (thread-safe)
func (s *Server) getSchedd() *htcondor.Schedd {
	s.scheddMu.RLock()
	defer s.scheddMu.RUnlock()
	return s.schedd
}

// updateSchedd updates the schedd instance with a new address (thread-safe)
func (s *Server) updateSchedd(newAddress string) {
	s.scheddMu.Lock()
	defer s.scheddMu.Unlock()

	// Only update if the address has changed
	if s.schedd.Address() != newAddress {
		s.logger.Info(logging.DestinationSchedd, "Updating schedd address",
			"old_address", s.schedd.Address(),
			"new_address", newAddress)
		s.schedd = htcondor.NewSchedd(s.scheddName, newAddress)
	}
}

// startScheddAddressUpdater starts a background goroutine that periodically
// checks for schedd address updates from the collector
func (s *Server) startScheddAddressUpdater() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		s.logger.Info(logging.DestinationSchedd, "Started schedd address updater",
			"interval", "60s",
			"schedd_name", s.scheddName)

		for {
			select {
			case <-ticker.C:
				// Query collector for updated schedd address
				newAddr, err := discoverSchedd(s.collector, s.scheddName, 5*time.Second, s.logger)
				if err != nil {
					s.logger.Warn(logging.DestinationSchedd, "Failed to discover schedd address",
						"error", err,
						"schedd_name", s.scheddName)
					continue
				}

				// Update schedd if address changed
				s.updateSchedd(newAddr)

			case <-s.stopChan:
				s.logger.Info(logging.DestinationSchedd, "Stopping schedd address updater")
				return
			}
		}
	}()
}

// startSessionCleanup starts a background goroutine that periodically
// cleans up expired sessions
func (s *Server) startSessionCleanup() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		// Clean up expired sessions every hour
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		s.logger.Info(logging.DestinationHTTP, "Started session cleanup goroutine", "interval", "1h")

		for {
			select {
			case <-ticker.C:
				s.sessionStore.Cleanup()
				s.logger.Debug(logging.DestinationHTTP, "Cleaned up expired sessions",
					"active_sessions", s.sessionStore.Size())

			case <-s.stopChan:
				s.logger.Info(logging.DestinationHTTP, "Stopping session cleanup goroutine")
				return
			}
		}
	}()
}

// GetOAuth2Provider returns the OAuth2 provider (for testing)
func (s *Server) GetOAuth2Provider() *OAuth2Provider {
	return s.oauth2Provider
}

// GetAddr returns the actual listening address of the server.
// Returns empty string if the server hasn't started yet.
func (s *Server) GetAddr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// UpdateOAuth2RedirectURL updates the OAuth2 redirect URL for SSO integration.
// This is useful when the server is started with a dynamic port (e.g., "127.0.0.1:0")
// and you need to update the redirect URL after the server has started.
func (s *Server) UpdateOAuth2RedirectURL(redirectURL string) {
	if s.oauth2Config != nil {
		s.oauth2Config.RedirectURL = redirectURL
	}
}

// responseWriter wraps http.ResponseWriter to capture status code and bytes written
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if rw.statusCode == 0 {
		rw.statusCode = http.StatusOK
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}

// accessLogMiddleware logs HTTP requests in access log style
func (s *Server) accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap the response writer to capture status code
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     0,
			bytesWritten:   0,
		}

		// Get client IP (handle X-Forwarded-For and X-Real-IP)
		clientIP := r.RemoteAddr
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			clientIP = strings.Split(xff, ",")[0]
		} else if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
			clientIP = xrip
		}
		// Strip port from RemoteAddr if present
		if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
			clientIP = clientIP[:idx]
		}

		// Extract identity from context (will be set by auth middleware if present)
		identity := "-"
		// Try session cookie first
		if sessionData, ok := s.getSessionFromRequest(r); ok {
			identity = sessionData.Username
		} else if s.userHeader != "" {
			if username := r.Header.Get(s.userHeader); username != "" {
				identity = username
			}
		}
		// Try to extract from bearer token if no session or user header
		if identity == "-" {
			if token, err := extractBearerToken(r); err == nil && token != "" {
				// For now, just indicate that token auth was used
				// Could parse JWT to extract subject if needed
				identity = "token"
			}
		}

		// Process the request
		next.ServeHTTP(rw, r)

		// Calculate duration
		duration := time.Since(start)

		// Log in access log format
		statusCode := rw.statusCode
		if statusCode == 0 {
			statusCode = http.StatusOK
		}

		s.logger.Info(
			logging.DestinationHTTP,
			"HTTP request",
			"client_ip", clientIP,
			"identity", identity,
			"method", r.Method,
			"path", r.URL.Path,
			"status", statusCode,
			"duration_ms", duration.Milliseconds(),
			"bytes", rw.bytesWritten,
			"user_agent", r.UserAgent(),
		)
	})
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
}

// writeError writes an error response
func (s *Server) writeError(w http.ResponseWriter, statusCode int, message string) {
	// Add WWW-Authenticate header for 401 Unauthorized responses per RFC 6750
	// This is required for Bearer token authentication regardless of OAuth2 provider
	if statusCode == http.StatusUnauthorized {
		s.addWWWAuthenticateHeader(w, "", "")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(ErrorResponse{
		Error:   http.StatusText(statusCode),
		Message: message,
		Code:    statusCode,
	}); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to encode error response", "error", err, "status_code", statusCode)
	}
}

// writeOAuthError writes an error response with appropriate WWW-Authenticate header
func (s *Server) writeOAuthError(w http.ResponseWriter, statusCode int, errorCode, errorDescription string) {
	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		s.addWWWAuthenticateHeader(w, errorCode, errorDescription)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(ErrorResponse{
		Error:   errorCode,
		Message: errorDescription,
		Code:    statusCode,
	}); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to encode error response", "error", err, "status_code", statusCode)
	}
}

// addWWWAuthenticateHeader adds RFC 6750 compliant WWW-Authenticate header
// See: https://datatracker.ietf.org/doc/html/rfc6750#section-3
func (s *Server) addWWWAuthenticateHeader(w http.ResponseWriter, errorCode, errorDescription string) {
	var headerValue string

	if s.oauth2Provider != nil {
		// Get the issuer from OAuth2 provider config
		realm := s.oauth2Provider.config.AccessTokenIssuer

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
func (s *Server) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			s.logger.Error(logging.DestinationHTTP, "Error encoding JSON response", "error", err, "status_code", statusCode)
		}
	}
}

// extractBearerToken extracts the bearer token from the Authorization header
func extractBearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", fmt.Errorf("no authorization header")
	}

	const prefix = "Bearer "
	if len(auth) < len(prefix) || auth[:len(prefix)] != prefix {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return auth[len(prefix):], nil
}

// extractOrGenerateToken extracts a bearer token from the Authorization header,
// checks for a session cookie, or if userHeader is set and no auth token is present,
// generates a token for the username from the specified header.
// Priority: Bearer token → Session cookie → User header
func (s *Server) extractOrGenerateToken(r *http.Request) (string, error) {
	// Try to extract bearer token first
	token, err := extractBearerToken(r)
	if err == nil {
		return token, nil
	}

	// Try to get username from session cookie
	if sessionData, ok := s.getSessionFromRequest(r); ok {
		username := sessionData.Username
		// If session has a cached token, use it
		if sessionData.Token != "" {
			return sessionData.Token, nil
		}

		// Generate a token for the session username if signing key is available
		if s.signingKeyPath != "" {
			iat := time.Now().Unix()
			exp := time.Now().Add(1 * time.Minute).Unix()
			issuer := s.trustDomain
			if issuer == "" {
				return "", fmt.Errorf("TRUST_DOMAIN not configured for server; cannot generate token")
			}
			if !strings.Contains(username, "@") {
				if s.uidDomain == "" {
					return "", fmt.Errorf("UID_DOMAIN not configured for server; cannot create username %s", username)
				}
				username = username + "@" + s.uidDomain
			}
			kid := filepath.Base(s.signingKeyPath)
			s.logger.Debug(logging.DestinationSecurity, "Generating token for session user", "username", username, "issuer", issuer, "key", kid)
			token, err := security.GenerateJWT(filepath.Dir(s.signingKeyPath), kid, username, issuer, iat, exp, nil)
			if err != nil {
				return "", fmt.Errorf("failed to generate token for session user %s: %w", username, err)
			}
			return token, nil
		}

		// No signing key configured, cannot generate token from session
		return "", fmt.Errorf("session cookie found but token generation not configured")
	}

	// If userHeader is configured and signing key is available, try to generate token
	if s.userHeader != "" && s.signingKeyPath != "" {
		username := r.Header.Get(s.userHeader)
		if username == "" {
			return "", fmt.Errorf("no authorization token and %s header is empty", s.userHeader)
		}

		// Generate token for this user
		iat := time.Now().Unix()
		exp := time.Now().Add(1 * time.Minute).Unix()
		issuer := s.trustDomain
		if issuer == "" {
			return "", fmt.Errorf("TRUST_DOMAIN not configured for server; cannot generate token")
		}
		if !strings.Contains(username, "@") {
			if s.uidDomain == "" {
				return "", fmt.Errorf("UID_DOMAIN not configured for server; cannot create username %s", username)
			}
			username = username + "@" + s.uidDomain
		}
		kid := filepath.Base(s.signingKeyPath)
		s.logger.Debug(logging.DestinationSecurity, "Generating token for user", "username", username, "header", s.userHeader, "issuer", issuer, "key", kid)
		token, err := security.GenerateJWT(filepath.Dir(s.signingKeyPath), kid, username, issuer, iat, exp, nil)
		if err != nil {
			return "", fmt.Errorf("failed to generate token for user %s: %w", username, err)
		}

		return token, nil
	}

	// No token and can't generate one
	return "", fmt.Errorf("no authorization token and user header not configured")
}

// createAuthenticatedContext creates a context with both token and SecurityConfig set
// This is a helper to avoid duplicating security setup code in every handler
func (s *Server) createAuthenticatedContext(r *http.Request) (context.Context, error) {
	// Extract bearer token or generate from user header
	token, err := s.extractOrGenerateToken(r)
	if err != nil {
		return nil, err
	}

	// Create context with token
	ctx := WithToken(r.Context(), token)

	// Determine which session cache to use based on authentication mode
	var sessionCache *security.SessionCache

	// Check if we're using user header mode (generated token)
	if s.userHeader != "" {
		// Try to extract bearer token to see if this is a real JWT
		_, bearerErr := extractBearerToken(r)
		if bearerErr != nil {
			// No bearer token, so we generated one from user header
			// In user header mode, tokens are regenerated per request (with new jti, iat)
			// So we can't use token as cache key. Instead, use global cache which
			// supports tagging by username in cedar's session cache implementation.
			username := r.Header.Get(s.userHeader)
			sessionCache = nil // nil means use global cache
			s.logger.Debug(logging.DestinationSecurity, "Using global session cache for user header mode", "username", username)
		} else {
			// Real bearer token provided even though user header is configured
			// Use per-token cache
			entry, exists := s.tokenCache.Get(token)
			if exists {
				sessionCache = entry.SessionCache
				s.logger.Debug(logging.DestinationSecurity, "Using cached session cache for bearer token")
			} else {
				entry, err := s.tokenCache.Add(token)
				if err != nil {
					return nil, fmt.Errorf("failed to cache token: %w", err)
				}
				sessionCache = entry.SessionCache
				s.logger.Debug(logging.DestinationSecurity, "Created new session cache for bearer token", "expiration", entry.Expiration)
			}
		}
	} else {
		// Not using user header mode - this is a real JWT token
		// Check if token is already in cache
		entry, exists := s.tokenCache.Get(token)
		if exists {
			// Use the cached session cache
			sessionCache = entry.SessionCache
			s.logger.Debug(logging.DestinationSecurity, "Using cached session cache for token")
		} else {
			// First time seeing this token - attempt authentication
			// Add to cache which will validate expiration and create session cache
			entry, err := s.tokenCache.Add(token)
			if err != nil {
				// If failed to parse as JWT, check if it's an opaque token and we have OAuth2 provider
				if s.oauth2Provider != nil {
					// Try to validate as opaque token
					session, accessErr := s.oauth2Provider.IntrospectToken(r.Context(), token)
					if accessErr == nil {
						username := session.GetSubject()
						expiration := session.GetExpiresAt(fosite.AccessToken)

						entry, err = s.tokenCache.AddValidated(token, username, expiration)
						if err != nil {
							return nil, fmt.Errorf("failed to cache validated token: %w", err)
						}
						sessionCache = entry.SessionCache
						s.logger.Debug(logging.DestinationSecurity, "Validated opaque token via OAuth2 storage", "username", username)
					} else {
						// Both JWT parsing and opaque token introspection failed
						return nil, fmt.Errorf("failed to validate token: %w (jwt error: %s)", accessErr, err.Error())
					}
				} else {
					return nil, fmt.Errorf("failed to cache token: %w", err)
				}
			} else {
				sessionCache = entry.SessionCache
				s.logger.Debug(logging.DestinationSecurity, "Created new session cache for token", "expiration", entry.Expiration)
			}
		}
	}

	// Convert token to SecurityConfig with the appropriate session cache
	// Determine if we should allow FS fallback:
	// - In user-header mode, tokens are generated but not validated by schedd, so FS fallback is needed
	// - In session-based auth, tokens are properly signed and validated, so TOKEN-only should be used
	allowFSFallback := s.userHeader != ""
	secConfig, err := ConfigureSecurityForTokenWithCacheAndFallback(token, sessionCache, allowFSFallback)
	if err != nil {
		return nil, fmt.Errorf("failed to configure security: %w", err)
	}
	ctx = htcondor.WithSecurityConfig(ctx, secConfig)

	// Extract username for rate limiting - only use from tokens that have been cached (validated)
	var username string

	// Try to get username from session cookie first
	if sessionData, ok := s.getSessionFromRequest(r); ok {
		username = sessionData.Username
	} else if s.userHeader != "" {
		// Check if using user header mode
		_, bearerErr := extractBearerToken(r)
		if bearerErr != nil {
			// User header mode - username is always trusted from header
			username = r.Header.Get(s.userHeader)
		} else {
			// Real bearer token - only use username if token is already in cache (validated)
			if entry, exists := s.tokenCache.Get(token); exists {
				// Token has been successfully used before, use cached username
				username = entry.Username
			}
		}
	} else {
		// Not using user header mode - only use username if token is in cache
		if entry, exists := s.tokenCache.Get(token); exists {
			// Token has been successfully used before, use cached username
			username = entry.Username
		}
	}

	// Set username in context for rate limiting only if from validated token
	// Otherwise treated as "unauthenticated"
	if username != "" {
		ctx = htcondor.WithAuthenticatedUser(ctx, username)
	}

	return ctx, nil
}

// discoverSchedd discovers the schedd address from the collector
func discoverSchedd(collector *htcondor.Collector, scheddName string, timeout time.Duration, logger *logging.Logger) (string, error) {
	deadline := time.Now().Add(timeout)
	pollInterval := 1 * time.Second

	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		// Query collector for schedd ads
		constraint := ""
		if scheddName != "" {
			constraint = fmt.Sprintf("Name == \"%s\"", scheddName)
		}

		ads, _, err := collector.QueryAdsWithOptions(ctx, "ScheddAd", constraint, nil)
		cancel()

		if err != nil {
			logger.Warn(logging.DestinationSchedd, "QueryAdsWithOptions failed", "error", err)
		} else {
			logger.Info(logging.DestinationSchedd, "QueryAdsWithOptions returned ads", "count", len(ads))
		}

		if err == nil && len(ads) > 0 {
			var selectedAd *classad.ClassAd

			// If scheddName is empty, try to match hostname or use first schedd
			if scheddName == "" {
				hostname, _ := os.Hostname()
				// Try to find a schedd whose name matches the hostname
				for _, ad := range ads {
					if nameExpr, ok := ad.Lookup("Name"); ok {
						name := nameExpr.String()
						name = strings.Trim(name, "\"")
						if name == hostname {
							selectedAd = ad
							logger.Info(logging.DestinationSchedd, "Found schedd matching hostname", "hostname", hostname)
							break
						}
					}
				}

				// If no match found, use the first schedd
				if selectedAd == nil {
					selectedAd = ads[0]
					if nameExpr, ok := selectedAd.Lookup("Name"); ok {
						name := nameExpr.String()
						name = strings.Trim(name, "\"")
						logger.Info(logging.DestinationSchedd, "Using first schedd found", "name", name)
					}
				}
			} else {
				// Use the first ad (which should match the constraint)
				selectedAd = ads[0]
			}

			// Extract MyAddress from the selected schedd ad
			myAddressExpr, ok := selectedAd.Lookup("MyAddress")
			if !ok {
				return "", fmt.Errorf("schedd ad missing MyAddress attribute")
			}

			// ClassAd String() returns a quoted string; trim surrounding
			// quotes and whitespace. Also remove surrounding angle brackets so
			// the cedar client receives a clean sinful-like address.
			myAddress := strings.TrimSpace(myAddressExpr.String())
			myAddress = strings.Trim(myAddress, "\"")
			myAddress = strings.TrimPrefix(myAddress, "<")
			myAddress = strings.TrimSuffix(myAddress, ">")

			// Reconstruct as a sinful string without outer angle brackets
			// (client.ConnectToAddress accepts either form; normalizing
			// avoids shared-port parsing issues that include trailing '>').
			sinful := fmt.Sprintf("<%s>", myAddress)

			logger.Info(logging.DestinationSchedd, "Schedd MyAddress from collector", "address", sinful)

			return sinful, nil
		}

		// Wait before retrying
		if time.Now().Add(pollInterval).Before(deadline) {
			time.Sleep(pollInterval)
		}
	}

	if scheddName != "" {
		return "", fmt.Errorf("timeout after %v: schedd '%s' not found in collector", timeout, scheddName)
	}
	return "", fmt.Errorf("timeout after %v: no schedds found in collector", timeout)
}

// periodicPing runs in a goroutine and periodically pings the collector and schedd
func (s *Server) periodicPing() {
	ticker := time.NewTicker(s.pingInterval)
	defer ticker.Stop()

	s.logger.Info(logging.DestinationHTTP, "Starting periodic daemon ping", "interval", s.pingInterval)

	for {
		select {
		case <-s.pingStopCh:
			s.logger.Info(logging.DestinationHTTP, "Stopping periodic daemon ping")
			return
		case <-ticker.C:
			s.performPeriodicPing()
		}
	}
}

// performPeriodicPing performs a single ping to collector and schedd
func (s *Server) performPeriodicPing() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// If we have a token, configure security
	if s.token != "" {
		secConfig, err := ConfigureSecurityForToken(s.token)
		if err != nil {
			s.logger.Error(logging.DestinationHTTP, "Failed to configure security for periodic ping", "error", err)
		} else {
			ctx = htcondor.WithSecurityConfig(ctx, secConfig)
		}
	}

	// Ping collector if configured
	if s.collector != nil {
		_, err := s.collector.Ping(ctx)
		if err != nil {
			s.logger.Warn(logging.DestinationHTTP, "Periodic collector ping failed", "error", err)
		} else {
			s.logger.Debug(logging.DestinationHTTP, "Periodic collector ping succeeded")
		}
	}

	// Ping schedd
	_, err := s.schedd.Ping(ctx)
	if err != nil {
		s.logger.Warn(logging.DestinationHTTP, "Periodic schedd ping failed", "error", err)
	} else {
		s.logger.Debug(logging.DestinationHTTP, "Periodic schedd ping succeeded")
	}
}

// redirectToLogin redirects a browser request to the OAuth2 login flow
// preserving the original URL in the state parameter
func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	if s.oauth2Config == nil {
		s.writeError(w, http.StatusUnauthorized, "Authentication required but no OAuth2 provider configured")
		return
	}

	// Build the original URL (relative path with query string)
	// Check if a return_to parameter is provided (e.g. from /login?return_to=/dashboard)
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
	state, err := s.oauth2StateStore.GenerateState()
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to generate OAuth2 state", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to initiate authentication")
		return
	}

	// Store the state with the original URL (no authorize request for browser flow)
	s.oauth2StateStore.StoreWithURL(state, nil, originalURL)

	// Build authorization URL
	authURL := s.oauth2Config.AuthCodeURL(state)

	s.logger.Info(logging.DestinationHTTP, "Redirecting unauthenticated browser to login",
		"original_url", originalURL, "state", state, "auth_url", authURL)

	// Redirect to IDP
	http.Redirect(w, r, authURL, http.StatusFound)
}

// getHTTPClient returns an HTTP client with the configured CA certificate
func (s *Server) getHTTPClient() *http.Client {
	if s.tlsCACertFile == "" {
		return http.DefaultClient
	}

	// Load CA cert
	caCert, err := os.ReadFile(s.tlsCACertFile)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to read CA certificate", "error", err)
		return http.DefaultClient
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caCertPool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}
