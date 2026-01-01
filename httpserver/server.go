package httpserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/ory/fosite"
)

// Server represents the HTTP API server
type Server struct {
	*Handler                      // Embedded handler for business logic
	httpServer *http.Server       // HTTP server instance
	listener   net.Listener       // Explicit listener to get actual address
	logger     *logging.Logger    // Logger instance (duplicated for convenience)
	handlerCtx context.Context    // Context for handler's lifetime
	cancelFunc context.CancelFunc // Function to cancel handler context
}

// Config holds server configuration
type Config struct {
	ListenAddr          string               // Address to listen on (e.g., ":8080")
	ScheddName          string               // Schedd name
	ScheddAddr          string               // Schedd address (e.g., "127.0.0.1:9618"). If empty, discovered from collector.
	UserHeader          string               // HTTP header to extract username from (optional)
	SigningKeyPath      string               // Path to token signing key (optional, for token generation)
	TrustDomain         string               // Trust domain for token issuer (optional; only used if UserHeader is set)
	UIDDomain           string               // UID domain for generated token username (optional; only used if UserHeader is set)
	HTTPBaseURL         string               // Base URL for HTTP API (e.g., "http://localhost:8080") for generating file download links in MCP responses
	TLSCertFile         string               // Path to TLS certificate file (optional, enables HTTPS)
	TLSKeyFile          string               // Path to TLS key file (optional, enables HTTPS)
	TLSCACertFile       string               // Path to TLS CA certificate file (optional, for trusting self-signed certs)
	ReadTimeout         time.Duration        // HTTP read timeout (default: 30s)
	WriteTimeout        time.Duration        // HTTP write timeout (default: 30s)
	IdleTimeout         time.Duration        // HTTP idle timeout (default: 120s)
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

// NewServer creates a new HTTP API server
func NewServer(cfg Config) (*Server, error) {
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

	// Convert Config to HandlerConfig
	handlerCfg := HandlerConfig{
		ScheddName:          cfg.ScheddName,
		ScheddAddr:          cfg.ScheddAddr,
		UserHeader:          cfg.UserHeader,
		SigningKeyPath:      cfg.SigningKeyPath,
		TrustDomain:         cfg.TrustDomain,
		UIDDomain:           cfg.UIDDomain,
		HTTPBaseURL:         cfg.HTTPBaseURL,
		TLSCACertFile:       cfg.TLSCACertFile,
		Collector:           cfg.Collector,
		EnableMetrics:       cfg.EnableMetrics,
		MetricsCacheTTL:     cfg.MetricsCacheTTL,
		Logger:              cfg.Logger,
		EnableMCP:           cfg.EnableMCP,
		OAuth2DBPath:        cfg.OAuth2DBPath,
		OAuth2Issuer:        cfg.OAuth2Issuer,
		OAuth2ClientID:      cfg.OAuth2ClientID,
		OAuth2ClientSecret:  cfg.OAuth2ClientSecret,
		OAuth2AuthURL:       cfg.OAuth2AuthURL,
		OAuth2TokenURL:      cfg.OAuth2TokenURL,
		OAuth2RedirectURL:   cfg.OAuth2RedirectURL,
		OAuth2UserInfoURL:   cfg.OAuth2UserInfoURL,
		OAuth2Scopes:        cfg.OAuth2Scopes,
		OAuth2UsernameClaim: cfg.OAuth2UsernameClaim,
		OAuth2GroupsClaim:   cfg.OAuth2GroupsClaim,
		MCPAccessGroup:      cfg.MCPAccessGroup,
		MCPReadGroup:        cfg.MCPReadGroup,
		MCPWriteGroup:       cfg.MCPWriteGroup,
		EnableIDP:           cfg.EnableIDP,
		IDPDBPath:           cfg.IDPDBPath,
		IDPIssuer:           cfg.IDPIssuer,
		SessionTTL:          cfg.SessionTTL,
		HTCondorConfig:      cfg.HTCondorConfig,
		PingInterval:        cfg.PingInterval,
		StreamBufferSize:    cfg.StreamBufferSize,
		StreamWriteTimeout:  cfg.StreamWriteTimeout,
		Token:               cfg.Token,
		Credd:               cfg.Credd,
	}

	// Create the handler
	handler, err := NewHandler(handlerCfg)
	if err != nil {
		return nil, err
	}

	// Create HTTP server with the handler
	s := &Server{
		Handler: handler,
		httpServer: &http.Server{
			Addr:         cfg.ListenAddr,
			Handler:      nil, // Will be set below after wrapping with middleware
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			IdleTimeout:  idleTimeout,
		},
		logger: handler.logger,
	}

	// Wrap handler with access logging middleware
	// Routes will be set up in Handler.Initialize()
	s.httpServer.Handler = s.accessLogMiddleware(s.Handler)

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

// initializeOAuth2 initializes the OAuth2 provider with actual listening address (delegates to Handler)

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

	// Create a cancellable context for the handler's lifetime
	s.handlerCtx, s.cancelFunc = context.WithCancel(context.Background())

	// Start Handler with actual listening address
	if err := s.Handler.Start(s.handlerCtx, ln, "http"); err != nil {
		return err
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

	// Create a cancellable context for the handler's lifetime
	s.handlerCtx, s.cancelFunc = context.WithCancel(context.Background())

	// Start Handler with actual listening address
	if err := s.Handler.Start(s.handlerCtx, ln, "https"); err != nil {
		return err
	}

	s.logger.Info(logging.DestinationHTTP, "Listening on", "address", ln.Addr().String())
	// Print to stdout for integration tests to detect start up
	fmt.Printf("Server started on https://%s\n", ln.Addr().String())
	return s.httpServer.ServeTLS(ln, certFile, keyFile)
}

// Shutdown gracefully shuts down the HTTP server
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info(logging.DestinationHTTP, "Shutting down HTTP server")

	// Cancel the handler's context to signal background goroutines to stop
	if s.cancelFunc != nil {
		s.cancelFunc()
	}

	// Stop handler (waits for goroutines to finish and closes providers)
	if err := s.Stop(ctx); err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to stop handler", "error", err)
	}

	return s.httpServer.Shutdown(ctx)
}

// GetAddr returns the actual listening address of the server.
// Returns empty string if the server hasn't started yet.
func (s *Server) GetAddr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
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
func (s *Handler) extractOrGenerateToken(r *http.Request) (string, error) {
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
func (s *Handler) createAuthenticatedContext(r *http.Request) (context.Context, error) {
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

// discoverCredd discovers the credd address by:
// 1. Checking for a local .credd_address file if schedd was found via address file
// 2. Querying the collector for a CreddAd with the same Name as the schedd
// Returns the credd address or error if not found
func discoverCredd(scheddName string, scheddAddr string, collector *htcondor.Collector, logger *logging.Logger) (string, error) {
	// First, try to find credd via local address file if schedd address looks local
	if strings.Contains(scheddAddr, "127.0.0.1") || strings.Contains(scheddAddr, "localhost") {
		logger.Info(logging.DestinationHTTP, "Schedd appears local, checking for .credd_address file")

		// Try to find credd address file in common HTCondor locations
		creddAddressFile := findCreddAddressFile(logger)
		if creddAddressFile != "" {
			data, err := os.ReadFile(creddAddressFile) //nolint:gosec // creddAddressFile comes from HTCondor config or known paths
			if err == nil {
				// Only take the first line (address), ignore version info
				lines := strings.Split(string(data), "\n")
				address := strings.TrimSpace(lines[0])
				if address != "" && !strings.Contains(address, "(null)") {
					logger.Info(logging.DestinationHTTP, "Found local credd via address file", "address", address)
					return address, nil
				}
			}
		}
	}

	// If no local credd found, query collector
	if collector != nil {
		logger.Info(logging.DestinationHTTP, "Querying collector for credd", "scheddName", scheddName)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Query for CreddAd with same Name as schedd
		constraint := ""
		if scheddName != "" {
			constraint = fmt.Sprintf(`Name == "%s"`, scheddName)
		}

		ads, _, err := collector.QueryAdsWithOptions(ctx, "CredD", constraint, nil)
		if err != nil {
			return "", fmt.Errorf("failed to query collector for credd: %w", err)
		}

		if len(ads) == 0 {
			return "", fmt.Errorf("no credd ads found in collector")
		}

		// Use the first credd ad
		myAddressExpr, ok := ads[0].Lookup("MyAddress")
		if !ok {
			return "", fmt.Errorf("credd ad missing MyAddress attribute")
		}

		myAddress := myAddressExpr.String()
		myAddress = strings.Trim(myAddress, `"`)

		if myAddress != "" {
			return myAddress, nil
		}
	}

	return "", fmt.Errorf("no credd found via local file or collector")
}

// findCreddAddressFile searches for .credd_address file in common HTCondor locations
func findCreddAddressFile(logger *logging.Logger) string {
	// First, try to get the configured path from HTCondor config
	if htcConfig, err := config.New(); err == nil {
		if creddAddressFile, ok := htcConfig.Get("CREDD_ADDRESS_FILE"); ok {
			if _, err := os.Stat(creddAddressFile); err == nil {
				logger.Info(logging.DestinationHTTP, "Found credd address file from config", "path", creddAddressFile)
				return creddAddressFile
			}
			logger.Debug(logging.DestinationHTTP, "CREDD_ADDRESS_FILE configured but not found", "path", creddAddressFile)
		}
	}

	// Fall back to common locations
	commonPaths := []string{
		"/var/log/condor/.credd_address",
		"/var/lib/condor/log/.credd_address",
		"./log/.credd_address", // relative for testing
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			logger.Info(logging.DestinationHTTP, "Found credd address file", "path", path)
			return path
		}
	}

	return ""
}

// getHTTPClient returns an HTTP client with the configured CA certificate
func (s *Handler) getHTTPClient() *http.Client {
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
