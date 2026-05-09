package httpserver

import (
	"bufio"
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
	"github.com/bbockelm/golang-htcondor/httpserver/apikey"
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
	ListenAddr      string              // Address to listen on (e.g., ":8080")
	ScheddName      string              // Schedd name
	ScheddAddr      string              // Schedd address (e.g., "127.0.0.1:9618"). If empty, discovered from collector.
	UserHeader      string              // HTTP header to extract username from (optional)
	SigningKeyPath  string              // Path to token signing key (optional, for token generation)
	TrustDomain     string              // Trust domain for token issuer (optional; only used if UserHeader is set)
	UIDDomain       string              // UID domain for generated token username (optional; only used if UserHeader is set)
	HTTPBaseURL     string              // Base URL for HTTP API (e.g., "http://localhost:8080") for generating file download links in MCP responses
	TLSCertFile     string              // Path to TLS certificate file (optional, enables HTTPS)
	TLSKeyFile      string              // Path to TLS key file (optional, enables HTTPS)
	TLSCACertFile   string              // Path to TLS CA certificate file (optional, for trusting self-signed certs)
	ReadTimeout     time.Duration       // HTTP read timeout (default: 30s)
	WriteTimeout    time.Duration       // HTTP write timeout (default: 30s)
	IdleTimeout     time.Duration       // HTTP idle timeout (default: 120s)
	Collector       *htcondor.Collector // Collector for metrics (optional)
	EnableMetrics   bool                // Enable /metrics endpoint (default: true if Collector is set)
	MetricsCacheTTL time.Duration       // Metrics cache TTL (default: 10s)
	// MetricsPublic disables the API-key auth gate on /metrics.
	// Configurable via HTTP_API_METRICS_PUBLIC; see HandlerConfig.
	MetricsPublic  bool
	Logger         *logging.Logger // Logger instance (optional, creates default if nil)
	JupyterWorkDir string          // Per-instance scratch dir for JupyterLab submission artifacts; default <TempDir>/htcondor-api-jupyter

	// InteractiveExtraSubmit is an optional verbatim block of extra
	// HTCondor submit-file directives merged into every
	// interactive-terminal and Jupyter job. See
	// HandlerConfig.InteractiveExtraSubmit for the trust model and
	// full documentation. Configurable via
	// HTTP_API_INTERACTIVE_EXTRA_SUBMIT.
	InteractiveExtraSubmit string

	// Batch-submission template paths.
	TemplateGlobalPath string // Optional YAML file with operator-curated templates
	// TemplateUserStoreDBPath is deprecated; the templates store
	// shares the unified DBPath. Kept so existing callers compile.
	TemplateUserStoreDBPath string //nolint:unused // back-compat; ignored.
	EnableMCP               bool   // Enable MCP endpoints with OAuth2 (default: false)
	// DBPath is the unified SQLite database file. See HandlerConfig.DBPath.
	DBPath string
	// KEKFilePath enables envelope encryption for long-lived secrets
	// in the DB. See HandlerConfig.KEKFilePath.
	KEKFilePath string
	// OAuth2DBPath is the legacy name for DBPath; kept for back-compat.
	OAuth2DBPath        string
	OAuth2Issuer        string   // OAuth2 issuer URL (default: listen address)
	OAuth2ClientID      string   // OAuth2 client ID for SSO (optional)
	OAuth2ClientSecret  string   // OAuth2 client secret for SSO (optional)
	OAuth2AuthURL       string   // OAuth2 authorization URL for SSO (optional)
	OAuth2TokenURL      string   // OAuth2 token URL for SSO (optional)
	OAuth2RedirectURL   string   // OAuth2 redirect URL for SSO (optional)
	OAuth2UserInfoURL   string   // OAuth2 user info endpoint for SSO (optional)
	OAuth2Scopes        []string // OAuth2 scopes to request (default: ["openid", "profile", "email"])
	OAuth2UsernameClaim string   // Claim name for username in token (default: "sub")
	OAuth2GroupsClaim   string   // Claim name for groups in user info (default: "groups")
	// OAuth2AccessTokenLifespan / OAuth2RefreshTokenLifespan control how long the
	// embedded MCP issuer's tokens are valid. Zero means "use the package default"
	// (1h access, 30d refresh). RefreshTokenLifespan must be >= AccessTokenLifespan.
	OAuth2AccessTokenLifespan  time.Duration
	OAuth2RefreshTokenLifespan time.Duration
	MCPAccessGroup             string // Group required for any MCP access (empty = all authenticated)
	MCPReadGroup               string // Group required for read operations (empty = all have read)
	MCPWriteGroup              string // Group required for write operations (empty = all have write)
	MCPInstructions            string // Server-level instructions provided to all MCP agents (e.g., AP-specific guidance)
	WebUIAdminGroup            string // Group required for Web UI admin pages (empty disables admin UI). Configurable via HTTP_API_WEBUI_ADMIN_GROUP.
	EnableIDP                  bool   // Enable built-in IDP (always enabled in demo mode)
	// IDPDBPath is deprecated; the IDP shares the unified DBPath.
	IDPDBPath string //nolint:unused // back-compat; ignored.
	IDPIssuer string // IDP issuer URL (default: listen address)
	// IDPAccessTokenLifespan / IDPRefreshTokenLifespan: see OAuth2*Lifespan above.
	IDPAccessTokenLifespan  time.Duration
	IDPRefreshTokenLifespan time.Duration
	SessionTTL              time.Duration        // HTTP session TTL (default: 24h)
	HTCondorConfig          *config.Config       // HTCondor configuration (optional, used for LOCAL_DIR default)
	PingInterval            time.Duration        // Interval for periodic daemon pings (default: 1 minute, 0 = disabled)
	StreamBufferSize        int                  // Buffer size for streaming queries (default: 100)
	StreamWriteTimeout      time.Duration        // Write timeout for streaming queries (default: 5s)
	Token                   string               // Token for daemon authentication (optional)
	Credd                   htcondor.CreddClient // Optional credd client; defaults to in-memory implementation

	// LLMAPIKeyFile is the path to a file holding the Anthropic API
	// key. Empty disables the chat endpoint. See HandlerConfig.
	LLMAPIKeyFile string
	// LLMAPIURL is an optional override for the upstream Anthropic
	// endpoint, useful when the operator runs an LLM gateway. Empty
	// = direct to api.anthropic.com.
	LLMAPIURL string
	// LLMModel overrides the default model id. Empty = package default.
	LLMModel string
	// LLMOperatorInstructionsFile is the path to a file with extra
	// system-prompt rules the operator wants the chat assistant to
	// follow on every turn. Empty disables. See HandlerConfig for
	// the file-mode requirement and rationale.
	LLMOperatorInstructionsFile string
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
		ScheddName:                  cfg.ScheddName,
		ScheddAddr:                  cfg.ScheddAddr,
		UserHeader:                  cfg.UserHeader,
		SigningKeyPath:              cfg.SigningKeyPath,
		TrustDomain:                 cfg.TrustDomain,
		UIDDomain:                   cfg.UIDDomain,
		HTTPBaseURL:                 cfg.HTTPBaseURL,
		TLSCACertFile:               cfg.TLSCACertFile,
		Collector:                   cfg.Collector,
		EnableMetrics:               cfg.EnableMetrics,
		MetricsPublic:               cfg.MetricsPublic,
		MetricsCacheTTL:             cfg.MetricsCacheTTL,
		Logger:                      cfg.Logger,
		EnableMCP:                   cfg.EnableMCP,
		DBPath:                      cfg.DBPath,
		KEKFilePath:                 cfg.KEKFilePath,
		OAuth2DBPath:                cfg.OAuth2DBPath,
		JupyterWorkDir:              cfg.JupyterWorkDir,
		InteractiveExtraSubmit:      cfg.InteractiveExtraSubmit,
		TemplateGlobalPath:          cfg.TemplateGlobalPath,
		OAuth2Issuer:                cfg.OAuth2Issuer,
		OAuth2ClientID:              cfg.OAuth2ClientID,
		OAuth2ClientSecret:          cfg.OAuth2ClientSecret,
		OAuth2AuthURL:               cfg.OAuth2AuthURL,
		OAuth2TokenURL:              cfg.OAuth2TokenURL,
		OAuth2RedirectURL:           cfg.OAuth2RedirectURL,
		OAuth2UserInfoURL:           cfg.OAuth2UserInfoURL,
		OAuth2Scopes:                cfg.OAuth2Scopes,
		OAuth2UsernameClaim:         cfg.OAuth2UsernameClaim,
		OAuth2GroupsClaim:           cfg.OAuth2GroupsClaim,
		OAuth2AccessTokenLifespan:   cfg.OAuth2AccessTokenLifespan,
		OAuth2RefreshTokenLifespan:  cfg.OAuth2RefreshTokenLifespan,
		MCPAccessGroup:              cfg.MCPAccessGroup,
		MCPReadGroup:                cfg.MCPReadGroup,
		MCPWriteGroup:               cfg.MCPWriteGroup,
		MCPInstructions:             cfg.MCPInstructions,
		WebUIAdminGroup:             cfg.WebUIAdminGroup,
		EnableIDP:                   cfg.EnableIDP,
		IDPIssuer:                   cfg.IDPIssuer,
		IDPAccessTokenLifespan:      cfg.IDPAccessTokenLifespan,
		IDPRefreshTokenLifespan:     cfg.IDPRefreshTokenLifespan,
		SessionTTL:                  cfg.SessionTTL,
		HTCondorConfig:              cfg.HTCondorConfig,
		PingInterval:                cfg.PingInterval,
		StreamBufferSize:            cfg.StreamBufferSize,
		StreamWriteTimeout:          cfg.StreamWriteTimeout,
		Token:                       cfg.Token,
		Credd:                       cfg.Credd,
		LLMAPIKeyFile:               cfg.LLMAPIKeyFile,
		LLMAPIURL:                   cfg.LLMAPIURL,
		LLMModel:                    cfg.LLMModel,
		LLMOperatorInstructionsFile: cfg.LLMOperatorInstructionsFile,
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
			// Disable HTTP/2 (otherwise auto-negotiated via ALPN on
			// HTTPS). Our JupyterLab reverse proxy uses
			// httputil.ReverseProxy's WebSocket-upgrade path, which
			// requires Hijack() on the response writer. HTTP/2's
			// response writer does not implement Hijacker — bytes
			// stop flowing on the response side after the upgrade,
			// JupyterLab's WS handler accepts the connection but the
			// browser never sees the 101, retries, and Jupyter logs
			// "Replacing stale connection ... 400 GET .../channels".
			// Forcing HTTP/1.1 for all TLS sessions keeps Hijack
			// available and is fine for our scale.
			TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
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

// getDefaultDBPath returns a default database path under HTCondor's
// per-host state directory ($(LOCAL_DIR)/lib/condor) — the same
// directory that holds EXECUTE, SPOOL siblings, and the schedd's
// job_queue.log on a stock install. Living next to those files
// means our DB inherits the same backup / quota / mount policy the
// operator already applies to the rest of the daemon's state.
//
// Skips LOCAL_DIR when it's set to a known-unwritable system root.
// Specifically: cmd/htcondor-api's fixConfigDefaults forces
// LOCAL_DIR=/usr when the `condor` user doesn't exist (a common
// containerised deployment), to satisfy other HTCondor knobs that
// derive `/usr/etc`, `/usr/lib`, etc. from LOCAL_DIR. /usr is
// system-owned and never writable by an unprivileged daemon, so a
// DB path of `/usr/lib/condor/<filename>` produces SQLite's
// misleading "out of memory (14)" on first write. We detect that
// case (and the adjacent system roots) and fall through to a
// writable default.
func getDefaultDBPath(cfg *config.Config, filename string) string {
	if cfg != nil {
		if localDir, ok := cfg.Get("LOCAL_DIR"); ok && localDir != "" {
			if !isReadOnlySystemPath(localDir) {
				return filepath.Join(localDir, "lib", "condor", filename)
			}
		}
	}
	// Fallback to standard HTCondor location.
	return filepath.Join("/var/lib/condor", filename)
}

// isReadOnlySystemPath reports whether path is one of the well-known
// non-writable system roots. Used to short-circuit DB-path defaults
// that would otherwise inherit a misconfigured LOCAL_DIR.
//
// We deliberately don't try to write-probe here: the caller does that
// at open time, and short-circuiting the default lets the error
// message say "LOCAL_DIR=/usr is not a writable home for the DB"
// rather than the more confusing post-hoc permission error.
func isReadOnlySystemPath(p string) bool {
	clean := filepath.Clean(p)
	switch clean {
	case "/", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc":
		return true
	}
	// A path under /usr/{bin,lib,...} is also system-owned. We
	// don't enumerate them — anything starting with /usr/ except
	// /usr/local/* counts.
	if strings.HasPrefix(clean, "/usr/") && !strings.HasPrefix(clean, "/usr/local/") {
		return true
	}
	return false
}

// safeListenerAddr returns a string representation of ln's listening
// address that's safe to put in operator-facing logs. For TCP it's the
// usual "host:port" form. For Unix-domain listeners it strips
// everything except the endpoint basename — the rest of the path
// embeds the shared-port cookie (a long-lived secret HTCondor uses
// to authenticate shared_port_server fd-pass requests) and must not
// land in stdout, log files, or kubectl logs.
//
// The endpoint basename ("http_api") is what an external client would
// reference via `?sock=http_api` in a sinful string, so it's the
// useful piece for an operator to see at startup.
func safeListenerAddr(ln net.Listener) string {
	if ln == nil {
		return ""
	}
	addr := ln.Addr()
	if addr == nil {
		return ""
	}
	if addr.Network() == "unix" {
		path := addr.String()
		// Linux abstract namespace prefix.
		path = strings.TrimPrefix(path, "@")
		base := path
		if i := strings.LastIndexByte(path, '/'); i >= 0 {
			base = path[i+1:]
		}
		return "<shared-port endpoint " + base + ">"
	}
	return addr.String()
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

	addrStr := safeListenerAddr(ln)
	s.logger.Info(logging.DestinationHTTP, "Listening on", "address", addrStr)
	// Print to stdout for integration tests to detect start up
	fmt.Printf("Server started on http://%s\n", addrStr)
	return s.httpServer.Serve(ln)
}

// ServeListener runs the API server on a caller-supplied net.Listener.
// scheme controls which protocol the request URLs are advertised under
// ("http" or "https") — use "https" if the caller has configured
// httpServer.TLSConfig, "http" otherwise.
//
// This is the entry point used when condor_master spawns us as a
// managed daemon and we accept forwarded connections from
// condor_shared_port via a sharedport.Listener instead of binding our
// own TCP port. The handler bootstrap (issuer URL, OAuth2 setup) is
// the same as Start/StartTLS; the only difference is the kind of
// listener we hand to http.Server.Serve.
func (s *Server) ServeListener(ln net.Listener, scheme string) error {
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported scheme %q (want http or https)", scheme)
	}
	addrStr := safeListenerAddr(ln)
	s.logger.Info(logging.DestinationHTTP, "Starting HTCondor API server on shared listener",
		"scheme", scheme, "addr", addrStr)

	s.listener = ln
	s.handlerCtx, s.cancelFunc = context.WithCancel(context.Background())

	if err := s.Handler.Start(s.handlerCtx, ln, scheme); err != nil {
		return err
	}

	s.logger.Info(logging.DestinationHTTP, "Listening on shared listener", "address", addrStr)
	fmt.Printf("Server started on %s://%s\n", scheme, addrStr)

	// httpServer.Serve and ServeTLS differ only in the TLS handshake
	// that wraps each accepted conn. When the caller supplies TLSConfig
	// directly on httpServer (or a tls.Listener), Serve handles either.
	// For shared_port we always pass a plain net.Listener: shared_port
	// hands us already-accepted TCP fds, so http.Server.Serve speaks
	// HTTP/1.1 directly. TLS termination, if any, lives inside
	// http.Server's TLSConfig.
	if scheme == "https" && s.httpServer.TLSConfig != nil {
		// ServeTLS wraps accepts in tls.Server. We pass empty cert/key
		// so it uses TLSConfig.GetCertificate / Certificates already
		// configured.
		return s.httpServer.ServeTLS(ln, "", "")
	}
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

	addrStr := safeListenerAddr(ln)
	s.logger.Info(logging.DestinationHTTP, "Listening on", "address", addrStr)
	// Print to stdout for integration tests to detect start up
	fmt.Printf("Server started on https://%s\n", addrStr)
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

// Hijack passes through to the underlying ResponseWriter so that WebSocket
// upgrades (and any other hijack-based protocol) work behind this wrapper.
// Without this, gorilla/websocket's Upgrade() returns
// "websocket: response does not implement http.Hijacker" → 500.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
	}
	return hj.Hijack()
}

// Unwrap exposes the underlying ResponseWriter to Go 1.20+'s
// http.NewResponseController, which walks the Unwrap chain to find
// real Flusher / Hijacker / etc. implementations on wrapped writers.
//
// Without this, the chat SSE writer's Flush calls were silent no-ops:
// the type assertion `rw.(http.Flusher)` against this wrapper returns
// nil because Flush isn't re-declared here, so streaming SSE chunks
// piled up in Go's chunked-encoding buffer until the response ended.
// Result: every text-delta from the LLM appeared at once at the end
// of the turn, looking exactly like a buffered (not streaming)
// response — see chat/protocol.go's NewWriter for the consumer side.
func (rw *responseWriter) Unwrap() http.ResponseWriter { return rw.ResponseWriter }

// Compile-time assertion that *responseWriter implements http.Hijacker.
// Mirrors the same pin we keep on *statusRecorder in metrics.go — every
// response-writer wrapper that sits in front of the SSH or Jupyter
// WebSocket upgraders MUST implement Hijacker, and we want a future
// refactor that removes the Hijack method to fail at compile time
// rather than at runtime via a 500.
var _ http.Hijacker = (*responseWriter)(nil)

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
		// SessionData no longer carries a per-session HTCondor token —
		// the http_sessions.token column was dropped in migration
		// 0002 (it was reserved but never written). Tokens are
		// generated below from the signing key on each call.

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
			// Logged at Info so demo failures surface the iss/kid the
			// schedd will see, without needing the operator to flip on
			// debug logging first. The "trust domain mismatch" class of
			// errors is otherwise opaque from the server log alone.
			s.logger.Info(logging.DestinationSecurity, "Minted JWT for session user",
				"subject", username, "issuer", issuer, "kid", kid,
				"signing_key_path", s.signingKeyPath)
			token, err := security.GenerateJWT(filepath.Dir(s.signingKeyPath), kid, username, issuer, iat, exp, nil)
			if err != nil {
				return "", fmt.Errorf("failed to generate token for session user %s: %w", username, err)
			}
			return token, nil
		}

		// No signing key configured, cannot generate token from session
		return "", fmt.Errorf("session cookie found but token generation not configured")
	}

	// If userHeader is configured and signing key is available, try to generate token.
	// We honor the header ONLY when the request originates from a
	// trusted-proxy CIDR (or the demo-mode unsafe override is on);
	// otherwise an attacker who can reach the listener directly could
	// spoof identity by setting the header. See isUserHeaderTrustedSource
	// and the NewHandler trust-policy block for the full rationale.
	if s.userHeader != "" && s.signingKeyPath != "" {
		if !s.isUserHeaderTrustedSource(r) {
			s.logger.Warn(logging.DestinationSecurity,
				"Refusing user-header authentication from untrusted source",
				"remote_addr", r.RemoteAddr, "header", s.userHeader)
			return "", fmt.Errorf("user header authentication not permitted from this source")
		}
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
	// API-key short-circuit. Bearer tokens beginning with the
	// distinctive `htca-v1-` prefix are this server's own admin-
	// minted API keys; we resolve them to a user identity + scope
	// set without going through JWT parsing or the schedd cedar
	// handshake (API keys don't authenticate against the schedd —
	// they're for HTTP-only endpoints like /metrics). The branch is
	// before token-cache / SecurityConfig setup so an API-key
	// request never accidentally inherits an unrelated cached token.
	if raw, err := extractBearerToken(r); err == nil && apikey.LooksLikeKey(raw) {
		ctx, kerr := s.authenticateAPIKey(r, raw)
		if kerr != nil {
			return nil, kerr
		}
		return ctx, nil
	}

	// Extract bearer token or generate from user header
	token, err := s.extractOrGenerateToken(r)
	if err != nil {
		return nil, err
	}

	// Create context with token. Stash the bearer token where the
	// markValidatedOnSuccess middleware can find it after the
	// handler returns — so a 2xx response promotes the token to
	// validated and subsequent requests get authoritative identity.
	ctx := withRequestToken(r.Context(), token)
	ctx = WithToken(ctx, token)

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
				s.logger.Debug(logging.DestinationSecurity, "Using cached session cache for bearer token", "validated", entry.Validated)
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
			// Real bearer token. Use the cached username only if a
			// previous request marked the token Validated (i.e. it
			// got a 2xx from a handler, which implies the schedd
			// CEDAR handshake accepted it). Until then, identity is
			// empty: ownedByMe filters and any other identity-keyed
			// authz default to "unauthenticated", which is the safe
			// fallback. This is the fix for the "ParseUnverified
			// trusts sub" issue identified in the 2026-05 audit.
			username = s.tokenCache.ValidatedUsername(token)
		}
	} else {
		// Not using user header mode — same gating as above.
		username = s.tokenCache.ValidatedUsername(token)
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
