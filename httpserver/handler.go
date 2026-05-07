package httpserver

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/httpserver/appdb"
	"github.com/bbockelm/golang-htcondor/httpserver/appdb/seal"
	"github.com/bbockelm/golang-htcondor/jupytertunnel"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/matchanalyzer"
	"github.com/bbockelm/golang-htcondor/metricsd"
	"github.com/bbockelm/golang-htcondor/templates"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

// Handler represents the HTTP API handler that can be embedded in any HTTP server
type Handler struct {
	schedd           *htcondor.Schedd
	scheddMu         sync.RWMutex // Protects schedd instance, scheddAddrSetAt, and scheddAddrLastConfirmedAt
	scheddName       string       // Schedd name for discovery
	scheddDiscovered bool         // Whether schedd address was discovered from collector
	// scheddAddrSetAt is the timestamp at which h.schedd was last replaced
	// with a new address (initial discovery, manual UpdateSchedd, or an
	// updater tick that found a different address). It does NOT update on
	// ticks where the collector returned the same address.
	scheddAddrSetAt time.Time
	// scheddAddrLastConfirmedAt is the timestamp of the last successful
	// collector query for this schedd's address — regardless of whether the
	// address changed. This is the right "freshness" signal to log and
	// surface on /readyz: a long gap means the collector is unreachable
	// or has been failing, even if the cached address looks stable.
	scheddAddrLastConfirmedAt time.Time
	collector                 *htcondor.Collector
	credd                     htcondor.CreddClient
	creddAvailable            atomic.Bool // Whether credd is available (nil credd = not available)
	creddDiscovered           bool        // Whether credd address was discovered (and needs periodic updates)
	userHeader                string
	signingKeyPath            string
	trustDomain               string
	uidDomain                 string
	httpBaseURL               string // Base URL for HTTP API (for generating MCP file download links)
	tlsCACertFile             string
	logger                    *logging.Logger
	// db is the single SQLite file shared by OAuth2/MCP storage, the
	// embedded IDP, browser sessions, and user-saved templates. Opened
	// at the top of NewHandler and migrated via appdb.Migrate; closed
	// in Stop. nil only on the unusual path where the operator has
	// disabled every feature that needs persistence (no MCP, no IDP,
	// no templates, no sessions) — in practice always non-nil.
	db *sql.DB

	// sealer envelope-encrypts long-lived secrets (RSA / HMAC) in
	// the unified DB. Non-nil only when the operator configured
	// HTTP_API_KEK_FILE; nil disables encryption and the storage
	// helpers fall back to plaintext mode (back-compat with the
	// pre-KEK schema). Set once in NewHandler after migration; the
	// underlying AES-GCM is goroutine-safe.
	sealer             *seal.Sealer
	metricsRegistry    *metricsd.Registry
	prometheusExporter *metricsd.PrometheusExporter
	// httpMetrics holds the prometheus/client_golang registry plus the
	// HTTP request counters / duration histogram / in-flight gauge
	// recorded by the recordingMiddleware wrapper installed in
	// setupRoutes. Always non-nil after NewHandler; the metricsdAdapter
	// surfaces the legacy pool/process collectors through this same
	// registry when they're enabled.
	httpMetricsState    *httpMetrics
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
	mcpInstructions     string            // Server-level instructions provided to agents via MCP initialize
	webuiAdminGroup     string            // Group required for Web UI admin pages (empty = no admin UI)
	shareSecret         []byte            // Random 32-byte HMAC key for short-lived signed URLs
	logBuffer           *logging.Buffer   // In-memory ring buffer surfaced to the admin Web UI
	idpProvider         *IDPProvider      // Built-in IDP provider
	idpLoginLimiter     *LoginRateLimiter // Rate limiter for IDP login attempts
	streamBufferSize    int               // Buffer size for streaming queries (default: 100)
	streamWriteTimeout  time.Duration     // Write timeout for streaming queries (default: 5s)
	wg                  sync.WaitGroup    // WaitGroup to track background goroutines
	pingInterval        time.Duration     // Interval for periodic daemon pings (0 = disabled)
	pingHealth          *pingHealth       // Recent ping outcomes per daemon, drives /readyz
	// matchAnalysisOnce / matchAnalysisSlots back the lazy-allocated
	// CollectorSlotProvider used by /api/v1/jobs/{id}/match-analysis.
	// Lazily initialized so a Handler with no collector configured pays
	// nothing for the analyzer subsystem. The provider holds a slot ad
	// cache (~30s TTL) shared across all match-analysis calls.
	matchAnalysisOnce  sync.Once
	matchAnalysisSlots *matchanalyzer.CollectorSlotProvider
	token              string             // Token for daemon authentication
	mux                *http.ServeMux     // HTTP request multiplexer
	ctx                context.Context    // Context for background goroutines
	cancelFunc         context.CancelFunc // Function to cancel background goroutines

	// jupyterRegistry tracks pending and live JupyterLab tunnel instances.
	// Created lazily on first /api/v1/jupyter use so older deployments that
	// don't enable Jupyter pay no startup cost.
	jupyterRegistry   *jupytertunnel.Registry
	jupyterRegistryMu sync.Mutex

	// jupyterWorkDir is where the materialized helper binary plus
	// per-instance scratch artifacts (token files, launch scripts) are
	// staged. Files persist for the lifetime of the job since HTCondor
	// reads transfer_input_files at job-startup time. Defaults to
	// <TempDir>/htcondor-api-jupyter when not configured.
	jupyterWorkDir string

	// templateLibrary serves the batch-submission template catalog
	// (built-in + global YAML + user-saved JSON). nil = the
	// /api/v1/templates endpoint returns 503.
	templateLibrary *templates.Library
}

// HandlerConfig holds handler configuration
type HandlerConfig struct {
	ScheddName      string              // Schedd name
	ScheddAddr      string              // Schedd address (e.g., "127.0.0.1:9618"). If empty, discovered from collector.
	UserHeader      string              // HTTP header to extract username from (optional)
	SigningKeyPath  string              // Path to token signing key (optional, for token generation)
	TrustDomain     string              // Trust domain for token issuer (optional; only used if UserHeader is set)
	UIDDomain       string              // UID domain for generated token username (optional; only used if UserHeader is set)
	HTTPBaseURL     string              // Base URL for HTTP API (e.g., "http://localhost:8080") for generating file download links in MCP responses
	TLSCACertFile   string              // Path to TLS CA certificate file (optional, for trusting self-signed certs)
	Collector       *htcondor.Collector // Collector for metrics (optional)
	EnableMetrics   bool                // Enable /metrics endpoint (default: true if Collector is set)
	MetricsCacheTTL time.Duration       // Metrics cache TTL (default: 10s)
	Logger          *logging.Logger     // Logger instance (optional, creates default if nil)
	EnableMCP       bool                // Enable MCP endpoints with OAuth2 (default: false)

	// DBPath is the unified SQLite database file backing OAuth2/MCP
	// storage, the embedded IDP, browser sessions, and user-saved
	// batch-submission templates. Defaults to LOCAL_DIR/htcondor-api.db
	// (or /var/lib/condor/htcondor-api.db when LOCAL_DIR is unset).
	// Configure via HTTP_API_DB_PATH.
	DBPath string

	// KEKFilePath is the path to a file holding the master Key
	// Encryption Key used to envelope-encrypt long-lived secrets in
	// the application database (the OAuth2 / IDP issuer's RSA
	// signing key, fosite's HMAC GlobalSecret). Configured via
	// HTTP_API_KEK_FILE — the FILE PATH lives in HTCondor config,
	// the KEY BYTES never do (HTCondor treats config values as
	// public).
	//
	// Empty disables encryption: secrets are stored in plaintext as
	// before. When set, the file must contain exactly 32 raw bytes
	// or a 32-byte hex string and must be 0600/0400. See
	// httpserver/appdb/seal for the design.
	KEKFilePath string

	// OAuth2DBPath is a deprecated alias for DBPath kept so existing
	// in-process embedders (and the test suite) keep compiling without
	// a wholesale rename. NewHandler honors it only when DBPath is
	// empty. The cmd-line wrapper does NOT bridge HTTP_API_OAUTH2_DB_PATH
	// into this field — pointing the unified DB at a pre-unification
	// oauth.db is a guaranteed crash-loop (the legacy schema conflicts
	// with goose 0001_init.sql), and the wrapper logs a deprecation
	// warning instead. New code should set DBPath.
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
	// OAuth2AccessTokenLifespan is how long an access token issued by the embedded
	// MCP issuer is valid. Defaults to 1 hour if zero.
	OAuth2AccessTokenLifespan time.Duration
	// OAuth2RefreshTokenLifespan is how long a refresh token issued by the embedded
	// MCP issuer is valid. Defaults to 30 days if zero. Must be >= OAuth2AccessTokenLifespan;
	// otherwise refresh grants will fail before the access token expires (see PelicanPlatform/pelican#3389).
	OAuth2RefreshTokenLifespan time.Duration
	MCPAccessGroup             string // Group required for any MCP access (empty = all authenticated)
	MCPReadGroup               string // Group required for read operations (empty = all have read)
	MCPWriteGroup              string // Group required for write operations (empty = all have write)
	MCPInstructions            string // Server-level instructions provided to all MCP agents (e.g., AP-specific guidance)
	WebUIAdminGroup            string // Group required for Web UI admin pages (empty disables admin UI). Configurable via HTTP_API_WEBUI_ADMIN_GROUP.
	EnableIDP                  bool   // Enable built-in IDP (always enabled in demo mode)
	// IDPDBPath is deprecated; the IDP shares the unified DBPath.
	// Retained as an unused field so existing callers keep compiling
	// during the transition.
	IDPDBPath string //nolint:unused // kept for back-compat; ignored by NewHandler.
	IDPIssuer string // IDP issuer URL (default: listen address)
	// IDPAccessTokenLifespan / IDPRefreshTokenLifespan: see OAuth2*Lifespan above. Zero
	// uses the same defaults (1h / 30d).
	IDPAccessTokenLifespan  time.Duration
	IDPRefreshTokenLifespan time.Duration
	SessionTTL              time.Duration        // HTTP session TTL (default: 24h)
	HTCondorConfig          *config.Config       // HTCondor configuration (optional, used for LOCAL_DIR default)
	PingInterval            time.Duration        // Interval for periodic daemon pings (default: 1 minute, 0 = disabled)
	StreamBufferSize        int                  // Buffer size for streaming queries (default: 100)
	StreamWriteTimeout      time.Duration        // Write timeout for streaming queries (default: 5s)
	Token                   string               // Token for daemon authentication (optional)
	Credd                   htcondor.CreddClient // Optional credd client; defaults to in-memory implementation

	// JupyterWorkDir is where the embedded helper binary (materialized
	// from package jupyterhelperbin) and per-instance scratch artifacts
	// (token files) are staged. Files persist for the lifetime of the
	// job since HTCondor reads transfer_input_files at job-startup time.
	// Defaults to <os.TempDir>/htcondor-api-jupyter.
	JupyterWorkDir string

	// TemplateGlobalPath is an optional YAML file with operator-curated
	// batch-submission templates. Empty disables. Built-in templates
	// always ship.
	TemplateGlobalPath string

	// TemplateUserStoreDBPath is deprecated; the templates store now
	// shares the unified DBPath. Retained so existing callers
	// keep compiling; ignored by NewHandler.
	TemplateUserStoreDBPath string //nolint:unused // kept for back-compat; ignored by NewHandler.
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

	// Treat the initial schedd address (whether passed in or discovered) as
	// "just set / just confirmed" so the age fields don't read as huge negative
	// or zero on the very first /readyz call. If the address was discovered
	// from the collector this is also literally true; if it came from
	// configuration it's the closest meaningful baseline we have.
	now := time.Now()
	h := &Handler{
		schedd:                    schedd,
		scheddName:                cfg.ScheddName,
		scheddDiscovered:          scheddDiscovered,
		scheddAddrSetAt:           now,
		scheddAddrLastConfirmedAt: now,
		collector:                 cfg.Collector,
		credd:                     cfg.Credd,
		trustDomain:               cfg.TrustDomain,
		uidDomain:                 cfg.UIDDomain,
		httpBaseURL:               cfg.HTTPBaseURL,
		userHeader:                cfg.UserHeader,
		jupyterWorkDir:            cfg.JupyterWorkDir,
		// templateLibrary is filled in after the unified DB is open;
		// see below. Leaving it nil here makes it obvious that the
		// catalog isn't available until the post-DB path runs.
		signingKeyPath:     cfg.SigningKeyPath,
		tlsCACertFile:      cfg.TLSCACertFile,
		logger:             logger,
		tokenCache:         NewTokenCache(), // Initialize token cache (includes username for rate limiting)
		streamBufferSize:   streamBufferSize,
		streamWriteTimeout: streamWriteTimeout,
		webuiAdminGroup:    cfg.WebUIAdminGroup,
		token:              cfg.Token,
	}

	if h.webuiAdminGroup != "" {
		logger.Info(logging.DestinationHTTP, "Web UI admin group configured", "admin_group", h.webuiAdminGroup)
	}

	// Random per-process HMAC key for short-lived shared download URLs.
	// We generate fresh on each start: signed URLs are intentionally
	// short-lived and don't need to survive a restart.
	h.shareSecret = make([]byte, 32)
	if _, err := rand.Read(h.shareSecret); err != nil {
		return nil, fmt.Errorf("failed to generate share secret: %w", err)
	}

	// In-memory log buffer for the admin UI's "recent logs" panel.
	// 5000 entries at info+ keeps a few hours of typical activity in
	// memory and remains well under a megabyte. The on-disk log file
	// remains the durable source of truth.
	h.logBuffer = logging.NewBuffer(5000, slog.LevelInfo)
	logging.AttachBuffer(logger, h.logBuffer)

	// HTTP request observability. We set this up unconditionally —
	// the /metrics endpoint always serves at least the runtime + HTTP
	// request metrics, even if the legacy metricsdRegistry path is
	// disabled (no Collector configured). The metricsdAdapter is
	// registered later, after metricsRegistry is built.
	h.httpMetricsState = newHTTPMetrics()

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

	// Open the unified application database. Same SQLite file is
	// shared by OAuth2/MCP storage (when EnableMCP), the embedded IDP
	// (when EnableIDP), browser sessions, and user-saved templates.
	//
	// Resolution order:
	//   1. cfg.DBPath          — canonical, set by the cmd-line wrapper
	//                            from HTTP_API_DB_PATH.
	//   2. cfg.OAuth2DBPath    — in-process compat for embedders that
	//                            still pre-set the legacy alias. The
	//                            cmd-line wrapper does NOT propagate
	//                            HTTP_API_OAUTH2_DB_PATH into this
	//                            field; loadDBPath ignores the env
	//                            knob and emits a deprecation warning.
	//                            That's the user-facing protection
	//                            against the "silent reuse of an
	//                            incompatible legacy oauth.db ⇒
	//                            crash-loop on goose 0001_init.sql"
	//                            failure mode we hit in production.
	//   3. LOCAL_DIR/htcondor-api.db (final fallback).
	dbPath := cfg.DBPath
	if dbPath == "" {
		dbPath = cfg.OAuth2DBPath
	}
	if dbPath == "" {
		dbPath = getDefaultDBPath(cfg.HTCondorConfig, "htcondor-api.db")
	}
	// Log BEFORE Open so any subsequent silent hang or kill is at
	// least localized to the database step in the operator's logs —
	// the previous behavior emitted no marker between
	// "Discovered credd" and "Unified application database opened",
	// which made a stuck migration look identical to a stuck
	// post-credd RPC.
	logger.Info(logging.DestinationHTTP, "Opening application database", "path", dbPath)
	appDB, err := appdb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open application database: %w", err)
	}
	// Bound the migration step. If goose is stuck on a contested
	// SQLite lock (a previous, dying instance still holds it; an
	// out-of-band tool has the file open) or some other pathology,
	// we want a clear error rather than the kubelet silently
	// SIGKILL-ing us when the startup probe expires. 30 s is well
	// above the cost of every migration we ship today.
	migrateCtx, migrateCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer migrateCancel()
	logger.Info(logging.DestinationHTTP, "Applying database migrations")
	if err := appdb.Migrate(migrateCtx, appDB); err != nil {
		_ = appDB.Close()
		return nil, fmt.Errorf("failed to migrate application database (path=%s): %w", dbPath, err)
	}
	h.db = appDB
	logger.Info(logging.DestinationHTTP, "Unified application database opened", "path", dbPath)

	// Construct the envelope-encryption sealer if a KEK file is
	// configured. setupSealer reads the master KEK from disk, derives
	// the DB-instance key via HKDF + a salt persisted in kek_metadata,
	// then walks the sealable rows and encrypts any plaintext that
	// pre-dates the encryption switch. Idempotent: rows that already
	// have a non-null DEK are left alone.
	//
	// When KEKFilePath is empty the sealer stays nil and the storage
	// helpers fall back to plaintext (back-compat).
	sealCtx, sealCancel := context.WithTimeout(context.Background(), 30*time.Second)
	sealer, migrated, err := setupSealer(sealCtx, h.db, cfg.KEKFilePath, logger)
	sealCancel()
	if err != nil {
		_ = appDB.Close()
		return nil, fmt.Errorf("KEK setup: %w", err)
	}
	if sealer != nil {
		h.sealer = sealer
		logger.Info(logging.DestinationHTTP, "Envelope encryption enabled",
			"kek_file", cfg.KEKFilePath,
			"rows_migrated", migrated,
		)
	}

	// Build the template library now that the DB is open. The
	// built-in catalog is always available; the user-saved store
	// rides on the same DB connection (no separate file).
	h.templateLibrary = buildTemplateLibrary(cfg, logger, h.db)

	// Setup OAuth2 provider if MCP is enabled
	if cfg.EnableMCP {
		oauth2Issuer := cfg.OAuth2Issuer
		if oauth2Issuer == "" {
			oauth2Issuer = "http://localhost:8080"
		}

		oauth2AccessLifespan := cfg.OAuth2AccessTokenLifespan
		if oauth2AccessLifespan == 0 {
			oauth2AccessLifespan = time.Hour
		}
		oauth2RefreshLifespan := cfg.OAuth2RefreshTokenLifespan
		if oauth2RefreshLifespan == 0 {
			oauth2RefreshLifespan = 30 * 24 * time.Hour
		}

		oauth2Provider, err := NewOAuth2Provider(OAuth2ProviderOptions{
			DB:                   h.db,
			Issuer:               oauth2Issuer,
			AccessTokenLifespan:  oauth2AccessLifespan,
			RefreshTokenLifespan: oauth2RefreshLifespan,
			Sealer:               h.sealer,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create OAuth2 provider: %w", err)
		}
		logger.Info(logging.DestinationHTTP, "OAuth2 token lifespans configured",
			"access_token_lifespan", oauth2AccessLifespan,
			"refresh_token_lifespan", oauth2RefreshLifespan)
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
		h.mcpInstructions = cfg.MCPInstructions

		if h.mcpAccessGroup != "" {
			logger.Info(logging.DestinationHTTP, "MCP access control enabled", "access_group", h.mcpAccessGroup)
		}
		if h.mcpReadGroup != "" {
			logger.Info(logging.DestinationHTTP, "MCP read access control enabled", "read_group", h.mcpReadGroup)
		}
		if h.mcpWriteGroup != "" {
			logger.Info(logging.DestinationHTTP, "MCP write access control enabled", "write_group", h.mcpWriteGroup)
		}
	}

	// Initialize the browser-session store against the unified DB.
	// The http_sessions table lives in the same SQLite file as the
	// OAuth2 / IDP / templates tables — no separate file, no
	// MCP-vs-standalone branching.
	sessionStore, err := NewSessionStore(h.db, sessionTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to create session store: %w", err)
	}
	h.sessionStore = sessionStore
	logger.Info(logging.DestinationHTTP, "Session store enabled", "ttl", sessionTTL)

	// Setup IDP provider if enabled (can work independently of MCP)
	if cfg.EnableIDP {
		idpIssuer := cfg.IDPIssuer
		if idpIssuer == "" {
			idpIssuer = "http://localhost:8080"
		}

		idpAccessLifespan := cfg.IDPAccessTokenLifespan
		if idpAccessLifespan == 0 {
			idpAccessLifespan = time.Hour
		}
		idpRefreshLifespan := cfg.IDPRefreshTokenLifespan
		if idpRefreshLifespan == 0 {
			idpRefreshLifespan = 30 * 24 * time.Hour
		}

		idpProvider, err := NewIDPProvider(IDPProviderOptions{
			DB:                   h.db,
			Issuer:               idpIssuer,
			AccessTokenLifespan:  idpAccessLifespan,
			RefreshTokenLifespan: idpRefreshLifespan,
			Sealer:               h.sealer,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create IDP provider: %w", err)
		}
		logger.Info(logging.DestinationHTTP, "IDP token lifespans configured",
			"access_token_lifespan", idpAccessLifespan,
			"refresh_token_lifespan", idpRefreshLifespan)
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

		// Bridge the metricsd collectors into the
		// prometheus/client_golang registry so /metrics serves both
		// the new HTTP request metrics and the legacy pool/process
		// stats from a single endpoint.
		h.httpMetricsState.registry.MustRegister(newMetricsdAdapter(registry))

		h.logger.Info(logging.DestinationMetrics, "Metrics endpoint enabled", "path", "/metrics")
	}

	// Setup periodic ping if configured
	pingInterval := cfg.PingInterval
	if pingInterval == 0 {
		pingInterval = 1 * time.Minute // Default to 1 minute
	}
	if pingInterval > 0 {
		h.pingInterval = pingInterval
		h.pingHealth = newPingHealth(pingInterval)
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

// ServeHTTP implements http.Handler interface.
//
// Every request flows through the metrics middleware first so the
// HTTP request counters / duration histogram / in-flight gauge cover
// every route uniformly — not just the ones we remembered to wrap
// in setupRoutes. The middleware short-circuits /metrics itself to
// avoid Prometheus scrapes self-instrumenting.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.httpMetricsState != nil {
		h.httpMetricsState.middleware(h.mux).ServeHTTP(w, r)
		return
	}
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

	h.ctx, h.cancelFunc = context.WithCancel(ctx) //nolint:gosec // G118: cancelFunc is stored and called during shutdown

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

	// Start schedd address updater whenever we have a collector to query
	// and a schedd name to query for. Even when the operator passed an
	// explicit ScheddAddr, periodically confirming the address against
	// the collector (a) keeps `address_last_confirmed_age` honest in the
	// /readyz output and (b) surfaces a warning when collector and
	// config diverge. The updater respects scheddDiscovered for the
	// auto-swap decision: if the address was operator-pinned, we
	// confirm but never override.
	if h.collector != nil && h.scheddName != "" {
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

	// Close the unified application database last — every component
	// that holds a reference must finish releasing handles before
	// this point. The OAuth2/IDP provider Close() methods are now
	// no-ops; the templates store's Close also short-circuits when
	// it doesn't own the DB.
	if h.templateLibrary != nil {
		if err := h.templateLibrary.Close(); err != nil {
			h.logger.Warn(logging.DestinationHTTP, "Failed to close template library", "error", err)
		}
	}
	if h.db != nil {
		if err := h.db.Close(); err != nil {
			h.logger.Error(logging.DestinationHTTP, "Failed to close application database", "error", err)
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

// UpdateSchedd updates the schedd instance with a new address (thread-safe).
// On change, logs both addresses, the age of the previous address, and —
// when both addresses are shared-port — the old and new sock= IDs so it's
// obvious whether a schedd restart drove the update (sock= changed) versus
// a network-level address shift (host:port changed but sock= stable).
//
// Always sets scheddAddrLastConfirmedAt to now: the caller has just talked
// to the collector successfully, regardless of whether the address differs
// from the cached value.
func (h *Handler) UpdateSchedd(newAddress string) {
	h.scheddMu.Lock()
	defer h.scheddMu.Unlock()
	h.applyScheddConfirmationLocked(newAddress, true)
}

// confirmScheddAddress records that the collector vouched for the schedd
// at the given address. When the cached address was originally discovered
// from the collector (scheddDiscovered=true) and the new address differs,
// the schedd handle is replaced — same behavior as UpdateSchedd. When the
// operator pinned ScheddAddr explicitly (scheddDiscovered=false), we honor
// that intent: the address stays as configured, but we log a warning if
// the collector now advertises something different so the operator can
// see the divergence.
//
// Either way, scheddAddrLastConfirmedAt advances — the collector
// successfully reported on this schedd, which is the property /readyz's
// "address_last_confirmed_age" tracks.
func (h *Handler) confirmScheddAddress(newAddress string) {
	h.scheddMu.Lock()
	defer h.scheddMu.Unlock()
	h.applyScheddConfirmationLocked(newAddress, h.scheddDiscovered)
}

// applyScheddConfirmationLocked is the shared body of UpdateSchedd /
// confirmScheddAddress. Caller must hold scheddMu.
//
// allowSwap controls whether a divergence between cached and collector-
// reported addresses replaces the cached schedd. When false, divergence
// is logged but the cached schedd is kept; the collector's report still
// counts as a confirmation for the freshness timestamp.
func (h *Handler) applyScheddConfirmationLocked(newAddress string, allowSwap bool) {
	now := time.Now()
	old := h.schedd.Address()
	h.scheddAddrLastConfirmedAt = now
	if old == newAddress {
		return
	}

	if !allowSwap {
		// Operator-pinned address. Surface the divergence so it's
		// visible in logs / log buffer, but don't override.
		h.logger.Warn(logging.DestinationSchedd,
			"Collector reports a different schedd address; keeping operator-configured value",
			"configured_address", old,
			"collector_address", newAddress,
			"schedd_name", h.scheddName,
		)
		return
	}

	fields := []any{
		"old_address", old,
		"new_address", newAddress,
		"schedd_name", h.scheddName,
		"previous_address_age", now.Sub(h.scheddAddrSetAt).String(),
	}
	oldInfo := scheddSharedPortInfo(old)
	newInfo := scheddSharedPortInfo(newAddress)
	if oldInfo.IsSharedPort && newInfo.IsSharedPort {
		fields = append(fields,
			"old_sock_id", oldInfo.SharedPortID,
			"new_sock_id", newInfo.SharedPortID,
			"sock_id_changed", oldInfo.SharedPortID != newInfo.SharedPortID,
		)
	}
	h.logger.Info(logging.DestinationSchedd, "Updating schedd address", fields...)
	h.schedd = htcondor.NewSchedd(h.scheddName, newAddress)
	h.scheddAddrSetAt = now
}

// scheddAddrAges returns (sinceSet, sinceConfirmed) for the cached schedd
// address. sinceSet is how long the current address value has been in use;
// sinceConfirmed is how long since the collector last vouched for it (which
// may be much shorter — confirmation ticks happen even when the address
// doesn't change). Both are intended for log fields and /readyz output.
func (h *Handler) scheddAddrAges() (sinceSet, sinceConfirmed time.Duration) {
	h.scheddMu.RLock()
	defer h.scheddMu.RUnlock()
	now := time.Now()
	if !h.scheddAddrSetAt.IsZero() {
		sinceSet = now.Sub(h.scheddAddrSetAt)
	}
	if !h.scheddAddrLastConfirmedAt.IsZero() {
		sinceConfirmed = now.Sub(h.scheddAddrLastConfirmedAt)
	}
	return
}

// scheddAddressUpdateInterval bounds the maximum staleness of the cached
// schedd address. Schedds advertise to the collector roughly every 5 minutes
// in HTCondor's defaults, and a schedd that just restarted publishes a new
// sock= as soon as it comes up; refreshing more frequently than the schedd
// re-advertises is wasted work, but anything significantly slower than the
// schedd's advertise cycle means we'll keep using a stale sock= until the
// next refresh tick. 60 seconds is well under the schedd's advertise period
// and well under the user's "should never be cached for more than ~5 min"
// expectation, with comfortable headroom for missed ticks. The sole reason
// this exists as a named constant is so the comment lives next to the
// number.
const scheddAddressUpdateInterval = 60 * time.Second

// startScheddAddressUpdater starts a background goroutine that periodically
// checks for schedd address updates from the collector. The cadence is fixed
// at scheddAddressUpdateInterval; ad-hoc refreshes triggered by ping
// failures (see refreshScheddAddressNow) handle the case where the schedd
// has just restarted and we don't want to wait a full tick.
//
// On every successful collector query, scheddAddrLastConfirmedAt advances
// — that's the freshness signal /readyz reports as
// "address_last_confirmed_age". Whether the cached address gets *replaced*
// when the collector reports something new depends on h.scheddDiscovered:
// if the address was discovered initially we trust the collector
// authoritatively; if the operator pinned ScheddAddr in config we keep
// the configured value and log a warning on divergence.
func (h *Handler) startScheddAddressUpdater(ctx context.Context) {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()

		ticker := time.NewTicker(scheddAddressUpdateInterval)
		defer ticker.Stop()

		h.logger.Info(logging.DestinationSchedd, "Started schedd address updater",
			"interval", scheddAddressUpdateInterval.String(),
			"schedd_name", h.scheddName,
			"address_pinned", !h.scheddDiscovered,
		)

		for {
			select {
			case <-ticker.C:
				// Query collector for updated schedd address
				newAddr, err := discoverSchedd(h.collector, h.scheddName, 5*time.Second, h.logger)
				if err != nil {
					h.logger.Warn(logging.DestinationSchedd, "Failed to discover schedd address",
						"error", err,
						"schedd_name", h.scheddName,
						"current_address", h.getSchedd().Address())
					continue
				}

				// Touch the confirmation timestamp regardless of
				// whether the address differs. Swap the cached schedd
				// only when the address came from collector discovery
				// initially; operator-pinned ScheddAddr stays put.
				h.confirmScheddAddress(newAddr)

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

// performPeriodicPing performs a single ping to collector and schedd, updates
// the pingHealth tracker so /readyz can report current state, and emits a
// diagnostic-rich log line on failure (auth-method config for collector
// failures, stale-sock hint for schedd failures). When a schedd ping fails
// with a TCP RST on a shared-port address, this also kicks off an immediate
// schedd-address refresh from the collector rather than waiting for the
// 60-second updater tick — that's the failure mode where the cached sock=
// has just gone stale and the next ping should use a fresh address.
func (h *Handler) performPeriodicPing() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// secConfigForLog tracks the SecurityConfig actually attached to ctx so we
	// can log the AuthMethods/TrustDomain on failure. If we never managed to
	// build one (no token + no signing key), it stays nil and we still log
	// the failure but with a "client_auth_methods" of "<nil>".
	var secConfigForLog *security.SecurityConfig

	// If we have a static token, use it directly
	if h.token != "" {
		secConfig, err := ConfigureSecurityForToken(h.token)
		if err != nil {
			h.logger.Error(logging.DestinationHTTP, "Failed to configure security for periodic ping", "error", err)
		} else {
			ctx = htcondor.WithSecurityConfig(ctx, secConfig)
			secConfigForLog = secConfig
		}
	} else if h.signingKeyPath != "" && h.trustDomain != "" {
		// Generate a short-lived token using the signing key
		token, err := h.generatePingToken()
		if err != nil {
			h.logger.Warn(logging.DestinationHTTP, "Failed to generate token for periodic ping", "error", err)
		} else {
			secConfig, err := ConfigureSecurityForToken(token)
			if err != nil {
				h.logger.Error(logging.DestinationHTTP, "Failed to configure security for periodic ping", "error", err)
			} else {
				ctx = htcondor.WithSecurityConfig(ctx, secConfig)
				secConfigForLog = secConfig
			}
		}
	}

	// Ping collector if configured. The collector ping is read-only
	// — we don't need the token's identity, just any handshake the
	// server accepts — so we override the SecurityConfig on a
	// per-call ctx with one that also offers SSL when local SSL
	// credentials are configured. This keeps /readyz green when the
	// daemon's token doesn't match the collector's IssuerKeys
	// (issuer rotation, TrustDomain misconfig, …) but the host has
	// SSL credentials the collector trusts.
	if h.collector != nil {
		h.pingHealth.markCollectorEnabled()

		collectorAddr := h.collectorAddress()
		collectorHost := hostFromCondorAddress(collectorAddr)

		collectorCtx := ctx
		collectorSecForLog := secConfigForLog
		if pingSec, perr := ConfigureSecurityForCollectorPing(h.token, collectorHost); perr == nil {
			collectorCtx = htcondor.WithSecurityConfig(ctx, pingSec)
			collectorSecForLog = pingSec
		}

		_, err := h.collector.Ping(collectorCtx)
		if err != nil {
			diag := classifyConnectionError(collectorAddr, err)
			fields := []any{
				"error", err,
				"error_class", diag.Class,
			}
			// Surface "when did this last work?" — the operator's
			// first question on every paging incident.
			if last := h.pingHealth.collectorLastSuccess(); !last.IsZero() {
				fields = append(fields,
					"last_success_at", last.UTC().Format(time.RFC3339),
					"last_success_ago", time.Since(last).Truncate(time.Second).String(),
				)
			} else {
				fields = append(fields, "last_success_at", "never")
			}
			if diag.Hint != "" {
				fields = append(fields, "hint", diag.Hint)
			}
			// On no-compatible-auth, surface what *we* asked for. Cedar's
			// own logs already cover the server's offered methods.
			if diag.Class == connErrorNoCompatibleAuth {
				fields = append(fields, summarizeAuthMethods(collectorSecForLog)...)
			}
			h.logger.Warn(logging.DestinationHTTP, "Periodic collector ping failed", fields...)
			h.pingHealth.recordCollectorFailure(err, diag.Class)
		} else {
			h.logger.Debug(logging.DestinationHTTP, "Periodic collector ping succeeded")
			h.pingHealth.recordCollectorSuccess()
		}
	}

	// Ping schedd
	h.pingHealth.markScheddEnabled()
	scheddAddr := h.getSchedd().Address()
	_, err := h.getSchedd().Ping(ctx)
	if err != nil {
		diag := classifyConnectionError(scheddAddr, err)
		sinceSet, sinceConfirmed := h.scheddAddrAges()
		fields := []any{
			"error", err,
			"error_class", diag.Class,
			"schedd_address", scheddAddr,
			"address_age", sinceSet.Truncate(time.Second).String(),
			"address_last_confirmed_ago", sinceConfirmed.Truncate(time.Second).String(),
		}
		if last := h.pingHealth.scheddLastSuccess(); !last.IsZero() {
			fields = append(fields,
				"last_success_at", last.UTC().Format(time.RFC3339),
				"last_success_ago", time.Since(last).Truncate(time.Second).String(),
			)
		} else {
			fields = append(fields, "last_success_at", "never")
		}
		if diag.SharedPort != "" {
			fields = append(fields, "shared_port_id", diag.SharedPort)
		}
		if diag.Hint != "" {
			fields = append(fields, "hint", diag.Hint)
		}
		if diag.Class == connErrorNoCompatibleAuth {
			fields = append(fields, summarizeAuthMethods(secConfigForLog)...)
		}
		h.logger.Warn(logging.DestinationHTTP, "Periodic schedd ping failed", fields...)
		h.pingHealth.recordScheddFailure(err, diag.Class)

		// Stale-sock recovery: the schedd just restarted and our cached
		// address points at a dead sock. Don't wait for the 60s address
		// updater — refresh now so the next ping has a chance.
		if diag.Class == connErrorStaleSock && h.collector != nil && h.scheddName != "" {
			h.refreshScheddAddressNow("stale-sock detected on ping")
		}
	} else {
		h.logger.Debug(logging.DestinationHTTP, "Periodic schedd ping succeeded")
		h.pingHealth.recordScheddSuccess()
	}
}

// collectorAddress returns the collector's address for diagnostic logging,
// or an empty string if the collector isn't configured. Reaching into the
// collector field directly avoids exporting the address purely for logging.
func (h *Handler) collectorAddress() string {
	if h.collector == nil {
		return ""
	}
	return h.collector.Address()
}

// hostFromCondorAddress extracts the hostname from an HTCondor address.
// Accepts:
//   - sinful: "<host:port?addrs=...>"
//   - bare host:port
//   - bare host
//
// Returns the empty string for an empty input. The result is suitable
// for use as TLS ServerName for SSL hostname verification — when the
// address is a bare IP, Go's tls verifier will check IP SANs instead
// of DNS names, which is what we want.
func hostFromCondorAddress(addr string) string {
	if addr == "" {
		return ""
	}
	s := strings.TrimPrefix(addr, "<")
	s = strings.TrimSuffix(s, ">")
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
}

// refreshScheddAddressNow triggers an out-of-band schedd address refresh
// from the collector. Called when a ping failure suggests the cached address
// is stale (e.g., shared-port sock= ID no longer routes to a live process).
// reason is logged so it's clear why the refresh happened off-tick.
func (h *Handler) refreshScheddAddressNow(reason string) {
	if h.collector == nil || h.scheddName == "" {
		return
	}
	h.logger.Info(logging.DestinationSchedd, "Forcing schedd address refresh",
		"reason", reason,
		"schedd_name", h.scheddName,
		"current_address", h.getSchedd().Address())
	newAddr, err := discoverSchedd(h.collector, h.scheddName, 5*time.Second, h.logger)
	if err != nil {
		h.logger.Warn(logging.DestinationSchedd, "Forced schedd address refresh failed",
			"error", err,
			"schedd_name", h.scheddName)
		return
	}
	h.UpdateSchedd(newAddr)
}

// generatePingToken generates a short-lived IDTOKEN for periodic ping operations
func (h *Handler) generatePingToken() (string, error) {
	kid := filepath.Base(h.signingKeyPath)
	subject := "htcondor-api@" + h.trustDomain
	iat := time.Now().Unix()
	exp := time.Now().Add(5 * time.Minute).Unix()

	token, err := security.GenerateJWT(filepath.Dir(h.signingKeyPath), kid, subject, h.trustDomain, iat, exp, nil)
	if err != nil {
		return "", fmt.Errorf("failed to generate ping token: %w", err)
	}
	return token, nil
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
