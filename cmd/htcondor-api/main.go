// Package main provides an HTTP API server for HTCondor job management.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/droppriv"
	"github.com/bbockelm/golang-htcondor/httpserver"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/sharedport"
)

var (
	demoMode          = flag.Bool("demo", false, "Run in demo mode with mini condor")
	demoShutdownAfter = flag.Duration("demo-shutdown-after", 0, "Shutdown demo mode after specified duration (e.g., 30s, 5m, 1h). 0 = run indefinitely")
	listenAddr        = flag.String("listen", ":8080", "Address to listen on")
	userHeader        = flag.String("user-header", "", "HTTP header to read username from (e.g., X-Remote-User). Only used in demo mode with token generation.")
	collectorHost     = flag.String("collector", "", "Collector host:port (overrides COLLECTOR_HOST from config)")
	scheddName        = flag.String("schedd", "", "Schedd name (overrides SCHEDD_NAME from config)")
	scheddAddr        = flag.String("schedd-addr", "", "Schedd address (if specified, schedd name is ignored)")
	// -local-name is the HTCondor-standard flag every DaemonCore daemon
	// has to accept. condor_master automatically appends it for daemons
	// that aren't in the built-in DC list — see masterDaemon.cpp:791.
	// We capture it here so flag.Parse() doesn't reject our launch and
	// thread the value through the HTCondor config layer so subsystem-
	// scoped lookups (HTTP_API.<key> beats <key>) resolve correctly.
	localName = flag.String("local-name", "", "HTCondor subsystem local-name; passed by condor_master for non-default DC daemons. Used as a config-lookup prefix.")
)

func main() {
	// Capture every stdlib log.* line emitted before the structured
	// logger is built. The buffer tees writes to stderr (preserving
	// the operator-visible startup trace) and accumulates an in-
	// memory copy that runNormalMode replays through slog once the
	// daemon log file is open. Without this, the daemon-core env
	// diagnostic and "Using UID_DOMAIN" lines never reach
	// $(LOG)/HttpApiLog — making it look like the daemon's first
	// few seconds vanished.
	earlyBuf := logging.InstallEarlyBuffer(os.Stderr, 256)

	// Pre-flag-parse diagnostic: log the daemon-core env vars
	// condor_master *should* be passing us. If CONDOR_INHERIT is empty
	// here, the daemon-mode path in runNormalMode will not engage and
	// we'll fall through to a regular TCP bind — making it look like
	// shared-port forwarding "didn't work" when in reality the master
	// never wired it up. Logging this unconditionally at startup
	// turns "shared-port silently broken" into a one-line diagnostic
	// the operator can see in /tmp/error.log without recompiling.
	logCondorEnvDiagnostic()

	flag.Parse()

	// Check for subcommands
	args := flag.Args()
	if len(args) > 0 {
		switch args[0] {
		case "token":
			if len(args) > 1 && args[1] == "fetch" {
				if err := runTokenFetch(args[2:]); err != nil {
					log.Fatalf("Token fetch failed: %v", err)
				}
				return
			}
			log.Fatalf("Unknown token subcommand. Usage: htcondor-api token fetch <issuer-url>")
		default:
			log.Fatalf("Unknown command: %s", args[0])
		}
		return
	}

	// Default behavior: run as server
	if *demoMode {
		if err := runDemoMode(earlyBuf); err != nil {
			// On the failure path, restore stdlib log to plain
			// stderr so log.Fatalf below isn't swallowed by the
			// buffer.
			earlyBuf.Detach()
			log.Fatalf("Demo mode failed: %v", err)
		}
	} else {
		if err := runNormalMode(earlyBuf); err != nil {
			earlyBuf.Detach()
			log.Fatalf("Server failed: %v", err)
		}
	}
}

// mcpConfig holds MCP-related configuration
type mcpConfig struct {
	enabled             bool
	oauth2DBPath        string
	oauth2Issuer        string
	oauth2ClientID      string
	oauth2ClientSecret  string
	oauth2AuthURL       string
	oauth2TokenURL      string
	oauth2RedirectURL   string
	oauth2UserInfoURL   string
	oauth2Scopes        []string
	oauth2UsernameClaim string
	oauth2GroupsClaim   string
	mcpAccessGroup      string
	mcpReadGroup        string
	mcpWriteGroup       string
	instructions        string
	// Token lifespans for the embedded MCP issuer. Zero means "use the package
	// default" (1h access, 30d refresh).
	oauth2AccessTokenLifespan  time.Duration
	oauth2RefreshTokenLifespan time.Duration
}

// fixConfigDefaults handles edge cases in HTCondor configuration
// defaults. When the `condor` user doesn't exist on the host (which
// happens in development containers, CI, and minimal images), HTCondor's
// own defaults that derive from `$(TILDE)` collapse to empty strings —
// most notably LOCAL_DIR and LOG. We patch those here so the binary
// can come up with sensible paths instead of refusing to start.
//
// We deliberately set LOG (the log directory) and let HTTP_API_LOG
// default to `$(LOG)/HttpApiLog` via the param-overrides table — that
// keeps every per-daemon log knob (HTTP_API_LOG, MAX_HTTP_API_LOG,
// TRUNC_HTTP_API_LOG_ON_OPEN…) consistent with how every other DC
// daemon resolves its log path.
func fixConfigDefaults(cfg *config.Config, debug bool) {
	tilde, hasTilde := cfg.Get("TILDE")
	if !hasTilde || tilde == "" {
		if localDir, hasLocalDir := cfg.Get("LOCAL_DIR"); !hasLocalDir || localDir == "" || localDir == "$(TILDE)" {
			if debug {
				log.Println("DEBUG: condor user does not exist, setting LOCAL_DIR to /usr and LOG to /var/log/condor")
			}
			cfg.Set("LOCAL_DIR", "/usr")
			cfg.Set("LOG", "/var/log/condor")
		}
	}
}

// checkLogPathWritable verifies the log file path is workable: the
// parent directory exists (we'll create it if not), is writable, and
// — when an existing file is present at logPath — is openable for
// append.
func checkLogPathWritable(logPath string) error {
	parent := filepath.Dir(logPath)
	info, err := os.Stat(parent)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(parent, 0750); err != nil {
				return fmt.Errorf("logfile parent directory %s does not exist and cannot be created: %w", parent, err)
			}
			return nil
		}
		return fmt.Errorf("cannot stat logfile parent directory %s: %w", parent, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("logfile parent path %s is not a directory", parent)
	}

	// Probe writability via a temp file in the parent directory.
	// CreateTemp + the random suffix avoids racing with an existing
	// .write_test left over from a prior run / a sibling daemon.
	probe, err := os.CreateTemp(parent, ".logfile-probe-*")
	if err != nil {
		return fmt.Errorf("parent directory %s is not writable: %w", parent, err)
	}
	probeName := probe.Name()
	_ = probe.Close()
	_ = os.Remove(probeName)

	// If a log file already exists at logPath, ensure we can open it
	// for append — covers the case of a leftover file owned by a
	// different uid in the same writable directory.
	if fi, err := os.Stat(logPath); err == nil && !fi.IsDir() {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // path is operator-controlled
		if err != nil {
			return fmt.Errorf("existing log file %s is not writable by the daemon user: %w", logPath, err)
		}
		_ = f.Close()
	} else if err == nil && fi.IsDir() {
		return fmt.Errorf("log path %s exists but is a directory; HTTP_API_LOG must be a file (e.g. $(LOG)/HttpApiLog)", logPath)
	}
	return nil
}

// createLogger creates a logger with reasonable defaults for unprivileged operation
func createLogger(cfg *config.Config) (*logging.Logger, error) {
	// Check if LOG path is configured and writable
	logPath, hasLogPath := cfg.Get("HTTP_API_LOG")
	needStdout := false

	if hasLogPath && logPath != "" && logPath != "stdout" && logPath != "stderr" {
		if err := checkLogPathWritable(logPath); err != nil {
			log.Printf("LOG directory '%s' is not writable: %v", logPath, err)
			log.Println("Falling back to stdout logging (debug config preserved)")
			needStdout = true
		}
	} else if !hasLogPath || logPath == "" {
		log.Println("No LOG path configured, using stdout")
		needStdout = true
	}

	// Temporarily override LOG to stdout if needed
	originalLog := logPath
	if needStdout {
		cfg.Set("HTTP_API_LOG", "stdout")
	}

	// Create logger with HTTP_API daemon-specific settings
	logger, err := logging.FromConfigWithDaemon("HTTP_API", cfg)

	// Restore original LOG value if we changed it
	if needStdout && hasLogPath {
		cfg.Set("HTTP_API_LOG", originalLog)
	}

	if err != nil {
		log.Printf("Failed to create logger: %v", err)
		// Fall back to basic stdout logger
		return logging.New(&logging.Config{
			OutputPath: "stdout",
		})
	}

	return logger, nil
}

// discoverSchedd attempts to discover a schedd address
// Priority order:
// 1. Check local schedd address file (SCHEDD_ADDRESS_FILE)
// 2. Query collector for schedds and use the first one (or filter by requestedName if provided)
func discoverSchedd(cfg *config.Config, collector *htcondor.Collector, logger *logging.Logger, requestedName string) (addr, name string) {
	// Try to find local schedd address file
	if spoolDir, ok := cfg.Get("SPOOL"); ok && spoolDir != "" {
		scheddAddrFile := filepath.Join(spoolDir, ".schedd_address")
		// #nosec G304 -- Reading HTCondor schedd address file from configured SPOOL directory
		if data, err := os.ReadFile(scheddAddrFile); err == nil {
			addr = string(data)
			addr = strings.TrimSpace(addr)
			if addr != "" {
				logger.Info(logging.DestinationSchedd, "Found local schedd address file", "path", scheddAddrFile, "address", addr)
				// Try to extract name from address or use hostname
				if hostname, ok := cfg.Get("FULL_HOSTNAME"); ok && hostname != "" {
					name = hostname
				}
				return addr, name
			}
		}
	}

	// Try SCHEDD_ADDRESS_FILE directly if SPOOL isn't set
	if addrFile, ok := cfg.Get("SCHEDD_ADDRESS_FILE"); ok && addrFile != "" {
		// #nosec G304 -- Reading HTCondor schedd address file from SCHEDD_ADDRESS_FILE configuration
		if data, err := os.ReadFile(addrFile); err == nil {
			addr = string(data)
			addr = strings.TrimSpace(addr)
			if addr != "" {
				logger.Info(logging.DestinationSchedd, "Found schedd address file", "path", addrFile, "address", addr)
				if hostname, ok := cfg.Get("FULL_HOSTNAME"); ok && hostname != "" {
					name = hostname
				}
				return addr, name
			}
		}
	}

	// If we have a collector, query for schedds
	if collector != nil {
		if requestedName != "" {
			logger.Info(logging.DestinationSchedd, "Querying collector for schedd", "name", requestedName)
		} else {
			logger.Info(logging.DestinationSchedd, "Querying collector for schedds")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Build constraint to filter by name if requested
		constraint := ""
		if requestedName != "" {
			constraint = fmt.Sprintf("Name == \"%s\"", requestedName)
		}

		schedds, _, err := collector.QueryAdsWithOptions(ctx, "ScheddAd", constraint, nil)
		if err != nil {
			logger.Error(logging.DestinationSchedd, "Failed to query collector for schedds", "error", err)
			return "", ""
		}

		if len(schedds) == 0 && requestedName != "" {
			logger.Error(logging.DestinationSchedd, "Schedd not found in collector", "name", requestedName)
			return "", ""
		}

		if len(schedds) > 0 {
			// Use the first schedd
			scheddAd := schedds[0]

			// Extract MyAddress
			if myAddr, ok := scheddAd.Lookup("MyAddress"); ok {
				addrStr := myAddr.String()
				// Remove quotes if present
				addrStr = strings.Trim(addrStr, "\"")
				if addrStr != "" {
					addr = addrStr
				}
			}

			// Extract Name
			if nameExpr, ok := scheddAd.Lookup("Name"); ok {
				nameStr := nameExpr.String()
				// Remove quotes if present
				nameStr = strings.Trim(nameStr, "\"")
				if nameStr != "" {
					name = nameStr
				}
			}

			if addr != "" {
				logger.Info(logging.DestinationSchedd, "Found schedd from collector", "name", name, "address", addr)
				return addr, name
			}
		}
	}

	logger.Warn(logging.DestinationSchedd, "Could not discover schedd - no local address file and no collector available")
	return "", ""
}

// discoverOIDCEndpoints performs OIDC discovery to find authorization, token, and userinfo endpoints
func discoverOIDCEndpoints(issuerURL string) (authURL, tokenURL, userInfoURL string, err error) {
	// Construct the well-known OIDC configuration URL
	configURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"

	// Fetch the OIDC configuration
	req, err := http.NewRequestWithContext(context.Background(), "GET", configURL, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create OIDC configuration request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req) // #nosec G107 -- URL is from configuration, admin-controlled
	if err != nil {
		return "", "", "", fmt.Errorf("failed to fetch OIDC configuration: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("OIDC configuration endpoint returned status %d", resp.StatusCode)
	}

	// Parse the configuration
	var config struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		UserinfoEndpoint      string `json:"userinfo_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", "", "", fmt.Errorf("failed to parse OIDC configuration: %w", err)
	}

	if config.AuthorizationEndpoint == "" || config.TokenEndpoint == "" {
		return "", "", "", fmt.Errorf("OIDC configuration missing required endpoints")
	}

	return config.AuthorizationEndpoint, config.TokenEndpoint, config.UserinfoEndpoint, nil
}

// loadLLMConfig pulls the optional chat-feature configuration out of
// HTCondor config:
//
//   - apiKeyFile: path to the Anthropic API key (always a file, never
//     inline bytes — same rationale as KEK).
//   - url: optional URL override (for proxy/cache deployments).
//   - model: optional model id override.
//   - operatorInstructionsFile: optional file with site-specific extra
//     system-prompt rules appended to every chat turn.
//
// All four are zero-valued when unset; the chat package treats an
// empty apiKeyFile as "feature disabled" and the others have safe
// defaults.
func loadLLMConfig(cfg *config.Config) (apiKeyFile, url, model, operatorInstructionsFile string) {
	if v, ok := cfg.Get("HTTP_API_LLM_API_KEY_FILE"); ok {
		apiKeyFile = strings.TrimSpace(v)
	}
	if v, ok := cfg.Get("HTTP_API_LLM_API_URL"); ok {
		url = strings.TrimSpace(v)
	}
	if v, ok := cfg.Get("HTTP_API_LLM_MODEL"); ok {
		model = strings.TrimSpace(v)
	}
	if v, ok := cfg.Get("HTTP_API_LLM_OPERATOR_INSTRUCTIONS_FILE"); ok {
		operatorInstructionsFile = strings.TrimSpace(v)
	}
	return
}

// loadKEKFilePath returns the path of the master KEK file from
// HTCondor configuration, or "" when no KEK is configured.
//
// Only the FILE PATH lives in HTCondor config — HTCondor treats
// configuration values as public information (any user on the
// machine can dump them via condor_config_val), so the KEY BYTES
// must come from a file the operator has separately permission-locked
// (mode 0600 / 0400). Empty path = encryption disabled, secrets
// stored in plaintext (back-compat with the pre-KEK schema).
//
// The KEK file is never auto-created. The operator generates it
// out-of-band (`openssl rand -hex 32 > /etc/secrets/kek && chmod 0600 ...`)
// and mounts it via whatever secrets mechanism their deployment
// uses (k8s Secret, sealed-secret, vault csi). Auto-generating a
// missing file would be unsafe in containerised deployments — a
// fresh KEK on an emptyDir path would silently change every
// restart, and every encrypted row in the DB would become
// un-openable. seal.LoadMasterKEKFromFile enforces this at the
// load layer.
//
// We don't validate the file content here — that happens later,
// inside seal.LoadMasterKEKFromFile, which checks length,
// permissions, and parses raw-or-hex content. Surfacing those
// errors at the server-construction layer keeps this function
// side-effect free.
func loadKEKFilePath(cfg *config.Config, logger *logging.Logger) string {
	path, ok := cfg.Get("HTTP_API_KEK_FILE")
	if !ok || path == "" {
		if logger != nil {
			logger.Warn(logging.DestinationHTTP,
				"HTTP_API_KEK_FILE is not configured; long-lived secrets (RSA signing keys, HMAC GlobalSecrets) will be stored in the application DB in plaintext. To enable envelope encryption, generate a 32-byte key OUT-OF-BAND (e.g. `openssl rand -hex 32 > /path/to/kek && chmod 0600 /path/to/kek`), stage the file via your secrets mechanism on a path that survives restarts, and set HTTP_API_KEK_FILE to point at it. The server will never create or auto-generate this file.",
			)
		}
		return ""
	}
	return path
}

// loadDBPath resolves the unified application database path.
//
// Only HTTP_API_DB_PATH is honored. The legacy HTTP_API_OAUTH2_DB_PATH
// is intentionally NOT a silent fallback: pre-unification oauth.db
// files have a schema (oauth2_clients, oauth2_access_tokens, …) that
// conflicts with the unified 0001_init.sql migration on its first
// CREATE TABLE, producing a guaranteed crash-loop. We saw exactly this
// on a deployed pod whose HTTP_API_OAUTH2_DB_PATH was being silently
// reused. Operators who still set the legacy knob get a clear
// deprecation warning telling them it's ignored — those who want to
// preserve their old data can rename the file to htcondor-api.db (or
// set HTTP_API_DB_PATH explicitly) before bringing the new binary up;
// the migration will still fail on schema conflicts there, but the
// failure mode is now operator-initiated rather than surprise-on-deploy.
//
// Default is LOCAL_DIR/htcondor-api.db, with the historical
// /var/lib/condor location as a final fallback.
func loadDBPath(cfg *config.Config, logger *logging.Logger) string {
	dbPath, hasDBPath := cfg.Get("HTTP_API_DB_PATH")
	legacy, hasLegacy := cfg.Get("HTTP_API_OAUTH2_DB_PATH")

	if hasLegacy && legacy != "" && (!hasDBPath || dbPath == "") && logger != nil {
		logger.Warn(logging.DestinationHTTP,
			"HTTP_API_OAUTH2_DB_PATH is deprecated and ignored; the unified application DB is HTTP_API_DB_PATH (default LOCAL_DIR/htcondor-api.db). The legacy oauth.db has a schema that conflicts with the unified migration, so it cannot be reused as-is — rename the file or set HTTP_API_DB_PATH explicitly to opt in to a manual migration.",
			"legacy_path", legacy,
		)
	}

	if hasDBPath && dbPath != "" {
		return dbPath
	}
	// Default location: $(LOCAL_DIR)/lib/condor/htcondor-api.db —
	// peer of EXECUTE, SPOOL, and the schedd's job_queue.log on a
	// stock HTCondor install. Living in the daemon's per-host
	// state directory means an operator's existing backup /
	// retention / quota policy for that tree applies to us too.
	if localDir, ok := cfg.Get("LOCAL_DIR"); ok && localDir != "" {
		return filepath.Join(localDir, "lib", "condor", "htcondor-api.db")
	}
	return "/var/lib/condor/htcondor-api.db"
}

// loadJupyterWorkDir resolves the per-instance scratch directory used to
// stage the embedded helper binary and token files for Jupyter submissions.
// Empty string lets the handler pick a default under os.TempDir().
//
// The helper binary itself is embedded into the api binary via package
// httpserver/jupyterhelperbin (when built with -tags embed_jupyter_helper),
// so there is no separate path-discovery step.
func loadJupyterWorkDir(cfg *config.Config) string {
	if p, ok := cfg.Get("HTTP_API_JUPYTER_WORK_DIR"); ok && p != "" {
		return p
	}
	return ""
}

// loadTemplateGlobalPath resolves the YAML file (if any) the operator
// has populated with shared batch-submission templates. Empty disables.
func loadTemplateGlobalPath(cfg *config.Config) string {
	if p, ok := cfg.Get("HTTP_API_TEMPLATE_GLOBAL_PATH"); ok && p != "" {
		return p
	}
	return ""
}

// loadInteractiveExtraSubmit returns the verbatim block of extra
// submit-file directives the operator wants spliced into every
// interactive-terminal and Jupyter submission. Empty disables. See
// HandlerConfig.InteractiveExtraSubmit for the trust model. Restart
// the API server to pick up changes (the value is read once at
// startup).
func loadInteractiveExtraSubmit(cfg *config.Config) string {
	if v, ok := cfg.Get("HTTP_API_INTERACTIVE_EXTRA_SUBMIT"); ok {
		return v
	}
	return ""
}

// (User-templates DB path resolution was removed: the templates store
// now shares the unified application database resolved by loadDBPath.)

// loadHTTPBaseURL constructs the HTTP base URL for the API server.
// It uses HTTP_API_BASE_URL if configured, otherwise constructs from:
// - Protocol: https if TLS is enabled, http otherwise
// - Hostname: FULL_HOSTNAME if available, otherwise falls back to listen address
// - Port: appended if non-standard for the protocol
func loadHTTPBaseURL(cfg *config.Config, listenAddr string, useTLS bool) string {
	// Check for explicit base URL configuration
	if baseURL, ok := cfg.Get("HTTP_API_BASE_URL"); ok && baseURL != "" {
		return strings.TrimSuffix(baseURL, "/")
	}

	// Determine protocol
	protocol := "http"
	defaultPort := "80"
	if useTLS {
		protocol = "https"
		defaultPort = "443"
	}

	// Pick a hostname:
	//   1. FULL_HOSTNAME from config (production deployments)
	//   2. The host portion of listenAddr (if it has one)
	//   3. localhost (last resort — handles ":8080"-style addrs in demo mode
	//      and prevents URLs like "https://:8080/" that browsers reject)
	hostname := ""
	if fullHostname, ok := cfg.Get("FULL_HOSTNAME"); ok && fullHostname != "" {
		hostname = fullHostname
	}

	// Split listenAddr into host + port (handles "host:port", ":port", and
	// IPv6 "[::1]:port"). net.SplitHostPort fails on bare ":port" without
	// a leading colon-aware fallback, so we prefix when needed.
	listen := listenAddr
	if strings.HasPrefix(listen, ":") {
		listen = "0.0.0.0" + listen
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		// Fall back to the original string; ugly but at least returns
		// something rather than panicking.
		return protocol + "://" + listenAddr
	}
	if hostname == "" {
		// Treat the wildcard / unspecified-listen forms as localhost when
		// constructing externally-visible URLs; otherwise use whatever
		// host the operator pinned the listener to.
		switch host {
		case "", "0.0.0.0", "::", "[::]":
			hostname = "localhost"
		default:
			hostname = host
		}
	}

	if port != "" && port != defaultPort {
		hostname = hostname + ":" + port
	}
	return protocol + "://" + hostname
}

// loadOAuth2Issuer loads OAuth2 issuer from config or constructs it
func loadOAuth2Issuer(cfg *config.Config, listenAddrFromConfig string) string {
	if issuer, ok := cfg.Get("HTTP_API_OAUTH2_ISSUER"); ok && issuer != "" {
		return issuer
	}

	// Use loadHTTPBaseURL with TLS enabled (OAuth2 defaults to https)
	return loadHTTPBaseURL(cfg, listenAddrFromConfig, true)
}

// loadOAuth2ClientSecret loads OAuth2 client secret from file
func loadOAuth2ClientSecret(cfg *config.Config, logger *logging.Logger) string {
	secretFile, ok := cfg.Get("HTTP_API_OAUTH2_CLIENT_SECRET_FILE")
	if !ok || secretFile == "" {
		return ""
	}

	// #nosec G304 -- Reading OAuth2 client secret from configured file path
	secretData, err := os.ReadFile(secretFile)
	if err != nil {
		logger.Warn(logging.DestinationHTTP, "Failed to read OAuth2 client secret file", "path", secretFile, "error", err)
		return ""
	}

	logger.Info(logging.DestinationHTTP, "OAuth2 client secret loaded from file", "path", secretFile)
	return strings.TrimSpace(string(secretData))
}

// loadOAuth2Endpoints loads OAuth2 auth, token, and userinfo URLs via OIDC discovery or explicit config
func loadOAuth2Endpoints(cfg *config.Config, logger *logging.Logger) (authURL, tokenURL, userInfoURL string) {
	// Check for OIDC discovery first
	if idpURL, ok := cfg.Get("HTTP_API_OAUTH2_IDP"); ok && idpURL != "" {
		logger.Info(logging.DestinationHTTP, "Attempting OIDC discovery", "url", idpURL)
		auth, token, userInfo, err := discoverOIDCEndpoints(idpURL)
		if err == nil {
			logger.Info(logging.DestinationHTTP, "OIDC discovery successful", "authURL", auth, "tokenURL", token)
			if userInfo != "" {
				logger.Info(logging.DestinationHTTP, "OIDC discovery found UserInfo URL", "url", userInfo)
			}
			return auth, token, userInfo
		}
		logger.Warn(logging.DestinationHTTP, "OIDC discovery failed", "error", err)
	}

	// Fall back to explicit URLs
	if auth, ok := cfg.Get("HTTP_API_OAUTH2_AUTH_URL"); ok && auth != "" {
		authURL = auth
	}
	if token, ok := cfg.Get("HTTP_API_OAUTH2_TOKEN_URL"); ok && token != "" {
		tokenURL = token
	}
	if userInfo, ok := cfg.Get("HTTP_API_OAUTH2_USERINFO_URL"); ok && userInfo != "" {
		userInfoURL = userInfo
	}

	return authURL, tokenURL, userInfoURL
}

// loadOAuth2RedirectURL loads or derives OAuth2 redirect URL
func loadOAuth2RedirectURL(cfg *config.Config, issuer string, logger *logging.Logger) string {
	if redirectURL, ok := cfg.Get("HTTP_API_OAUTH2_REDIRECT_URL"); ok && redirectURL != "" {
		return redirectURL
	}

	if issuer != "" {
		url := issuer + "/mcp/oauth2/callback"
		logger.Info(logging.DestinationHTTP, "OAuth2 redirect URL derived from issuer", "url", url)
		return url
	}

	return ""
}

// loadOAuth2Scopes loads OAuth2 scopes from config
// Format: HTTP_API_OAUTH2_SCOPES = openid profile email org.cilogon.userinfo
func loadOAuth2Scopes(cfg *config.Config, logger *logging.Logger) []string {
	if scopesStr, ok := cfg.Get("HTTP_API_OAUTH2_SCOPES"); ok && scopesStr != "" {
		// Split by whitespace
		scopes := strings.Fields(scopesStr)
		if len(scopes) > 0 {
			logger.Info(logging.DestinationHTTP, "OAuth2 scopes from config", "scopes", scopes)
			return scopes
		}
	}
	return nil // Will use defaults
}

// durationUnits are the suffixes accepted by Go's time.ParseDuration. We require
// the configured value to end in one of these explicitly: a bare number like "300"
// is forbidden because some config layers (and unfortunately some users' mental
// models) silently treat it as nanoseconds, which would set a 300ns token lifetime
// — short enough that the token is effectively expired before it leaves the server.
// Forcing a unit means a typo fails loudly rather than silently producing a server
// that re-authenticates every microsecond.
var durationUnits = []string{"ns", "us", "µs", "ms", "s", "m", "h"}

// validateDurationHasUnit returns an error if s is not a valid Go duration string
// with an explicit unit suffix. It does not validate the numeric portion — that is
// time.ParseDuration's job — only that *some* unit is present.
func validateDurationHasUnit(s string) error {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return fmt.Errorf("empty value")
	}
	for _, u := range durationUnits {
		if strings.HasSuffix(trimmed, u) {
			return nil
		}
	}
	return fmt.Errorf("missing time unit; use a Go duration like \"1h\", \"30m\", \"168h\" (valid units: %s)",
		strings.Join(durationUnits, ", "))
}

// loadTokenLifespan parses a duration from cfg and returns it, or 0 if the key is
// unset (which signals "use the package default" downstream). If the key is set
// but the value is malformed — including the unit-less case — startup fails via
// log.Fatalf rather than falling back to a default, because a token lifespan
// silently reverting to a default that the operator did not choose is exactly the
// "horribly confusing" failure mode this validation exists to prevent.
func loadTokenLifespan(cfg *config.Config, key string, logger *logging.Logger) time.Duration {
	raw, ok := cfg.Get(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return 0
	}
	if err := validateDurationHasUnit(raw); err != nil {
		logger.Error(logging.DestinationHTTP, "Invalid token lifespan: refusing to start",
			"key", key, "value", raw, "error", err)
		log.Fatalf("invalid %s=%q: %v", key, raw, err)
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		logger.Error(logging.DestinationHTTP, "Failed to parse token lifespan: refusing to start",
			"key", key, "value", raw, "error", err)
		log.Fatalf("invalid %s=%q: %v", key, raw, err)
	}
	if d <= 0 {
		logger.Error(logging.DestinationHTTP, "Token lifespan must be > 0: refusing to start",
			"key", key, "value", raw)
		log.Fatalf("invalid %s=%q: must be > 0", key, raw)
	}
	return d
}

// loadAccessControlGroups loads MCP access control group settings
func loadAccessControlGroups(cfg *config.Config, config *mcpConfig, logger *logging.Logger) {
	if accessGroup, ok := cfg.Get("HTTP_API_MCP_ACCESS_GROUP"); ok && accessGroup != "" {
		config.mcpAccessGroup = accessGroup
		logger.Info(logging.DestinationHTTP, "MCP access group", "group", accessGroup)
	}
	if readGroup, ok := cfg.Get("HTTP_API_MCP_READ_GROUP"); ok && readGroup != "" {
		config.mcpReadGroup = readGroup
		logger.Info(logging.DestinationHTTP, "MCP read group", "group", readGroup)
	}
	if writeGroup, ok := cfg.Get("HTTP_API_MCP_WRITE_GROUP"); ok && writeGroup != "" {
		config.mcpWriteGroup = writeGroup
		logger.Info(logging.DestinationHTTP, "MCP write group", "group", writeGroup)
	}
}

// loadMCPConfig loads MCP configuration from HTCondor config
func loadMCPConfig(cfg *config.Config, listenAddrFromConfig string, logger *logging.Logger) mcpConfig {
	config := mcpConfig{}

	// Check if MCP should be enabled from config
	if mcpEnable, ok := cfg.Get("HTTP_API_ENABLE_MCP"); ok && mcpEnable == "true" {
		config.enabled = true
		logger.Info(logging.DestinationHTTP, "MCP enabled via configuration")
	}

	if !config.enabled {
		return config
	}

	// Resolve the unified application database path. The
	// OAuth2DBPath alias on the Config struct is no longer a silent
	// fallback (see loadDBPath); a deprecation warning is logged here
	// when the legacy HTTP_API_OAUTH2_DB_PATH is set without
	// HTTP_API_DB_PATH.
	config.oauth2DBPath = loadDBPath(cfg, logger)
	logger.Info(logging.DestinationHTTP, "Unified DB path", "path", config.oauth2DBPath)

	// Load OAuth2 issuer
	config.oauth2Issuer = loadOAuth2Issuer(cfg, listenAddrFromConfig)
	logger.Info(logging.DestinationHTTP, "OAuth2 issuer", "issuer", config.oauth2Issuer)

	// Load OAuth2 client ID
	if clientID, ok := cfg.Get("HTTP_API_OAUTH2_CLIENT_ID"); ok && clientID != "" {
		config.oauth2ClientID = clientID
	}

	// Load OAuth2 client secret
	config.oauth2ClientSecret = loadOAuth2ClientSecret(cfg, logger)

	// Load OAuth2 endpoints (auth, token, and userinfo URLs)
	// This will auto-discover from IDP if configured, or use explicit URLs
	config.oauth2AuthURL, config.oauth2TokenURL, config.oauth2UserInfoURL = loadOAuth2Endpoints(cfg, logger)

	// Load OAuth2 redirect URL
	config.oauth2RedirectURL = loadOAuth2RedirectURL(cfg, config.oauth2Issuer, logger)

	// Log the user info URL if set
	if config.oauth2UserInfoURL != "" {
		logger.Info(logging.DestinationHTTP, "OAuth2 user info URL", "url", config.oauth2UserInfoURL)
	}

	// Load OAuth2 scopes
	config.oauth2Scopes = loadOAuth2Scopes(cfg, logger)

	// Load groups claim name (default: "groups")
	config.oauth2GroupsClaim = "groups"
	if groupsClaim, ok := cfg.Get("HTTP_API_OAUTH2_GROUPS_CLAIM"); ok && groupsClaim != "" {
		config.oauth2GroupsClaim = groupsClaim
	}
	logger.Info(logging.DestinationHTTP, "OAuth2 groups claim", "claim", config.oauth2GroupsClaim)

	// Load username claim name (default: "sub")
	if usernameClaim, ok := cfg.Get("HTTP_API_OAUTH2_USERNAME_CLAIM"); ok && usernameClaim != "" {
		config.oauth2UsernameClaim = usernameClaim
		logger.Info(logging.DestinationHTTP, "OAuth2 username claim", "claim", usernameClaim)
	}

	// Load access control groups
	loadAccessControlGroups(cfg, &config, logger)

	// Load token lifespans (zero means "use the httpserver-package default")
	config.oauth2AccessTokenLifespan = loadTokenLifespan(cfg, "HTTP_API_OAUTH2_ACCESS_TOKEN_LIFESPAN", logger)
	if config.oauth2AccessTokenLifespan > 0 {
		logger.Info(logging.DestinationHTTP, "OAuth2 access token lifespan", "duration", config.oauth2AccessTokenLifespan)
	}
	config.oauth2RefreshTokenLifespan = loadTokenLifespan(cfg, "HTTP_API_OAUTH2_REFRESH_TOKEN_LIFESPAN", logger)
	if config.oauth2RefreshTokenLifespan > 0 {
		logger.Info(logging.DestinationHTTP, "OAuth2 refresh token lifespan", "duration", config.oauth2RefreshTokenLifespan)
	}

	// Load server-level instructions for MCP agents
	if instructions, ok := cfg.Get("MCP_INSTRUCTIONS"); ok && instructions != "" {
		config.instructions = instructions
		logger.Info(logging.DestinationMCP, "MCP instructions configured", "length", len(instructions))
	} else {
		logger.Info(logging.DestinationMCP, "MCP_INSTRUCTIONS not configured")
	}

	return config
}

// loadConfigWithDefaults loads HTCondor configuration with fallbacks.
// The Subsystem ("HTTP_API") and LocalName flow into ConfigOptions so
// param-style lookups can pick up subsystem-scoped or instance-scoped
// keys (e.g. HTTP_API.LISTEN, <localname>.LISTEN) before falling back
// to the bare key. condor_master always passes -local-name <NAME>
// when starting custom DC daemons, so honoring it here keeps us
// consistent with how every other HTCondor daemon resolves config.
func loadConfigWithDefaults() *config.Config {
	cfg, err := config.NewWithOptions(config.ConfigOptions{
		Subsystem: "HTTP_API",
		LocalName: *localName,
	})
	if err != nil {
		// If config loading fails, create an empty config with minimal defaults
		log.Printf("Warning: failed to load HTCondor configuration: %v", err)
		log.Println("Proceeding with minimal configuration...")
		cfg = config.NewEmpty()
	}

	// Fix TILDE and LOCAL_DIR defaults if needed
	// Enable debug messages in development (can be controlled by env var if needed)
	debug := os.Getenv("HTCONDOR_API_DEBUG") != ""
	fixConfigDefaults(cfg, debug)
	return cfg
}

// dropPrivilegesIfRoot transitions the process to the condor user
// when the binary was started as root (e.g., directly via systemd or
// `sudo bin/htcondor-api`). When started by condor_master, the master
// has already dropped to condor before exec'ing us, so euid is non-
// zero on entry and this is a no-op.
//
// We honor CONDOR_USER / CONDOR_IDS / DROP_PRIVILEGES from the loaded
// config (same knobs HTCondor's own daemons read), and tolerate the
// condor user not existing — in that case we leave the binary
// running as root with a warning, matching what HTCondor does in
// containers where the user is missing.
//
// Must be called before opening the log file, the unified app DB, or
// any other persistent resource the daemon will own — otherwise
// those files end up root-owned and the daemon's later
// operations-as-condor will hit EACCES.
func dropPrivilegesIfRoot(cfg *config.Config) error {
	if os.Geteuid() != 0 {
		// Already running as a non-root user (the common case
		// when started by condor_master). Nothing to do.
		return nil
	}

	conf := droppriv.ConfigFromHTCondor(cfg)
	// HTCondor's set_priv() machinery doesn't gate on
	// DROP_PRIVILEGES — when running as root, the daemon always
	// drops. Match that: force Enabled=true here so the daemon
	// can't accidentally run-as-root because of a stale config
	// knob. Operators who need to keep root for some reason can
	// run the binary as a non-root user directly, which makes
	// this whole function a no-op.
	conf.Enabled = true

	mgr, err := droppriv.NewManager(conf)
	if err != nil {
		// Most likely cause: condor user doesn't exist in the
		// host's nsswitch chain (dev containers, CI). Log loud
		// and continue as root rather than refusing to start —
		// the operator may be doing local testing.
		log.Printf("WARNING: cannot resolve condor user identity (%v); continuing as root", err)
		return nil //nolint:nilerr // intentional: log + continue
	}
	if err := mgr.Start(); err != nil {
		return fmt.Errorf("droppriv.Start: %w", err)
	}
	// Confirm via /proc/self that the drop took effect — the kernel
	// state is what matters; if mgr.Start succeeds but the syscall
	// underneath was a no-op (impossible in well-built droppriv,
	// but a useful sanity check during the transition) we'd at
	// least see it logged.
	log.Printf("Dropped privileges to euid=%d egid=%d (was running as root)",
		os.Geteuid(), os.Getegid())
	return nil
}

// getScheddConfig extracts schedd configuration from CLI flags and config
func getScheddConfig(cfg *config.Config) (scheddNameValue, scheddAddrValue string) {
	scheddNameValue = *scheddName
	if scheddNameValue == "" {
		scheddNameValue, _ = cfg.Get("SCHEDD_NAME")
	}
	scheddAddrValue = *scheddAddr
	return scheddNameValue, scheddAddrValue
}

// getHTTPConfig extracts HTTP API configuration from config
func getHTTPConfig(cfg *config.Config) (listenAddrResult, tlsCertFile, tlsKeyFile, tlsCACertFile string) {
	listenAddrResult = *listenAddr
	if addr, ok := cfg.Get("HTTP_API_LISTEN_ADDR"); ok && addr != "" {
		listenAddrResult = addr
	}
	tlsCertFile, _ = cfg.Get("HTTP_API_TLS_CERT")
	tlsKeyFile, _ = cfg.Get("HTTP_API_TLS_KEY")
	tlsCACertFile, _ = cfg.Get("HTTP_API_TLS_CA_CERT")
	return listenAddrResult, tlsCertFile, tlsKeyFile, tlsCACertFile
}

// getTimeoutConfig parses timeout configuration with defaults
func getTimeoutConfig(cfg *config.Config) (readTimeout, writeTimeout, idleTimeout time.Duration) {
	readTimeout = 30 * time.Second
	if timeoutStr, ok := cfg.Get("HTTP_API_READ_TIMEOUT"); ok {
		if duration, err := time.ParseDuration(timeoutStr); err == nil {
			readTimeout = duration
		} else {
			log.Printf("Warning: failed to parse HTTP_API_READ_TIMEOUT '%s', using default: %v", timeoutStr, err)
		}
	}

	writeTimeout = 30 * time.Second
	if timeoutStr, ok := cfg.Get("HTTP_API_WRITE_TIMEOUT"); ok {
		if duration, err := time.ParseDuration(timeoutStr); err == nil {
			writeTimeout = duration
		} else {
			log.Printf("Warning: failed to parse HTTP_API_WRITE_TIMEOUT '%s', using default: %v", timeoutStr, err)
		}
	}

	idleTimeout = 120 * time.Second
	if timeoutStr, ok := cfg.Get("HTTP_API_IDLE_TIMEOUT"); ok {
		if duration, err := time.ParseDuration(timeoutStr); err == nil {
			idleTimeout = duration
		} else {
			log.Printf("Warning: failed to parse HTTP_API_IDLE_TIMEOUT '%s', using default: %v", timeoutStr, err)
		}
	}

	return readTimeout, writeTimeout, idleTimeout
}

// getUserHeaderConfig extracts user header and domain configuration
func getUserHeaderConfig(cfg *config.Config) (userHeaderFromConfig, uidDomain, trustDomain string) {
	userHeaderFromConfig = *userHeader
	if header, ok := cfg.Get("HTTP_API_USER_HEADER"); ok && header != "" {
		userHeaderFromConfig = header
		log.Printf("Using user header: %s", userHeaderFromConfig)
	}
	if domain, ok := cfg.Get("UID_DOMAIN"); ok && domain != "" {
		uidDomain = domain
		log.Printf("Using UID_DOMAIN: %s", uidDomain)
	}
	if domain, ok := cfg.Get("TRUST_DOMAIN"); ok && domain != "" {
		trustDomain = domain
		log.Printf("Using TRUST_DOMAIN: %s", trustDomain)
	}
	return userHeaderFromConfig, uidDomain, trustDomain
}

// setupCollector creates collector from CLI flag or config
func setupCollector(cfg *config.Config, logger *logging.Logger) *htcondor.Collector {
	collectorHostValue := *collectorHost
	if collectorHostValue == "" {
		if ch, ok := cfg.Get("COLLECTOR_HOST"); ok && ch != "" {
			collectorHostValue = ch
		}
	}
	if collectorHostValue != "" {
		// Add default port if not specified
		if !strings.Contains(collectorHostValue, ":") {
			collectorHostValue += ":9618"
			logger.Info(logging.DestinationCollector, "Added default port to collector host", "host", collectorHostValue)
		}
		collector := htcondor.NewCollector(collectorHostValue)
		logger.Info(logging.DestinationCollector, "Created collector", "host", collectorHostValue)
		return collector
	}
	return nil
}

// runNormalMode runs the server using existing HTCondor configuration.
//
// Named-return + deferred slog write: any error returned from this
// function gets logged through the structured logger before main()'s
// log.Fatalf prints it to stderr. That matters in deployment shapes
// where stderr isn't captured by the operator's log reader (e.g.
// running under condor_master with HTTP_API_LOG pointed at a file —
// kubectl logs sees the slog stream but not stdlib stderr, so an
// init failure used to vanish into the void). The defer is a no-op
// when logger is nil (createLogger itself failed) — main() still
// reports that case via log.Fatalf to stderr.
//
// HTCondor config knob the server understands and threads it into the
// struct literal. Splitting it scatters related lookups across helpers
// for no real readability gain.
//
//nolint:gocyclo // intentionally a long glue function: collects every
func runNormalMode(earlyBuf *logging.EarlyBuffer) (rerr error) {
	var logger *logging.Logger
	defer func() {
		if rerr == nil || logger == nil {
			return
		}
		logger.Error(logging.DestinationGeneral, "Server failed to start", "error", rerr.Error())
	}()

	// Load configuration
	cfg := loadConfigWithDefaults()

	// Drop privileges to the condor user before we touch any
	// daemon-owned resources (log file, app DB, listener). HTCondor
	// daemons started as root by condor_master are expected to run
	// as the condor user — the master itself drops before our exec,
	// but operators may also start the binary directly via systemd
	// or for testing, in which case we'd inherit root and need to
	// drop ourselves.
	//
	// Credentials that need root to read (pool signing key, KEK,
	// TLS cert/key) are expected to be condor-readable per HTCondor
	// convention (mode 0600 condor:condor or 0640 root:condor).
	// dropPrivilegesIfRoot is a no-op when we're already non-root
	// or when the condor user doesn't exist (dev/CI containers).
	if err := dropPrivilegesIfRoot(cfg); err != nil {
		return fmt.Errorf("failed to drop privileges: %w", err)
	}

	// Get schedd configuration
	scheddNameValue, scheddAddrValue := getScheddConfig(cfg)

	// Get HTTP API configuration
	listenAddrFromConfig, tlsCertFile, tlsKeyFile, tlsCACertFile := getHTTPConfig(cfg)

	// Get timeout configuration
	readTimeout, writeTimeout, idleTimeout := getTimeoutConfig(cfg)

	// Get user header configuration
	userHeaderFromConfig, uidDomain, trustDomain := getUserHeaderConfig(cfg)

	// Get optional signing key path - default to SEC_TOKEN_POOL_SIGNING_KEY_FILE
	signingKeyPath, ok := cfg.Get("HTTP_API_SIGNING_KEY")
	if !ok || signingKeyPath == "" {
		signingKeyPath, _ = cfg.Get("SEC_TOKEN_POOL_SIGNING_KEY_FILE")
	}

	// Web UI admin group (empty disables admin pages — see PR (c)).
	webuiAdminGroup, _ := cfg.Get("HTTP_API_WEBUI_ADMIN_GROUP")

	// Create logger with reasonable defaults for unprivileged operation.
	// Assigning to the OUTER `logger` (declared at the top of the
	// function) is intentional — the deferred error-logger reads the
	// same variable. If this fails, the defer is a no-op and main's
	// log.Fatalf still surfaces the message to stderr.
	var err error
	logger, err = createLogger(cfg)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	// Drain everything stdlib log emitted before this point into the
	// structured logger (so the early daemon-core diagnostic, the
	// UID_DOMAIN/TRUST_DOMAIN trace, etc. show up in
	// $(LOG)/HttpApiLog) and re-route subsequent stdlib log writes
	// straight to slog. Replay encapsulates RedirectStdLog so we
	// don't double-redirect.
	if earlyBuf != nil {
		earlyBuf.Replay(logger)
	} else {
		logger.RedirectStdLog()
	}

	// Create collector
	collector := setupCollector(cfg, logger)

	// Discover schedd if address not specified
	// If a schedd name is provided, we'll search for that specific schedd
	if scheddAddrValue == "" {
		if scheddNameValue != "" {
			logger.Info(logging.DestinationSchedd, "ScheddAddr not provided, discovering schedd from collector...", "name", scheddNameValue)
		}
		var discoveredName string
		scheddAddrValue, discoveredName = discoverSchedd(cfg, collector, logger, scheddNameValue)
		// If we discovered a name and didn't have one before, use it
		if scheddNameValue == "" && discoveredName != "" {
			scheddNameValue = discoveredName
		}
	}

	// Load MCP configuration
	mcpCfg := loadMCPConfig(cfg, listenAddrFromConfig, logger)

	// Check if IDP should be enabled
	enableIDP := false
	if idpEnable, ok := cfg.Get("HTTP_API_ENABLE_IDP"); ok && idpEnable == "true" {
		enableIDP = true
		log.Println("Built-in IDP enabled via configuration")
	}

	// Load IDP configuration
	// IDP shares the unified application database now; its own
	// HTTP_API_IDP_DB_PATH knob is no longer consulted.
	idpIssuer := ""
	var idpAccessLifespan, idpRefreshLifespan time.Duration
	if enableIDP {
		// Load IDP issuer
		if issuer, ok := cfg.Get("HTTP_API_IDP_ISSUER"); ok && issuer != "" {
			idpIssuer = issuer
		} else {
			idpIssuer = loadOAuth2Issuer(cfg, listenAddrFromConfig)
		}
		log.Printf("IDP issuer: %s", idpIssuer)

		idpAccessLifespan = loadTokenLifespan(cfg, "HTTP_API_IDP_ACCESS_TOKEN_LIFESPAN", logger)
		idpRefreshLifespan = loadTokenLifespan(cfg, "HTTP_API_IDP_REFRESH_TOKEN_LIFESPAN", logger)
	}

	// Compute HTTP base URL for MCP file download links
	useTLS := tlsCertFile != "" && tlsKeyFile != ""
	httpBaseURL := loadHTTPBaseURL(cfg, listenAddrFromConfig, useTLS)
	log.Printf("HTTP base URL: %s", httpBaseURL)

	// LLM / chat-feature config. Zero-strings = chat disabled.
	llmAPIKeyFile, llmAPIURL, llmModel, llmOperatorInstructions := loadLLMConfig(cfg)

	// Metrics-endpoint exposure. Default: false (auth required). Set
	// HTTP_API_METRICS_PUBLIC=true to skip the API-key gate when the
	// endpoint is already isolated by network ACLs.
	metricsPublic := false
	if v, ok := cfg.Get("HTTP_API_METRICS_PUBLIC"); ok {
		metricsPublic = strings.EqualFold(strings.TrimSpace(v), "true") ||
			strings.TrimSpace(v) == "1"
	}

	// Create and start server
	server, err := httpserver.NewServer(httpserver.Config{
		ListenAddr:     listenAddrFromConfig,
		ScheddName:     scheddNameValue,
		ScheddAddr:     scheddAddrValue,
		UserHeader:     userHeaderFromConfig,
		SigningKeyPath: signingKeyPath,
		HTTPBaseURL:    httpBaseURL,
		TLSCertFile:    tlsCertFile,
		TLSKeyFile:     tlsKeyFile,
		TLSCACertFile:  tlsCACertFile,
		TrustDomain:    trustDomain,
		UIDDomain:      uidDomain,
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		IdleTimeout:    idleTimeout,
		Collector:      collector,
		Logger:         logger,
		EnableMCP:      mcpCfg.enabled,
		// DBPath is the canonical name; OAuth2DBPath kept for back-compat.
		DBPath:                     mcpCfg.oauth2DBPath,
		KEKFilePath:                loadKEKFilePath(cfg, logger),
		OAuth2DBPath:               mcpCfg.oauth2DBPath,
		OAuth2Issuer:               mcpCfg.oauth2Issuer,
		OAuth2ClientID:             mcpCfg.oauth2ClientID,
		OAuth2ClientSecret:         mcpCfg.oauth2ClientSecret,
		OAuth2AuthURL:              mcpCfg.oauth2AuthURL,
		OAuth2TokenURL:             mcpCfg.oauth2TokenURL,
		OAuth2RedirectURL:          mcpCfg.oauth2RedirectURL,
		OAuth2UserInfoURL:          mcpCfg.oauth2UserInfoURL,
		OAuth2Scopes:               mcpCfg.oauth2Scopes,
		OAuth2UsernameClaim:        mcpCfg.oauth2UsernameClaim,
		OAuth2GroupsClaim:          mcpCfg.oauth2GroupsClaim,
		OAuth2AccessTokenLifespan:  mcpCfg.oauth2AccessTokenLifespan,
		OAuth2RefreshTokenLifespan: mcpCfg.oauth2RefreshTokenLifespan,
		MCPAccessGroup:             mcpCfg.mcpAccessGroup,
		MCPReadGroup:               mcpCfg.mcpReadGroup,
		MCPWriteGroup:              mcpCfg.mcpWriteGroup,
		MCPInstructions:            mcpCfg.instructions,
		WebUIAdminGroup:            webuiAdminGroup,
		EnableIDP:                  enableIDP,
		IDPIssuer:                  idpIssuer,
		IDPAccessTokenLifespan:     idpAccessLifespan,
		IDPRefreshTokenLifespan:    idpRefreshLifespan,
		JupyterWorkDir:             loadJupyterWorkDir(cfg),
		InteractiveExtraSubmit:     loadInteractiveExtraSubmit(cfg),
		TemplateGlobalPath:         loadTemplateGlobalPath(cfg),
		HTCondorConfig:             cfg,
		// LLM/chat configuration. Optional; the chat endpoint
		// returns 503 unless all three (key file, MCP enabled, key
		// readable) line up. The values are zero-strings when
		// nothing is configured.
		LLMAPIKeyFile:               llmAPIKeyFile,
		LLMAPIURL:                   llmAPIURL,
		LLMModel:                    llmModel,
		LLMOperatorInstructionsFile: llmOperatorInstructions,
		MetricsPublic:               metricsPublic,
	})
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Daemon mode: when launched by condor_master, attach the master
	// keepalive loop and (optionally) accept HTTP/HTTPS connections
	// forwarded by condor_shared_port instead of binding our own TCP
	// port. The ctx is plumbed all the way through so SIGTERM tears
	// down keepalive cleanly along with the HTTP server.
	hookCtx, hookCancel := context.WithCancel(context.Background())
	defer hookCancel()
	var hooks *daemonHooks
	var spListener *sharedport.Listener
	if runUnderCondorMaster() {
		hooks, err = startDaemonHooks(hookCtx, logger)
		if err != nil {
			logger.Warn(logging.DestinationGeneral,
				"condor_master detected but hook setup failed; running standalone",
				"error", err)
		}
		spListener, err = resolveSharedPortListener(cfg, logger)
		if err != nil {
			return fmt.Errorf("shared-port listener: %w", err)
		}
	}

	// Start server in goroutine. Three flavors:
	//   - shared_port forwarding: serve on the UDS-backed listener
	//   - TLS: traditional HTTPS bind
	//   - plain HTTP bind
	errChan := make(chan error, 1)
	go func() {
		switch {
		case spListener != nil:
			scheme := "http"
			if tlsCertFile != "" && tlsKeyFile != "" {
				// In shared-port mode, TLS termination at the daemon
				// requires the http.Server to have its TLSConfig pre-
				// populated. Today the regular Start/StartTLS handle
				// that internally; the cleanest way to surface that
				// limitation is to refuse to start TLS over shared_port
				// rather than silently fall back to HTTP.
				errChan <- fmt.Errorf("shared-port forwarding with TLS is not yet supported; use plain HTTP for the forwarded connections")
				return
			}
			errChan <- server.ServeListener(spListener, scheme)
		case tlsCertFile != "" && tlsKeyFile != "":
			errChan <- server.StartTLS(tlsCertFile, tlsKeyFile)
		default:
			errChan <- server.Start()
		}
	}()

	// Once the listener is up, tell the master we're ready and start
	// the keepalive loop. We delay both until *after* the goroutine
	// kicked off above has had a chance to bind, on the theory that
	// "ready" is meaningful only when we can actually answer requests.
	if hooks != nil {
		go func() {
			// Tiny delay to let the listener bind before we claim ready.
			// The master's idle timer is on the order of minutes, so
			// being a few hundred ms late here is harmless.
			time.Sleep(200 * time.Millisecond)
			hooks.SignalReady(hookCtx)
			hooks.StartKeepAlive(hookCtx)
		}()
	}

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logger.Info(logging.DestinationGeneral, "Received shutdown signal", "signal", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hooks.Stop()
		if spListener != nil {
			_ = spListener.Close()
		}
		return server.Shutdown(ctx)
	case err := <-errChan:
		hooks.Stop()
		if spListener != nil {
			_ = spListener.Close()
		}
		return err
	}
}

// runDemoMode runs the server with a mini condor setup
func runDemoMode(earlyBuf *logging.EarlyBuffer) error {
	// Create logger for demo mode (stdout for access logs)
	logger, err := logging.New(&logging.Config{
		OutputPath: "stdout",
		DestinationLevels: map[logging.Destination]logging.Verbosity{
			logging.DestinationGeneral:  logging.VerbosityDebug,
			logging.DestinationHTTP:     logging.VerbosityDebug,
			logging.DestinationSecurity: logging.VerbosityDebug,
			logging.DestinationCedar:    logging.VerbosityInfo, // Reduce Cedar noise in demo mode
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	// Same as runNormalMode: drain anything stdlib log captured
	// before the structured logger existed.
	if earlyBuf != nil {
		earlyBuf.Replay(logger)
	} else {
		logger.RedirectStdLog()
	}

	logger.Info(logging.DestinationGeneral, "Starting in demo mode")

	// Create temporary directory for mini condor
	tempDir, err := os.MkdirTemp("", "htcondor-demo-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	tempDir, err = filepath.Abs(tempDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	defer func() {
		logger.Info(logging.DestinationGeneral, "Cleaning up temporary directory", "path", tempDir)
		if err := os.RemoveAll(tempDir); err != nil {
			logger.Error(logging.DestinationGeneral, "Failed to remove temp directory", "error", err)
		}
	}()

	logger.Info(logging.DestinationGeneral, "Using temporary directory", "path", tempDir)

	// Create required directories for HTCondor
	logDir := filepath.Join(tempDir, "log")
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	spoolDir := filepath.Join(tempDir, "spool")
	if err := os.MkdirAll(spoolDir, 0750); err != nil {
		return fmt.Errorf("failed to create spool directory: %w", err)
	}
	executeDir := filepath.Join(tempDir, "execute")
	if err := os.MkdirAll(executeDir, 0750); err != nil {
		return fmt.Errorf("failed to create execute directory: %w", err)
	}

	// Find condor_master to determine release directory
	condorMasterPath, err := exec.LookPath("condor_master")
	if err != nil {
		return fmt.Errorf("condor_master not found in PATH: %w", err)
	}

	// Extract release directory from condor_master path
	// If condor_master is at /usr/sbin/condor_master, release dir is /usr
	releaseDir := filepath.Dir(filepath.Dir(condorMasterPath))
	log.Printf("Detected HTCondor release directory: %s", releaseDir)

	// Write mini condor configuration
	// Note: HTCondor will auto-generate signing keys when condor_master starts
	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDir, releaseDir); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	if err := os.Setenv("CONDOR_CONFIG", configFile); err != nil {
		return fmt.Errorf("failed to set CONDOR_CONFIG: %w", err)
	}
	cfg, err := config.New()
	if err != nil {
		return fmt.Errorf("failed to load HTCondor configuration: %w", err)
	}

	// Start condor_master
	log.Println("Starting condor_master...")
	condorMaster, err := startCondorMaster(context.Background(), configFile)
	if err != nil {
		return fmt.Errorf("failed to start condor_master: %w", err)
	}

	// Ensure condor_master is stopped on exit
	defer func() {
		log.Println("Stopping condor_master...")
		stopCondorMaster(condorMaster)
	}()

	// Wait for condor to be ready
	log.Println("Waiting for HTCondor to be ready...")
	collectorAddr, err := waitForCondor(tempDir)
	if err != nil {
		return fmt.Errorf("condor failed to start: %w", err)
	}

	log.Printf("HTCondor is ready! Collector address: %s", collectorAddr)

	uidDomain := ""
	trustDomain := ""

	// Load domains from config first (needed for token generation).
	// Both should be set by writeMiniCondorConfig — if they're empty
	// here, JWT minting will produce tokens the schedd rejects with
	// "no compatible authentication methods found", so log loudly.
	if domain, ok := cfg.Get("UID_DOMAIN"); ok && domain != "" {
		uidDomain = domain
		log.Printf("Using UID_DOMAIN: %s", uidDomain)
	} else {
		log.Println("WARNING: UID_DOMAIN is empty — session-user tokens will be rejected by daemons")
	}
	if domain, ok := cfg.Get("TRUST_DOMAIN"); ok && domain != "" {
		trustDomain = domain
		log.Printf("Using TRUST_DOMAIN: %s", trustDomain)
	} else {
		log.Println("WARNING: TRUST_DOMAIN is empty — JWTs will have empty `iss` and be rejected")
	}

	// Generate a token for the server to use for self-operations (like ping)
	// The token must use the same trust domain as the HTCondor daemons
	log.Println("Generating server token...")
	serverToken, err := generateServerToken(tempDir, trustDomain)
	if err != nil {
		log.Printf("Warning: failed to generate server token: %v", err)
	} else {
		log.Println("Generated server token successfully")
	}

	// Determine signing key path for token generation
	// HTCondor auto-generates $(LOCAL_DIR)/passwords.d/POOL when needed
	// In demo mode, we always want to enable token generation for IDP/session support
	signingKeyPath := filepath.Join(tempDir, "passwords.d", "POOL")
	log.Printf("Will use HTCondor-generated signing key at: %s", signingKeyPath)
	if info, err := os.Stat(signingKeyPath); err != nil {
		log.Printf("WARNING: signing key not yet present at %s (%v) — JWTs will fail to sign until condor_master writes it", signingKeyPath, err)
	} else {
		log.Printf("Signing key present (%d bytes, mode %s)", info.Size(), info.Mode())
	}

	if *userHeader != "" {
		log.Printf("User header mode enabled: %s", *userHeader)
	}

	// Create collector for demo mode
	collector := htcondor.NewCollector(collectorAddr)
	logger.Info(logging.DestinationCollector, "Created collector for demo mode", "host", collectorAddr)

	// Unified application database path. Demo mode keeps it under
	// the temp dir alongside the rest of the demo state.
	appDBPath := filepath.Join(tempDir, "htcondor-api.db")

	// Generate CA and server certificate for demo mode to enable HTTPS.
	// We collect every hostname the server might be reached at so the
	// cert covers in-process callbacks (the OAuth2 SSO flow has the
	// server POST to its own /idp/token, and that hits httpBaseURL —
	// which can be FULL_HOSTNAME on macOS).
	caPath := filepath.Join(tempDir, "ca.crt")
	certPath := filepath.Join(tempDir, "server.crt")
	keyPath := filepath.Join(tempDir, "server.key")
	hostnames := demoCertHostnames(cfg, *listenAddr)
	log.Printf("Generating CA and server certificate for demo mode (SANs: %v)...", hostnames)
	if err := generateCAAndCert(caPath, certPath, keyPath, hostnames); err != nil {
		log.Printf("Warning: failed to generate certificates: %v", err)
		log.Println("Falling back to HTTP (cookie Secure flag will be disabled)")
		certPath = ""
		keyPath = ""
	}

	// Use HTTPS if we successfully generated certificates
	useTLS := certPath != "" && keyPath != ""
	if useTLS {
		log.Println("Demo mode will use HTTPS with generated certificate")
		log.Printf("CA Certificate: %s", caPath)
	}

	// Compute HTTP base URL - in demo mode, use the listen address directly
	// since we don't have FULL_HOSTNAME configured. loadHTTPBaseURL
	// substitutes "localhost" when listenAddr is in ":port" form.
	httpBaseURL := loadHTTPBaseURL(cfg, *listenAddr, useTLS)
	log.Printf("HTTP base URL: %s", httpBaseURL)

	// LLM / chat-feature config. Zero-strings = chat disabled.
	demoLLMKeyFile, demoLLMURL, demoLLMModel, demoLLMOperatorInstructions := loadLLMConfig(cfg)

	// Create and start HTTP server with MCP and IDP enabled
	server, err := httpserver.NewServer(httpserver.Config{
		ListenAddr:     *listenAddr,
		UserHeader:     *userHeader,
		SigningKeyPath: signingKeyPath,
		TrustDomain:    trustDomain,
		UIDDomain:      uidDomain,
		HTTPBaseURL:    httpBaseURL,
		TLSCertFile:    certPath,
		TLSKeyFile:     keyPath,
		TLSCACertFile:  caPath,
		Collector:      collector,
		Logger:         logger,
		Token:          serverToken, // Token for daemon authentication
		EnableMCP:      true,        // Enable MCP in demo mode
		DBPath:         appDBPath,
		// All OAuth2/IDP URLs derive from httpBaseURL so a `:8080` listen
		// addr gets a real host (localhost) instead of producing
		// browser-invalid URLs like "https://:8080/".
		OAuth2Issuer:           httpBaseURL,
		OAuth2ClientID:         "demo-client",
		OAuth2ClientSecret:     "demo-secret",
		OAuth2AuthURL:          httpBaseURL + "/mcp/oauth2/authorize",
		OAuth2TokenURL:         httpBaseURL + "/mcp/oauth2/token",
		OAuth2RedirectURL:      httpBaseURL + "/mcp/oauth2/callback",
		OAuth2Scopes:           []string{"openid", "profile", "email"},
		EnableIDP:              true,
		IDPIssuer:              httpBaseURL,
		JupyterWorkDir:         loadJupyterWorkDir(cfg),
		InteractiveExtraSubmit: loadInteractiveExtraSubmit(cfg),
		TemplateGlobalPath:     loadTemplateGlobalPath(cfg),
		HTCondorConfig:         cfg,
		// In demo mode, the auto-created `admin` IDP user is a real
		// admin: the IDP userinfo endpoint emits groups=["admin"]
		// for state=admin users (see handleIDPUserInfo), and we
		// match that here so the admin pages (api-keys, clients,
		// etc.) become usable out of the box.
		WebUIAdminGroup: "admin",
		// Pick up the LLM/chat knobs in demo mode too so an
		// operator can hand-test the chat surface against the
		// embedded mini-condor without spinning up a real pool.
		LLMAPIKeyFile:               demoLLMKeyFile,
		LLMAPIURL:                   demoLLMURL,
		LLMModel:                    demoLLMModel,
		LLMOperatorInstructionsFile: demoLLMOperatorInstructions,
	})
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	// Start server in goroutine. We log the error here as well as
	// returning it through errChan because previously a startup
	// failure on some shells (notably make-driven runs) appeared to
	// swallow the log.Fatalf line, leaving the operator with only a
	// "make: *** [demo] Error 1" and no clue what failed.
	errChan := make(chan error, 1)
	go func() {
		var err error
		if certPath != "" && keyPath != "" {
			err = server.StartTLS(certPath, keyPath)
		} else {
			err = server.Start()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "demo: server start failed: %v\n", err)
		}
		errChan <- err
	}()

	// Wait for shutdown
	return waitForShutdown(server, errChan)
}

// waitForShutdown waits for a signal, timer, or server error and handles graceful shutdown
func waitForShutdown(server *httpserver.Server, errChan <-chan error) error {
	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Set up shutdown timer if specified
	var shutdownTimer *time.Timer
	if *demoShutdownAfter > 0 {
		shutdownTimer = time.NewTimer(*demoShutdownAfter)
		log.Printf("Demo mode will automatically shutdown after %v", *demoShutdownAfter)
	}

	// Wait for shutdown signal, timer, or error
	select {
	case sig := <-sigChan:
		log.Printf("Received signal: %v, shutting down...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown server: %w", err)
		}
		log.Println("Server stopped gracefully")
	case <-func() <-chan time.Time {
		if shutdownTimer != nil {
			return shutdownTimer.C
		}
		// Return a channel that never fires if no timer
		return make(chan time.Time)
	}():
		log.Printf("Shutdown timer expired after %v, shutting down...", *demoShutdownAfter)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown server: %w", err)
		}
		log.Println("Server stopped gracefully")
	case err := <-errChan:
		return err
	}

	return nil
}

// writeMiniCondorConfig writes a minimal HTCondor configuration for a personal condor
func writeMiniCondorConfig(configFile, localDir, releaseDir string) error {
	// Determine LIBEXEC directory by looking for condor_shared_port
	var libexecDir string
	sharedPortPath, err := exec.LookPath("condor_shared_port")
	if err == nil {
		// Found condor_shared_port, use its parent directory
		libexecDir = filepath.Dir(sharedPortPath)
		log.Printf("Found condor_shared_port at %s, using LIBEXEC=%s", sharedPortPath, libexecDir)
	} else {
		// Not found in PATH, try deriving from condor_master location
		masterPath, _ := exec.LookPath("condor_master")
		if masterPath != "" {
			sbinDir := filepath.Dir(masterPath)
			derivedLibexec := filepath.Join(filepath.Dir(sbinDir), "libexec")

			// Check if the derived path exists
			if _, err := os.Stat(filepath.Join(derivedLibexec, "condor_shared_port")); err == nil {
				libexecDir = derivedLibexec
				log.Printf("Using derived LIBEXEC=%s (from condor_master location)", libexecDir)
			} else {
				// Try standard location /usr/libexec/condor
				stdLibexec := "/usr/libexec/condor"
				if _, err := os.Stat(filepath.Join(stdLibexec, "condor_shared_port")); err == nil {
					libexecDir = stdLibexec
					log.Printf("Using standard LIBEXEC=%s", libexecDir)
				}
			}
		}
	}

	// Compute SBIN path from condor_master location
	var sbinDir string
	if masterPath, err := exec.LookPath("condor_master"); err == nil {
		sbinDir = filepath.Dir(masterPath)
	}

	// Build LIBEXEC line if we found a valid directory
	libexecLine := "LIBEXEC = $(RELEASE_DIR)/libexec\n"
	if libexecDir != "" {
		libexecLine = fmt.Sprintf("LIBEXEC = %s\n", libexecDir)
	}

	// Build SBIN line if we found it
	sbinLine := "SBIN = $(RELEASE_DIR)/sbin\n"
	if sbinDir != "" {
		sbinLine = fmt.Sprintf("SBIN = %s\n", sbinDir)
	}

	config := fmt.Sprintf(`# Mini HTCondor Configuration for Demo Mode
LOCAL_DIR = %s
RELEASE_DIR = %s
LOG = $(LOCAL_DIR)/log
SPOOL = $(LOCAL_DIR)/spool
EXECUTE = $(LOCAL_DIR)/execute
BIN = $(RELEASE_DIR)/bin
LIB = $(RELEASE_DIR)/lib
%s%s

# Run all daemons locally
DAEMON_LIST = MASTER, COLLECTOR, NEGOTIATOR, SCHEDD, STARTD

# Use only local system resources
START = TRUE
SUSPEND = FALSE
PREEMPT = FALSE
KILL = FALSE

# Network settings
CONDOR_HOST = 127.0.0.1
COLLECTOR_HOST = $(CONDOR_HOST):0
DAEMON_SOCKET_DIR = $(LOCAL_DIR)/log
SHARED_PORT_ADDRESS_FILE = $(LOG)/shared_port_ad
SHARED_PORT_DEBUG = D_FULLDEBUG D_SECURITY D_NETWORK:2 D_COMMAND
SHARED_PORT_MAX_WORKERS = 1000
BIND_ALL_INTERFACES = FALSE
NETWORK_INTERFACE = 127.0.0.1

# Pin TRUST_DOMAIN / UID_DOMAIN to stable, machine-independent values.
# Without these HTCondor derives TRUST_DOMAIN from the host's FQDN
# (e.g. macOS gives you something.local), and the API server's parsed
# config — read before condor_master starts — sees an empty value.
# That mismatch makes generatePingToken() mint JWTs with iss="" that
# the collector rejects with "no compatible authentication methods".
TRUST_DOMAIN = htcondor-api-demo
UID_DOMAIN = htcondor-api-demo

# Collector configuration
COLLECTOR_ADDRESS_FILE = $(LOG)/.collector_address

# Schedd configuration
SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address

# Security settings - allow local access
ALLOW_WRITE = 127.0.0.1, $(IP_ADDRESS)
ALLOW_READ = *
ALLOW_NEGOTIATOR = 127.0.0.1, $(IP_ADDRESS)
ALLOW_ADMINISTRATOR = 127.0.0.1, $(IP_ADDRESS)

# Use TOKEN authentication
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = TOKEN, FS
SEC_READ_AUTHENTICATION = OPTIONAL
SEC_CLIENT_AUTHENTICATION = OPTIONAL

# Enable file transfer
ENABLE_FILE_TRANSFER = TRUE

# Keep jobs in queue after completion for output retrieval
SYSTEM_PERIODIC_REMOVE = (JobStatus == 4) && ((time() - CompletionDate) > 86400)

# Reduce resource requirements for demo
NUM_CPUS = 2
MEMORY = 2048

# Logging
MAX_DEFAULT_LOG = 10000000
MAX_NUM_DEFAULT_LOG = 3
`, localDir, releaseDir, sbinLine, libexecLine)

	//nolint:gosec // Config file needs to be readable by condor daemons
	return os.WriteFile(configFile, []byte(config), 0644)
}

// startCondorMaster starts the condor_master process
func startCondorMaster(ctx context.Context, configFile string) (*exec.Cmd, error) {
	// Check if condor_master is in PATH
	condorMasterPath, err := exec.LookPath("condor_master")
	if err != nil {
		return nil, fmt.Errorf("condor_master not found in PATH: %w", err)
	}

	//nolint:gosec // condorMasterPath is validated via exec.LookPath
	cmd := exec.CommandContext(ctx, condorMasterPath, "-f")
	cmd.Env = append(os.Environ(),
		"CONDOR_CONFIG="+configFile,
		"_CONDOR_MASTER_LOG=$(LOCAL_DIR)/log/MasterLog",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start condor_master: %w", err)
	}

	return cmd, nil
}

// stopCondorMaster gracefully stops condor_master
func stopCondorMaster(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}

	// Send SIGTERM
	log.Printf("Sending SIGTERM to condor_master (PID %d)", cmd.Process.Pid)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		log.Printf("Failed to send SIGTERM: %v", err)
		if killErr := cmd.Process.Kill(); killErr != nil {
			log.Printf("Failed to kill process: %v", killErr)
		}
		return
	}

	// Wait for process to exit (with timeout)
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(10 * time.Second):
		log.Println("condor_master did not stop gracefully, forcing kill")
		if err := cmd.Process.Kill(); err != nil {
			log.Printf("Failed to kill process: %v", err)
		}
		<-done
	case err := <-done:
		if err != nil {
			log.Printf("condor_master exited with error: %v", err)
		} else {
			log.Println("condor_master stopped successfully")
		}
	}
}

// waitForCondor waits for HTCondor to be ready and returns the collector address
func waitForCondor(localDir string) (string, error) {
	maxWait := 20 * time.Second
	deadline := time.Now().Add(maxWait)

	collectorAddrFile := filepath.Join(localDir, "log", ".collector_address")
	scheddAddrFile := filepath.Join(localDir, "log", ".schedd_address")

	for time.Now().Before(deadline) {
		// Check if collector address file exists
		cAddr, err := readAddressFile(collectorAddrFile)
		if err == nil && cAddr != "" {
			// Check if schedd address file exists (ensure schedd is also ready)
			sAddr, err := readAddressFile(scheddAddrFile)
			if err == nil && sAddr != "" {
				return cAddr, nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	return "", fmt.Errorf("timeout waiting for HTCondor to be ready")
}

// readAddressFile reads an HTCondor address file and returns the address
func readAddressFile(path string) (string, error) {
	//nolint:gosec // Path is from config, admin-controlled
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "$") {
			return line, nil
		}
	}
	return "", fmt.Errorf("no valid address found in %s", path)
}

// generateCAAndCert generates a CA and a server certificate signed by that CA
// demoCertHostnames collects all the names the demo cert needs to cover.
// In addition to the obvious localhost / loopback IPs it includes
// FULL_HOSTNAME from HTCondor config (set after condor_master starts) and
// the OS hostname — both upper- and lower-case forms, since macOS
// sometimes reports the hostname uppercased ("F4HP7QL65F-2.local") even
// though Go's TLS verification matches case-insensitively, having both
// is harmless and unsurprising in tcpdump output.
func demoCertHostnames(cfg *config.Config, listenAddr string) []string {
	candidates := []string{"localhost"}

	if hn, err := os.Hostname(); err == nil && hn != "" {
		candidates = append(candidates, hn, strings.ToLower(hn))
	}
	if full, ok := cfg.Get("FULL_HOSTNAME"); ok && full != "" {
		candidates = append(candidates, full, strings.ToLower(full))
	}
	// If listenAddr has an explicit host (e.g. "myhost:8080"), include
	// that too — the operator chose it deliberately.
	listen := listenAddr
	if strings.HasPrefix(listen, ":") {
		listen = "0.0.0.0" + listen
	}
	if host, _, err := net.SplitHostPort(listen); err == nil {
		switch host {
		case "", "0.0.0.0", "::", "[::]":
			// nothing meaningful to add
		default:
			candidates = append(candidates, host, strings.ToLower(host))
		}
	}

	// Dedupe while preserving order so the cert's Subject Alternative
	// Names list is stable across runs (helps when comparing logs).
	seen := make(map[string]bool, len(candidates))
	out := make([]string, 0, len(candidates))
	for _, h := range candidates {
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

func generateCAAndCert(caPath, certPath, keyPath string, hostnames []string) error {
	// 1. Generate CA
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "HTCondor Demo CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Write CA cert to file
	//nolint:gosec // Path is from config, admin-controlled
	caFile, err := os.Create(caPath)
	if err != nil {
		return fmt.Errorf("failed to create CA file: %w", err)
	}
	if err := pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes}); err != nil {
		_ = caFile.Close()
		return fmt.Errorf("failed to encode CA certificate: %w", err)
	}
	if err := caFile.Close(); err != nil {
		return fmt.Errorf("failed to close CA file: %w", err)
	}

	// 2. Generate Server Certificate
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate server key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	dnsNames := hostnames
	if len(dnsNames) == 0 {
		dnsNames = []string{"localhost"}
	}
	commonName := dnsNames[0]
	serverTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	serverBytes, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Write server cert
	//nolint:gosec // Path is from config, admin-controlled
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: serverBytes}); err != nil {
		_ = certFile.Close()
		return fmt.Errorf("failed to encode server certificate: %w", err)
	}
	if err := certFile.Close(); err != nil {
		return fmt.Errorf("failed to close cert file: %w", err)
	}

	// Write server key
	//nolint:gosec // Path is from config, admin-controlled
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(serverPrivKey)
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		_ = keyFile.Close()
		return fmt.Errorf("failed to encode private key: %w", err)
	}
	if err := keyFile.Close(); err != nil {
		return fmt.Errorf("failed to close key file: %w", err)
	}

	log.Printf("Generated CA certificate: %s", caPath)
	log.Printf("Generated server certificate: %s", certPath)
	log.Printf("Generated server private key: %s", keyPath)
	return nil
}

// generateServerToken generates a token for the server to use
func generateServerToken(tempDir, trustDomain string) (string, error) {
	// Use Cedar's GenerateJWT function to create a token
	// The signing key should be at $(LOCAL_DIR)/passwords.d/POOL
	keyDir := filepath.Join(tempDir, "passwords.d")
	keyID := "POOL"
	subject := "htcondor-api@" + trustDomain
	issuer := trustDomain // Issuer must match the trust domain of HTCondor daemons
	issuedAt := time.Now().Unix()
	expiration := time.Now().Add(24 * time.Hour).Unix()                 // Valid for 24 hours
	authzLimits := []string{"READ", "WRITE", "DAEMON", "ADMINISTRATOR"} // Full permissions for server operations

	token, err := security.GenerateJWT(keyDir, keyID, subject, issuer, issuedAt, expiration, authzLimits)
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT token: %w", err)
	}

	return token, nil
}
