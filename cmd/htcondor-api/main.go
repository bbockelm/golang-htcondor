// Package main provides an HTTP API server for HTCondor job management.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/httpserver"
	"github.com/bbockelm/golang-htcondor/logging"
)

var (
	demoMode      = flag.Bool("demo", false, "Run in demo mode with mini condor")
	listenAddr    = flag.String("listen", ":8080", "Address to listen on")
	userHeader    = flag.String("user-header", "", "HTTP header to read username from (e.g., X-Remote-User). Only used in demo mode with token generation.")
	collectorHost = flag.String("collector", "", "Collector host:port (overrides COLLECTOR_HOST from config)")
	scheddName    = flag.String("schedd", "", "Schedd name (overrides SCHEDD_NAME from config)")
	scheddAddr    = flag.String("schedd-addr", "", "Schedd address (if specified, schedd name is ignored)")
)

func main() {
	flag.Parse()

	if *demoMode {
		if err := runDemoMode(); err != nil {
			log.Fatalf("Demo mode failed: %v", err)
		}
	} else {
		if err := runNormalMode(); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}
}

// mcpConfig holds MCP-related configuration
type mcpConfig struct {
	enabled            bool
	oauth2DBPath       string
	oauth2Issuer       string
	oauth2ClientID     string
	oauth2ClientSecret string
	oauth2AuthURL      string
	oauth2TokenURL     string
	oauth2RedirectURL  string
}

// fixConfigDefaults handles edge cases in HTCondor configuration defaults
func fixConfigDefaults(cfg *config.Config, debug bool) {
	// If TILDE is empty or unset, LOCAL_DIR should default to /usr
	tilde, hasTilde := cfg.Get("TILDE")
	if !hasTilde || tilde == "" {
		// Check if LOCAL_DIR is already set
		if localDir, hasLocalDir := cfg.Get("LOCAL_DIR"); !hasLocalDir || localDir == "" || localDir == "$(TILDE)" {
			if debug {
				log.Println("DEBUG: condor user does not exist, setting LOCAL_DIR to /usr and LOG to /var/log/condor")
			}
			cfg.Set("LOCAL_DIR", "/usr")
			cfg.Set("LOG", "/var/log/condor")
		}
	}
}

// checkLogPathWritable checks if the log path directory exists and is writable
func checkLogPathWritable(logPath string) error {
	// Check if directory exists
	info, err := os.Stat(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Try to create the directory
			if err := os.MkdirAll(logPath, 0750); err != nil {
				return fmt.Errorf("directory does not exist and cannot be created: %w", err)
			}
			return nil
		}
		return fmt.Errorf("cannot stat directory: %w", err)
	}

	// Check if it's a directory
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory")
	}

	// Check if writable by trying to create a temp file
	tempFile := filepath.Join(logPath, ".write_test")
	// #nosec G304 -- Writing test file to verify log directory is writable
	f, err := os.OpenFile(tempFile, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("directory is not writable: %w", err)
	}
	if err := f.Close(); err != nil {
		// Best effort cleanup
		_ = os.Remove(tempFile)
		return fmt.Errorf("failed to close test file: %w", err)
	}
	if err := os.Remove(tempFile); err != nil {
		return fmt.Errorf("failed to remove test file: %w", err)
	}
	return nil
}

// createLogger creates a logger with reasonable defaults for unprivileged operation
func createLogger(cfg *config.Config) (*logging.Logger, error) {
	// Check if we can write to the LOG path specified in config
	logPath, hasLogPath := cfg.Get("LOG")

	// If no LOG path is configured, default to stdout
	if !hasLogPath || logPath == "" {
		log.Println("Using stdout logging")
		return logging.New(&logging.Config{
			OutputPath:   "stdout",
			MinVerbosity: logging.VerbosityInfo,
		})
	}

	// Check if LOG directory exists and is writable
	if err := checkLogPathWritable(logPath); err != nil {
		log.Printf("LOG directory '%s' is not writable: %v", logPath, err)
		log.Println("Using stdout logging")
		return logging.New(&logging.Config{
			OutputPath:   "stdout",
			MinVerbosity: logging.VerbosityInfo,
		})
	}

	// Try to create logger from config
	logger, err := logging.FromConfig(cfg)
	if err != nil {
		// If it fails (e.g., permission denied), fall back to stdout
		log.Printf("Failed to create logger with configured path '%s': %v", logPath, err)
		log.Println("Using stdout logging")
		return logging.New(&logging.Config{
			OutputPath:   "stdout",
			MinVerbosity: logging.VerbosityInfo,
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

		schedds, err := collector.QueryAds(ctx, "ScheddAd", constraint)
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

// discoverOIDCEndpoints performs OIDC discovery to find authorization and token endpoints
func discoverOIDCEndpoints(issuerURL string) (authURL, tokenURL string, err error) {
	// Construct the well-known OIDC configuration URL
	configURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"

	// Fetch the OIDC configuration
	req, err := http.NewRequestWithContext(context.Background(), "GET", configURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create OIDC configuration request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req) // #nosec G107 -- URL is from configuration, admin-controlled
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch OIDC configuration: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("OIDC configuration endpoint returned status %d", resp.StatusCode)
	}

	// Parse the configuration
	var config struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", "", fmt.Errorf("failed to parse OIDC configuration: %w", err)
	}

	if config.AuthorizationEndpoint == "" || config.TokenEndpoint == "" {
		return "", "", fmt.Errorf("OIDC configuration missing required endpoints")
	}

	return config.AuthorizationEndpoint, config.TokenEndpoint, nil
}

// loadMCPConfig loads MCP configuration from HTCondor config
func loadMCPConfig(cfg *config.Config, listenAddrFromConfig string) mcpConfig {
	config := mcpConfig{}

	// Check if MCP should be enabled from config
	if mcpEnable, ok := cfg.Get("HTTP_API_ENABLE_MCP"); ok && mcpEnable == "true" {
		config.enabled = true
		log.Println("MCP endpoints enabled via configuration")
	}

	// Get OAuth2 DB path from config, default to /var/lib/condor/oauth2.db
	if config.enabled {
		if dbPath, ok := cfg.Get("HTTP_API_OAUTH2_DB_PATH"); ok && dbPath != "" {
			config.oauth2DBPath = dbPath
		} else if localDir, ok := cfg.Get("LOCAL_DIR"); ok && localDir != "" {
			config.oauth2DBPath = filepath.Join(localDir, "oauth2.db")
		} else {
			config.oauth2DBPath = "/var/lib/condor/oauth2.db"
		}
		log.Printf("OAuth2 database path: %s", config.oauth2DBPath)

		// Get OAuth2 issuer from config or construct from FULL_HOSTNAME
		if issuer, ok := cfg.Get("HTTP_API_OAUTH2_ISSUER"); ok && issuer != "" {
			config.oauth2Issuer = issuer
		} else {
			// Default to https:// and use FULL_HOSTNAME if available
			hostname := listenAddrFromConfig
			if fullHostname, ok := cfg.Get("FULL_HOSTNAME"); ok && fullHostname != "" {
				hostname = fullHostname
			}
			// Append port if non-standard (not 443 for https)
			if strings.HasPrefix(listenAddrFromConfig, ":") {
				// Extract port from listen address
				port := strings.TrimPrefix(listenAddrFromConfig, ":")
				if port != "443" && port != "" {
					hostname = hostname + ":" + port
				}
			}
			config.oauth2Issuer = "https://" + hostname
		}
		log.Printf("OAuth2 issuer: %s", config.oauth2Issuer)

		// Get OAuth2 client ID
		if clientID, ok := cfg.Get("HTTP_API_OAUTH2_CLIENT_ID"); ok && clientID != "" {
			config.oauth2ClientID = clientID
		}

		// Get OAuth2 client secret from file
		if secretFile, ok := cfg.Get("HTTP_API_OAUTH2_CLIENT_SECRET_FILE"); ok && secretFile != "" {
			// #nosec G304 -- Reading OAuth2 client secret from configured file path
			if secretData, err := os.ReadFile(secretFile); err == nil {
				config.oauth2ClientSecret = strings.TrimSpace(string(secretData))
				log.Printf("OAuth2 client secret loaded from file: %s", secretFile)
			} else {
				log.Printf("Warning: failed to read OAuth2 client secret file '%s': %v", secretFile, err)
			}
		}

		// Check for OIDC discovery or explicit URLs
		if idpURL, ok := cfg.Get("HTTP_API_OAUTH2_IDP"); ok && idpURL != "" {
			// Use OIDC discovery to find auth and token URLs
			log.Printf("Attempting OIDC discovery from: %s", idpURL)
			if authURL, tokenURL, err := discoverOIDCEndpoints(idpURL); err == nil {
				config.oauth2AuthURL = authURL
				config.oauth2TokenURL = tokenURL
				log.Printf("OIDC discovery successful - Auth URL: %s, Token URL: %s", authURL, tokenURL)
			} else {
				log.Printf("Warning: OIDC discovery failed: %v", err)
			}
		} else {
			// Get explicit auth and token URLs
			if authURL, ok := cfg.Get("HTTP_API_OAUTH2_AUTH_URL"); ok && authURL != "" {
				config.oauth2AuthURL = authURL
			}
			if tokenURL, ok := cfg.Get("HTTP_API_OAUTH2_TOKEN_URL"); ok && tokenURL != "" {
				config.oauth2TokenURL = tokenURL
			}
		}

		// Get redirect URL or derive from issuer
		if redirectURL, ok := cfg.Get("HTTP_API_OAUTH2_REDIRECT_URL"); ok && redirectURL != "" {
			config.oauth2RedirectURL = redirectURL
		} else if config.oauth2Issuer != "" {
			// Default: derive from issuer by appending /oauth2/callback
			config.oauth2RedirectURL = config.oauth2Issuer + "/oauth2/callback"
			log.Printf("OAuth2 redirect URL derived from issuer: %s", config.oauth2RedirectURL)
		}
	}

	return config
}

// loadConfigWithDefaults loads HTCondor configuration with fallbacks
func loadConfigWithDefaults() *config.Config {
	cfg, err := config.New()
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
func getHTTPConfig(cfg *config.Config) (listenAddrResult, tlsCertFile, tlsKeyFile string) {
	listenAddrResult = *listenAddr
	if addr, ok := cfg.Get("HTTP_API_LISTEN_ADDR"); ok && addr != "" {
		listenAddrResult = addr
	}
	tlsCertFile, _ = cfg.Get("HTTP_API_TLS_CERT")
	tlsKeyFile, _ = cfg.Get("HTTP_API_TLS_KEY")
	return listenAddrResult, tlsCertFile, tlsKeyFile
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
	}
	if userHeaderFromConfig != "" {
		log.Printf("Using user header: %s", userHeaderFromConfig)
		if domain, ok := cfg.Get("UID_DOMAIN"); ok && domain != "" {
			uidDomain = domain
			log.Printf("Using UID_DOMAIN: %s", uidDomain)
		}
		if domain, ok := cfg.Get("TRUST_DOMAIN"); ok && domain != "" {
			trustDomain = domain
			log.Printf("Using TRUST_DOMAIN: %s", trustDomain)
		}
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

// runNormalMode runs the server using existing HTCondor configuration
func runNormalMode() error {
	// Load configuration
	cfg := loadConfigWithDefaults()

	// Get schedd configuration
	scheddNameValue, scheddAddrValue := getScheddConfig(cfg)

	// Get HTTP API configuration
	listenAddrFromConfig, tlsCertFile, tlsKeyFile := getHTTPConfig(cfg)

	// Get timeout configuration
	readTimeout, writeTimeout, idleTimeout := getTimeoutConfig(cfg)

	// Get user header configuration
	userHeaderFromConfig, uidDomain, trustDomain := getUserHeaderConfig(cfg)

	// Get optional signing key path - default to SEC_TOKEN_POOL_SIGNING_KEY_FILE
	signingKeyPath, ok := cfg.Get("HTTP_API_SIGNING_KEY")
	if !ok || signingKeyPath == "" {
		signingKeyPath, _ = cfg.Get("SEC_TOKEN_POOL_SIGNING_KEY_FILE")
	}

	// Create logger with reasonable defaults for unprivileged operation
	logger, err := createLogger(cfg)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
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
	mcpCfg := loadMCPConfig(cfg, listenAddrFromConfig)

	// Create and start server
	server, err := httpserver.NewServer(httpserver.Config{
		ListenAddr:         listenAddrFromConfig,
		ScheddName:         scheddNameValue,
		ScheddAddr:         scheddAddrValue,
		UserHeader:         userHeaderFromConfig,
		SigningKeyPath:     signingKeyPath,
		TLSCertFile:        tlsCertFile,
		TLSKeyFile:         tlsKeyFile,
		TrustDomain:        trustDomain,
		UIDDomain:          uidDomain,
		ReadTimeout:        readTimeout,
		WriteTimeout:       writeTimeout,
		IdleTimeout:        idleTimeout,
		Collector:          collector,
		Logger:             logger,
		EnableMCP:          mcpCfg.enabled,
		OAuth2DBPath:       mcpCfg.oauth2DBPath,
		OAuth2Issuer:       mcpCfg.oauth2Issuer,
		OAuth2ClientID:     mcpCfg.oauth2ClientID,
		OAuth2ClientSecret: mcpCfg.oauth2ClientSecret,
		OAuth2AuthURL:      mcpCfg.oauth2AuthURL,
		OAuth2TokenURL:     mcpCfg.oauth2TokenURL,
		OAuth2RedirectURL:  mcpCfg.oauth2RedirectURL,
	})
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		// Check if TLS is enabled
		if tlsCertFile != "" && tlsKeyFile != "" {
			errChan <- server.StartTLS(tlsCertFile, tlsKeyFile)
		} else {
			errChan <- server.Start()
		}
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logger.Info(logging.DestinationGeneral, "Received shutdown signal", "signal", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	case err := <-errChan:
		return err
	}
}

// runDemoMode runs the server with a mini condor setup
func runDemoMode() error {
	// Create logger for demo mode (stdout for access logs)
	logger, err := logging.New(&logging.Config{
		OutputPath:   "stdout",
		MinVerbosity: logging.VerbosityInfo,
	})
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
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
	if err := waitForCondor(tempDir); err != nil {
		return fmt.Errorf("condor failed to start: %w", err)
	}

	log.Println("HTCondor is ready!")

	// Determine signing key path for token generation
	// HTCondor auto-generates $(LOCAL_DIR)/passwords.d/POOL when needed
	var signingKeyPath string
	if *userHeader != "" {
		signingKeyPath = filepath.Join(tempDir, "passwords.d", "POOL")
		log.Printf("User header mode enabled: %s", *userHeader)
		log.Printf("Will use HTCondor-generated signing key at: %s", signingKeyPath)
	}

	uidDomain := ""
	trustDomain := ""
	if *userHeader != "" {
		log.Printf("Using user header: %s", *userHeader)
		if domain, ok := cfg.Get("UID_DOMAIN"); ok && domain != "" {
			uidDomain = domain
			log.Printf("Using UID_DOMAIN: %s", uidDomain)
		}
		if domain, ok := cfg.Get("TRUST_DOMAIN"); ok && domain != "" {
			trustDomain = domain
			log.Printf("Using TRUST_DOMAIN: %s", trustDomain)
		}
	}

	// Create collector for demo mode (points to local collector at 127.0.0.1:9618)
	collector := htcondor.NewCollector("127.0.0.1:9618")
	logger.Info(logging.DestinationCollector, "Created collector for demo mode", "host", "127.0.0.1:9618")

	// OAuth2 database path for MCP
	oauth2DBPath := filepath.Join(tempDir, "oauth2.db")

	// Create and start HTTP server with MCP enabled
	server, err := httpserver.NewServer(httpserver.Config{
		ListenAddr:     *listenAddr,
		UserHeader:     *userHeader,
		SigningKeyPath: signingKeyPath,
		TrustDomain:    trustDomain,
		UIDDomain:      uidDomain,
		Collector:      collector,
		Logger:         logger,
		EnableMCP:      true,                    // Enable MCP in demo mode
		OAuth2DBPath:   oauth2DBPath,            // OAuth2 database path
		OAuth2Issuer:   "http://" + *listenAddr, // OAuth2 issuer URL
	})
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start()
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		log.Printf("Received signal: %v, shutting down...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	case err := <-errChan:
		return err
	}
}

// writeMiniCondorConfig writes a minimal HTCondor configuration for a personal condor
func writeMiniCondorConfig(configFile, localDir, releaseDir string) error {
	config := fmt.Sprintf(`# Mini HTCondor Configuration for Demo Mode
LOCAL_DIR = %s
RELEASE_DIR = %s
LOG = $(LOCAL_DIR)/log
SPOOL = $(LOCAL_DIR)/spool
EXECUTE = $(LOCAL_DIR)/execute
BIN = $(RELEASE_DIR)/bin
SBIN = $(RELEASE_DIR)/sbin
LIB = $(RELEASE_DIR)/lib
LIBEXEC = $(RELEASE_DIR)/libexec

# Run all daemons locally
DAEMON_LIST = MASTER, COLLECTOR, NEGOTIATOR, SCHEDD, STARTD

# Use only local system resources
START = TRUE
SUSPEND = FALSE
PREEMPT = FALSE
KILL = FALSE

# Network settings
CONDOR_HOST = 127.0.0.1
COLLECTOR_HOST = $(CONDOR_HOST):9618

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
`, localDir, releaseDir)

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

// waitForCondor waits for HTCondor to be ready
func waitForCondor(localDir string) error {
	maxWait := 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), maxWait)
	defer cancel()

	deadline := time.Now().Add(maxWait)

	for time.Now().Before(deadline) {
		// Check if schedd log exists and contains startup message
		scheddLog := filepath.Join(localDir, "log", "SchedLog")
		if _, err := os.Stat(scheddLog); err == nil {
			// Log exists, check if schedd is accepting connections
			if isScheddReady(ctx) {
				return nil
			}
		}

		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("timeout waiting for HTCondor to be ready")
}

// isScheddReady checks if the schedd is accepting connections
func isScheddReady(ctx context.Context) bool {
	// Try running condor_q to check if schedd is ready
	cmd := exec.CommandContext(ctx, "condor_q", "-version")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}
