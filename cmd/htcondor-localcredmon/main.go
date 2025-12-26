// Command htcondor-localcredmon implements a local credential monitor daemon
// for HTCondor that runs under condor_master with keepalive/ready signaling.
//
// Usage:
//
//	htcondor-localcredmon [options]
//
// Options:
//
//	-provider string
//	      Credential provider name (default "github")
//	-cred-dir string
//	      Credential directory to monitor (default from config: SEC_CREDENTIAL_DIRECTORY_OAUTH)
//	-scan-interval duration
//	      Scan interval for credential files (default 5m)
//	-issuer string
//	      Token issuer URL (default "https://localhost")
//	-audience strings
//	      Token audience(s), comma-separated (default from issuer)
//	-lifetime duration
//	      Token lifetime (default 20m)
//	-key-file string
//	      Private key file for signing tokens (PEM format, RSA or ECDSA)
//	-key-id string
//	      Key identifier for token header (default "local")
//
// Environment:
//
//	CONDOR_INHERIT      - Parent PID and master address (required when running under condor_master)
//	_CONDOR_DAEMON_NAME - Daemon name for readiness signaling
//
// The daemon:
// 1. Loads HTCondor configuration
// 2. Connects to condor_master via CONDOR_INHERIT
// 3. Starts keepalive heartbeats
// 4. Signals readiness
// 5. Monitors credential directory for .top files
// 6. Generates SciTokens and writes .use files
// 7. Handles SIGHUP for immediate rescans
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/localcredmon"
	"github.com/lestrrat-go/jwx/v2/jwa"
)

var (
	name         = flag.String("name", "", "Daemon name (overrides config)")
	n            = flag.String("n", "", "Daemon name (alias for -name)")
	provider     = flag.String("provider", "", "Credential provider name (default from config: LOCAL_CREDMON_PROVIDER or 'github')")
	credDir      = flag.String("cred-dir", "", "Credential directory to monitor (default from config: SEC_CREDENTIAL_DIRECTORY_OAUTH)")
	scanInterval = flag.Duration("scan-interval", 0, "Scan interval for credential files (default from config: LOCAL_CREDMON_SCAN_INTERVAL or 5m)")
	issuer       = flag.String("issuer", "", "Token issuer URL (default from config: LOCAL_CREDMON_ISSUER or 'https://localhost')")
	audience     = flag.String("audience", "", "Token audience(s), comma-separated (default from config: LOCAL_CREDMON_AUDIENCE or issuer)")
	lifetime     = flag.Duration("lifetime", 0, "Token lifetime (default from config: LOCAL_CREDMON_LIFETIME or 20m)")
	keyFile      = flag.String("key-file", "", "Private key file for signing tokens (default from config: LOCAL_CREDMON_KEY_FILE)")
	keyID        = flag.String("key-id", "", "Key identifier for token header (default from config: LOCAL_CREDMON_KEY_ID or 'local')")
)

// credmonConfig holds the runtime configuration for the credmon daemon
type credmonConfig struct {
	daemonName      string
	providerName    string
	credDirPath     string
	scanIntervalDur time.Duration
	issuerURL       string
	lifetimeDur     time.Duration
	keyIDStr        string
	keyFilePath     string
	audienceStr     string
}

// loadCredmonConfig loads configuration from flags and HTCondor config
func loadCredmonConfig(htcConfig *config.Config) (*credmonConfig, error) {
	cfg := &credmonConfig{}

	// Get daemon name from flag or config
	cfg.daemonName = *name
	if cfg.daemonName == "" {
		if n, ok := htcConfig.Get("LOCAL_CREDMON_NAME"); ok {
			cfg.daemonName = n
		} else {
			cfg.daemonName = "LOCAL_CREDMON"
		}
	}

	// Get provider from flag or config
	cfg.providerName = *provider
	if cfg.providerName == "" {
		if p, ok := htcConfig.Get("LOCAL_CREDMON_PROVIDER"); ok {
			cfg.providerName = p
		} else {
			cfg.providerName = "github"
		}
	}

	// Determine credential directory from flag or config
	cfg.credDirPath = *credDir
	if cfg.credDirPath == "" {
		if dir, ok := htcConfig.Get("SEC_CREDENTIAL_DIRECTORY_OAUTH"); ok {
			cfg.credDirPath = dir
		} else {
			return nil, errors.New("credential directory not specified and SEC_CREDENTIAL_DIRECTORY_OAUTH not set in config")
		}
	}

	// Get scan interval from flag or config
	cfg.scanIntervalDur = *scanInterval
	if cfg.scanIntervalDur == 0 {
		if intervalStr, ok := htcConfig.Get("LOCAL_CREDMON_SCAN_INTERVAL"); ok {
			if d, err := time.ParseDuration(intervalStr); err == nil {
				cfg.scanIntervalDur = d
			} else {
				cfg.scanIntervalDur = 5 * time.Minute
			}
		} else {
			cfg.scanIntervalDur = 5 * time.Minute
		}
	}

	// Get issuer from flag or config
	cfg.issuerURL = *issuer
	if cfg.issuerURL == "" {
		if iss, ok := htcConfig.Get("LOCAL_CREDMON_ISSUER"); ok {
			cfg.issuerURL = iss
		} else {
			cfg.issuerURL = "https://localhost"
		}
	}

	// Get lifetime from flag or config
	cfg.lifetimeDur = *lifetime
	if cfg.lifetimeDur == 0 {
		if lifetimeStr, ok := htcConfig.Get("LOCAL_CREDMON_LIFETIME"); ok {
			if d, err := time.ParseDuration(lifetimeStr); err == nil {
				cfg.lifetimeDur = d
			} else {
				cfg.lifetimeDur = 20 * time.Minute
			}
		} else {
			cfg.lifetimeDur = 20 * time.Minute
		}
	}

	// Get key ID from flag or config
	cfg.keyIDStr = *keyID
	if cfg.keyIDStr == "" {
		if kid, ok := htcConfig.Get("LOCAL_CREDMON_KEY_ID"); ok {
			cfg.keyIDStr = kid
		} else {
			cfg.keyIDStr = "local"
		}
	}

	// Load private key path from flag or config
	cfg.keyFilePath = *keyFile
	if cfg.keyFilePath == "" {
		if kf, ok := htcConfig.Get("LOCAL_CREDMON_KEY_FILE"); ok {
			cfg.keyFilePath = kf
		} else {
			return nil, errors.New("key file not specified and LOCAL_CREDMON_KEY_FILE not set in config")
		}
	}

	// Parse audience from flag or config
	cfg.audienceStr = *audience
	if cfg.audienceStr == "" {
		if aud, ok := htcConfig.Get("LOCAL_CREDMON_AUDIENCE"); ok {
			cfg.audienceStr = aud
		}
	}

	return cfg, nil
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("Fatal error: %v", err)
	}
}

func run() error {
	flag.Parse()

	// Determine daemon name for config loading (respects -n or -name)
	localName := *name
	if localName == "" && *n != "" {
		localName = *n
	}

	// Load HTCondor configuration with subsystem and local name
	htcConfig, err := config.NewWithOptions(config.ConfigOptions{
		Subsystem: "CREDMON",
		LocalName: localName,
	})
	if err != nil {
		return fmt.Errorf("failed to load HTCondor config: %w", err)
	}

	// Load configuration from flags and HTCondor config
	cfg, err := loadCredmonConfig(htcConfig)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Set up logger - write to configured log file if under condor_master, otherwise stdout
	var logWriter io.Writer = os.Stdout
	var logFile *os.File
	if logPath, ok := htcConfig.Get(cfg.daemonName + "_LOG"); ok {
		//nolint:gosec // Log file path from HTCondor config is trusted
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file %s: %w", logPath, err)
		}
		logFile = f
		logWriter = f
		defer func() {
			if err := logFile.Close(); err != nil {
				log.Printf("Failed to close log file: %v", err)
			}
		}()
	}
	logger := log.New(logWriter, "[localcredmon] ", log.LstdFlags)

	logger.Printf("Using credential directory: %s", cfg.credDirPath)

	//nolint:gosec // User-provided key file path is intentional
	privateKey, algorithm, err := loadPrivateKey(cfg.keyFilePath)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}
	logger.Printf("Loaded %s private key from %s", algorithm, cfg.keyFilePath)

	// Parse audience
	var audiences []string
	if cfg.audienceStr != "" {
		audiences = strings.Split(cfg.audienceStr, ",")
		for i := range audiences {
			audiences[i] = strings.TrimSpace(audiences[i])
		}
	} else {
		audiences = []string{cfg.issuerURL}
	}

	// Create localcredmon instance
	credmon, err := localcredmon.New(localcredmon.Config{
		CredDir:        cfg.credDirPath,
		Provider:       cfg.providerName,
		PrivateKey:     privateKey,
		KeyID:          cfg.keyIDStr,
		Algorithm:      algorithm,
		Issuer:         cfg.issuerURL,
		Audience:       audiences,
		TokenLifetime:  cfg.lifetimeDur,
		AuthzTemplate:  "read:/user/{username} write:/user/{username}",
		UseJSON:        false,
		Logger:         logger,
		HTCondorConfig: htcConfig,
		DaemonName:     cfg.daemonName,
	})
	if err != nil {
		return fmt.Errorf("failed to create localcredmon: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// Start keepalive heartbeats
	logger.Printf("Starting keepalive heartbeats to condor_master...")
	stopKeepAlive, keepAliveErrs, err := credmon.StartKeepAlive(ctx)
	if err != nil {
		return fmt.Errorf("failed to start keepalive: %w", err)
	}
	defer stopKeepAlive()

	// Monitor keepalive errors
	go func() {
		for err := range keepAliveErrs {
			logger.Printf("Keepalive error: %v", err)
		}
	}()

	// Signal readiness to condor_master
	logger.Printf("Signaling readiness to condor_master...")
	if err := credmon.SendReady(ctx); err != nil {
		return fmt.Errorf("failed to send ready: %w", err)
	}
	logger.Printf("Ready signal sent successfully")

	// Start watching for credential requests
	logger.Printf("Starting credential monitor (provider=%s, interval=%v)", cfg.providerName, cfg.scanIntervalDur)
	if err := credmon.Watch(ctx, cfg.scanIntervalDur); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("credential monitor failed: %w", err)
	}

	logger.Printf("Shutting down gracefully...")
	return nil
}

// loadPrivateKey loads a private key from PEM file and returns the key and algorithm
func loadPrivateKey(path string) (interface{}, jwa.SignatureAlgorithm, error) {
	//nolint:gosec // User-provided key file path is intentional
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, "", fmt.Errorf("failed to decode PEM block")
	}

	// Try RSA first
	if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rsaKey, jwa.RS256, nil
	}

	// Try PKCS8 format (supports both RSA and ECDSA)
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k, jwa.RS256, nil
		case *ecdsa.PrivateKey:
			return k, jwa.ES256, nil
		default:
			return nil, "", fmt.Errorf("unsupported key type in PKCS8: %T", key)
		}
	}

	// Try EC private key
	if ecKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return ecKey, jwa.ES256, nil
	}

	return nil, "", fmt.Errorf("failed to parse private key (tried RSA, ECDSA, PKCS8)")
}
