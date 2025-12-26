// Package localcredmon implements a local credential monitor for HTCondor
// that processes OAuth credential requests (.top files) and generates
// SciTokens (.use files) using a local signing key.
//
// This daemon runs under condor_master and uses keepalive/ready signaling.
//
// Features:
// - Keepalive heartbeats to condor_master
// - Readiness signaling on startup
// - HTCondor config integration
// - SIGHUP signal handling for immediate rescans
// - Periodic token renewal at 2/3 of lifetime
// - Atomic file updates (temp file + rename)
package localcredmon

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Config holds the configuration for the local credmon
type Config struct {
	// CredDir is the credential directory to monitor
	CredDir string

	// Provider is the credential provider name (e.g., "github")
	Provider string

	// PrivateKey is the RSA or ECDSA private key for signing tokens
	PrivateKey interface{} // *rsa.PrivateKey or *ecdsa.PrivateKey

	// KeyID is the key identifier for the token header
	KeyID string

	// Algorithm is the signing algorithm (RS256 or ES256)
	Algorithm jwa.SignatureAlgorithm

	// Issuer is the token issuer URL
	Issuer string

	// Audience is the token audience (required for scitoken:2.0)
	Audience []string

	// TokenLifetime is the token lifetime in seconds
	TokenLifetime time.Duration

	// AuthzTemplate is the authorization template (e.g., "read:/user/{username} write:/user/{username}")
	AuthzTemplate string

	// UseJSON determines if .use file should be JSON format
	UseJSON bool

	// Logger for debug output
	Logger *log.Logger

	// HTCondorConfig is the HTCondor configuration instance (optional, loaded from env if nil)
	HTCondorConfig *config.Config

	// Master is the Master interface for keepalive/ready (optional, loaded from env if nil)
	Master *htcondor.Master

	// DaemonName is the daemon name for readiness signaling (read from config if empty)
	DaemonName string

	// DaemonType is the daemon type/subsystem (e.g., "CREDD", "LOCAL_CREDMON")
	DaemonType string
}

// LocalCredmon monitors credential requests and generates tokens
type LocalCredmon struct {
	config            Config
	sighupChan        chan os.Signal
	rescanChan        chan struct{}
	tokenCache        map[string]time.Time // username/provider -> last renewal time
	master            *htcondor.Master
	htcConfig         *config.Config
	lastConfigReload  time.Time   // last time config was reloaded
	configReloadTimer *time.Timer // pending deferred config reload
	configMu          sync.Mutex  // protects lastConfigReload and configReloadTimer
}

// New creates a new LocalCredmon instance
func New(cfg Config) (*LocalCredmon, error) {
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stderr, "[localcredmon] ", log.LstdFlags)
	}
	if cfg.TokenLifetime == 0 {
		cfg.TokenLifetime = 20 * time.Minute
	}
	if cfg.AuthzTemplate == "" {
		cfg.AuthzTemplate = "read:/user/{username} write:/user/{username}"
	}
	if cfg.KeyID == "" {
		cfg.KeyID = "local"
	}

	// Load HTCondor config if not provided
	htcConfig := cfg.HTCondorConfig
	if htcConfig == nil {
		var err error
		htcConfig, err = config.New()
		if err != nil {
			return nil, fmt.Errorf("failed to load HTCondor config: %w", err)
		}
	}

	// Get daemon name from config if not provided
	if cfg.DaemonName == "" {
		cfg.DaemonName = os.Getenv("_CONDOR_DAEMON_NAME")
		if cfg.DaemonName == "" {
			if name, ok := htcConfig.Get("LOCAL_CREDMON_NAME"); ok {
				cfg.DaemonName = name
			} else {
				cfg.DaemonName = "LOCAL_CREDMON"
			}
		}
	}

	// Get daemon type from config if not provided
	if cfg.DaemonType == "" {
		if dt, ok := htcConfig.Get("LOCAL_CREDMON_TYPE"); ok {
			cfg.DaemonType = dt
		} else {
			cfg.DaemonType = "LOCAL_CREDMON"
		}
	}

	// Initialize Master for keepalive/ready if not provided
	master := cfg.Master
	if master == nil {
		var err error
		master, err = htcondor.MasterFromEnv()
		if err != nil {
			cfg.Logger.Printf("Warning: Failed to initialize Master from env: %v (running standalone?)", err)
			// Continue without master - allows standalone operation
		}
	}

	lc := &LocalCredmon{
		config:     cfg,
		sighupChan: make(chan os.Signal, 1),
		rescanChan: make(chan struct{}, 1),
		tokenCache: make(map[string]time.Time),
		master:     master,
		htcConfig:  htcConfig,
	}

	// Set up SIGHUP handler for immediate rescans
	signal.Notify(lc.sighupChan, syscall.SIGHUP)

	return lc, nil
}

// SendReady sends a ready signal to condor_master
func (lc *LocalCredmon) SendReady(ctx context.Context) error {
	if lc.master == nil {
		lc.config.Logger.Printf("No master connection, skipping ready signal")
		return nil
	}

	return lc.master.SendReady(ctx, &htcondor.ReadyOptions{
		Name:  lc.config.DaemonName,
		State: "Ready",
	})
}

// StartKeepAlive starts the keepalive loop to condor_master
// Returns a stop function and error channel
func (lc *LocalCredmon) StartKeepAlive(ctx context.Context) (stop func(), errs <-chan error, err error) {
	if lc.master == nil {
		lc.config.Logger.Printf("No master connection, skipping keepalive")
		// Return a closed channel so range loops terminate immediately
		errChan := make(chan error)
		close(errChan)
		return func() {}, errChan, nil
	}

	return lc.master.StartKeepAlive(ctx, &htcondor.KeepAliveOptions{
		HangTimeout: 10 * time.Minute,
	})
}

// ScanOnce scans for .top files and processes them once
func (lc *LocalCredmon) ScanOnce(ctx context.Context) error {
	pattern := filepath.Join(lc.config.CredDir, "*", lc.config.Provider+".top")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to glob pattern %s: %w", pattern, err)
	}

	lc.config.Logger.Printf("Found %d %s tokens to process", len(matches), lc.config.Provider)

	for _, topFile := range matches {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := lc.processCredFile(topFile); err != nil {
			lc.config.Logger.Printf("Error processing %s: %v", topFile, err)
		}
	}

	return nil
}

// Watch continuously monitors for .top files and processes them
// Supports:
// - SIGHUP signal for immediate rescans
// - Periodic rescanning at specified interval
// - Automatic token renewal at 2/3 of lifetime
func (lc *LocalCredmon) Watch(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Do initial scan
	if err := lc.ScanOnce(ctx); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			signal.Stop(lc.sighupChan)
			lc.configMu.Lock()
			if lc.configReloadTimer != nil {
				lc.configReloadTimer.Stop()
			}
			lc.configMu.Unlock()
			return ctx.Err()

		case <-lc.sighupChan:
			// SIGHUP received - reload config (rate-limited/deferred) and rescan immediately
			lc.scheduleConfigReload()

			if err := lc.ScanOnce(ctx); err != nil {
				lc.config.Logger.Printf("Scan error after SIGHUP: %v", err)
			}

		case <-lc.rescanChan:
			// Manual rescan trigger
			if err := lc.ScanOnce(ctx); err != nil {
				lc.config.Logger.Printf("Scan error: %v", err)
			}

		case <-ticker.C:
			// Periodic scan
			if err := lc.ScanOnce(ctx); err != nil {
				lc.config.Logger.Printf("Scan error: %v", err)
			}
		}
	}
}

// TriggerRescan manually triggers a rescan (non-blocking)
func (lc *LocalCredmon) TriggerRescan() {
	select {
	case lc.rescanChan <- struct{}{}:
	default:
		// Already pending, skip
	}
}

// scheduleConfigReload schedules a config reload, either immediately or deferred.
// If a reload happened within the last 5 seconds, it schedules one for 5 seconds
// after the last reload. Multiple requests during the window are coalesced.
func (lc *LocalCredmon) scheduleConfigReload() {
	lc.configMu.Lock()
	timeSinceReload := time.Since(lc.lastConfigReload)

	if timeSinceReload >= 5*time.Second {
		// Enough time has passed, reload immediately
		lc.configMu.Unlock()
		lc.config.Logger.Printf("Received SIGHUP, reloading configuration...")
		if err := lc.reloadConfig(); err != nil {
			lc.config.Logger.Printf("Config reload error: %v", err)
		}
	} else {
		// Too soon, schedule a deferred reload
		if lc.configReloadTimer != nil {
			// Already scheduled, coalesce (do nothing)
			lc.configMu.Unlock()
			lc.config.Logger.Printf("Received SIGHUP, config reload already scheduled")
			return
		}

		// Schedule reload for 5 seconds after last reload
		delay := 5*time.Second - timeSinceReload
		lc.config.Logger.Printf("Received SIGHUP, scheduling config reload in %.1fs", delay.Seconds())

		lc.configReloadTimer = time.AfterFunc(delay, func() {
			lc.configMu.Lock()
			lc.configReloadTimer = nil
			lc.configMu.Unlock()

			lc.config.Logger.Printf("Executing deferred config reload...")
			if err := lc.reloadConfig(); err != nil {
				lc.config.Logger.Printf("Config reload error: %v", err)
			}
		})
		lc.configMu.Unlock()
	}
}

// reloadConfig reloads the HTCondor configuration and updates credmon settings
func (lc *LocalCredmon) reloadConfig() error {
	// Update last reload timestamp
	lc.configMu.Lock()
	lc.lastConfigReload = time.Now()
	lc.configMu.Unlock()

	// Reload HTCondor config with same options as initial load
	newConfig, err := config.NewWithOptions(config.ConfigOptions{
		Subsystem: "CREDMON",
		LocalName: lc.config.DaemonName,
	})
	if err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}

	lc.htcConfig = newConfig

	// Update configurable parameters from reloaded config
	if scanIntervalStr, ok := newConfig.Get("LOCAL_CREDMON_SCAN_INTERVAL"); ok {
		if d, err := time.ParseDuration(scanIntervalStr); err == nil {
			lc.config.Logger.Printf("Updated scan interval to %v", d)
			// Note: scan interval change will take effect on next Watch() call
		}
	}

	if lifetimeStr, ok := newConfig.Get("LOCAL_CREDMON_LIFETIME"); ok {
		if d, err := time.ParseDuration(lifetimeStr); err == nil {
			lc.config.TokenLifetime = d
			lc.config.Logger.Printf("Updated token lifetime to %v", d)
		}
	}

	if issuer, ok := newConfig.Get("LOCAL_CREDMON_ISSUER"); ok {
		lc.config.Issuer = issuer
		lc.config.Logger.Printf("Updated issuer to %s", issuer)
	}

	if audience, ok := newConfig.Get("LOCAL_CREDMON_AUDIENCE"); ok {
		if audience != "" {
			audiences := strings.Split(audience, ",")
			for i := range audiences {
				audiences[i] = strings.TrimSpace(audiences[i])
			}
			lc.config.Audience = audiences
			lc.config.Logger.Printf("Updated audience to %v", audiences)
		}
	}

	lc.config.Logger.Printf("Configuration reloaded successfully")
	return nil
}

// processCredFile processes a single .top file
func (lc *LocalCredmon) processCredFile(topFile string) error {
	// Extract username from path: <cred_dir>/<username>/<provider>.top
	dir := filepath.Dir(topFile)
	username := filepath.Base(dir)

	lc.config.Logger.Printf("Processing %s for user %s", topFile, username)

	useFile := filepath.Join(dir, lc.config.Provider+".use")
	cacheKey := username + "/" + lc.config.Provider

	// Check if .use file exists
	useFileInfo, err := os.Stat(useFile)
	needsRenewal := false

	switch {
	case os.IsNotExist(err):
		// .use file doesn't exist, must create it
		lc.config.Logger.Printf(".use file for %s doesn't exist, creating", username)
		needsRenewal = true
	case err != nil:
		return fmt.Errorf("failed to stat .use file: %w", err)
	default:
		// .use file exists, check if token needs renewal (2/3 of lifetime)
		fileAge := time.Since(useFileInfo.ModTime())
		renewalThreshold := lc.config.TokenLifetime * 2 / 3

		if fileAge < renewalThreshold {
			// Token is still fresh, skip renewal
			lc.config.Logger.Printf("Token for %s is still fresh (age: %v, threshold: %v)",
				username, fileAge, renewalThreshold)
			return nil
		}
		lc.config.Logger.Printf("Token for %s needs renewal (age: %v, threshold: %v)",
			username, fileAge, renewalThreshold)
		needsRenewal = true
	}

	if !needsRenewal {
		return nil
	}

	// Generate and write the token
	if err := lc.refreshAccessToken(username, lc.config.Provider, useFile); err != nil {
		return fmt.Errorf("failed to refresh token for %s: %w", username, err)
	}

	// Update cache with renewal time
	lc.tokenCache[cacheKey] = time.Now()

	lc.config.Logger.Printf("Successfully created token for user %s", username)
	return nil
}

// refreshAccessToken generates a new SciToken and writes it to the .use file
func (lc *LocalCredmon) refreshAccessToken(username, _ /* tokenName */, useFile string) error {
	// Generate scopes from template
	scopes := strings.ReplaceAll(lc.config.AuthzTemplate, "{username}", username)

	// Create the token
	now := time.Now()
	token := jwt.New()

	// Standard claims
	_ = token.Set(jwt.SubjectKey, username)
	_ = token.Set(jwt.IssuerKey, lc.config.Issuer)
	_ = token.Set(jwt.IssuedAtKey, now.Unix())
	_ = token.Set(jwt.ExpirationKey, now.Add(lc.config.TokenLifetime).Unix())

	// SciToken-specific claims
	_ = token.Set("scope", scopes)
	_ = token.Set("ver", "scitoken:2.0")

	// Audience (required for scitoken:2.0)
	if len(lc.config.Audience) > 0 {
		if len(lc.config.Audience) == 1 {
			_ = token.Set(jwt.AudienceKey, lc.config.Audience[0])
		} else {
			_ = token.Set(jwt.AudienceKey, lc.config.Audience)
		}
	}

	// Sign the token
	var signed []byte
	var err error

	switch key := lc.config.PrivateKey.(type) {
	case *rsa.PrivateKey:
		signed, err = jwt.Sign(token, jwt.WithKey(jwa.RS256, key))
	case *ecdsa.PrivateKey:
		signed, err = jwt.Sign(token, jwt.WithKey(jwa.ES256, key))
	default:
		return fmt.Errorf("unsupported key type: %T", lc.config.PrivateKey)
	}

	if err != nil {
		return fmt.Errorf("failed to sign token: %w", err)
	}

	// Write the token to the .use file (atomically)
	return lc.writeAccessToken(useFile, string(signed))
}

// writeAccessToken writes the serialized token to the .use file atomically
// Uses temp file + rename to ensure atomic updates
func (lc *LocalCredmon) writeAccessToken(useFile, serializedToken string) error {
	// Create temporary file in the same directory for atomic rename
	dir := filepath.Dir(useFile)
	tmpFile, err := os.CreateTemp(dir, ".use-tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() { _ = os.Remove(tmpPath) }() // Clean up on error

	var content string
	if lc.config.UseJSON {
		// Write JSON format
		data := map[string]interface{}{
			"access_token": serializedToken,
			"expires_in":   int(lc.config.TokenLifetime.Seconds()),
		}
		jsonBytes, err := json.Marshal(data)
		if err != nil {
			_ = tmpFile.Close()
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		content = string(jsonBytes)
	} else {
		// Write bare token
		content = serializedToken + "\n"
	}

	if _, err := tmpFile.WriteString(content); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write token: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Atomic rename (overwrites existing file)
	if err := os.Rename(tmpPath, useFile); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	lc.config.Logger.Printf("Wrote token to %s", useFile)
	return nil
}
