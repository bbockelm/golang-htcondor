// Package main provides an HTTP API server for HTCondor job management.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/httpserver"
)

var (
	demoMode   = flag.Bool("demo", false, "Run in demo mode with mini condor")
	listenAddr = flag.String("listen", ":8080", "Address to listen on (use 0.0.0.0:8080 to listen on all interfaces)")
	userHeader = flag.String("user-header", "", "HTTP header to read username from (e.g., X-Remote-User). Only used in demo mode with token generation.")
)

func main() {
	flag.Parse()

	// Force listenAddr to 0.0.0.0:8080 if not explicitly set
	if *listenAddr == ":8080" {
		*listenAddr = "0.0.0.0:8080"
	}

	// Set a default user header if not provided
	if *userHeader == "" {
		*userHeader = "X-Remote-User"
	}

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

// runNormalMode runs the server using existing HTCondor configuration
func runNormalMode() error {
	// Load HTCondor configuration
	cfg, err := config.New()
	if err != nil {
		return fmt.Errorf("failed to load HTCondor configuration: %w", err)
	}

	// Get schedd configuration
	scheddName, _ := cfg.Get("SCHEDD_NAME")
	if scheddName == "" {
		scheddName = "local"
	}

	scheddHost, ok := cfg.Get("SCHEDD_HOST")
	if !ok {
		return fmt.Errorf("SCHEDD_HOST not configured")
	}

	scheddPort := 9619 // Default schedd port
	if portStr, ok := cfg.Get("SCHEDD_PORT"); ok {
		if _, err := fmt.Sscanf(portStr, "%d", &scheddPort); err != nil {
			log.Printf("Warning: failed to parse SCHEDD_PORT '%s', using default %d: %v", portStr, scheddPort, err)
		}
	}

	// Get HTTP API configuration
	listenAddrFromConfig := *listenAddr
	if addr, ok := cfg.Get("HTTP_API_LISTEN_ADDR"); ok && addr != "" {
		listenAddrFromConfig = addr
	}

	// Get TLS configuration
	tlsCertFile, _ := cfg.Get("HTTP_API_TLS_CERT")
	tlsKeyFile, _ := cfg.Get("HTTP_API_TLS_KEY")

	// Get timeout configuration
	readTimeout := 30 * time.Second
	if timeoutStr, ok := cfg.Get("HTTP_API_READ_TIMEOUT"); ok {
		if duration, err := time.ParseDuration(timeoutStr); err == nil {
			readTimeout = duration
		} else {
			log.Printf("Warning: failed to parse HTTP_API_READ_TIMEOUT '%s', using default: %v", timeoutStr, err)
		}
	}

	writeTimeout := 30 * time.Second
	if timeoutStr, ok := cfg.Get("HTTP_API_WRITE_TIMEOUT"); ok {
		if duration, err := time.ParseDuration(timeoutStr); err == nil {
			writeTimeout = duration
		} else {
			log.Printf("Warning: failed to parse HTTP_API_WRITE_TIMEOUT '%s', using default: %v", timeoutStr, err)
		}
	}

	idleTimeout := 120 * time.Second
	if timeoutStr, ok := cfg.Get("HTTP_API_IDLE_TIMEOUT"); ok {
		if duration, err := time.ParseDuration(timeoutStr); err == nil {
			idleTimeout = duration
		} else {
			log.Printf("Warning: failed to parse HTTP_API_IDLE_TIMEOUT '%s', using default: %v", timeoutStr, err)
		}
	}

	// Get optional user header configuration
	userHeaderFromConfig := *userHeader
	if header, ok := cfg.Get("HTTP_API_USER_HEADER"); ok && header != "" {
		userHeaderFromConfig = header
	}

	// Get optional signing key path
	signingKeyPath, _ := cfg.Get("HTTP_API_SIGNING_KEY")

	// Create and start server
	server, err := httpserver.NewServer(httpserver.Config{
		ListenAddr:     listenAddrFromConfig,
		ScheddName:     scheddName,
		ScheddAddr:     scheddHost,
		ScheddPort:     scheddPort,
		UserHeader:     userHeaderFromConfig,
		SigningKeyPath: signingKeyPath,
		TLSCertFile:    tlsCertFile,
		TLSKeyFile:     tlsKeyFile,
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		IdleTimeout:    idleTimeout,
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
		log.Printf("Received signal: %v, shutting down...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	case err := <-errChan:
		return err
	}
}

// runDemoMode runs the server with a mini condor setup
func runDemoMode() error {
	log.Println("Starting in demo mode...")

	// Create temporary directory for mini condor
	tempDir, err := os.MkdirTemp("", "htcondor-demo-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Use absolute path for all config and directory creation
	tempDirAbs, err := filepath.Abs(tempDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Ensure required subdirectories exist
	for _, sub := range []string{"log", "spool", "execute"} {
		if err := os.MkdirAll(filepath.Join(tempDirAbs, sub), 0777); err != nil {
			return fmt.Errorf("failed to create %s: %w", sub, err)
		}
	}
	defer func() {
		log.Printf("Cleaning up temporary directory: %s", tempDirAbs)
		if err := os.RemoveAll(tempDirAbs); err != nil {
			log.Printf("Warning: failed to remove temp directory: %v", err)
		}
	}()

	log.Printf("Using temporary directory: %s", tempDirAbs)

	// Write mini condor configuration
	configFile := filepath.Join(tempDirAbs, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDirAbs); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
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
	if err := waitForCondor(tempDirAbs); err != nil {
		return fmt.Errorf("condor failed to start: %w", err)
	}

	log.Println("HTCondor is ready!")

	// Generate signing key if user-header is set
	var signingKeyPath string
	if *userHeader != "" {
		log.Printf("User header mode enabled: %s", *userHeader)
		signingKeyPath = filepath.Join(tempDirAbs, "signing.key")

		// Generate a signing key
		key, err := httpserver.GenerateSigningKey()
		if err != nil {
			return fmt.Errorf("failed to generate signing key: %w", err)
		}

		// Write the key to file
		if err := os.WriteFile(signingKeyPath, key, 0600); err != nil {
			return fmt.Errorf("failed to write signing key: %w", err)
		}

		log.Printf("Generated signing key at: %s", signingKeyPath)
	}

	// Create and start HTTP server
	server, err := httpserver.NewServer(httpserver.Config{
		ListenAddr:     *listenAddr,
		ScheddName:     "local",
		ScheddAddr:     "127.0.0.1",
		ScheddPort:     9619,
		UserHeader:     *userHeader,
		SigningKeyPath: signingKeyPath,
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
func writeMiniCondorConfig(configFile, localDir string) error {
	uid := os.Getuid()
	gid := os.Getgid()
	config := fmt.Sprintf(`# Mini HTCondor Configuration for Demo Mode
LOCAL_DIR = %s
CONDOR_IDS = %d.%d
LOG = $(LOCAL_DIR)/log
SPOOL = $(LOCAL_DIR)/spool
EXECUTE = $(LOCAL_DIR)/execute
BIN = $(LOCAL_DIR)/bin
LIB = $(LOCAL_DIR)/lib
RELEASE_DIR = /usr

# Run all daemons locally
DAEMON_LIST = MASTER, COLLECTOR, NEGOTIATOR, SCHEDD, STARTD

# Use only local system resources
START = TRUE
SUSPEND = FALSE
PREEMPT = FALSE
KILL = FALSE

# hardcode no shared port
USE_SHARED_PORT = FALSE

# Network settings
CONDOR_HOST = 127.0.0.1
COLLECTOR_HOST = $(CONDOR_HOST):9618
SCHEDD_HOST = $(CONDOR_HOST)
SCHEDD_ARGS = -p 9619

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
`, localDir, uid, gid)

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
