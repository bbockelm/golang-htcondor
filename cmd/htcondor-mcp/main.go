// Package main provides an MCP server for HTCondor job management.
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

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/mcpserver"
)

var (
	demoMode = flag.Bool("demo", false, "Run in demo mode with mini condor")
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

// runNormalMode runs the server using existing HTCondor configuration
func runNormalMode() error {
	// Load HTCondor configuration
	cfg, err := config.New()
	if err != nil {
		return fmt.Errorf("failed to load HTCondor configuration: %w", err)
	}

	// Get schedd configuration
	scheddName, _ := cfg.Get("SCHEDD_NAME")

	// Get optional signing key path
	signingKeyPath, ok := cfg.Get("SEC_TOKEN_POOL_SIGNING_KEY_FILE")
	if !ok {
		signingKeyPath = ""
	}

	// Get trust/UID domains
	trustDomain, _ := cfg.Get("TRUST_DOMAIN")
	uidDomain, _ := cfg.Get("UID_DOMAIN")

	// Create logger from configuration
	logger, err := logging.FromConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	// Create collector from COLLECTOR_HOST
	var collector *htcondor.Collector
	if collectorHost, ok := cfg.Get("COLLECTOR_HOST"); ok && collectorHost != "" {
		collector = htcondor.NewCollector(collectorHost)
		logger.Info(logging.DestinationCollector, "Created collector", "host", collectorHost)
	}

	// Create MCP server
	server, err := mcpserver.NewServer(mcpserver.Config{
		ScheddName:     scheddName,
		SigningKeyPath: signingKeyPath,
		TrustDomain:    trustDomain,
		UIDDomain:      uidDomain,
		Collector:      collector,
		Logger:         logger,
		Stdin:          os.Stdin,
		Stdout:         os.Stdout,
	})
	if err != nil {
		return fmt.Errorf("failed to create MCP server: %w", err)
	}

	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info(logging.DestinationGeneral, "Received shutdown signal")
		cancel()
	}()

	logger.Info(logging.DestinationGeneral, "Starting MCP server", "schedd", scheddName)

	// Run the server
	if err := server.Run(ctx); err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// runDemoMode runs the server with a mini HTCondor setup
func runDemoMode() error {
	// Create logger for demo mode
	logger, err := logging.New(&logging.Config{
		OutputPath: "stdout",
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
	releaseDir := filepath.Dir(filepath.Dir(condorMasterPath))
	log.Printf("Detected HTCondor release directory: %s", releaseDir)

	// Write mini condor configuration
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
	signingKeyPath := filepath.Join(tempDir, "passwords.d", "POOL")
	log.Printf("Will use HTCondor-generated signing key at: %s", signingKeyPath)

	// Get configuration values
	trustDomain, _ := cfg.Get("TRUST_DOMAIN")
	uidDomain, _ := cfg.Get("UID_DOMAIN")
	collectorHost, _ := cfg.Get("COLLECTOR_HOST")

	// Create collector for demo mode
	var collector *htcondor.Collector
	if collectorHost != "" {
		collector = htcondor.NewCollector(collectorHost)
		logger.Info(logging.DestinationCollector, "Created collector for demo mode", "host", collectorHost)
	}

	// Create MCP server
	server, err := mcpserver.NewServer(mcpserver.Config{
		SigningKeyPath: signingKeyPath,
		TrustDomain:    trustDomain,
		UIDDomain:      uidDomain,
		Collector:      collector,
		Logger:         logger,
		Stdin:          os.Stdin,
		Stdout:         os.Stdout,
	})
	if err != nil {
		return fmt.Errorf("failed to create MCP server: %w", err)
	}

	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info(logging.DestinationGeneral, "Received shutdown signal")
		cancel()
	}()

	logger.Info(logging.DestinationGeneral, "Starting MCP server in demo mode")

	// Run the server
	if err := server.Run(ctx); err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// writeMiniCondorConfig writes a minimal HTCondor configuration
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
