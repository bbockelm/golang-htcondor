package htcondor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/config"
)

// condorTestHarness manages a mini HTCondor instance for integration testing
type condorTestHarness struct {
	tmpDir        string
	configFile    string
	logDir        string
	executeDir    string
	spoolDir      string
	lockDir       string
	masterCmd     *exec.Cmd
	collectorAddr string
	scheddName    string
	t             *testing.T
}

// setupCondorHarness creates and starts a mini HTCondor instance
func setupCondorHarness(t *testing.T) *condorTestHarness {
	t.Helper()

	// Check if condor_master is available
	masterPath, err := exec.LookPath("condor_master")
	if err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Determine daemon binary directory from condor_master location
	sbinDir := filepath.Dir(masterPath)

	// Also check for other required daemons
	requiredDaemons := []string{"condor_collector", "condor_schedd", "condor_negotiator", "condor_startd"}
	for _, daemon := range requiredDaemons {
		if _, err := exec.LookPath(daemon); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", daemon)
		}
	}

	// Create temporary directory structure
	tmpDir := t.TempDir()

	h := &condorTestHarness{
		tmpDir:     tmpDir,
		configFile: filepath.Join(tmpDir, "condor_config"),
		logDir:     filepath.Join(tmpDir, "log"),
		executeDir: filepath.Join(tmpDir, "execute"),
		spoolDir:   filepath.Join(tmpDir, "spool"),
		lockDir:    filepath.Join(tmpDir, "lock"),
		t:          t,
	}

	// Create directories
	for _, dir := range []string{h.logDir, h.executeDir, h.spoolDir, h.lockDir} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}

	// Generate HTCondor configuration
	h.collectorAddr = "127.0.0.1:0" // Use dynamic port
	h.scheddName = fmt.Sprintf("test_schedd_%d", os.Getpid())

	configContent := fmt.Sprintf(`
# Mini HTCondor configuration for integration testing
CONDOR_HOST = 127.0.0.1
COLLECTOR_HOST = $(CONDOR_HOST)

# Daemon binary locations
SBIN = %s

# Use local directory structure
LOCAL_DIR = %s
LOG = $(LOCAL_DIR)/log
SPOOL = $(LOCAL_DIR)/spool
EXECUTE = $(LOCAL_DIR)/execute
LOCK = $(LOCAL_DIR)/lock

# Daemon list - run collector, schedd, negotiator, and startd
DAEMON_LIST = MASTER, COLLECTOR, SCHEDD, NEGOTIATOR, STARTD

# Disable shared port for testing to avoid complexity
USE_SHARED_PORT = False

# Collector configuration
COLLECTOR_NAME = test_collector
COLLECTOR_HOST = 127.0.0.1:0
CONDOR_VIEW_HOST = $(COLLECTOR_HOST)

# Schedd configuration
SCHEDD_NAME = %s
SCHEDD_INTERVAL = 5

# Negotiator configuration - run frequently for testing
NEGOTIATOR_INTERVAL = 2
NEGOTIATOR_MIN_INTERVAL = 1

# Startd configuration
STARTD_NAME = test_startd@$(FULL_HOSTNAME)
NUM_CPUS = 1
MEMORY = 512
STARTER_ALLOW_RUNAS_OWNER = False
STARTD_ATTRS = HasFileTransfer

# Enable file transfer capability
HasFileTransfer = True

# Disable GPU detection entirely
STARTD_DETECT_GPUS = false

# Security settings - permissive for testing
SEC_DEFAULT_AUTHENTICATION = OPTIONAL
SEC_DEFAULT_AUTHENTICATION_METHODS = FS, PASSWORD, IDTOKENS, CLAIMTOBE
SEC_DEFAULT_ENCRYPTION = OPTIONAL
SEC_DEFAULT_INTEGRITY = OPTIONAL
SEC_CLIENT_AUTHENTICATION_METHODS = FS, PASSWORD, IDTOKENS, CLAIMTOBE

# Allow all operations for testing
ALLOW_READ = *
ALLOW_WRITE = *
ALLOW_NEGOTIATOR = *
ALLOW_ADMINISTRATOR = *
ALLOW_OWNER = *
ALLOW_CLIENT = *

# Specifically allow queue management operations for testing
QUEUE_SUPER_USERS = root, condor, $(CONDOR_IDS)
QUEUE_ALL_USERS_TRUSTED = True
SCHEDD.ALLOW_WRITE = *
SCHEDD.ALLOW_ADMINISTRATOR = *

# Network settings
BIND_ALL_INTERFACES = False
NETWORK_INTERFACE = 127.0.0.1

	# Logging configuration
	SCHEDD_DEBUG = D_FULLDEBUG D_SECURITY D_SYSCALLS
	SCHEDD_LOG = $(LOG)/ScheddLog
	MAX_SCHEDD_LOG = 10000000

# Fast polling for testing
POLLING_INTERVAL = 5
NEGOTIATOR_INTERVAL = 10
UPDATE_INTERVAL = 5

# Disable unwanted features for testing
ENABLE_SOAP = False
ENABLE_WEB_SERVER = False
`, sbinDir, h.tmpDir, h.scheddName)

	if err := os.WriteFile(h.configFile, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Start condor_master
	ctx := context.Background()
	h.masterCmd = exec.CommandContext(ctx, masterPath, "-f", "-t") //nolint:gosec // Test code launching condor_master
	h.masterCmd.Env = append(os.Environ(),
		"CONDOR_CONFIG="+h.configFile,
		"_CONDOR_LOCAL_DIR="+h.tmpDir,
	)
	h.masterCmd.Dir = h.tmpDir

	// Capture output for debugging
	h.masterCmd.Stdout = os.Stdout
	h.masterCmd.Stderr = os.Stderr

	if err := h.masterCmd.Start(); err != nil {
		t.Fatalf("Failed to start condor_master: %v", err)
	}

	// Register cleanup
	t.Cleanup(func() {
		h.Shutdown()
	})

	// Wait for daemons to start and discover collector address
	if err := h.waitForDaemons(); err != nil {
		t.Fatalf("Failed to wait for daemons: %v", err)
	}

	return h
}

// waitForDaemons waits for the HTCondor daemons to start and become responsive
func (h *condorTestHarness) waitForDaemons() error {
	// Wait for collector to write its address file
	addressFile := filepath.Join(h.logDir, ".collector_address")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// On timeout, print collector log for debugging
			h.printCollectorLog()
			return fmt.Errorf("timeout waiting for collector to start")
		case <-ticker.C:
			// Check if address file exists
			if data, err := os.ReadFile(addressFile); err == nil { //nolint:gosec // Test code reading test address file
				// The address file may contain multiple lines; take the first non-empty line
				lines := strings.Split(string(data), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "$") {
						h.collectorAddr = line
						break
					}
				}

				if h.collectorAddr == "" {
					continue // Keep waiting
				}

				// Check for invalid address (null)
				if strings.Contains(h.collectorAddr, "(null)") {
					h.printCollectorLog()
					return fmt.Errorf("collector address file contains '(null)' - daemon failed to start")
				}

				h.t.Logf("Collector started at: %s", h.collectorAddr)

				// Give a bit more time for other daemons to start
				time.Sleep(2 * time.Second)

				return nil
			}
		}
	}
}

// printCollectorLog prints the collector log contents for debugging
func (h *condorTestHarness) printCollectorLog() {
	collectorLog := filepath.Join(h.logDir, "CollectorLog")
	data, err := os.ReadFile(collectorLog) //nolint:gosec // Test code reading test logs
	if err != nil {
		h.t.Logf("Failed to read CollectorLog: %v", err)
		return
	}

	h.t.Logf("=== CollectorLog contents ===\n%s\n=== End CollectorLog ===", string(data))
}

// printStartdLog prints the startd log contents for debugging
//
//nolint:unused // Test helper function kept for debugging
func (h *condorTestHarness) printStartdLog() {
	startdLog := filepath.Join(h.logDir, "StartLog")
	data, err := os.ReadFile(startdLog) //nolint:gosec // Test code reading test logs
	if err != nil {
		h.t.Logf("Failed to read StartLog: %v", err)
		return
	}

	h.t.Logf("=== StartLog contents ===\n%s\n=== End StartLog ===", string(data))
}

// printScheddLog prints the schedd log contents for debugging
func (h *condorTestHarness) printScheddLog() {
	scheddLog := filepath.Join(h.logDir, "ScheddLog")
	data, err := os.ReadFile(scheddLog) //nolint:gosec // Test code reading test logs
	if err != nil {
		h.t.Logf("Failed to read ScheddLog: %v", err)
		return
	}

	h.t.Logf("=== ScheddLog contents ===\n%s\n=== End ScheddLog ===", string(data))
}

// printMasterLog prints the master log contents for debugging
//
//nolint:unused // Test helper function kept for debugging
func (h *condorTestHarness) printMasterLog() {
	masterLog := filepath.Join(h.logDir, "MasterLog")
	data, err := os.ReadFile(masterLog) //nolint:gosec // Test code reading test logs
	if err != nil {
		h.t.Logf("Failed to read MasterLog: %v", err)
		return
	}

	h.t.Logf("=== MasterLog contents ===\n%s\n=== End MasterLog ===", string(data))
}

// checkStartdStatus checks if startd has crashed and prints its log
//
//nolint:unused // Test helper function kept for debugging
func (h *condorTestHarness) checkStartdStatus() {
	startdLog := filepath.Join(h.logDir, "StartLog")
	if data, err := os.ReadFile(startdLog); err == nil { //nolint:gosec // Test code reading test logs
		logContent := string(data)
		// Check for common error patterns
		if strings.Contains(logContent, "ERROR") || strings.Contains(logContent, "FATAL") ||
			strings.Contains(logContent, "exiting") || strings.Contains(logContent, "Failed") {
			h.t.Log("Detected startd errors, printing log:")
			h.printStartdLog()
		}
	}
}

// Shutdown stops the HTCondor instance
func (h *condorTestHarness) Shutdown() {
	if h.masterCmd != nil && h.masterCmd.Process != nil {
		h.t.Log("Shutting down HTCondor master")

		// Try graceful shutdown first
		if err := h.masterCmd.Process.Signal(os.Interrupt); err != nil {
			h.t.Logf("Failed to send interrupt to master: %v", err)
		}

		// Wait a bit for graceful shutdown
		done := make(chan error, 1)
		go func() {
			done <- h.masterCmd.Wait()
		}()

		select {
		case <-time.After(5 * time.Second):
			// Force kill if graceful shutdown times out
			if err := h.masterCmd.Process.Kill(); err != nil {
				h.t.Logf("Failed to kill master: %v", err)
			}
			<-done // Wait for process to finish
		case <-done:
			// Graceful shutdown succeeded
		}
	}
}

// GetCollectorAddr returns the collector address
func (h *condorTestHarness) GetCollectorAddr() string {
	return h.collectorAddr
}

// GetConfig returns a Config instance configured for this harness
func (h *condorTestHarness) GetConfig() (*config.Config, error) {
	f, err := os.Open(h.configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer func() { _ = f.Close() }()

	cfg, err := config.NewFromReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	return cfg, nil
}

// TestCollectorQueryIntegration tests collector queries against a real HTCondor instance
//
//nolint:gocyclo // Complex test with multiple subtests is acceptable
func TestCollectorQueryIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup mini HTCondor instance
	harness := setupCondorHarness(t)

	t.Logf("HTCondor instance started with collector at: %s", harness.GetCollectorAddr())

	// Parse collector address - HTCondor uses "sinful strings" like <127.0.0.1:9618?addrs=...>
	// Extract the host:port from within the angle brackets
	addr := harness.GetCollectorAddr()
	addr = strings.TrimPrefix(addr, "<")
	if idx := strings.Index(addr, "?"); idx > 0 {
		addr = addr[:idx] // Remove query parameters
	}
	addr = strings.TrimSuffix(addr, ">")

	// Create a Collector client
	collector := NewCollector(addr)

	// Test 1: Query for collector daemon ad
	t.Run("QueryCollectorAd", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ads, err := collector.QueryAds(ctx, "Collector", "")
		if err != nil {
			t.Fatalf("Failed to query collector: %v", err)
		}

		if len(ads) == 0 {
			t.Fatal("Expected at least one collector ad, got none")
		}

		t.Logf("Found %d collector ad(s)", len(ads))

		// Verify the collector ad has expected attributes
		collectorAd := ads[0]
		if name := collectorAd.EvaluateAttr("Name"); name.IsError() {
			t.Error("Collector ad missing Name attribute")
		} else {
			t.Logf("Collector Name: %v", name)
		}

		if myType := collectorAd.EvaluateAttr("MyType"); myType.IsError() {
			t.Error("Collector ad missing MyType attribute")
		} else if str, _ := myType.StringValue(); str != "Collector" {
			t.Errorf("Expected MyType='Collector', got '%s'", str)
		}
	})

	// Test 2: Query for schedd daemon ads
	t.Run("QueryScheddAd", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ads, err := collector.QueryAds(ctx, "Schedd", "")
		if err != nil {
			t.Fatalf("Failed to query schedd: %v", err)
		}

		if len(ads) == 0 {
			t.Fatal("Expected at least one schedd ad, got none")
		}

		t.Logf("Found %d schedd ad(s)", len(ads))

		scheddAd := ads[0]
		if name := scheddAd.EvaluateAttr("Name"); name.IsError() {
			t.Error("Schedd ad missing Name attribute")
		} else {
			t.Logf("Schedd Name: %v", name)
		}

		if myType := scheddAd.EvaluateAttr("MyType"); myType.IsError() {
			t.Error("Schedd ad missing MyType attribute")
		} else if str, _ := myType.StringValue(); str != "Scheduler" {
			t.Errorf("Expected MyType='Scheduler', got '%s'", str)
		}
	})

	// Test 3: Query for startd daemon ads
	t.Run("QueryStartdAd", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ads, err := collector.QueryAds(ctx, "Startd", "")
		if err != nil {
			t.Fatalf("Failed to query startd: %v", err)
		}

		if len(ads) == 0 {
			t.Skip("No startd ads found - startd may not have started successfully")
		}

		t.Logf("Found %d startd ad(s)", len(ads))

		startdAd := ads[0]
		if name := startdAd.EvaluateAttr("Name"); name.IsError() {
			t.Error("Startd ad missing Name attribute")
		} else {
			t.Logf("Startd Name: %v", name)
		}

		if myType := startdAd.EvaluateAttr("MyType"); myType.IsError() {
			t.Error("Startd ad missing MyType attribute")
		} else if str, _ := myType.StringValue(); str != "Machine" {
			t.Errorf("Expected MyType='Machine', got '%s'", str)
		}

		// Check for resource attributes
		if cpus := startdAd.EvaluateAttr("Cpus"); cpus.IsError() {
			t.Error("Startd ad missing Cpus attribute")
		} else {
			t.Logf("Startd Cpus: %v", cpus)
		}

		if memory := startdAd.EvaluateAttr("Memory"); memory.IsError() {
			t.Error("Startd ad missing Memory attribute")
		} else {
			t.Logf("Startd Memory: %v", memory)
		}
	})

	// Test 4: Query with constraint
	t.Run("QueryWithConstraint", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Query for machines with at least 1 CPU
		ads, err := collector.QueryAds(ctx, "Startd", "Cpus >= 1")
		if err != nil {
			t.Fatalf("Failed to query with constraint: %v", err)
		}

		if len(ads) == 0 {
			t.Skip("No startd ads found - startd may not have started successfully")
		}

		t.Logf("Found %d machine(s) matching constraint", len(ads))

		// Verify constraint is satisfied
		for i, ad := range ads {
			if cpus := ad.EvaluateAttr("Cpus"); cpus.IsError() {
				t.Errorf("Ad %d missing Cpus attribute", i)
			} else if val, err := cpus.IntValue(); err != nil || val < 1 {
				t.Errorf("Ad %d does not satisfy constraint: Cpus = %v", i, val)
			}
		}
	})

	// Test 5: Query non-existent daemon type (should return error)
	t.Run("QueryNonExistentType", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ads, err := collector.QueryAds(ctx, "NonExistentDaemon", "")
		if err == nil {
			t.Errorf("Expected error for non-existent daemon type, but query succeeded with %d ads", len(ads))
			// Print the unexpected ad(s) for debugging
			for i, ad := range ads {
				t.Logf("Unexpected ad %d:", i)
				if myType := ad.EvaluateAttr("MyType"); !myType.IsError() {
					t.Logf("  MyType: %v", myType)
				}
				if name := ad.EvaluateAttr("Name"); !name.IsError() {
					t.Logf("  Name: %v", name)
				}
			}
		} else {
			t.Logf("Got expected error: %v", err)
		}
	})
}
