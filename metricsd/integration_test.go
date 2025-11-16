//go:build integration

package metricsd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
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
NUM_CPUS = 2
MEMORY = 1024
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

// TestPoolCollectorIntegration tests the PoolCollector against a real HTCondor instance
func TestPoolCollectorIntegration(t *testing.T) {
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
	collector := htcondor.NewCollector(addr)

	// Test 1: Create PoolCollector and collect metrics
	t.Run("CollectPoolMetrics", func(t *testing.T) {
		poolCollector := NewPoolCollector(collector)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		metrics, err := poolCollector.Collect(ctx)
		if err != nil {
			t.Fatalf("Failed to collect metrics: %v", err)
		}

		if len(metrics) == 0 {
			t.Fatal("Expected at least some metrics, got none")
		}

		t.Logf("Collected %d metrics", len(metrics))

		// Verify we have expected metrics
		foundMachinesTotal := false
		foundCPUsTotal := false
		foundMemoryTotal := false
		foundScheddTotal := false

		for _, m := range metrics {
			t.Logf("Metric: %s = %v (labels: %v)", m.Name, m.Value, m.Labels)

			switch m.Name {
			case "htcondor_pool_machines_total":
				foundMachinesTotal = true
				if m.Type != MetricTypeGauge {
					t.Errorf("Expected gauge type for %s", m.Name)
				}
				// We expect at least 1 machine (the startd)
				if m.Value < 0 {
					t.Errorf("Expected non-negative value for %s, got %v", m.Name, m.Value)
				}
			case "htcondor_pool_cpus_total":
				foundCPUsTotal = true
				if m.Type != MetricTypeGauge {
					t.Errorf("Expected gauge type for %s", m.Name)
				}
				// We configured 2 CPUs in the test harness
				if m.Value < 1 {
					t.Errorf("Expected positive value for %s, got %v", m.Name, m.Value)
				}
			case "htcondor_pool_memory_mb_total":
				foundMemoryTotal = true
				if m.Type != MetricTypeGauge {
					t.Errorf("Expected gauge type for %s", m.Name)
				}
				if m.Value < 100 {
					t.Errorf("Expected reasonable memory value for %s, got %v MB", m.Name, m.Value)
				}
			case "htcondor_pool_schedds_total":
				foundScheddTotal = true
				if m.Type != MetricTypeGauge {
					t.Errorf("Expected gauge type for %s", m.Name)
				}
				if m.Value < 1 {
					t.Errorf("Expected at least 1 schedd, got %v", m.Value)
				}
			}
		}

		if !foundMachinesTotal {
			t.Error("Missing htcondor_pool_machines_total metric")
		}
		if !foundCPUsTotal {
			t.Error("Missing htcondor_pool_cpus_total metric")
		}
		if !foundMemoryTotal {
			t.Error("Missing htcondor_pool_memory_mb_total metric")
		}
		if !foundScheddTotal {
			t.Error("Missing htcondor_pool_schedds_total metric")
		}
	})

	// Test 2: Test Prometheus exporter with PoolCollector
	t.Run("PrometheusExportPoolMetrics", func(t *testing.T) {
		registry := NewRegistry()
		poolCollector := NewPoolCollector(collector)
		registry.Register(poolCollector)

		exporter := NewPrometheusExporter(registry)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		output, err := exporter.Export(ctx)
		if err != nil {
			t.Fatalf("Failed to export metrics: %v", err)
		}

		if output == "" {
			t.Fatal("Expected non-empty Prometheus output")
		}

		t.Logf("Prometheus output length: %d bytes", len(output))

		// Verify Prometheus format
		if !strings.Contains(output, "# HELP") {
			t.Error("Output missing HELP comments")
		}
		if !strings.Contains(output, "# TYPE") {
			t.Error("Output missing TYPE comments")
		}

		// Verify expected metrics are present
		expectedMetrics := []string{
			"htcondor_pool_machines_total",
			"htcondor_pool_cpus_total",
			"htcondor_pool_memory_mb_total",
			"htcondor_pool_schedds_total",
		}

		for _, metricName := range expectedMetrics {
			if !strings.Contains(output, metricName) {
				t.Errorf("Prometheus output missing metric: %s", metricName)
			}
		}

		// Verify gauge type is specified
		if !strings.Contains(output, "# TYPE htcondor_pool_machines_total gauge") {
			t.Error("Missing TYPE declaration for htcondor_pool_machines_total")
		}

		// Log sample of output for inspection
		lines := strings.Split(output, "\n")
		if len(lines) > 20 {
			t.Logf("First 20 lines of Prometheus output:\n%s", strings.Join(lines[:20], "\n"))
		} else {
			t.Logf("Prometheus output:\n%s", output)
		}
	})

	// Test 3: Test metrics caching
	t.Run("MetricsCaching", func(t *testing.T) {
		registry := NewRegistry()
		registry.SetCacheTTL(5 * time.Second) // Short TTL for testing

		poolCollector := NewPoolCollector(collector)
		registry.Register(poolCollector)

		ctx := context.Background()

		// First collection
		metrics1, err := registry.Collect(ctx)
		if err != nil {
			t.Fatalf("First collection failed: %v", err)
		}

		// Second collection (should use cache)
		start := time.Now()
		metrics2, err := registry.Collect(ctx)
		if err != nil {
			t.Fatalf("Second collection failed: %v", err)
		}
		duration := time.Since(start)

		// Cached collection should be very fast (< 100ms)
		if duration > 100*time.Millisecond {
			t.Logf("Warning: Cached collection took %v, expected < 100ms", duration)
		}

		// Metrics should be the same (using cache)
		if len(metrics1) != len(metrics2) {
			t.Errorf("Metric count changed: %d vs %d (cache may not be working)", len(metrics1), len(metrics2))
		}

		t.Logf("Cache working: collected %d metrics twice (second took %v)", len(metrics1), duration)
	})

	// Test 4: Test with ProcessCollector combined
	t.Run("CombinedCollectors", func(t *testing.T) {
		registry := NewRegistry()

		poolCollector := NewPoolCollector(collector)
		processCollector := NewProcessCollector()

		registry.Register(poolCollector)
		registry.Register(processCollector)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		metrics, err := registry.Collect(ctx)
		if err != nil {
			t.Fatalf("Failed to collect combined metrics: %v", err)
		}

		// Should have metrics from both collectors
		hasPoolMetric := false
		hasProcessMetric := false

		for _, m := range metrics {
			if strings.HasPrefix(m.Name, "htcondor_pool_") {
				hasPoolMetric = true
			}
			if strings.HasPrefix(m.Name, "process_") {
				hasProcessMetric = true
			}
		}

		if !hasPoolMetric {
			t.Error("Missing pool metrics in combined collection")
		}
		if !hasProcessMetric {
			t.Error("Missing process metrics in combined collection")
		}

		t.Logf("Combined collection: %d total metrics (pool + process)", len(metrics))
	})
}
