package htcondor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/config"
)

// TestingT is an interface that matches the testing.T methods used by the test harness.
// This allows the harness to be used without directly depending on the testing package.
type TestingT interface {
	Helper()
	Skip(...interface{})
	Skipf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	Logf(format string, args ...interface{})
	Log(...interface{})
	TempDir() string
	Cleanup(func())
}

// CondorTestHarness manages a mini HTCondor instance for integration testing
type CondorTestHarness struct {
	tmpDir        string
	configFile    string
	logDir        string
	executeDir    string
	spoolDir      string
	lockDir       string
	masterCmd     *exec.Cmd
	collectorAddr string
	scheddName    string
	t             TestingT
}

// SetupCondorHarness creates and starts a mini HTCondor instance
func SetupCondorHarness(t TestingT) *CondorTestHarness {
	t.Helper()

	// Check if condor_master is available
	masterPath, err := exec.LookPath("condor_master")
	if err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Determine daemon binary directory from condor_master location
	sbinDir := filepath.Dir(masterPath)

	// Determine bin directory for condor_history
	// First try to find condor_history in PATH
	var binDir string
	if historyPath, err := exec.LookPath("condor_history"); err == nil {
		binDir = filepath.Dir(historyPath)
	} else {
		// If not in PATH, assume bin is sibling of sbin
		binDir = filepath.Join(filepath.Dir(sbinDir), "bin")
	}

	// Determine LIBEXEC directory by looking for condor_shared_port
	var libexecDir string
	sharedPortPath, err := exec.LookPath("condor_shared_port")
	if err == nil {
		// Found condor_shared_port, use its parent directory
		libexecDir = filepath.Dir(sharedPortPath)
		t.Logf("Found condor_shared_port at %s, using LIBEXEC=%s", sharedPortPath, libexecDir)
	} else {
		// Not found in PATH, try deriving from condor_master location
		derivedLibexec := filepath.Join(filepath.Dir(sbinDir), "libexec")

		// Check if the derived path exists
		if _, err := os.Stat(filepath.Join(derivedLibexec, "condor_shared_port")); err == nil {
			libexecDir = derivedLibexec
			t.Logf("Using derived LIBEXEC=%s (from condor_master location)", libexecDir)
		} else {
			// Try standard location /usr/libexec/condor
			stdLibexec := "/usr/libexec/condor"
			if _, err := os.Stat(filepath.Join(stdLibexec, "condor_shared_port")); err == nil {
				libexecDir = stdLibexec
				t.Logf("Using standard LIBEXEC=%s", libexecDir)
			}
		}
	}

	// Also check for other required daemons
	requiredDaemons := []string{"condor_collector", "condor_schedd", "condor_negotiator", "condor_startd"}
	for _, daemon := range requiredDaemons {
		if _, err := exec.LookPath(daemon); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", daemon)
		}
	}

	// Create temporary directory structure
	tmpDir := t.TempDir()

	h := &CondorTestHarness{
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

	// Build LIBEXEC line if we found a valid directory
	libexecLine := ""
	if libexecDir != "" {
		libexecLine = fmt.Sprintf("LIBEXEC = %s\n", libexecDir)
	}

	configContent := fmt.Sprintf(`
# Mini HTCondor configuration for integration testing
CONDOR_HOST = 127.0.0.1
COLLECTOR_HOST = $(CONDOR_HOST)

# Daemon binary locations
SBIN = %s
BIN = %s
%s
# Use local directory structure
LOCAL_DIR = %s
LOG = $(LOCAL_DIR)/log
SPOOL = $(LOCAL_DIR)/spool
EXECUTE = $(LOCAL_DIR)/execute
LOCK = $(LOCAL_DIR)/lock

# Daemon list - run collector, schedd, negotiator, and startd
DAEMON_LIST = MASTER, COLLECTOR, SCHEDD, NEGOTIATOR, STARTD

USE_SHARED_PORT = True

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
`, sbinDir, binDir, libexecLine, h.tmpDir, h.scheddName)

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
	if err := h.WaitForDaemons(); err != nil {
		t.Fatalf("Failed to wait for daemons: %v", err)
	}

	return h
}

// WaitForDaemons waits for the HTCondor daemons to start and become responsive
func (h *CondorTestHarness) WaitForDaemons() error {
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

// WaitForStartd waits for the startd daemon to advertise to the collector.
// This is useful because the startd may take longer to start up and advertise
// than the collector and schedd, especially on slower systems.
func (h *CondorTestHarness) WaitForStartd(timeout time.Duration) error {
	// Parse collector address
	addr := h.collectorAddr

	collector := NewCollector(addr)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			h.printStartdLog()
			return fmt.Errorf("timeout waiting for startd to advertise to collector")
		case <-ticker.C:
			// Try to locate the startd
			location, err := collector.LocateDaemon(ctx, "Startd", "")
			if err == nil && location != nil && location.Address != "" {
				h.t.Logf("Startd advertised at: %s", location.Address)
				return nil
			}
			// Keep trying
		}
	}
}

// printCollectorLog prints the collector log contents for debugging
func (h *CondorTestHarness) printCollectorLog() {
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
func (h *CondorTestHarness) printStartdLog() {
	startdLog := filepath.Join(h.logDir, "StartLog")
	data, err := os.ReadFile(startdLog) //nolint:gosec // Test code reading test logs
	if err != nil {
		h.t.Logf("Failed to read StartLog: %v", err)
		return
	}

	h.t.Logf("=== StartLog contents ===\n%s\n=== End StartLog ===", string(data))
}

// PrintScheddLog prints the schedd log contents for debugging
func (h *CondorTestHarness) PrintScheddLog() {
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
func (h *CondorTestHarness) printMasterLog() {
	masterLog := filepath.Join(h.logDir, "MasterLog")
	data, err := os.ReadFile(masterLog) //nolint:gosec // Test code reading test logs
	if err != nil {
		h.t.Logf("Failed to read MasterLog: %v", err)
		return
	}

	h.t.Logf("=== MasterLog contents ===\n%s\n=== End MasterLog ===", string(data))
}

// printShadowLog prints the shadow log contents for debugging
func (h *CondorTestHarness) printShadowLog() {
	shadowLog := filepath.Join(h.logDir, "ShadowLog")
	data, err := os.ReadFile(shadowLog) //nolint:gosec // Test code reading test logs
	if err != nil {
		h.t.Logf("Failed to read ShadowLog: %v", err)
		return
	}

	h.t.Logf("=== ShadowLog contents ===\n%s\n=== End ShadowLog ===", string(data))
}

// printStarterLogs prints all starter log contents for debugging
// Starter logs are dynamically named (StarterLog.slot1, StarterLog.slot2, etc.)
func (h *CondorTestHarness) printStarterLogs() {
	// Find all StarterLog.* files, but skip StarterLog.test
	pattern := filepath.Join(h.logDir, "StarterLog.*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		h.t.Logf("Failed to glob StarterLog files: %v", err)
		return
	}

	if len(matches) == 0 {
		h.t.Log("No StarterLog files found")
		return
	}

	for _, logPath := range matches {
		// Skip StarterLog.test
		if filepath.Base(logPath) == "StarterLog.testing" {
			continue
		}

		data, err := os.ReadFile(logPath) //nolint:gosec // Test code reading test logs
		if err != nil {
			h.t.Logf("Failed to read %s: %v", logPath, err)
			continue
		}

		h.t.Logf("=== %s contents ===\n%s\n=== End %s ===", filepath.Base(logPath), string(data), filepath.Base(logPath))
	}
}

// checkStartdStatus checks if startd has crashed and prints its log
//
//nolint:unused // Test helper function kept for debugging
func (h *CondorTestHarness) checkStartdStatus() {
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
func (h *CondorTestHarness) Shutdown() {
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
func (h *CondorTestHarness) GetCollectorAddr() string {
	return h.collectorAddr
}

// GetConfig returns a Config instance configured for this harness
func (h *CondorTestHarness) GetConfig() (*config.Config, error) {
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

// GetScheddName returns the schedd name for this harness
func (h *CondorTestHarness) GetScheddName() string {
	return h.scheddName
}

// GetSpoolDir returns the spool directory path for this harness
func (h *CondorTestHarness) GetSpoolDir() string {
	return h.spoolDir
}
