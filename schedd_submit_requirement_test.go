//go:build integration

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
)

// TestCommitTransactionWithSubmitRequirement tests that job commit failures
// due to submit requirements return the error reason from the schedd
func TestCommitTransactionWithSubmitRequirement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Set up mini HTCondor with submit requirement
	h := setupCondorHarnessWithConfig(t, getSubmitRequirementConfig())

	// Get schedd connection info
	scheddAddr := getScheddAddressFromHarness(t, h)
	t.Logf("Schedd discovered at: %s", scheddAddr)

	// Create schedd instance
	schedd := NewSchedd(h.scheddName, scheddAddr)

	// Try to submit a job that violates the requirement
	// Request less than 1024 MB of memory
	submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 1
request_memory = 512
output = test.out
error = test.err
log = test.log
queue
`

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Log("Attempting to submit job that violates submit requirement...")
	_, err := schedd.Submit(ctx, submitFile)

	// We expect this to fail
	if err == nil {
		t.Fatal("Expected job submission to fail due to submit requirement, but it succeeded")
	}

	t.Logf("Got expected error: %v", err)

	// Check that the error message contains the reason from the submit requirement
	errMsg := err.Error()

	// The error should contain details about the memory requirement
	if !strings.Contains(errMsg, "512") {
		t.Errorf("Error message should mention the requested memory (512 MB)")
		t.Errorf("Got: %s", errMsg)
	}

	if !strings.Contains(errMsg, "1024") || !strings.Contains(errMsg, "minimum") {
		t.Errorf("Error message should mention the minimum requirement (1024 MB)")
		t.Errorf("Got: %s", errMsg)
	}

	// Verify we got a meaningful error, not just an error code
	if strings.Contains(errMsg, "CommitTransaction failed with error code") &&
		!strings.Contains(errMsg, "minimum") {
		t.Errorf("Got basic error code without detailed reason - ClassAd parsing may have failed")
		t.Errorf("Got: %s", errMsg)
	}

	t.Log("Successfully verified that error message includes submit requirement details!")
}

// getScheddAddressFromHarness queries the collector to get the schedd address
func getScheddAddressFromHarness(t *testing.T, harness *condorTestHarness) string {
	t.Helper()

	// Parse collector address
	collectorAddr := harness.GetCollectorAddr()
	addr := parseCollectorSinfulString(collectorAddr)

	t.Logf("Querying collector at %s for schedd location", addr)

	collector := NewCollector(addr)
	ctx := context.Background()
	scheddAds, err := collector.QueryAds(ctx, "ScheddAd", "")
	if err != nil {
		t.Fatalf("Failed to query collector for schedd ads: %v", err)
	}

	if len(scheddAds) == 0 {
		t.Fatal("No schedd ads found in collector")
	}

	// Extract schedd address from ad
	scheddAd := scheddAds[0]

	// Get MyAddress attribute
	myAddressExpr, ok := scheddAd.Lookup("MyAddress")
	if !ok {
		t.Fatal("ScheddAd missing MyAddress attribute")
	}

	// Evaluate as string
	myAddress := myAddressExpr.String()
	if myAddress == "" {
		t.Fatal("MyAddress evaluated to empty string")
	}

	// Remove quotes if present (ClassAd strings include quotes)
	myAddress = strings.Trim(myAddress, "\"")

	// Parse sinful string to extract host:port
	scheddAddr := parseCollectorSinfulString(myAddress)
	return scheddAddr
}

// getSubmitRequirementConfig returns HTCondor configuration with a submit requirement
func getSubmitRequirementConfig() string {
	return `
# Submit requirement for testing error message parsing
SUBMIT_REQUIREMENT_NAMES = MinimalRequestMemory
SUBMIT_REQUIREMENT_MinimalRequestMemory = (TARGET.RequestMemory >= 1024)
SUBMIT_REQUIREMENT_MinimalRequestMemory_REASON = strcat("Job requested ", TARGET.RequestMemory, " MB, but the minimum is 1024 MB")
`
}

// setupCondorHarnessWithConfig creates a test HTCondor instance with custom configuration
// built into the initial config file before the daemons start
func setupCondorHarnessWithConfig(t *testing.T, additionalConfig string) *condorTestHarness {
	t.Helper()

	// This is based on setupCondorHarness but includes the additional config
	// Check dependencies first
	masterPath, err := exec.LookPath("condor_master")
	if err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	sbinDir := filepath.Dir(masterPath)
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

	// Generate HTCondor configuration WITH the additional config
	h.collectorAddr = "127.0.0.1:0"
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

# Daemon list
DAEMON_LIST = MASTER, COLLECTOR, SCHEDD, NEGOTIATOR, STARTD

USE_SHARED_PORT = False

# Collector configuration
COLLECTOR_NAME = test_collector
COLLECTOR_HOST = 127.0.0.1:0
CONDOR_VIEW_HOST = $(COLLECTOR_HOST)

# Schedd configuration
SCHEDD_NAME = %s
SCHEDD_INTERVAL = 5

# Negotiator configuration
NEGOTIATOR_INTERVAL = 2
NEGOTIATOR_MIN_INTERVAL = 1

# Startd configuration
STARTD_NAME = test_startd@$(FULL_HOSTNAME)
NUM_CPUS = 1
MEMORY = 512
STARTER_ALLOW_RUNAS_OWNER = False
STARTD_ATTRS = HasFileTransfer
HasFileTransfer = True
STARTD_DETECT_GPUS = false

# Security settings
SEC_DEFAULT_AUTHENTICATION = OPTIONAL
SEC_DEFAULT_AUTHENTICATION_METHODS = FS, PASSWORD, IDTOKENS, CLAIMTOBE
SEC_DEFAULT_ENCRYPTION = OPTIONAL
SEC_DEFAULT_INTEGRITY = OPTIONAL
SEC_CLIENT_AUTHENTICATION_METHODS = FS, PASSWORD, IDTOKENS, CLAIMTOBE

ALLOW_READ = *
ALLOW_WRITE = *
ALLOW_NEGOTIATOR = *
ALLOW_ADMINISTRATOR = *
ALLOW_OWNER = *
ALLOW_CLIENT = *

QUEUE_SUPER_USERS = root, condor, $(CONDOR_IDS)
QUEUE_ALL_USERS_TRUSTED = True
SCHEDD.ALLOW_WRITE = *
SCHEDD.ALLOW_ADMINISTRATOR = *

BIND_ALL_INTERFACES = False
NETWORK_INTERFACE = 127.0.0.1

SCHEDD_DEBUG = D_FULLDEBUG D_SECURITY D_SYSCALLS
SCHEDD_LOG = $(LOG)/ScheddLog
MAX_SCHEDD_LOG = 10000000

POLLING_INTERVAL = 5
NEGOTIATOR_INTERVAL = 10
UPDATE_INTERVAL = 5

ENABLE_SOAP = False
ENABLE_WEB_SERVER = False

%s
`, sbinDir, h.tmpDir, h.scheddName, additionalConfig)

	if err := os.WriteFile(h.configFile, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Start condor_master
	ctx := context.Background()
	h.masterCmd = exec.CommandContext(ctx, masterPath, "-f", "-t")
	h.masterCmd.Env = append(os.Environ(),
		"CONDOR_CONFIG="+h.configFile,
		"_CONDOR_LOCAL_DIR="+h.tmpDir,
	)
	h.masterCmd.Dir = h.tmpDir
	h.masterCmd.Stdout = os.Stdout
	h.masterCmd.Stderr = os.Stderr

	if err := h.masterCmd.Start(); err != nil {
		t.Fatalf("Failed to start condor_master: %v", err)
	}

	t.Cleanup(func() {
		h.Shutdown()
	})

	if err := h.waitForDaemons(); err != nil {
		t.Fatalf("Failed to wait for daemons: %v", err)
	}

	return h
}
