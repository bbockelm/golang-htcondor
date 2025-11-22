//go:build integration

//nolint:errcheck,noctx,gosec,errorlint,govet // Integration test file with acceptable test patterns
package httpserver

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestHTTPAPIIntegration tests the full lifecycle of job submission via HTTP API in demo mode
func TestHTTPAPIIntegration(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Create temporary directory for mini condor
	tempDir, err := os.MkdirTemp("", "htcondor-http-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create secure socket directory in /tmp to avoid path length issues
	socketDir, err := os.MkdirTemp("/tmp", "htc_sock_*")
	if err != nil {
		t.Fatalf("Failed to create socket directory: %v", err)
	}
	defer os.RemoveAll(socketDir)

	t.Logf("Using temporary directory: %s", tempDir)
	t.Logf("Using socket directory: %s", socketDir)

	// Generate signing key for demo authentication in passwords.d directory
	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		t.Fatalf("Failed to create passwords.d directory: %v", err)
	}
	signingKeyPath := filepath.Join(passwordsDir, "POOL")
	// Generate a simple signing key for testing
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(signingKeyPath, key, 0600); err != nil {
		t.Fatalf("Failed to write signing key: %v", err)
	}

	trustDomain := "test.htcondor.org"

	// Write mini condor configuration
	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDir, socketDir, passwordsDir, trustDomain, t); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Set CONDOR_CONFIG environment variable and reload configuration
	// This ensures we don't inherit rate limits from other tests
	t.Setenv("CONDOR_CONFIG", configFile)
	htcondor.ReloadDefaultConfig()

	// Start condor_master
	t.Log("Starting condor_master...")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	condorMaster, err := startCondorMaster(ctx, configFile, tempDir)
	if err != nil {
		t.Fatalf("Failed to start condor_master: %v", err)
	}
	defer stopCondorMaster(condorMaster, t)

	// Wait for condor to be ready
	t.Log("Waiting for HTCondor to be ready...")
	if err := waitForCondor(tempDir, 60*time.Second, t); err != nil {
		t.Fatalf("Condor failed to start: %v", err)
	}
	t.Log("HTCondor is ready!")

	// Find the actual schedd address
	scheddAddr, err := getScheddAddress(tempDir, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to get schedd address: %v", err)
	}
	t.Logf("Using schedd address: %s", scheddAddr)

	// Use dynamic port for HTTP server
	serverAddr := "127.0.0.1:0"

	// Create HTTP server with collector for collector tests
	collector := htcondor.NewCollector(scheddAddr) // Use schedd address (shared port)

	// Create a directory for the DB to avoid any interference from Condor
	dbDir := filepath.Join(tempDir, "db")
	if err := os.Mkdir(dbDir, 0700); err != nil {
		t.Fatalf("Failed to create db directory: %v", err)
	}
	// Set OAuth2DBPath to tempDir to avoid permission issues
	oauth2DBPath := filepath.Join(dbDir, "sessions.db")

	server, err := NewServer(Config{
		ListenAddr:     serverAddr,
		ScheddName:     "local",
		ScheddAddr:     scheddAddr,
		UserHeader:     "X-Test-User",
		SigningKeyPath: signingKeyPath,
		TrustDomain:    trustDomain,
		UIDDomain:      "test.htcondor.org",
		Collector:      collector,
		OAuth2DBPath:   oauth2DBPath,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	serverErrChan := make(chan error, 1)
	go func() {
		serverErrChan <- server.Start()
	}()

	// Wait for server to start
	time.Sleep(500 * time.Millisecond)

	// Get actual server address using GetAddr() method
	actualAddr := server.GetAddr()
	if actualAddr == "" {
		t.Fatalf("Failed to get server address")
	}

	baseURL := fmt.Sprintf("http://%s", actualAddr)
	t.Logf("HTTP server listening on: %s", baseURL)

	// Wait for server to be fully ready
	if err := waitForServer(baseURL, 10*time.Second); err != nil {
		t.Fatalf("Server failed to start: %v", err)
	}
	t.Logf("Server is ready on %s", baseURL)

	// Ensure server is stopped at the end
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			t.Logf("Warning: server shutdown error: %v", err)
		}
	}()

	// Create HTTP client
	client := &http.Client{Timeout: 30 * time.Second}

	// Test user for authentication
	testUser := "testuser"

	// Step 1: Submit a job via HTTP
	t.Log("Step 1: Submitting job via HTTP...")
	submitFile := `executable = /bin/bash
arguments = script.sh
transfer_input_files = input.txt, script.sh
transfer_output_files = output.txt
transfer_executable = NO
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
queue`

	clusterID, jobID := submitJob(t, client, baseURL, testUser, submitFile)
	t.Logf("Job submitted: ClusterID=%d, JobID=%s", clusterID, jobID)

	// Step 2: Create and upload input tarball
	t.Log("Step 2: Creating and uploading input tarball...")
	inputTar := createInputTarball(t, map[string]string{
		"input.txt": "This is test input data\n",
		"script.sh": "#!/bin/bash\necho 'Hello from HTCondor!' > output.txt\necho 'Test successful' >> output.txt\n",
	})
	uploadInputTarball(t, client, baseURL, testUser, jobID, inputTar)
	t.Log("Input tarball uploaded successfully")

	// Step 3: Poll job status until complete
	t.Log("Step 3: Polling job status until complete...")
	waitForJobCompletion(t, client, baseURL, testUser, jobID, tempDir, 60*time.Second)
	t.Log("Job completed successfully!")

	// Step 4: Download output tarball
	t.Log("Step 4: Downloading output tarball...")
	outputTar := downloadOutputTarball(t, client, baseURL, testUser, jobID)
	t.Log("Output tarball downloaded successfully")

	// Step 5: Verify the results
	t.Log("Step 5: Verifying results...")
	outputFiles := extractTarball(t, outputTar)

	// Check if output.txt exists
	outputContent, ok := outputFiles["output.txt"]
	if !ok {
		t.Fatalf("output.txt not found in output tarball. Available files: %v", getFileNames(outputFiles))
	}

	// Verify content
	expectedContent := "Hello from HTCondor!\nTest successful\n"
	if outputContent != expectedContent {
		t.Errorf("Output content mismatch.\nExpected:\n%s\nGot:\n%s", expectedContent, outputContent)
	}

	t.Log("✅ Integration test passed! Full job lifecycle completed successfully.")
}

// submitJob submits a job via HTTP POST and returns cluster ID and job ID
func submitJob(t *testing.T, client *http.Client, baseURL, user, submitFile string) (int, string) {
	t.Helper()

	reqBody, _ := json.Marshal(map[string]string{
		"submit_file": submitFile,
	})

	req, err := http.NewRequest("POST", baseURL+"/api/v1/jobs", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-User", user)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to submit job: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Job submission failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		ClusterID int      `json:"cluster_id"`
		JobIDs    []string `json:"job_ids"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(result.JobIDs) == 0 {
		t.Fatal("No job IDs returned")
	}

	return result.ClusterID, result.JobIDs[0]
}

// createInputTarball creates a tarball with the given files
func createInputTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	defer tw.Close()

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if name == "script.sh" {
			hdr.Mode = 0755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("Failed to write tar header: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("Failed to write tar content: %v", err)
		}
	}

	return buf.Bytes()
}

// createSimpleInputTarball creates a tarball with a simple dummy input file
func createSimpleInputTarball(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Add a simple input file
	content := []byte("dummy input file for testing\n")
	hdr := &tar.Header{
		Name: "input.txt",
		Mode: 0644,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("Failed to write tar header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("Failed to write tar content: %v", err)
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("Failed to close tar writer: %v", err)
	}

	return buf.Bytes()
}

// uploadInputTarball uploads the input tarball via HTTP PUT
func uploadInputTarball(t *testing.T, client *http.Client, baseURL, user, jobID string, tarData []byte) {
	t.Helper()

	req, err := http.NewRequest("PUT", baseURL+"/api/v1/jobs/"+jobID+"/input", bytes.NewReader(tarData))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-tar")
	req.Header.Set("X-Test-User", user)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to upload input: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Input upload failed with status %d: %s", resp.StatusCode, string(body))
	}
}

// waitForJobCompletion polls the job status until it completes or times out
func waitForJobCompletion(t *testing.T, client *http.Client, baseURL, user, jobID, localDir string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	pollInterval := 2 * time.Second

	for time.Now().Before(deadline) {
		req, err := http.NewRequest("GET", baseURL+"/api/v1/jobs/"+jobID, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("X-Test-User", user)

		resp, err := client.Do(req)
		if err != nil {
			t.Logf("Warning: request failed: %v", err)
			time.Sleep(pollInterval)
			continue
		}

		var jobAd map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&jobAd); err != nil {
			resp.Body.Close()
			t.Logf("Warning: failed to decode response: %v", err)
			time.Sleep(pollInterval)
			continue
		}
		resp.Body.Close()

		// Check JobStatus
		// 1 = Idle, 2 = Running, 3 = Removed, 4 = Completed, 5 = Held, 6 = Transferring Output, 7 = Suspended
		jobStatus, ok := jobAd["JobStatus"].(float64)
		if !ok {
			t.Logf("Warning: JobStatus not found or not a number")
			time.Sleep(pollInterval)
			continue
		}

		t.Logf("Job status: %.0f (1=Idle, 2=Running, 4=Completed, 5=Held)", jobStatus)

		if jobStatus == 4 { // Completed
			return
		}

		if jobStatus == 5 { // Held
			holdReason := "unknown"
			if hr, ok := jobAd["HoldReason"].(string); ok {
				holdReason = hr
			}
			// Ignore spooling holds - these are normal and will be released automatically
			if holdReason != "Spooling input data files" {
				t.Fatalf("Job was held. Reason: %s", holdReason)
			}
			t.Logf("Job is in spooling hold (normal), waiting for release...")
		}

		time.Sleep(pollInterval)
	}

	t.Logf("Timeout waiting for job completion after %v", timeout)
	printHTCondorLogs(localDir, t)
	t.Fatalf("Timeout waiting for job completion after %v", timeout)
}

// downloadOutputTarball downloads the output tarball via HTTP GET
func downloadOutputTarball(t *testing.T, client *http.Client, baseURL, user, jobID string) []byte {
	t.Helper()

	req, err := http.NewRequest("GET", baseURL+"/api/v1/jobs/"+jobID+"/output", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Test-User", user)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to download output: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Output download failed with status %d: %s", resp.StatusCode, string(body))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	return data
}

// extractTarball extracts files from a tarball and returns them as a map
func extractTarball(t *testing.T, tarData []byte) map[string]string {
	t.Helper()

	files := make(map[string]string)
	tr := tar.NewReader(bytes.NewReader(tarData))

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read tar: %v", err)
		}

		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("Failed to read file content: %v", err)
		}

		files[hdr.Name] = string(content)
	}

	return files
}

// getFileNames returns a sorted list of filenames from the files map
func getFileNames(files map[string]string) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	return names
}

// writeMiniCondorConfig writes a minimal HTCondor configuration
func writeMiniCondorConfig(configFile, localDir, socketDir, passwordsDir, trustDomain string, t *testing.T) error {
	// Determine LIBEXEC directory by looking for condor_shared_port
	var libexecDir string
	sharedPortPath, err := exec.LookPath("condor_shared_port")
	if err == nil {
		// Found condor_shared_port, use its parent directory
		libexecDir = filepath.Dir(sharedPortPath)
		t.Logf("Found condor_shared_port at %s, using LIBEXEC=%s", sharedPortPath, libexecDir)
	} else {
		// Not found in PATH, try deriving from condor_master location
		masterPath, _ := exec.LookPath("condor_master")
		if masterPath != "" {
			sbinDir := filepath.Dir(masterPath)
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
	}

	// Compute SBIN path from condor_master location
	var sbinDir string
	if masterPath, err := exec.LookPath("condor_master"); err == nil {
		sbinDir = filepath.Dir(masterPath)
	}

	// Build LIBEXEC line if we found a valid directory
	libexecLine := ""
	if libexecDir != "" {
		libexecLine = fmt.Sprintf("LIBEXEC = %s\n", libexecDir)
	}

	// Build SBIN line if we found it
	sbinLine := ""
	if sbinDir != "" {
		sbinLine = fmt.Sprintf("SBIN = %s\n", sbinDir)
	}

	config := fmt.Sprintf(`# Mini HTCondor Configuration for HTTP API Integration Test
CONDOR_HOST = 127.0.0.1

# Use local directory structure
LOCAL_DIR = %s
LOG = $(LOCAL_DIR)/log
SPOOL = $(LOCAL_DIR)/spool
EXECUTE = $(LOCAL_DIR)/execute

# Set paths for HTCondor binaries
%s%s
# Collector configuration
COLLECTOR_HOST = 127.0.0.1:0

# Network settings
BIND_ALL_INTERFACES = False
NETWORK_INTERFACE = 127.0.0.1

# Enable shared port with proper configuration
USE_SHARED_PORT = True
SHARED_PORT_DEBUG = D_FULLDEBUG
DAEMON_SOCKET_DIR = %s

# Security settings - enable all authentication methods
SEC_DEFAULT_AUTHENTICATION = OPTIONAL
SEC_DEFAULT_AUTHENTICATION_METHODS = FS,TOKEN
SEC_DEFAULT_ENCRYPTION = OPTIONAL
SEC_DEFAULT_INTEGRITY = OPTIONAL
SEC_CLIENT_AUTHENTICATION_METHODS = FS,TOKEN

# Token configuration
SEC_TOKEN_DIRECTORY = %s
TRUST_DOMAIN = %s

# Allow all access for testing
ALLOW_READ = *
ALLOW_WRITE = *
ALLOW_NEGOTIATOR = *
ALLOW_ADMINISTRATOR = *
ALLOW_OWNER = *
ALLOW_CLIENT = *

# Schedd configuration
DAEMON_LIST = MASTER, COLLECTOR, SHARED_PORT, SCHEDD, NEGOTIATOR, STARTD
SCHEDD_NAME = test_schedd
SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address
MAX_SCHEDD_LOG = 10000000
SCHEDD_DEBUG = D_FULLDEBUG D_SECURITY

# Collector configuration
COLLECTOR_ADDRESS_FILE = $(LOG)/.collector_address
MAX_COLLECTOR_LOG = 10000000
COLLECTOR_DEBUG = D_FULLDEBUG D_SECURITY

# Shared port logging
SHARED_PORT_DEBUG = D_FULLDEBUG D_SECURITY D_NETWORK:2 D_COMMAND
MAX_SHARED_PORT_LOG = 10000000

# Master logging
MAX_MASTER_LOG = 10000000
MASTER_DEBUG = D_FULLDEBUG D_SECURITY

# Startd logging
MAX_STARTD_LOG = 10000000
STARTD_DEBUG = D_FULLDEBUG D_SECURITY

# Negotiator logging
MAX_NEGOTIATOR_LOG = 10000000
NEGOTIATOR_DEBUG = D_FULLDEBUG

# Use only local system resources
START = TRUE
SUSPEND = FALSE
PREEMPT = FALSE
KILL = FALSE

# Enable file transfer
ENABLE_FILE_TRANSFER = TRUE
ENABLE_HTTP_PUBLIC_FILES = TRUE

# Keep jobs in queue after completion for output retrieval
SYSTEM_PERIODIC_REMOVE = (JobStatus == 4) && ((time() - CompletionDate) > 3600)

# Reduce resource requirements for testing
NUM_CPUS = 2
MEMORY = 2048

# Run jobs quickly in test mode
SCHEDD_INTERVAL = 2
NEGOTIATOR_INTERVAL = 3
STARTER_UPDATE_INTERVAL = 5

# Disable unwanted features for testing
ENABLE_SOAP = False
ENABLE_WEB_SERVER = False
`, localDir, sbinLine, libexecLine, socketDir, passwordsDir, trustDomain)
	return os.WriteFile(configFile, []byte(config), 0644)
}

// startCondorMaster starts the condor_master process
func startCondorMaster(ctx context.Context, configFile, localDir string) (*exec.Cmd, error) {
	condorMasterPath, err := exec.LookPath("condor_master")
	if err != nil {
		return nil, fmt.Errorf("condor_master not found in PATH: %w", err)
	}

	// Create log directory
	logDir := filepath.Join(localDir, "log")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Create spool and execute directories
	spoolDir := filepath.Join(localDir, "spool")
	if err := os.MkdirAll(spoolDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create spool directory: %w", err)
	}

	executeDir := filepath.Join(localDir, "execute")
	if err := os.MkdirAll(executeDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create execute directory: %w", err)
	}

	cmd := exec.CommandContext(ctx, condorMasterPath, "-f")
	cmd.Env = append(os.Environ(),
		"CONDOR_CONFIG="+configFile,
		"_CONDOR_LOCAL_DIR="+localDir,
	)
	// Redirect output for debugging
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start condor_master: %w", err)
	}

	return cmd, nil
}

// stopCondorMaster gracefully stops condor_master
func stopCondorMaster(cmd *exec.Cmd, t *testing.T) {
	if cmd == nil || cmd.Process == nil {
		return
	}

	t.Log("Stopping condor_master...")
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Logf("Warning: failed to send interrupt: %v", err)
		cmd.Process.Kill()
		return
	}

	// Wait for process to exit with timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(10 * time.Second):
		t.Log("condor_master did not stop gracefully, forcing kill")
		cmd.Process.Kill()
		<-done
	case err := <-done:
		if err != nil {
			t.Logf("condor_master exited with error: %v", err)
		}
	}
}

// waitForCondor waits for HTCondor to be ready by checking address files
func waitForCondor(localDir string, timeout time.Duration, t *testing.T) error {
	collectorAddressFile := filepath.Join(localDir, "log", ".collector_address")
	scheddAddressFile := filepath.Join(localDir, "log", ".schedd_address")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	collectorReady := false
	scheddReady := false

	for {
		select {
		case <-ctx.Done():
			// List files in log directory for debugging
			if entries, err := os.ReadDir(filepath.Join(localDir, "log")); err == nil {
				t.Logf("Files in log directory:")
				for _, entry := range entries {
					t.Logf("  %s", entry.Name())
				}
			}
			printHTCondorLogs(localDir, t)

			if !collectorReady {
				return fmt.Errorf("timeout waiting for collector to start")
			}
			if !scheddReady {
				return fmt.Errorf("timeout waiting for schedd to start")
			}
			return fmt.Errorf("timeout waiting for HTCondor daemons to start")

		case <-ticker.C:
			// Check collector if not ready
			if !collectorReady {
				if data, err := os.ReadFile(collectorAddressFile); err == nil {
					content := strings.TrimSpace(string(data))
					if content != "" && !strings.Contains(content, "(null)") {
						collectorReady = true
						t.Logf("✅ Collector started at: %s", content)
					} else if strings.Contains(content, "(null)") {
						printHTCondorLogs(localDir, t)
						return fmt.Errorf("collector address file contains '(null)' - daemon failed to start")
					}
				}
			}

			// Check schedd if not ready
			if !scheddReady {
				if data, err := os.ReadFile(scheddAddressFile); err == nil {
					content := strings.TrimSpace(string(data))
					if content != "" && !strings.Contains(content, "(null)") {
						scheddReady = true
						t.Logf("✅ Schedd started (address file present)")
					} else if strings.Contains(content, "(null)") {
						printHTCondorLogs(localDir, t)
						return fmt.Errorf("schedd address file contains '(null)' - daemon failed to start")
					}
				}
			}

			// If both are ready, we're done
			if collectorReady && scheddReady {
				t.Logf("✅ All HTCondor daemons ready")
				// Give a bit more time for daemons to fully initialize
				time.Sleep(1 * time.Second)
				return nil
			}
		}
	}
}

// printHTCondorLogs prints all HTCondor logs for debugging
func printHTCondorLogs(localDir string, t *testing.T) {
	t.Logf("=== Printing HTCondor Logs (recent entries) ===")
	logDir := filepath.Join(localDir, "log")
	t.Logf("Log directory: %s", logDir)

	// List all files in log directory
	if files, err := os.ReadDir(logDir); err == nil {
		t.Logf("Files in log directory:")
		for _, file := range files {
			t.Logf("  - %s", file.Name())
		}
	} else {
		t.Logf("Failed to list log directory: %v", err)
	}

	// For SchedLog, show last 100 lines as it's most relevant
	schedLogPath := filepath.Join(logDir, "SchedLog")
	if data, err := os.ReadFile(schedLogPath); err == nil {
		t.Logf("=== SchedLog (last 100 lines) ===")
		lines := strings.Split(string(data), "\n")
		startLine := len(lines) - 100
		if startLine < 0 {
			startLine = 0
		}
		for _, line := range lines[startLine:] {
			if line != "" {
				t.Logf("%s", line)
			}
		}
		t.Logf("=== End SchedLog ===")
	} else {
		t.Logf("Failed to read SchedLog: %v", err)
	}

	// For other logs, just show last 50 lines
	otherLogs := []string{"MasterLog", "CollectorLog", "StartLog", "StarterLog.slot1_1", "ShadowLog", "NegotiatorLog"}
	for _, logFile := range otherLogs {
		logPath := filepath.Join(logDir, logFile)
		if data, err := os.ReadFile(logPath); err == nil {
			t.Logf("=== %s (last 50 lines) ===", logFile)
			lines := strings.Split(string(data), "\n")
			startLine := len(lines) - 50
			if startLine < 0 {
				startLine = 0
			}
			for _, line := range lines[startLine:] {
				if line != "" {
					t.Logf("%s", line)
				}
			}
			t.Logf("=== End %s ===", logFile)
		} else {
			t.Logf("Failed to read %s: %v", logFile, err)
		}
	}
	t.Logf("=== End of HTCondor Logs ===")
}

// getScheddAddress finds the actual schedd address from HTCondor address file
func getScheddAddress(localDir string, timeout time.Duration) (string, error) {
	scheddAddressFile := filepath.Join(localDir, "log", ".schedd_address")
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(scheddAddressFile); err == nil {
			// Parse address from file (first non-comment line)
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "$") {
					// Return the sinful string which includes shared port info
					return line, nil
				}
			}
		}

		time.Sleep(500 * time.Millisecond)
	}

	return "", fmt.Errorf("timeout finding schedd address")
}

// waitForServer waits for the HTTP server to be ready
func waitForServer(baseURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}

	for time.Now().Before(deadline) {
		resp, err := client.Get(baseURL + "/openapi.json")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for HTTP server to be ready")
}

// TestJobHoldReleaseIntegration tests job hold and release functionality
func TestJobHoldReleaseIntegration(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Setup mini condor and HTTP server (similar to TestHTTPAPIIntegration)
	tempDir, server, baseURL, cleanup := setupIntegrationTest(t)
	defer cleanup()

	client := &http.Client{Timeout: 30 * time.Second}
	testUser := "testuser"

	// Submit a job
	t.Log("Submitting test job...")
	submitFile := `executable = /bin/sleep
arguments = 60
queue`
	_, jobID := submitJob(t, client, baseURL, testUser, submitFile)
	t.Logf("Job submitted: %s", jobID)

	// Spool input files so the job can be released from hold
	t.Log("Spooling input files...")
	inputTar := createSimpleInputTarball(t)
	uploadInputTarball(t, client, baseURL, testUser, jobID, inputTar)
	t.Log("Input files spooled successfully")

	// Wait for job to be processed and released from initial hold
	time.Sleep(2 * time.Second)

	// Query and print the full job ad for debugging
	t.Log("Querying job ad for debugging...")
	jobAd := getJob(t, client, baseURL, testUser, jobID)
	t.Logf("=== Full Job Ad for %s ===", jobID)
	// Print job ad in a more readable format
	jobAdJSON, _ := json.MarshalIndent(jobAd, "", "  ")
	t.Logf("%s", string(jobAdJSON))
	t.Logf("=== End Job Ad ===")

	// Check key attributes
	if jobStatus, ok := jobAd["JobStatus"].(float64); ok {
		t.Logf("JobStatus: %v", jobStatus)
	}
	if procID, ok := jobAd["ProcId"]; ok {
		t.Logf("ProcId: %v", procID)
	} else {
		t.Logf("ProcId: NOT PRESENT")
	}
	if clusterID, ok := jobAd["ClusterId"]; ok {
		t.Logf("ClusterId: %v", clusterID)
	}

	// Test: Hold the job
	t.Log("Testing job hold...")
	holdReq := map[string]string{"reason": "Integration test hold"}
	holdBody, _ := json.Marshal(holdReq)
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/jobs/%s/hold", baseURL, jobID), bytes.NewReader(holdBody))
	req.Header.Set("X-Test-User", testUser)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		printHTCondorLogs(tempDir, t)
		t.Fatalf("Failed to hold job: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		printHTCondorLogs(tempDir, t)
		t.Fatalf("Hold job failed with status %d: %s", resp.StatusCode, string(body))
	}

	var holdResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&holdResp)
	t.Logf("Hold response: %+v", holdResp)

	// Verify job is held by checking job status
	time.Sleep(1 * time.Second)
	jobResp := getJob(t, client, baseURL, testUser, jobID)
	jobStatus, _ := jobResp["JobStatus"].(float64)
	if jobStatus != 5 { // 5 = HELD
		t.Logf("Warning: Job status is %v, expected 5 (HELD). May not have been held yet.", jobStatus)
	}

	// Test: Release the job
	t.Log("Testing job release...")
	releaseReq := map[string]string{"reason": "Integration test release"}
	releaseBody, _ := json.Marshal(releaseReq)
	req, _ = http.NewRequest("POST", fmt.Sprintf("%s/api/v1/jobs/%s/release", baseURL, jobID), bytes.NewReader(releaseBody))
	req.Header.Set("X-Test-User", testUser)
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		printHTCondorLogs(tempDir, t)
		t.Fatalf("Failed to release job: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		printHTCondorLogs(tempDir, t)
		t.Fatalf("Release job failed with status %d: %s", resp.StatusCode, string(body))
	}

	var releaseResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&releaseResp)
	t.Logf("Release response: %+v", releaseResp)

	// Clean up: Remove the job
	removeJob(t, client, baseURL, testUser, jobID)
	t.Log("Job hold/release test completed successfully")

	_ = tempDir
	_ = server
}

// TestBulkJobOperationsIntegration tests bulk hold and release by constraint
func TestBulkJobOperationsIntegration(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Setup mini condor and HTTP server
	tempDir, server, baseURL, cleanup := setupIntegrationTest(t)
	defer cleanup()

	client := &http.Client{Timeout: 30 * time.Second}
	testUser := "bulktest"

	// Submit multiple test jobs
	t.Log("Submitting test jobs...")
	submitFile := `executable = /bin/sleep
arguments = 120
queue 3`
	clusterID, _ := submitJob(t, client, baseURL, testUser, submitFile)
	t.Logf("Jobs submitted in cluster: %d", clusterID)

	// Spool input files for all jobs in the cluster to release them from initial hold
	t.Log("Spooling input files for all jobs...")
	inputTar := createSimpleInputTarball(t)
	for procID := 0; procID < 3; procID++ {
		jobID := fmt.Sprintf("%d.%d", clusterID, procID)
		uploadInputTarball(t, client, baseURL, testUser, jobID, inputTar)
	}
	t.Log("Input files spooled for all jobs")

	// Wait for jobs to be processed and released from initial hold
	time.Sleep(2 * time.Second)

	// Test: Bulk hold by constraint
	t.Log("Testing bulk hold...")
	holdReq := map[string]string{
		"constraint": fmt.Sprintf("ClusterId == %d", clusterID),
		"reason":     "Bulk integration test hold",
	}
	holdBody, _ := json.Marshal(holdReq)
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/jobs/hold", baseURL), bytes.NewReader(holdBody))
	req.Header.Set("X-Test-User", testUser)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to bulk hold jobs: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Bulk hold failed with status %d: %s", resp.StatusCode, string(body))
	}

	var holdResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&holdResp)
	t.Logf("Bulk hold response: %+v", holdResp)

	// Test: Bulk release by constraint
	t.Log("Testing bulk release...")
	releaseReq := map[string]string{
		"constraint": fmt.Sprintf("ClusterId == %d && JobStatus == 5", clusterID),
		"reason":     "Bulk integration test release",
	}
	releaseBody, _ := json.Marshal(releaseReq)
	req, _ = http.NewRequest("POST", fmt.Sprintf("%s/api/v1/jobs/release", baseURL), bytes.NewReader(releaseBody))
	req.Header.Set("X-Test-User", testUser)
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to bulk release jobs: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Bulk release failed with status %d: %s", resp.StatusCode, string(body))
	}

	var releaseResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&releaseResp)
	t.Logf("Bulk release response: %+v", releaseResp)

	// Clean up: Remove all test jobs
	removeReq := map[string]string{
		"constraint": fmt.Sprintf("ClusterId == %d", clusterID),
		"reason":     "Test cleanup",
	}
	removeBody, _ := json.Marshal(removeReq)
	req, _ = http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/jobs", baseURL), bytes.NewReader(removeBody))
	req.Header.Set("X-Test-User", testUser)
	req.Header.Set("Content-Type", "application/json")
	client.Do(req)

	t.Log("Bulk job operations test completed successfully")

	_ = tempDir
	_ = server
}

// TestCollectorQueryIntegration tests collector query APIs
func TestCollectorQueryIntegration(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Setup mini condor and HTTP server
	tempDir, server, baseURL, cleanup := setupIntegrationTest(t)
	defer cleanup()

	client := &http.Client{Timeout: 30 * time.Second}

	// Test: Query all collector ads
	t.Log("Testing collector ads query...")
	resp, err := client.Get(fmt.Sprintf("%s/api/v1/collector/ads", baseURL))
	if err != nil {
		t.Fatalf("Failed to query collector ads: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Collector query failed with status %d: %s", resp.StatusCode, string(body))
	}

	var adsResp CollectorAdsResponse
	json.NewDecoder(resp.Body).Decode(&adsResp)
	t.Logf("Found %d ads", len(adsResp.Ads))

	// Test: Query schedd ads
	t.Log("Testing schedd ads query...")
	resp, err = client.Get(fmt.Sprintf("%s/api/v1/collector/ads/schedd", baseURL))
	if err != nil {
		t.Fatalf("Failed to query schedd ads: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Schedd query failed with status %d: %s", resp.StatusCode, string(body))
	}

	json.NewDecoder(resp.Body).Decode(&adsResp)
	t.Logf("Found %d schedd ads", len(adsResp.Ads))

	// Test: Query with projection
	t.Log("Testing collector query with projection...")
	resp, err = client.Get(fmt.Sprintf("%s/api/v1/collector/ads/schedd?projection=Name,MyAddress", baseURL))
	if err != nil {
		t.Fatalf("Failed to query with projection: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Projection query failed with status %d: %s", resp.StatusCode, string(body))
	}

	json.NewDecoder(resp.Body).Decode(&adsResp)
	t.Logf("Found %d ads with projection", len(adsResp.Ads))
	if len(adsResp.Ads) > 0 {
		t.Logf("First ad attributes: %+v", adsResp.Ads[0])
	}

	t.Log("Collector query test completed successfully")

	_ = tempDir
	_ = server
}

// setupIntegrationTest is a helper to set up a test environment with mini condor and HTTP server
func setupIntegrationTest(t *testing.T) (tempDir string, server *Server, baseURL string, cleanup func()) {
	// Create temporary directory for mini condor
	tempDir, err := os.MkdirTemp("", "htcondor-integration-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Create secure socket directory
	socketDir, err := os.MkdirTemp("/tmp", "htc_sock_*")
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create socket directory: %v", err)
	}

	// Generate signing key
	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		os.RemoveAll(socketDir)
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create passwords.d directory: %v", err)
	}
	signingKeyPath := filepath.Join(passwordsDir, "POOL")
	// Generate a simple signing key for testing
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(signingKeyPath, key, 0600); err != nil {
		os.RemoveAll(socketDir)
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to write signing key: %v", err)
	}

	trustDomain := "test.htcondor.org"

	// Write mini condor configuration
	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDir, socketDir, passwordsDir, trustDomain, t); err != nil {
		os.RemoveAll(socketDir)
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to write config: %v", err)
	}

	// Start condor_master
	ctx, cancel := context.WithCancel(context.Background())
	condorMaster, err := startCondorMaster(ctx, configFile, tempDir)
	if err != nil {
		cancel()
		os.RemoveAll(socketDir)
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to start condor_master: %v", err)
	}

	// Wait for condor to be ready
	if err := waitForCondor(tempDir, 60*time.Second, t); err != nil {
		stopCondorMaster(condorMaster, t)
		cancel()
		os.RemoveAll(socketDir)
		os.RemoveAll(tempDir)
		t.Fatalf("Condor failed to start: %v", err)
	}

	// Find the actual schedd address (with dynamic port)
	scheddAddr, err := getScheddAddress(tempDir, 10*time.Second)
	if err != nil {
		stopCondorMaster(condorMaster, t)
		cancel()
		os.RemoveAll(socketDir)
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to get schedd address: %v", err)
	}
	t.Logf("Using schedd address: %s", scheddAddr)

	// Extract collector address from schedd address (same host, may need to query collector)
	collectorAddr := scheddAddr // For shared port, collector uses same port

	// Use dynamic port (0) for HTTP server
	serverAddr := "127.0.0.1:0"

	// Create collector pointing to local mini condor
	collector := htcondor.NewCollector(collectorAddr)

	// Set OAuth2DBPath to tempDir to avoid permission issues
	oauth2DBPath := filepath.Join(tempDir, "sessions.db")

	server, err = NewServer(Config{
		ListenAddr:     serverAddr,
		ScheddName:     "local",
		ScheddAddr:     scheddAddr,
		UserHeader:     "X-Test-User",
		SigningKeyPath: signingKeyPath,
		TrustDomain:    "test.htcondor.org",
		UIDDomain:      "test.htcondor.org",
		Collector:      collector,
		OAuth2DBPath:   oauth2DBPath,
	})
	if err != nil {
		stopCondorMaster(condorMaster, t)
		cancel()
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start()
	}()

	// Wait a bit for server to start
	time.Sleep(100 * time.Millisecond)

	// Get the actual listening address from the server
	addr := server.GetAddr()
	if addr == "" {
		server.Shutdown(context.Background())
		stopCondorMaster(condorMaster, t)
		cancel()
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to get server address (server may not have started)")
	}

	baseURL = fmt.Sprintf("http://%s", addr)
	t.Logf("HTTP server listening on: %s", baseURL)

	// Wait for server to be fully ready
	if err := waitForServer(baseURL, 10*time.Second); err != nil {
		server.Shutdown(context.Background())
		stopCondorMaster(condorMaster, t)
		cancel()
		os.RemoveAll(tempDir)
		t.Fatalf("Server failed to start: %v", err)
	}

	cleanup = func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
		stopCondorMaster(condorMaster, t)
		cancel()
		os.RemoveAll(socketDir)
		os.RemoveAll(tempDir)
	}

	return tempDir, server, baseURL, cleanup
}

// getJob retrieves a job's details
func getJob(t *testing.T, client *http.Client, baseURL, user, jobID string) map[string]interface{} {
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/jobs/%s", baseURL, jobID), nil)
	req.Header.Set("X-Test-User", user)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to get job: %v", err)
	}
	defer resp.Body.Close()

	var jobResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&jobResp)
	return jobResp
}

// removeJob removes a job
func removeJob(t *testing.T, client *http.Client, baseURL, user, jobID string) {
	req, _ := http.NewRequest("DELETE", fmt.Sprintf("%s/api/v1/jobs/%s", baseURL, jobID), nil)
	req.Header.Set("X-Test-User", user)
	client.Do(req)
}

// TestHTTPAPIRateLimiting tests that rate limiting works correctly with HTTP API
func TestHTTPAPIRateLimiting(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Create temporary directory for mini condor
	tempDir, err := os.MkdirTemp("", "htcondor-ratelimit-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	t.Logf("Using temporary directory: %s", tempDir)

	// Generate signing key for demo authentication BEFORE starting HTCondor
	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		t.Fatalf("Failed to create passwords.d directory: %v", err)
	}
	signingKeyPath := filepath.Join(passwordsDir, "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(signingKeyPath, key, 0600); err != nil {
		t.Fatalf("Failed to write signing key: %v", err)
	}

	// Write mini condor configuration with rate limiting
	trustDomain := "test.domain"
	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfigWithRateLimit(configFile, tempDir, passwordsDir, trustDomain); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Start condor_master
	t.Log("Starting condor_master...")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	condorMaster, err := startCondorMaster(ctx, configFile, tempDir)
	if err != nil {
		t.Fatalf("Failed to start condor_master: %v", err)
	}
	defer stopCondorMaster(condorMaster, t)

	// Wait for condor to be ready
	t.Log("Waiting for HTCondor to be ready...")
	if err := waitForCondor(tempDir, 30*time.Second, t); err != nil {
		t.Fatalf("Condor failed to start: %v", err)
	}
	t.Log("HTCondor is ready!")

	// Set CONDOR_CONFIG environment variable and reload configuration
	// This is required for rate limiting to work (the library reads config from environment)
	if err := os.Setenv("CONDOR_CONFIG", configFile); err != nil {
		t.Fatalf("Failed to set CONDOR_CONFIG: %v", err)
	}
	defer os.Unsetenv("CONDOR_CONFIG")
	htcondor.ReloadDefaultConfig()
	t.Logf("Loaded rate limiting config from %s", configFile)

	scheddAddr, err := getScheddAddress(tempDir, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to get schedd address: %v", err)
	}
	t.Logf("Using schedd address: %s", scheddAddr)

	// Start HTTP server with dynamic port allocation
	serverAddr := "127.0.0.1:0"

	// Create collector using local address (collector will auto-discover from condor config)
	// Since HTCondor is using port 0, the actual port will be assigned by HTCondor
	collector := htcondor.NewCollector("") // Empty string means use local condor config

	// Set OAuth2DBPath to tempDir to avoid permission issues
	oauth2DBPath := filepath.Join(tempDir, "sessions.db")

	server, err := NewServer(Config{
		ListenAddr:     serverAddr,
		ScheddAddr:     scheddAddr,
		ScheddName:     "local",
		UserHeader:     "X-Test-User",
		SigningKeyPath: signingKeyPath,
		TrustDomain:    "test.domain",
		UIDDomain:      "test.domain",
		Collector:      collector,
		ReadTimeout:    2 * time.Second, // Aggressive timeout for testing
		WriteTimeout:   2 * time.Second,
		IdleTimeout:    5 * time.Second,
		OAuth2DBPath:   oauth2DBPath,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	serverErrChan := make(chan error, 1)
	go func() {
		serverErrChan <- server.Start()
	}()

	// Ensure server is stopped at the end
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			t.Logf("Warning: server shutdown error: %v", err)
		}
	}()

	// Wait for server to start and get actual address
	time.Sleep(500 * time.Millisecond)
	actualAddr := server.GetAddr()
	if actualAddr == "" {
		t.Fatalf("Failed to get server address")
	}
	baseURL := fmt.Sprintf("http://%s", actualAddr)
	t.Logf("Server started on %s", baseURL)

	// Wait for server to be ready
	if err := waitForServer(baseURL, 10*time.Second); err != nil {
		t.Fatalf("Server failed to start: %v", err)
	}
	t.Logf("Server is ready")

	// Test rate limiting
	client := &http.Client{Timeout: 10 * time.Second} // Longer timeout to allow rate limiter to respond with 429
	user := "testuser"

	// Test 1: Make rapid queries to exceed rate limit
	t.Log("Test 1: Making rapid queries to trigger rate limit...")
	successCount := 0
	rateLimitCount := 0
	timeoutCount := 0

	// Make 10 rapid queries (rate limit is 0.2 per user = 1 per 5 seconds)
	// We should get 1 success, then multiple 429s
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/jobs", baseURL), nil)
		req.Header.Set("X-Test-User", user)

		resp, err := client.Do(req)
		if err != nil {
			t.Logf("Request %d failed with error: %v", i+1, err)
			timeoutCount++
			continue
		}

		if resp.StatusCode == http.StatusOK {
			successCount++
			t.Logf("Request %d: Success (200)", i+1)
		} else if resp.StatusCode == http.StatusTooManyRequests {
			rateLimitCount++
			t.Logf("Request %d: Rate limited (429)", i+1)
		} else {
			t.Logf("Request %d: Unexpected status %d", i+1, resp.StatusCode)
		}

		resp.Body.Close()

		// No delay - fire requests rapidly
	}

	t.Logf("Results: %d successful, %d rate limited, %d timeouts", successCount, rateLimitCount, timeoutCount)

	// We should have hit the rate limit at least once
	if rateLimitCount == 0 {
		t.Error("Expected to hit rate limit, but no 429 responses received")
	}

	// Test 2: Wait for rate limit to clear
	t.Log("Test 2: Waiting for rate limit to clear...")
	time.Sleep(6 * time.Second) // Wait longer than rate limit window (5 seconds for 0.2/sec rate)

	// Should succeed now
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/jobs", baseURL), nil)
	req.Header.Set("X-Test-User", user)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK after rate limit cleared, got %d", resp.StatusCode)
	} else {
		t.Log("Test 2: Query succeeded after rate limit cleared")
	}

	// Test 3: Test per-user isolation
	t.Log("Test 3: Testing per-user rate limit isolation...")
	user2 := "testuser2"

	// Exhaust user1's rate limit with rapid requests
	t.Log("Test 3: Exhausting user1's rate limit...")
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/jobs", baseURL), nil)
		req.Header.Set("X-Test-User", user)
		resp, _ := client.Do(req)
		if resp != nil {
			t.Logf("Test 3: User1 request %d: status=%d", i+1, resp.StatusCode)
			resp.Body.Close()
		}
	}

	// User2 should still be able to query (separate rate limit bucket)
	t.Log("Test 3: Testing user2 can still query...")
	req, _ = http.NewRequest("GET", fmt.Sprintf("%s/api/v1/jobs", baseURL), nil)
	req.Header.Set("X-Test-User", user2)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Test 3: User2 request failed: %v", err)
	}
	defer resp.Body.Close()

	t.Logf("Test 3: User2 request status: %d", resp.StatusCode)
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Error("Test 3: FAILED - User2 should not be rate limited when user1 exceeds limit")
	} else if resp.StatusCode == http.StatusOK {
		t.Log("Test 3: PASSED - Per-user isolation working correctly")
	} else {
		t.Errorf("Test 3: Unexpected status code %d for user2", resp.StatusCode)
	}
}

// writeMiniCondorConfigWithRateLimit writes a mini condor configuration with rate limiting enabled
func writeMiniCondorConfigWithRateLimit(configFile, baseDir, passwordsDir, trustDomain string) error {
	masterPath, err := exec.LookPath("condor_master")
	if err != nil {
		return err
	}
	sbinDir := filepath.Dir(masterPath)

	// Determine LIBEXEC directory by looking for condor_shared_port
	var libexecDir string
	sharedPortPath, err := exec.LookPath("condor_shared_port")
	if err == nil {
		// Found condor_shared_port, use its parent directory
		libexecDir = filepath.Dir(sharedPortPath)
	} else {
		// Not found in PATH, try deriving from condor_master location
		derivedLibexec := filepath.Join(filepath.Dir(sbinDir), "libexec")

		// Check if the derived path exists
		if _, err := os.Stat(filepath.Join(derivedLibexec, "condor_shared_port")); err == nil {
			libexecDir = derivedLibexec
		} else {
			// Try standard location /usr/libexec/condor
			stdLibexec := "/usr/libexec/condor"
			if _, err := os.Stat(filepath.Join(stdLibexec, "condor_shared_port")); err == nil {
				libexecDir = stdLibexec
			}
		}
	}

	// Build LIBEXEC line if we found a valid directory
	libexecLine := ""
	if libexecDir != "" {
		libexecLine = fmt.Sprintf("LIBEXEC = %s\n", libexecDir)
	}

	// Create socket directory for shared port daemon
	// Use a shorter path to avoid macOS socket path length limit (104 chars)
	socketDir := filepath.Join("/tmp", fmt.Sprintf("htc-%d", os.Getpid()))
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return fmt.Errorf("failed to create socket dir: %w", err)
	}

	config := fmt.Sprintf(`
# Mini HTCondor configuration for rate limiting tests
DAEMON_LIST = MASTER, SHARED_PORT, COLLECTOR, SCHEDD, STARTD, NEGOTIATOR

# Basic paths
LOCAL_DIR = %s
LOG = %s/log
SPOOL = %s/spool
EXECUTE = %s/execute
LOCK = %s/lock
RUN = %s

# Daemon paths
SBIN = %s
MASTER = %s/condor_master
SCHEDD = %s/condor_schedd
COLLECTOR = %s/condor_collector
STARTD = %s/condor_startd
NEGOTIATOR = %s/condor_negotiator
%s

# Network settings
COLLECTOR_HOST = 127.0.0.1:0
BIND_ALL_INTERFACES = False
NETWORK_INTERFACE = 127.0.0.1

# Enable shared port with proper configuration
USE_SHARED_PORT = True
SHARED_PORT_DEBUG = D_FULLDEBUG
DAEMON_SOCKET_DIR = %s

# Rate limiting configuration (extremely low limits for testing)
# Global limit higher to allow testing per-user isolation
# Per-user rate of 0.2 means 1 query per 5 seconds per user
SCHEDD_QUERY_RATE_LIMIT = 10
SCHEDD_QUERY_PER_USER_RATE_LIMIT = 0.2
COLLECTOR_QUERY_RATE_LIMIT = 10
COLLECTOR_QUERY_PER_USER_RATE_LIMIT = 0.5

# Security settings - enable all authentication methods
SEC_DEFAULT_AUTHENTICATION = OPTIONAL
SEC_DEFAULT_AUTHENTICATION_METHODS = FS,TOKEN
SEC_DEFAULT_ENCRYPTION = OPTIONAL
SEC_DEFAULT_INTEGRITY = OPTIONAL
SEC_CLIENT_AUTHENTICATION_METHODS = FS,TOKEN

# Token configuration
SEC_PASSWORD_DIRECTORY = %s
SEC_TOKEN_DIRECTORY = %s
TRUST_DOMAIN = %s

# Allow all access for testing
ALLOW_READ = *
ALLOW_WRITE = *
ALLOW_NEGOTIATOR = *
ALLOW_ADMINISTRATOR = *
ALLOW_OWNER = *
ALLOW_CLIENT = *

# Minimal machine resources for testing
NUM_CPUS = 1
MEMORY = 1024

SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address
SCHEDD_NAME = test_schedd
SCHEDD_DEBUG = D_FULLDEBUG D_SECURITY

# Collector configuration
COLLECTOR_ADDRESS_FILE = $(LOG)/.collector_address
MAX_COLLECTOR_LOG = 10000000
COLLECTOR_DEBUG = D_FULLDEBUG D_SECURITY

# Shared port logging
SHARED_PORT_DEBUG = D_FULLDEBUG D_SECURITY D_NETWORK:2 D_COMMAND
MAX_SHARED_PORT_LOG = 10000000

# Master logging
MAX_MASTER_LOG = 10000000
MASTER_DEBUG = D_FULLDEBUG D_SECURITY

# Startd logging
MAX_STARTD_LOG = 10000000
STARTD_DEBUG = D_FULLDEBUG D_SECURITY

# Negotiator logging
MAX_NEGOTIATOR_LOG = 10000000
NEGOTIATOR_DEBUG = D_FULLDEBUG

# Fast polling for testing
POLLING_INTERVAL = 5
NEGOTIATOR_INTERVAL = 10
UPDATE_INTERVAL = 5

# Use only local system resources
START = TRUE
SUSPEND = FALSE
PREEMPT = FALSE
KILL = FALSE

# Disable unwanted features
ENABLE_SOAP = False
ENABLE_WEB_SERVER = False
`, baseDir, baseDir, baseDir, baseDir, baseDir, socketDir,
		sbinDir, sbinDir, sbinDir, sbinDir, sbinDir, sbinDir,
		libexecLine, socketDir,
		passwordsDir, passwordsDir, trustDomain)

	return os.WriteFile(configFile, []byte(config), 0600)
}

// TestFileFetchIntegration tests fetching individual files from job output sandbox
func TestFileFetchIntegration(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Create temporary directory for mini condor
	tempDir, err := os.MkdirTemp("", "htcondor-file-fetch-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create secure socket directory in /tmp to avoid path length issues
	socketDir, err := os.MkdirTemp("/tmp", "htc_sock_*")
	if err != nil {
		t.Fatalf("Failed to create socket directory: %v", err)
	}
	defer os.RemoveAll(socketDir)

	t.Logf("Using temporary directory: %s", tempDir)
	t.Logf("Using socket directory: %s", socketDir)

	// Generate signing key for demo authentication
	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		t.Fatalf("Failed to create passwords.d directory: %v", err)
	}
	signingKeyPath := filepath.Join(passwordsDir, "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(signingKeyPath, key, 0600); err != nil {
		t.Fatalf("Failed to write signing key: %v", err)
	}

	trustDomain := "test.htcondor.org"

	// Write mini condor configuration
	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDir, socketDir, passwordsDir, trustDomain, t); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Set CONDOR_CONFIG environment variable
	t.Setenv("CONDOR_CONFIG", configFile)
	htcondor.ReloadDefaultConfig()

	// Start condor_master
	t.Log("Starting condor_master...")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	condorMaster, err := startCondorMaster(ctx, configFile, tempDir)
	if err != nil {
		t.Fatalf("Failed to start condor_master: %v", err)
	}
	defer stopCondorMaster(condorMaster, t)

	// Wait for condor to be ready
	t.Log("Waiting for HTCondor to be ready...")
	if err := waitForCondor(tempDir, 60*time.Second, t); err != nil {
		t.Fatalf("Condor failed to start: %v", err)
	}
	t.Log("HTCondor is ready!")

	// Find the actual schedd address
	scheddAddr, err := getScheddAddress(tempDir, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to get schedd address: %v", err)
	}
	t.Logf("Using schedd address: %s", scheddAddr)

	// Start HTTP server
	server, baseURL := startTestHTTPServer(ctx, tempDir, scheddAddr, passwordsDir, t)
	defer server.Shutdown(ctx)

	client := &http.Client{Timeout: 10 * time.Second}
	user := "testuser"

	// Submit a job that creates multiple output files
	submitFile := `
executable = /bin/sh
arguments = "-c 'echo hello > output.txt; echo world > result.json; echo test > data.log'"
output = stdout.txt
error = stderr.txt
log = job.log
request_cpus = 1
request_memory = 128
request_disk = 1024
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
queue
`

	jobID := submitJob(t, client, baseURL, user, submitFile)
	t.Logf("Submitted job: %s", jobID)

	// Wait for job to complete
	waitForJobCompletion(t, client, baseURL, user, jobID, tempDir, 120*time.Second)
	t.Log("Job completed!")

	// Test fetching individual files
	testCases := []struct {
		filename        string
		expectedContent string
		expectSuccess   bool
	}{
		{"output.txt", "hello\n", true},
		{"result.json", "world\n", true},
		{"data.log", "test\n", true},
		{"stdout.txt", "", true},      // stdout should exist but be empty
		{"nonexistent.txt", "", false}, // should return 404
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("fetch_%s", tc.filename), func(t *testing.T) {
			req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/jobs/%s/files/%s", baseURL, jobID, tc.filename), nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("X-Test-User", user)

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Failed to fetch file: %v", err)
			}
			defer resp.Body.Close()

			if tc.expectSuccess {
				if resp.StatusCode != http.StatusOK {
					body, _ := io.ReadAll(resp.Body)
					t.Fatalf("Expected status 200, got %d: %s", resp.StatusCode, string(body))
				}

				// Read the content
				content, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("Failed to read response body: %v", err)
				}

				// Verify content for non-empty files
				if tc.expectedContent != "" {
					if string(content) != tc.expectedContent {
						t.Errorf("Expected content %q, got %q", tc.expectedContent, string(content))
					}
				}

				// Verify Content-Type header was set
				contentType := resp.Header.Get("Content-Type")
				if contentType == "" {
					t.Error("Content-Type header not set")
				}
				t.Logf("Content-Type: %s", contentType)

				// Verify Content-Disposition header
				contentDisposition := resp.Header.Get("Content-Disposition")
				if !strings.Contains(contentDisposition, tc.filename) {
					t.Errorf("Content-Disposition doesn't contain filename: %s", contentDisposition)
				}
			} else {
				if resp.StatusCode != http.StatusNotFound {
					body, _ := io.ReadAll(resp.Body)
					t.Fatalf("Expected status 404, got %d: %s", resp.StatusCode, string(body))
				}
			}
		})
	}

	// Test path traversal protection
	t.Run("path_traversal_protection", func(t *testing.T) {
		maliciousFilenames := []string{
			"../etc/passwd",
			"etc/passwd",
			"etc\\passwd",
			"..",
		}

		for _, filename := range maliciousFilenames {
			req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/jobs/%s/files/%s", baseURL, jobID, filename), nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("X-Test-User", user)

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Failed to make request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("Expected status 400 for %q, got %d: %s", filename, resp.StatusCode, string(body))
			}
		}
	})
}

