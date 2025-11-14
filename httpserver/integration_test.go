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
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/httpserver"
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

	t.Logf("Using temporary directory: %s", tempDir)

	// Write mini condor configuration
	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDir); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Start condor_master
	t.Log("Starting condor_master...")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	condorMaster, err := startCondorMaster(ctx, configFile)
	if err != nil {
		t.Fatalf("Failed to start condor_master: %v", err)
	}
	defer stopCondorMaster(condorMaster, t)

	// Wait for condor to be ready
	t.Log("Waiting for HTCondor to be ready...")
	if err := waitForCondor(tempDir, 30*time.Second); err != nil {
		t.Fatalf("Condor failed to start: %v", err)
	}
	t.Log("HTCondor is ready!")

	// Generate signing key for demo authentication in passwords.d directory
	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		t.Fatalf("Failed to create passwords.d directory: %v", err)
	}
	signingKeyPath := filepath.Join(passwordsDir, "POOL")
	key, err := httpserver.GenerateSigningKey()
	if err != nil {
		t.Fatalf("Failed to generate signing key: %v", err)
	}
	if err := os.WriteFile(signingKeyPath, key, 0600); err != nil {
		t.Fatalf("Failed to write signing key: %v", err)
	}

	// Use a fixed port for testing
	serverPort := 18080
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	baseURL := fmt.Sprintf("http://%s", serverAddr)

	// Create HTTP server
	server, err := httpserver.NewServer(httpserver.Config{
		ListenAddr:     serverAddr,
		ScheddName:     "local",
		ScheddAddr:     "127.0.0.1",
		ScheddPort:     9618,
		UserHeader:     "X-Test-User",
		SigningKeyPath: signingKeyPath,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	serverErrChan := make(chan error, 1)
	go func() {
		serverErrChan <- server.Start()
	}()

	// Wait for server to be ready
	t.Logf("Waiting for server to start on %s", baseURL)
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
arguments = -c "echo 'Hello from HTCondor!' > output.txt && echo 'Test successful' >> output.txt"
transfer_input_files = input.txt
transfer_output_files = output.txt
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
queue`

	clusterID, jobID := submitJob(t, client, baseURL, testUser, submitFile)
	t.Logf("Job submitted: ClusterID=%d, JobID=%s", clusterID, jobID)

	// Step 2: Create and upload input tarball
	t.Log("Step 2: Creating and uploading input tarball...")
	inputTar := createInputTarball(t, map[string]string{
		"input.txt": "This is test input data\n",
	})
	uploadInputTarball(t, client, baseURL, testUser, jobID, inputTar)
	t.Log("Input tarball uploaded successfully")

	// Step 3: Poll job status until complete
	t.Log("Step 3: Polling job status until complete...")
	waitForJobCompletion(t, client, baseURL, testUser, jobID, 60*time.Second)
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
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("Failed to write tar header: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("Failed to write tar content: %v", err)
		}
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
func waitForJobCompletion(t *testing.T, client *http.Client, baseURL, user, jobID string, timeout time.Duration) {
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
			t.Fatalf("Job was held. Reason: %s", holdReason)
		}

		time.Sleep(pollInterval)
	}

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
func writeMiniCondorConfig(configFile, localDir string) error {
	config := fmt.Sprintf(`# Mini HTCondor Configuration for HTTP API Integration Test
LOCAL_DIR = %s
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

# Network settings
CONDOR_HOST = 127.0.0.1
COLLECTOR_HOST = $(CONDOR_HOST):9618
SCHEDD_HOST = $(CONDOR_HOST)
SCHEDD_PORT = 9618

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
ENABLE_HTTP_PUBLIC_FILES = TRUE

# Keep jobs in queue after completion for output retrieval
SYSTEM_PERIODIC_REMOVE = (JobStatus == 4) && ((time() - CompletionDate) > 3600)

# Reduce resource requirements for testing
NUM_CPUS = 2
MEMORY = 2048

# Logging
MAX_DEFAULT_LOG = 10000000
MAX_NUM_DEFAULT_LOG = 3

# Run jobs quickly in test mode
SCHEDD_INTERVAL = 5
NEGOTIATOR_INTERVAL = 5
STARTER_UPDATE_INTERVAL = 5
`, localDir)

	return os.WriteFile(configFile, []byte(config), 0644)
}

// startCondorMaster starts the condor_master process
func startCondorMaster(ctx context.Context, configFile string) (*exec.Cmd, error) {
	condorMasterPath, err := exec.LookPath("condor_master")
	if err != nil {
		return nil, fmt.Errorf("condor_master not found in PATH: %w", err)
	}

	cmd := exec.CommandContext(ctx, condorMasterPath, "-f")
	cmd.Env = append(os.Environ(),
		"CONDOR_CONFIG="+configFile,
		"_CONDOR_MASTER_LOG=$(LOCAL_DIR)/log/MasterLog",
	)
	// Redirect output to avoid cluttering test output
	cmd.Stdout = nil
	cmd.Stderr = nil

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

// waitForCondor waits for HTCondor to be ready
func waitForCondor(localDir string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		// Check if schedd log exists
		scheddLog := filepath.Join(localDir, "log", "SchedLog")
		if _, err := os.Stat(scheddLog); err == nil {
			// Try to run condor_q
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			cmd := exec.CommandContext(ctx, "condor_q", "-version")
			err := cmd.Run()
			cancel()
			if err == nil {
				return nil
			}
		}

		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("timeout waiting for HTCondor to be ready")
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
