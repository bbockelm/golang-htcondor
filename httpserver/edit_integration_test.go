//go:build integration

package httpserver

import (
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

// TestHTTPEditJobIntegration tests editing a job via HTTP API
func TestHTTPEditJobIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if condor_master is available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	// Set up mini HTCondor environment
	harness := htcondor.SetupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Locate schedd using collector
	addr := harness.GetCollectorAddr()

	collector := htcondor.NewCollector(addr)
	locateCtx := context.Background()
	location, err := collector.LocateDaemon(locateCtx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}

	// Create Schedd instance
	schedd := htcondor.NewSchedd(location.Name, location.Address)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Test user for authentication
	testUser := "testuser"

	// Setup signing key for user header authentication
	passwordsDir := filepath.Join(harness.GetSpoolDir(), "passwords.d")
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
		t.Fatalf("Failed to create signing key: %v", err)
	}

	// Setup test server
	server, err := NewServer(Config{
		ListenAddr:     "127.0.0.1:0",
		ScheddName:     location.Name,
		ScheddAddr:     location.Address,
		UserHeader:     "X-Test-User", // Enable header-based auth for testing
		SigningKeyPath: signingKeyPath,
		TrustDomain:    "test.htcondor.org",
		UIDDomain:      "test.htcondor.org",
		OAuth2DBPath:   filepath.Join(harness.GetSpoolDir(), "oauth2.db"),
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

	// Get actual server address
	actualAddr := server.GetAddr()
	if actualAddr == "" {
		t.Fatalf("Failed to get server address")
	}
	baseURL := fmt.Sprintf("http://%s", actualAddr)
	t.Logf("HTTP server listening on: %s", baseURL)

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

	// Submit a test job first
	submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 300
log = test_http_edit.log
request_memory = 128
queue
`
	clusterID, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		t.Fatalf("Failed to submit test job: %v", err)
	}

	jobID := fmt.Sprintf("%s.0", clusterID)
	t.Logf("Submitted test job: %s", jobID)

	// Clean up job at the end
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = schedd.RemoveJobsByID(cleanupCtx, []string{jobID}, "Test cleanup")
	}()

	// Wait a bit for job to settle
	time.Sleep(2 * time.Second)

	// Test editing job via HTTP PATCH
	t.Run("HTTPPatchJob", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"attributes": map[string]string{
				"RequestMemory": "256",
				"MyCustomAttr":  `"test_value"`,
			},
		}

		bodyBytes, err := json.Marshal(reqBody)
		if err != nil {
			t.Fatalf("Failed to marshal request: %v", err)
		}

		req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%s/api/v1/jobs/%s", baseURL, jobID), bytes.NewReader(bodyBytes))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-User", testUser)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("HTTP status = %d, want %d. Body: %s", resp.StatusCode, http.StatusOK, string(body))
		}

		// Verify the changes
		ads, err := schedd.Query(ctx, fmt.Sprintf("ClusterId == %s", clusterID), []string{"RequestMemory", "MyCustomAttr"})
		if err != nil {
			t.Fatalf("Failed to query job: %v", err)
		}

		if len(ads) == 0 {
			t.Fatal("Job not found after edit")
		}

		memory, ok := ads[0].EvaluateAttrInt("RequestMemory")
		if !ok {
			t.Fatal("RequestMemory attribute not found")
		}
		if memory != 256 {
			t.Errorf("RequestMemory = %d, want 256", memory)
		}

		customAttr, ok := ads[0].EvaluateAttrString("MyCustomAttr")
		if !ok {
			t.Fatal("MyCustomAttr attribute not found")
		}
		if customAttr != "test_value" {
			t.Errorf("MyCustomAttr = %q, want %q", customAttr, "test_value")
		}

		t.Logf("✓ Successfully edited job via HTTP API")
	})

	// Test editing with invalid job ID
	t.Run("HTTPPatchInvalidJobID", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"attributes": map[string]string{
				"RequestMemory": "512",
			},
		}

		bodyBytes, err := json.Marshal(reqBody)
		if err != nil {
			t.Fatalf("Failed to marshal request: %v", err)
		}

		req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%s/api/v1/jobs/999999.0", baseURL), bytes.NewReader(bodyBytes))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-User", testUser)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Errorf("Expected error for invalid job ID, got status %d", resp.StatusCode)
		}
		t.Logf("✓ Correctly rejected invalid job ID with status %d", resp.StatusCode)
	})

	// Test editing immutable attribute
	t.Run("HTTPPatchImmutableAttribute", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"attributes": map[string]string{
				"ClusterId": "99999",
			},
		}

		bodyBytes, err := json.Marshal(reqBody)
		if err != nil {
			t.Fatalf("Failed to marshal request: %v", err)
		}

		req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%s/api/v1/jobs/%s", baseURL, jobID), bytes.NewReader(bodyBytes))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-User", testUser)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("HTTP status = %d, want %d for immutable attribute", resp.StatusCode, http.StatusForbidden)
		}
		t.Logf("✓ Correctly rejected immutable attribute with status %d", resp.StatusCode)
	})
}

// TestHTTPBulkEditJobsIntegration tests bulk editing jobs via HTTP API
func TestHTTPBulkEditJobsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if condor_master is available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	// Set up mini HTCondor environment
	harness := htcondor.SetupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Locate schedd using collector
	addr := harness.GetCollectorAddr()
	addr = strings.TrimPrefix(addr, "<")
	if idx := strings.Index(addr, "?"); idx > 0 {
		addr = addr[:idx]
	}
	addr = strings.TrimSuffix(addr, ">")

	collector := htcondor.NewCollector(addr)
	locateCtx := context.Background()
	location, err := collector.LocateDaemon(locateCtx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}

	// Create Schedd instance
	schedd := htcondor.NewSchedd(location.Name, location.Address)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Test user for authentication
	testUser := "testuser"

	// Setup signing key for user header authentication
	passwordsDir := filepath.Join(harness.GetSpoolDir(), "passwords.d")
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
		t.Fatalf("Failed to create signing key: %v", err)
	}

	// Setup test server
	server, err := NewServer(Config{
		ListenAddr:     "127.0.0.1:0",
		ScheddName:     location.Name,
		ScheddAddr:     location.Address,
		UserHeader:     "X-Test-User", // Enable header-based auth for testing
		SigningKeyPath: signingKeyPath,
		TrustDomain:    "test.htcondor.org",
		UIDDomain:      "test.htcondor.org",
		OAuth2DBPath:   filepath.Join(harness.GetSpoolDir(), "oauth2.db"), // Use temp directory for database
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

	// Get actual server address
	actualAddr := server.GetAddr()
	if actualAddr == "" {
		t.Fatalf("Failed to get server address")
	}
	baseURL := fmt.Sprintf("http://%s", actualAddr)
	t.Logf("HTTP server listening on: %s", baseURL)

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

	// Submit multiple test jobs
	submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 300
log = test_http_bulk_edit.log
+MyTestTag = "bulk_test"
queue 3
`
	clusterID, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("Failed to submit test jobs: %v", err)
	}

	t.Logf("Submitted test jobs in cluster: %s", clusterID)

	// Clean up jobs at the end
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		constraint := fmt.Sprintf("ClusterId == %s", clusterID)
		_, _ = schedd.RemoveJobs(cleanupCtx, constraint, "Test cleanup")
	}()

	// Wait a bit for jobs to settle
	time.Sleep(2 * time.Second)

	// Verify all jobs are in the queue before editing
	verifyAds, err := schedd.Query(ctx, fmt.Sprintf("ClusterId == %s", clusterID), []string{"ProcId"})
	if err != nil {
		t.Fatalf("Failed to query jobs before edit: %v", err)
	}
	t.Logf("Found %d jobs in queue after submission", len(verifyAds))
	if len(verifyAds) != 3 {
		t.Fatalf("Expected 3 jobs after submission, found %d", len(verifyAds))
	}

	// Test bulk edit via HTTP PATCH
	t.Run("HTTPPatchBulk", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"constraint": fmt.Sprintf("ClusterId == %s", clusterID),
			"attributes": map[string]string{
				"RequestMemory": "512",
				"MyBulkEdit":    `"true"`,
			},
		}

		bodyBytes, err := json.Marshal(reqBody)
		if err != nil {
			t.Fatalf("Failed to marshal request: %v", err)
		}

		req, err := http.NewRequest(http.MethodPatch, fmt.Sprintf("%s/api/v1/jobs", baseURL), bytes.NewReader(bodyBytes))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-User", testUser)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("HTTP status = %d, want %d. Body: %s", resp.StatusCode, http.StatusOK, string(body))
		}

		// Parse response
		var response map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		jobsEdited, ok := response["jobs_edited"].(float64)
		if !ok {
			t.Fatalf("jobs_edited not found in response")
		}

		if int(jobsEdited) != 3 {
			t.Errorf("jobs_edited = %d, want 3", int(jobsEdited))
		}

		t.Logf("✓ Successfully bulk edited %d jobs via HTTP API", int(jobsEdited))

		// Verify the changes
		ads, err := schedd.Query(ctx, fmt.Sprintf("ClusterId == %s", clusterID), []string{"RequestMemory", "MyBulkEdit", "ProcId"})
		if err != nil {
			t.Fatalf("Failed to query jobs: %v", err)
		}

		if len(ads) != 3 {
			t.Fatalf("Found %d jobs, want 3", len(ads))
		}

		for _, ad := range ads {
			memory, ok := ad.EvaluateAttrInt("RequestMemory")
			if !ok || memory != 512 {
				t.Errorf("RequestMemory not set correctly")
			}

			bulkEdit, ok := ad.EvaluateAttrString("MyBulkEdit")
			if !ok || bulkEdit != "true" {
				t.Errorf("MyBulkEdit not set correctly")
			}
		}
	})
}
