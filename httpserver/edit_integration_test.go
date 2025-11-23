//go:build integration

package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
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

	// Discover schedd address
	addr := discoverScheddForTest(t, harness)

	// Create Schedd instance
	schedd := htcondor.NewSchedd("local", addr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Setup test server
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	server := &Server{
		logger: logger,
		schedd: schedd,
	}

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

		req := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/v1/jobs/%s", jobID), bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handleEditJob(w, req, jobID)

		if w.Code != http.StatusOK {
			t.Errorf("HTTP status = %d, want %d. Body: %s", w.Code, http.StatusOK, w.Body.String())
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

		req := httptest.NewRequest(http.MethodPatch, "/api/v1/jobs/999999.0", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handleEditJob(w, req, "999999.0")

		if w.Code == http.StatusOK {
			t.Errorf("Expected error for invalid job ID, got status %d", w.Code)
		}
		t.Logf("✓ Correctly rejected invalid job ID with status %d", w.Code)
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

		req := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/v1/jobs/%s", jobID), bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handleEditJob(w, req, jobID)

		if w.Code != http.StatusBadRequest {
			t.Errorf("HTTP status = %d, want %d for immutable attribute", w.Code, http.StatusBadRequest)
		}
		t.Logf("✓ Correctly rejected immutable attribute with status %d", w.Code)
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

	// Discover schedd address
	addr := discoverScheddForTest(t, harness)

	// Create Schedd instance
	schedd := htcondor.NewSchedd("local", addr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Setup test server
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	server := &Server{
		logger: logger,
		schedd: schedd,
	}

	// Submit multiple test jobs
	submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 300
log = test_http_bulk_edit.log
MyTestTag = "bulk_test"
queue 3
`
	clusterID, err := schedd.Submit(ctx, submitFile)
	if err != nil {
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

		req := httptest.NewRequest(http.MethodPatch, "/api/v1/jobs", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handleBulkEditJobs(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("HTTP status = %d, want %d. Body: %s", w.Code, http.StatusOK, w.Body.String())
		}

		// Parse response
		var response map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
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

// Helper function to discover schedd address from harness
func discoverScheddForTest(t *testing.T, harness *htcondor.CondorTestHarness) string {
	addr := harness.GetCollectorAddr()
	addr = strings.TrimPrefix(addr, "<")
	if idx := strings.Index(addr, "?"); idx > 0 {
		addr = addr[:idx]
	}
	addr = strings.TrimSuffix(addr, ">")
	return addr
}
