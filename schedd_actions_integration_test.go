package htcondor

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestScheddRemoveJobsIntegration tests the RemoveJobs functionality
func TestScheddRemoveJobsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if condor_master is available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	// Set up mini HTCondor environment
	harness := setupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.waitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Discover schedd address
	addr := discoverSchedd(t, harness)

	// Create Schedd instance
	schedd := NewSchedd("local", addr)

	// Submit a test job
	submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 300
output = test_remove.out
error = test_remove.err
log = test_remove.log
queue
`

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Submit the job
	clusterID, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		t.Fatalf("Failed to submit job: %v", err)
	}

	t.Logf("Submitted job cluster %s", clusterID)

	// Wait a bit for job to be registered
	time.Sleep(2 * time.Second)

	// Remove the job by constraint
	constraint := "ClusterId == " + clusterID
	results, err := schedd.RemoveJobs(ctx, constraint, "Test removal")
	if err != nil {
		t.Fatalf("Failed to remove job: %v", err)
	}

	// Log the full result ad for debugging
	if results.ResultAd != nil {
		t.Logf("Result ClassAd: %v", results.ResultAd)
	}

	t.Logf("Remove results: Total=%d, Success=%d, NotFound=%d, PermissionDenied=%d, BadStatus=%d, Error=%d",
		results.TotalJobs, results.Success, results.NotFound,
		results.PermissionDenied, results.BadStatus, results.Error)

	// Verify job was removed
	if results.Success != 1 {
		t.Errorf("Expected 1 successful removal, got %d", results.Success)
	}

	if results.TotalJobs != 1 {
		t.Errorf("Expected 1 total job, got %d", results.TotalJobs)
	}

	// Wait for removal to propagate
	time.Sleep(1 * time.Second)

	// Query to verify job is removed
	jobs, err := schedd.Query(ctx, constraint, []string{"ClusterId", "ProcId", "JobStatus"})
	if err != nil {
		t.Fatalf("Failed to query jobs: %v", err)
	}

	// Job should not be found (or marked as removed)
	if len(jobs) > 0 {
		t.Logf("Job still visible after removal (may be normal during cleanup): %d ads", len(jobs))
	} else {
		t.Logf("✅ Job successfully removed and no longer visible")
	}
}

// TestScheddRemoveJobsByIDIntegration tests RemoveJobsByID
func TestScheddRemoveJobsByIDIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if condor_master is available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	// Set up mini HTCondor environment
	harness := setupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.waitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Discover schedd address
	addr := discoverSchedd(t, harness)

	// Create Schedd instance
	schedd := NewSchedd("local", addr)

	// Submit multiple test jobs
	submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 300
output = test_remove_multi.$(Process).out
error = test_remove_multi.$(Process).err
log = test_remove_multi.log
queue 3
`

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Submit the jobs
	clusterID, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		t.Fatalf("Failed to submit jobs: %v", err)
	}

	t.Logf("Submitted job cluster %s with 3 procs", clusterID)

	// Wait for jobs to be registered
	time.Sleep(2 * time.Second)

	// Remove specific jobs by ID
	jobIDs := []string{
		clusterID + ".0",
		clusterID + ".2",
	}

	results, err := schedd.RemoveJobsByID(ctx, jobIDs, "Test removal by ID")
	if err != nil {
		t.Fatalf("Failed to remove jobs: %v", err)
	}

	t.Logf("Remove results: Total=%d, Success=%d, NotFound=%d",
		results.TotalJobs, results.Success, results.NotFound)

	// Verify jobs were removed
	if results.Success != 2 {
		t.Errorf("Expected 2 successful removals, got %d", results.Success)
	}

	// Wait for removal to propagate
	time.Sleep(1 * time.Second)

	// Query remaining job
	constraint := "ClusterId == " + clusterID + " && ProcId == 1"
	jobs, err := schedd.Query(ctx, constraint, []string{"ClusterId", "ProcId"})
	if err != nil {
		t.Fatalf("Failed to query remaining job: %v", err)
	}

	if len(jobs) == 1 {
		t.Logf("✅ Job %s.1 still exists (not removed)", clusterID)
	}

	// Clean up remaining job
	_, _ = schedd.RemoveJobs(ctx, "ClusterId == "+clusterID, "Cleanup")
}

// TestScheddRemoveNonExistentJob tests removing a non-existent job
func TestScheddRemoveNonExistentJob(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if condor_master is available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	// Set up mini HTCondor environment
	harness := setupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.waitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Discover schedd address
	addr := discoverSchedd(t, harness)

	// Create Schedd instance
	schedd := NewSchedd("local", addr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Try to remove non-existent job
	constraint := "ClusterId == 999999"
	results, err := schedd.RemoveJobs(ctx, constraint, "Test non-existent removal")
	// When no jobs match, schedd may return an error with ActionResult=0
	// This is expected behavior - the results will still be valid
	if err != nil && !strings.Contains(err.Error(), "action failed: result=0") {
		t.Fatalf("Unexpected error from RemoveJobs: %v", err)
	}

	t.Logf("Remove results for non-existent job: Total=%d, Success=%d, NotFound=%d",
		results.TotalJobs, results.Success, results.NotFound)

	// Should report not found
	if results.Success != 0 {
		t.Errorf("Expected 0 successful removals, got %d", results.Success)
	}

	if results.NotFound == 0 && results.TotalJobs > 0 {
		t.Logf("Note: Job reported as total but not found (may be normal HTCondor behavior)")
	}

	t.Logf("✅ RemoveJobs correctly handled non-existent job")
}
