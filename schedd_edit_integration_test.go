//go:build integration

package htcondor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestEditJobIntegration tests editing a single job's attributes
func TestEditJobIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if condor_master is available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	// Set up mini HTCondor environment
	harness := SetupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Discover schedd address
	addr := discoverSchedd(t, harness)

	// Create Schedd instance
	schedd := NewSchedd("local", addr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Submit a test job
	submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 300
log = test_edit.log
request_memory = 128
request_disk = 1024
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

	// Test 1: Edit a normal attribute (RequestMemory)
	t.Run("EditNormalAttribute", func(t *testing.T) {
		attributes := map[string]string{
			"RequestMemory": "256",
		}

		err := schedd.EditJobByID(ctx, jobID, attributes, nil)
		if err != nil {
			t.Fatalf("Failed to edit job: %v", err)
		}

		// Verify the change
		ads, err := schedd.Query(ctx, fmt.Sprintf("ClusterId == %s", clusterID), []string{"RequestMemory"})
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
		t.Logf("✓ Successfully edited RequestMemory to 256")
	})

	// Test 2: Try to edit an immutable attribute (should fail)
	t.Run("RejectImmutableAttribute", func(t *testing.T) {
		attributes := map[string]string{
			"ClusterId": "99999",
		}

		err := schedd.EditJobByID(ctx, jobID, attributes, nil)
		if err == nil {
			t.Fatal("Expected error when editing immutable attribute, got nil")
		}

		if !strings.Contains(err.Error(), "immutable") {
			t.Errorf("Expected error about immutable attribute, got: %v", err)
		}
		t.Logf("✓ Correctly rejected immutable attribute: %v", err)
	})

	// Test 3: Edit a custom attribute
	t.Run("EditCustomAttribute", func(t *testing.T) {
		attributes := map[string]string{
			"MyCustomField": `"test_value"`,
		}

		err := schedd.EditJobByID(ctx, jobID, attributes, nil)
		if err != nil {
			t.Fatalf("Failed to edit custom attribute: %v", err)
		}

		// Verify the change
		ads, err := schedd.Query(ctx, fmt.Sprintf("ClusterId == %s", clusterID), []string{"MyCustomField"})
		if err != nil {
			t.Fatalf("Failed to query job: %v", err)
		}

		if len(ads) == 0 {
			t.Fatal("Job not found after edit")
		}

		value, ok := ads[0].EvaluateAttrString("MyCustomField")
		if !ok {
			t.Fatal("MyCustomField attribute not found")
		}

		if value != "test_value" {
			t.Errorf("MyCustomField = %q, want %q", value, "test_value")
		}
		t.Logf("✓ Successfully edited custom attribute MyCustomField")
	})

	// Test 4: Try to edit a protected attribute without permission (should fail)
	t.Run("RejectProtectedAttributeWithoutPermission", func(t *testing.T) {
		attributes := map[string]string{
			"JobPrio": "10",
		}

		err := schedd.EditJobByID(ctx, jobID, attributes, nil)
		if err == nil {
			t.Fatal("Expected error when editing protected attribute without permission, got nil")
		}

		if !strings.Contains(err.Error(), "protected") {
			t.Errorf("Expected error about protected attribute, got: %v", err)
		}
		t.Logf("✓ Correctly rejected protected attribute without permission: %v", err)
	})
}

// TestEditJobsIntegration tests bulk editing multiple jobs
func TestEditJobsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if condor_master is available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	// Set up mini HTCondor environment
	harness := SetupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Discover schedd address
	addr := discoverSchedd(t, harness)

	// Create Schedd instance
	schedd := NewSchedd("local", addr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Submit multiple test jobs
	submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 300
log = test_bulk_edit.log
MyTestAttribute = "initial"
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

	// Test bulk edit
	t.Run("BulkEditMultipleJobs", func(t *testing.T) {
		constraint := fmt.Sprintf("ClusterId == %s", clusterID)
		attributes := map[string]string{
			"RequestMemory":   "512",
			"MyTestAttribute": `"updated"`,
		}

		count, err := schedd.EditJobs(ctx, constraint, attributes, nil)
		if err != nil {
			t.Fatalf("Failed to bulk edit jobs: %v", err)
		}

		if count != 3 {
			t.Errorf("Edited %d jobs, want 3", count)
		}
		t.Logf("✓ Successfully bulk edited %d jobs", count)

		// Verify the changes
		ads, err := schedd.Query(ctx, constraint, []string{"RequestMemory", "MyTestAttribute", "ProcId"})
		if err != nil {
			t.Fatalf("Failed to query jobs: %v", err)
		}

		if len(ads) != 3 {
			t.Fatalf("Found %d jobs, want 3", len(ads))
		}

		for _, ad := range ads {
			memory, ok := ad.EvaluateAttrInt("RequestMemory")
			if !ok {
				t.Error("RequestMemory attribute not found")
				continue
			}
			if memory != 512 {
				t.Errorf("RequestMemory = %d, want 512", memory)
			}

			value, ok := ad.EvaluateAttrString("MyTestAttribute")
			if !ok {
				t.Error("MyTestAttribute attribute not found")
				continue
			}
			if value != "updated" {
				t.Errorf("MyTestAttribute = %q, want %q", value, "updated")
			}

			procID, _ := ad.EvaluateAttrInt("ProcId")
			t.Logf("  Job %s.%d: RequestMemory=%d, MyTestAttribute=%q ✓", clusterID, procID, memory, value)
		}
	})

	// Test bulk edit with no matching jobs
	t.Run("BulkEditNoMatches", func(t *testing.T) {
		constraint := "ClusterId == 999999"
		attributes := map[string]string{
			"RequestMemory": "1024",
		}

		count, err := schedd.EditJobs(ctx, constraint, attributes, nil)
		if err != nil {
			t.Fatalf("Failed to bulk edit (no matches): %v", err)
		}

		if count != 0 {
			t.Errorf("Edited %d jobs, want 0", count)
		}
		t.Logf("✓ Bulk edit with no matches returned count=0")
	})
}
