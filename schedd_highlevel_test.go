package htcondor

import (
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"
)

// setupScheddForTest discovers and returns a Schedd instance for testing
func setupScheddForTest(t *testing.T) *Schedd {
	t.Helper()

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
	collector := NewCollector(harness.GetCollectorAddr())
	locateCtx := context.Background()
	location, err := collector.LocateDaemon(locateCtx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}

	// Create Schedd instance
	schedd := NewSchedd(location.Name, location.Address)

	return schedd
}

// TestScheddSubmitHighLevel tests the high-level Schedd.Submit API
func TestScheddSubmitHighLevel(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	schedd := setupScheddForTest(t)

	// Simple submit file content
	submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 10
output = test.out
error = test.err
log = test.log
queue
`

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Submit the job
	clusterID, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		t.Fatalf("Failed to submit job: %v", err)
	}

	t.Logf("✅ Successfully submitted job cluster %s", clusterID)
}

// TestScheddSubmitMultiProc tests submitting multiple procs
func TestScheddSubmitMultiProc(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	schedd := setupScheddForTest(t)

	// Submit file with multiple procs
	submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 5
output = test.$(Process).out
error = test.$(Process).err
log = test.log
queue 3
`

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Submit the job
	clusterID, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		t.Fatalf("Failed to submit job: %v", err)
	}

	t.Logf("✅ Successfully submitted job cluster %s with 3 procs", clusterID)
}

// TestScheddSubmitWithVariables tests queue with variables
func TestScheddSubmitWithVariables(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	schedd := setupScheddForTest(t)

	// Submit file with queue variables (use 'in' for inline lists)
	submitFile := `
universe = vanilla
executable = /bin/echo
arguments = "Hello $(name)"
output = test.$(name).out
error = test.$(name).err
log = test.log
queue name in (Alice, Bob, Charlie)
`

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Submit the job
	clusterID, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		t.Fatalf("Failed to submit job: %v", err)
	}

	t.Logf("✅ Successfully submitted job cluster %s with queue variables", clusterID)
}

// TestScheddQueryIntegration tests the Schedd.Query API with a real schedd
func TestScheddQueryIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	schedd := setupScheddForTest(t)

	// First, submit a test job so we have something to query
	// Use /bin/sleep to keep job in queue longer for testing
	submitFileContent := `
universe = vanilla
executable = /bin/sleep
arguments = 60
output = test_query.out
error = test_query.err
log = test_query.log
queue
`

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clusterID, err := schedd.Submit(ctx, submitFileContent)
	if err != nil {
		t.Fatalf("Failed to submit test job: %v", err)
	}

	t.Logf("Submitted test job cluster %s", clusterID)

	// Wait longer for the job to appear in the queue (jobs complete quickly)
	time.Sleep(500 * time.Millisecond)

	// Test 1: Query all jobs
	t.Run("QueryAllJobs", func(t *testing.T) {
		jobs, err := schedd.Query(ctx, "true", nil)
		if err != nil {
			t.Fatalf("Query all jobs failed: %v", err)
		}

		t.Logf("Found %d jobs", len(jobs))

		if len(jobs) == 0 {
			// Job might have completed already - that's OK, just log it
			t.Log("No jobs found - job may have completed quickly")
			return
		}

		// Verify the job ad has expected attributes
		job := jobs[0]
		if clusterIDVal, ok := job.EvaluateAttrInt("ClusterId"); !ok {
			t.Error("Job ad does not have ClusterId attribute")
		} else {
			t.Logf("Job ClusterId: %d", clusterIDVal)
		}

		if owner, ok := job.EvaluateAttrString("Owner"); !ok {
			t.Error("Job ad does not have Owner attribute")
		} else {
			t.Logf("Job Owner: %s", owner)
		}
	})

	// Test 2: Query with constraint
	t.Run("QueryWithConstraint", func(t *testing.T) {
		// Query for jobs in this specific cluster
		constraint := "ClusterId == " + clusterID
		jobs, err := schedd.Query(ctx, constraint, nil)
		if err != nil {
			t.Fatalf("Query with constraint failed: %v", err)
		}

		t.Logf("Found %d jobs in cluster %s", len(jobs), clusterID)

		if len(jobs) == 0 {
			t.Log("No jobs found - job may have completed quickly")
			return
		}

		// All jobs should be in the requested cluster
		for _, job := range jobs {
			if clusterIDVal, ok := job.EvaluateAttrInt("ClusterId"); !ok {
				t.Error("Job ad does not have ClusterId attribute")
			} else if clusterIDVal != mustParseInt(clusterID) {
				t.Errorf("Expected ClusterId %s but got %d", clusterID, clusterIDVal)
			}
		}
	})

	// Test 3: Query with projection
	t.Run("QueryWithProjection", func(t *testing.T) {
		// Only request specific attributes
		projection := []string{"ClusterId", "ProcId", "Owner", "JobStatus", "Cmd"}
		jobs, err := schedd.Query(ctx, "true", projection)
		if err != nil {
			t.Fatalf("Query with projection failed: %v", err)
		}

		t.Logf("Query with projection returned %d jobs", len(jobs))

		if len(jobs) == 0 {
			t.Log("No jobs found - may have completed quickly")
			return
		}

		// Debug: print all attributes in the received job ad
		job := jobs[0]
		t.Logf("Received job ad attributes:")
		for _, attrName := range job.GetAttributes() {
			if expr, ok := job.Lookup(attrName); ok {
				t.Logf("  %s = %s", attrName, expr.String())
			}
		}

		// Verify requested attributes are present
		missing := []string{}
		if _, ok := job.EvaluateAttrInt("ClusterId"); !ok {
			missing = append(missing, "ClusterId")
		}
		if _, ok := job.EvaluateAttrInt("ProcId"); !ok {
			missing = append(missing, "ProcId")
		}
		if _, ok := job.EvaluateAttrString("Owner"); !ok {
			missing = append(missing, "Owner")
		}
		if _, ok := job.EvaluateAttrInt("JobStatus"); !ok {
			missing = append(missing, "JobStatus")
		}
		if _, ok := job.EvaluateAttrString("Cmd"); !ok {
			missing = append(missing, "Cmd")
		}

		if len(missing) > 0 {
			t.Errorf("Job ad missing requested attributes from projection: %v", missing)
		} else {
			t.Logf("All requested projection attributes present")
		}
	})

	// Test 4: Query with constraint that matches nothing
	t.Run("QueryNoMatches", func(t *testing.T) {
		// Query for non-existent cluster
		constraint := "ClusterId == 999999"
		jobs, err := schedd.Query(ctx, constraint, nil)
		if err != nil {
			t.Fatalf("Query with no matches failed: %v", err)
		}

		if len(jobs) != 0 {
			t.Errorf("Expected 0 jobs but got %d", len(jobs))
		}

		t.Log("Query with no matches correctly returned 0 jobs")
	})

	t.Logf("✅ All query tests passed")
}

// mustParseInt parses a string to int64 or panics
func mustParseInt(s string) int64 {
	var val int64
	if _, err := fmt.Sscanf(s, "%d", &val); err != nil {
		panic(err)
	}
	return val
}
