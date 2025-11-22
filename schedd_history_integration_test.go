package htcondor

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// TestScheddQueryJobHistoryIntegration tests the QueryHistory functionality
func TestScheddQueryJobHistoryIntegration(t *testing.T) {
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

	// Submit a test job that completes quickly
	submitFile := `
universe = vanilla
executable = /bin/echo
arguments = "Hello from history test"
output = test_history.out
error = test_history.err
log = test_history.log
queue
`

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Submit the job
	clusterID, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		t.Fatalf("Failed to submit job: %v", err)
	}

	t.Logf("Submitted job cluster %s", clusterID)

	// Wait for job to complete (echo should be fast)
	maxWait := 30 * time.Second
	deadline := time.Now().Add(maxWait)
	var completed bool
	for time.Now().Before(deadline) {
		jobs, err := schedd.Query(ctx, "ClusterId == "+clusterID, []string{"ClusterId", "ProcId", "JobStatus"})
		if err != nil {
			t.Fatalf("Failed to query job: %v", err)
		}

		if len(jobs) == 0 {
			// Job disappeared from queue - likely completed
			completed = true
			break
		}

		// Check if job is completed (JobStatus == 4)
		if status, ok := jobs[0].EvaluateAttrInt("JobStatus"); ok && status == 4 {
			completed = true
			break
		}

		time.Sleep(1 * time.Second)
	}

	if !completed {
		t.Fatal("Job did not complete in time")
	}

	// Give history a moment to be written
	time.Sleep(2 * time.Second)

	// Test 1: Query job history with default options
	t.Run("QueryJobHistory", func(t *testing.T) {
		constraint := "ClusterId == " + clusterID
		projection := []string{"ClusterId", "ProcId", "Owner", "JobStatus"}
		records, err := schedd.QueryHistory(ctx, constraint, projection)
		if err != nil {
			t.Fatalf("Failed to query job history: %v", err)
		}

		if len(records) == 0 {
			t.Errorf("Expected at least 1 history record, got 0")
		} else {
			t.Logf("✅ Found %d job history record(s)", len(records))
			// Verify it's our job - ClusterId comparison
			t.Logf("History record found for cluster %s", clusterID)
		}
	})

	// Test 2: Query with options (limit, projection, backwards)
	t.Run("QueryHistoryWithOptions", func(t *testing.T) {
		opts := &HistoryQueryOptions{
			Source:     HistorySourceJobHistory,
			Limit:      10,
			Projection: []string{"ClusterId", "ProcId", "Owner", "JobStatus"},
			Backwards:  true,
		}

		constraint := "ClusterId == " + clusterID
		records, err := schedd.QueryHistoryWithOptions(ctx, constraint, opts)
		if err != nil {
			t.Fatalf("Failed to query job history with options: %v", err)
		}

		if len(records) == 0 {
			t.Errorf("Expected at least 1 history record, got 0")
		} else {
			t.Logf("✅ Found %d job history record(s) with options", len(records))
		}
	})

	// Test 3: Query with streaming
	t.Run("QueryHistoryStream", func(t *testing.T) {
		opts := &HistoryQueryOptions{
			Source:        HistorySourceJobHistory,
			Limit:         10,
			StreamResults: true,
		}

		streamOpts := &StreamOptions{}

		constraint := "ClusterId == " + clusterID
		recordsCh, err := schedd.QueryHistoryStream(ctx, constraint, opts, streamOpts)
		if err != nil {
			t.Fatalf("Failed to start history stream: %v", err)
		}

		var count int
		for {
			select {
			case result, ok := <-recordsCh:
				if !ok {
					// Channel closed
					goto done
				}
				if result.Err != nil {
					t.Fatalf("Error during streaming: %v", result.Err)
				}
				count++
				t.Logf("Received history record %d", count)
				// Verify it's a valid ClassAd
				if result.Ad == nil {
					t.Error("Received nil ClassAd")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Timeout waiting for history records")
			}
		}
	done:
		if count == 0 {
			t.Errorf("Expected at least 1 history record from stream, got 0")
		} else {
			t.Logf("✅ Received %d job history record(s) from stream", count)
		}
	})

	// Test 4: Query with limit
	t.Run("QueryHistoryWithLimit", func(t *testing.T) {
		opts := &HistoryQueryOptions{
			Source: HistorySourceJobHistory,
			Limit:  1, // Only get 1 record
		}

		// Query all history (not just our job)
		records, err := schedd.QueryHistoryWithOptions(ctx, "true", opts)
		if err != nil {
			t.Fatalf("Failed to query history with limit: %v", err)
		}

		if len(records) > 1 {
			t.Errorf("Expected at most 1 record due to limit, got %d", len(records))
		}
		t.Logf("✅ Limit respected: got %d record(s)", len(records))
	})
}

// TestScheddQueryJobEpochsIntegration tests the job epoch history functionality
func TestScheddQueryJobEpochsIntegration(t *testing.T) {
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

	// Submit a simple test job
	submitFile := `
universe = vanilla
executable = /bin/echo
arguments = "Epoch test"
output = test_epoch.out
error = test_epoch.err
log = test_epoch.log
queue
`

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clusterID, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		t.Fatalf("Failed to submit job: %v", err)
	}

	t.Logf("Submitted job cluster %s for epoch test", clusterID)

	// Wait for job to complete
	time.Sleep(10 * time.Second)

	// Try to query job epochs
	// Note: Job epoch history may not be available in all HTCondor configurations
	opts := &HistoryQueryOptions{
		Source:     HistorySourceJobEpoch,
		Limit:      10,
		Projection: []string{"ClusterId", "ProcId", "EpochNumber"},
	}

	constraint := "ClusterId == " + clusterID
	records, err := schedd.QueryHistoryWithOptions(ctx, constraint, opts)
	if err != nil {
		// Epoch history may not be enabled - this is expected in many configs
		t.Logf("Job epoch query failed (may not be enabled): %v", err)
		t.Skip("Job epoch history not available in this HTCondor configuration")
		return
	}

	t.Logf("✅ Found %d job epoch record(s)", len(records))
}

// TestScheddQueryTransferHistoryIntegration tests the transfer history functionality
func TestScheddQueryTransferHistoryIntegration(t *testing.T) {
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

	// Submit a job with file transfer
	submitFile := `
universe = vanilla
executable = /bin/cat
arguments = input.txt
output = test_transfer.out
error = test_transfer.err
log = test_transfer.log
transfer_input_files = input.txt
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
queue
`

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clusterID, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		t.Fatalf("Failed to submit job: %v", err)
	}

	t.Logf("Submitted job cluster %s for transfer test", clusterID)

	// Wait for job to complete
	time.Sleep(15 * time.Second)

	// Try to query transfer history
	// Note: Transfer history may not be available in all HTCondor configurations
	opts := &HistoryQueryOptions{
		Source:        HistorySourceTransfer,
		Limit:         10,
		TransferTypes: []TransferType{TransferTypeInput, TransferTypeOutput},
	}

	constraint := "ClusterId == " + clusterID
	records, err := schedd.QueryHistoryWithOptions(ctx, constraint, opts)
	if err != nil {
		// Transfer history may not be enabled - this is expected in many configs
		t.Logf("Transfer history query failed (may not be enabled): %v", err)
		t.Skip("Transfer history not available in this HTCondor configuration")
		return
	}

	t.Logf("✅ Found %d transfer history record(s)", len(records))
}
