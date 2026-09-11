//go:build integration

package classadlog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// locateSchedd asks the collector where the schedd is.
//
// The address it answers with has to be used whole. This test used to
// query the collector and then truncate the schedd's MyAddress at the
// "?", which drops the sock=schedd_... parameter that shared port
// routes on -- so every submission went to the collector's own endpoint
// and failed with
//
//	failed to parse server response: failed to read frame header: EOF
//
// which reads like an authentication failure and is not one. The same
// truncation bug was fixed in webapi/mcpserver's edit test (PR #314).
func locateSchedd(t *testing.T, harness *htcondor.CondorTestHarness) *htcondor.DaemonLocation {
	t.Helper()

	collector := htcondor.NewCollector(harness.GetCollectorAddr())
	loc, err := collector.LocateDaemon(context.Background(), "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate the schedd: %v", err)
	}
	return loc
}

// TestWatchLogWithJobSubmission tests the Watch API by submitting a job and monitoring the log
// This test:
// 1. Starts a mini HTCondor instance
// 2. Creates a classadlog Reader watching job_queue.log
// 3. Submits a job using Go-based submission
// 4. Verifies the Watch API receives notifications
// 5. Polls to read the changes and finds the submitted job
func TestWatchLogWithJobSubmission(t *testing.T) {
	// Setup HTCondor test harness
	harness := htcondor.SetupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Get schedd connection info
	scheddLoc := locateSchedd(t, harness)
	t.Logf("Schedd discovered: %s at %s", scheddLoc.Name, scheddLoc.Address)

	// Get the job_queue.log path
	logPath := filepath.Join(harness.GetSpoolDir(), "job_queue.log")

	// Wait for log file to be created
	timeout := time.After(10 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			t.Fatal("job_queue.log was not created")
		case <-ticker.C:
			if _, err := os.Stat(logPath); err == nil {
				goto LogCreated
			}
		}
	}

LogCreated:
	t.Logf("Found job_queue.log at %s", logPath)

	// Create reader
	reader, err := NewReader(logPath)
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}
	defer reader.Close()

	// Do initial poll to read existing state
	ctx := context.Background()
	if err := reader.Poll(ctx); err != nil {
		t.Fatalf("Initial poll failed: %v", err)
	}

	initialJobCount := reader.Len()
	t.Logf("Initial job count: %d", initialJobCount)

	// Start watching the log
	watchCtx, watchCancel := context.WithTimeout(ctx, 60*time.Second)
	defer watchCancel()

	updates := reader.Watch(watchCtx, 500*time.Millisecond)

	// Create schedd client and submit a job
	schedd := htcondor.NewSchedd(scheddLoc.Name, scheddLoc.Address)

	submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 2
output = test.out
error = test.err
log = test.log
queue
`

	t.Log("Submitting job using Go API...")
	submitCtx, submitCancel := context.WithTimeout(ctx, 30*time.Second)
	defer submitCancel()

	clusterID, procAds, err := schedd.SubmitRemote(submitCtx, submitFile)
	if err != nil {
		t.Fatalf("Failed to submit job: %v", err)
	}

	t.Logf("Job submitted successfully: cluster=%d, num_procs=%d", clusterID, len(procAds))

	// Give the schedd a moment to write to the log
	time.Sleep(2 * time.Second)

	// Capture the job_queue.log for debugging
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read job_queue.log: %v", err)
	}

	// Save a copy for unit testing
	capturedLogPath := filepath.Join(os.TempDir(), "captured_job_queue.log")
	if err := os.WriteFile(capturedLogPath, logData, 0644); err != nil {
		t.Fatalf("Failed to save captured log: %v", err)
	}
	t.Logf("Captured job_queue.log to %s (%d bytes)", capturedLogPath, len(logData))

	// Wait for update notification
	var jobFound bool
	maxAttempts := 10
	attempts := 0

	for attempts < maxAttempts {
		select {
		case <-updates:
			t.Log("Received update notification from watcher")
			attempts++

			// Poll to read the changes
			if err := reader.Poll(ctx); err != nil {
				t.Fatalf("Poll after update failed: %v", err)
			}

			currentJobCount := reader.Len()
			t.Logf("Job count after update: %d (was %d)", currentJobCount, initialJobCount)

			// Check if we have the new job
			if currentJobCount > initialJobCount {
				// Query for all jobs
				jobs, err := reader.Query("", []string{"ClusterId", "ProcId", "JobStatus", "Owner"})
				if err != nil {
					t.Fatalf("Query failed: %v", err)
				}

				// Find our job
				for _, job := range jobs {
					if clusterIDVal, ok := job.EvaluateAttrInt("ClusterId"); ok {
						if clusterIDVal == int64(clusterID) {
							jobFound = true
							t.Logf("Found submitted job %d in queue", clusterID)

							// Log job status
							if status, ok := job.EvaluateAttrInt("JobStatus"); ok {
								t.Logf("Job %d status: %d", clusterID, status)
							}

							goto JobFound
						}
					}
				}
			}

		case <-watchCtx.Done():
			t.Fatal("Timeout waiting for job to appear in log")
		}
	}

JobFound:
	if !jobFound {
		t.Fatal("Job not found in log after multiple updates")
	}

	t.Log("SUCCESS: Watch API successfully notified of job submission and job was found in queue")
} // TestWatchMultipleUpdates tests that Watch API handles multiple rapid updates
func TestWatchMultipleUpdates(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	if err := os.WriteFile(logPath, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to create log: %v", err)
	}

	reader, err := NewReader(logPath)
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}
	defer reader.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	updates := reader.Watch(ctx, 50*time.Millisecond)

	// Write updates
	go func() {
		for i := 0; i < 3; i++ {
			time.Sleep(100 * time.Millisecond)
			f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
			if f != nil {
				fmt.Fprintf(f, "NewClassAd %d.0 Job Undefined\n", i)
				f.Close()
			}
		}
	}()

	// Wait for at least one notification
	updateCount := 0
	timeout := time.After(3 * time.Second)

	for {
		select {
		case <-updates:
			updateCount++
			t.Logf("Received notification #%d", updateCount)
			if updateCount >= 1 {
				t.Log("Test completed - received update notification")
				return
			}
		case <-timeout:
			if updateCount == 0 {
				t.Fatal("Did not receive any notifications")
			}
			return
		case <-ctx.Done():
			if updateCount == 0 {
				t.Fatal("Context cancelled without receiving notifications")
			}
			return
		}
	}
}
