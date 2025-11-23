package classadlog

import (
	"context"
	"testing"
)

// TestParseRealJobSubmission tests parsing a real job_queue.log captured from HTCondor
func TestParseRealJobSubmission(t *testing.T) {
	ctx := context.Background()

	// Open the captured real log file
	reader, err := NewReader("testdata/real_job_submission.log")
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}
	defer func() { _ = reader.Close() }()

	// Poll to read initial state
	if err := reader.Poll(ctx); err != nil {
		t.Fatalf("Initial poll failed: %v", err)
	}

	// Check that we have jobs
	jobCount := reader.Len()
	t.Logf("Found %d jobs in log", jobCount)

	if jobCount == 0 {
		t.Error("Expected to find at least one job, but got 0")
	}

	// Try to query for all jobs
	jobs, err := reader.Query("", []string{"ClusterId", "ProcId", "JobStatus", "Cmd"})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	t.Logf("Query returned %d jobs", len(jobs))

	for _, job := range jobs {
		clusterID, _ := job.EvaluateAttrInt("ClusterId")
		procID, _ := job.EvaluateAttrInt("ProcId")
		status, _ := job.EvaluateAttrInt("JobStatus")
		cmd, _ := job.EvaluateAttrString("Cmd")

		t.Logf("Job %d.%d: Status=%d, Cmd=%s", clusterID, procID, status, cmd)

		// Verify we got the job we expect
		if clusterID == 1 && procID == 0 {
			if status != 5 {
				t.Errorf("Expected job 1.0 to have status 5 (Held), got %d", status)
			}
			if cmd != "sleep" {
				t.Errorf("Expected job 1.0 Cmd to be 'sleep', got %s", cmd)
			}
		}
	}

	if len(jobs) == 0 {
		t.Error("Query returned no jobs, but reader.Len() > 0")
	}
}
