package htcondor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// jobStatus* constants mirror HTCondor's JobStatus enum (src/condor_includes/proc.h).
const (
	jobStatusIdle    = 1
	jobStatusRunning = 2
	jobStatusRemoved = 3
	jobStatusHeld    = 5
)

// connectLifecycleSchedd starts a personal condor via the harness and returns a
// Schedd handle plus a bound context. It centralizes the boilerplate shared by
// the action lifecycle integration tests.
func connectLifecycleSchedd(t *testing.T) (*Schedd, context.Context, context.CancelFunc) {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH - skipping integration test")
	}

	harness := SetupCondorHarness(t)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	collector := NewCollector(harness.GetCollectorAddr())
	location, err := collector.LocateDaemon(context.Background(), "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}

	schedd := NewSchedd(location.Name, location.Address)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	return schedd, ctx, cancel
}

// waitForJobStatus polls the schedd until the single job in clusterID reaches
// wantStatus, or fails the test after a timeout. Returns the observed status.
func waitForJobStatus(ctx context.Context, t *testing.T, schedd *Schedd, clusterID string, wantStatus int) {
	t.Helper()
	constraint := "ClusterId == " + clusterID
	deadline := time.Now().Add(20 * time.Second)
	var last int64 = -1
	for time.Now().Before(deadline) {
		ads, err := schedd.Query(ctx, constraint, []string{"ClusterId", "ProcId", "JobStatus"})
		if err != nil {
			t.Fatalf("Query for job status failed: %v", err)
		}
		if len(ads) > 0 {
			if status, ok := ads[0].EvaluateAttrInt("JobStatus"); ok {
				last = status
				if int(status) == wantStatus {
					return
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("job %s never reached JobStatus=%d (last observed=%d)", clusterID, wantStatus, last)
}

// rawResultTotal reads result_total_<idx> directly from the schedd's result ad,
// which is the on-the-wire representation of the per-AR_* counters. Asserting on
// these (rather than only on exit/err) proves we correctly parsed the phase-1
// result ClassAd produced by JobActionResults::publishResults.
func rawResultTotal(t *testing.T, results *JobActionResults, idx int) int64 {
	t.Helper()
	if results == nil || results.ResultAd == nil {
		t.Fatalf("no result ad present")
	}
	val, _ := results.ResultAd.EvaluateAttrInt(fmt.Sprintf("result_total_%d", idx))
	return val
}

// TestScheddHoldReleaseRemoveLifecycleIntegration drives the full two-phase
// ACT_ON_JOBS handshake three times (hold, release, remove) against a real C++
// schedd. Each *successful* action makes the schedd proceed past phase 1 into
// the phase-2 commit exchange (src/condor_schedd.V6/schedd.cpp:8049-8080): it
// reads our 8-byte "ready" ack and replies with an 8-byte confirmation. Prior
// integration tests only removed a job; this exercises hold and release too and
// asserts the per-job AR_* results from the result ad, not just error codes.
func TestScheddHoldReleaseRemoveLifecycleIntegration(t *testing.T) {
	schedd, ctx, cancel := connectLifecycleSchedd(t)
	defer cancel()

	submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 300
output = test_lifecycle.out
error = test_lifecycle.err
log = test_lifecycle.log
queue
`
	clusterID, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		t.Fatalf("Failed to submit job: %v", err)
	}
	t.Logf("Submitted job cluster %s", clusterID)

	// Make sure the job is registered before acting on it.
	waitForJobStatus(ctx, t, schedd, clusterID, jobStatusIdle)

	constraint := "ClusterId == " + clusterID

	// --- HOLD (phase 2 exercised) ---
	holdRes, err := schedd.HoldJobs(ctx, constraint, "lifecycle hold")
	if err != nil {
		t.Fatalf("HoldJobs failed (phase-2 handshake likely broken): %v", err)
	}
	if holdRes.Success != 1 {
		t.Errorf("HoldJobs: expected Success=1, got %d (result ad: %v)", holdRes.Success, holdRes.ResultAd)
	}
	if got := rawResultTotal(t, holdRes, int(AR_SUCCESS)); got != 1 {
		t.Errorf("HoldJobs: expected result_total_1 (AR_SUCCESS)=1, got %d", got)
	}
	waitForJobStatus(ctx, t, schedd, clusterID, jobStatusHeld)
	t.Logf("Job %s held; success=%d", clusterID, holdRes.Success)

	// --- HOLD AGAIN (already held -> AR_ALREADY_DONE, aborts at phase 1) ---
	// The schedd records AR_ALREADY_DONE and, with num_success==0, aborts before
	// phase 2 (src/condor_schedd.V6/schedd.cpp:7850-7859, 8035-8046). The Go
	// client surfaces this as an "action failed" error while still returning the
	// parsed result ad.
	againRes, err := schedd.HoldJobs(ctx, constraint, "lifecycle hold again")
	if err == nil {
		t.Errorf("HoldJobs on already-held job: expected action-failed error, got nil")
	}
	if got := rawResultTotal(t, againRes, int(AR_ALREADY_DONE)); got != 1 {
		t.Errorf("re-hold: expected result_total_4 (AR_ALREADY_DONE)=1, got %d (err=%v)", got, err)
	}
	if againRes.AlreadyDone != 1 {
		t.Errorf("re-hold: expected AlreadyDone=1, got %d", againRes.AlreadyDone)
	}

	// --- RELEASE (phase 2 exercised) ---
	relRes, err := schedd.ReleaseJobs(ctx, constraint, "lifecycle release")
	if err != nil {
		t.Fatalf("ReleaseJobs failed (phase-2 handshake likely broken): %v", err)
	}
	if relRes.Success != 1 {
		t.Errorf("ReleaseJobs: expected Success=1, got %d (result ad: %v)", relRes.Success, relRes.ResultAd)
	}
	if got := rawResultTotal(t, relRes, int(AR_SUCCESS)); got != 1 {
		t.Errorf("ReleaseJobs: expected result_total_1 (AR_SUCCESS)=1, got %d", got)
	}
	waitForJobStatus(ctx, t, schedd, clusterID, jobStatusIdle)
	t.Logf("Job %s released; success=%d", clusterID, relRes.Success)

	// --- REMOVE (phase 2 exercised) ---
	rmRes, err := schedd.RemoveJobs(ctx, constraint, "lifecycle remove")
	if err != nil {
		t.Fatalf("RemoveJobs failed (phase-2 handshake likely broken): %v", err)
	}
	if rmRes.Success != 1 {
		t.Errorf("RemoveJobs: expected Success=1, got %d (result ad: %v)", rmRes.Success, rmRes.ResultAd)
	}
	if got := rawResultTotal(t, rmRes, int(AR_SUCCESS)); got != 1 {
		t.Errorf("RemoveJobs: expected result_total_1 (AR_SUCCESS)=1, got %d", got)
	}
	t.Logf("Job %s removed; success=%d", clusterID, rmRes.Success)
}

// TestScheddReleaseNonHeldReturnsBadStatusIntegration verifies that the phase-1
// result ad correctly carries a *non-success* AR_* code. Releasing an idle job
// is a bad-status action: the schedd records AR_BAD_STATUS and, with
// num_success==0, aborts before phase 2 (schedd.cpp:7791-7798, 8035-8046). We
// assert on the specific counter from the result ad, proving the AR_* mapping.
//
// This must go through the by-ID path: when acting by *constraint*, the schedd
// ANDs in a status pre-filter that only matches HELD jobs for a release
// (schedd.cpp:7612-7618), so an idle job would simply not match and yield empty
// totals. The by-ID path (schedd.cpp:7730-7749) skips that filter and reaches
// the per-job AR_BAD_STATUS check.
func TestScheddReleaseNonHeldReturnsBadStatusIntegration(t *testing.T) {
	schedd, ctx, cancel := connectLifecycleSchedd(t)
	defer cancel()

	submitFile := `
universe = vanilla
executable = /bin/sleep
arguments = 300
output = test_badstatus.out
error = test_badstatus.err
log = test_badstatus.log
queue
`
	clusterID, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		t.Fatalf("Failed to submit job: %v", err)
	}
	defer func() { _, _ = schedd.RemoveJobs(ctx, "ClusterId == "+clusterID, "cleanup") }()

	waitForJobStatus(ctx, t, schedd, clusterID, jobStatusIdle)

	// Release a specific idle job by ID -> AR_BAD_STATUS, action fails overall.
	res, err := schedd.actOnJobs(ctx, JA_RELEASE_JOBS, "", []string{clusterID + ".0"},
		"release idle job", "ReleaseReason", "", "", AR_TOTALS)
	if err == nil {
		t.Errorf("ReleaseJobs on idle job: expected action-failed error, got nil")
	}
	if res.BadStatus != 1 {
		t.Errorf("expected BadStatus=1, got %d (result ad: %v)", res.BadStatus, res.ResultAd)
	}
	if got := rawResultTotal(t, res, int(AR_BAD_STATUS)); got != 1 {
		t.Errorf("expected result_total_3 (AR_BAD_STATUS)=1, got %d", got)
	}
	if res.Success != 0 {
		t.Errorf("expected Success=0, got %d", res.Success)
	}
	t.Logf("Release of idle job correctly reported BadStatus=%d", res.BadStatus)
}

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
	harness := SetupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Locate schedd using collector
	collector := NewCollector(harness.GetCollectorAddr())
	locateCtx := context.Background()
	location, err := collector.LocateDaemon(locateCtx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}

	// Create Schedd instance
	schedd := NewSchedd(location.Name, location.Address)

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
	harness := SetupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Locate schedd using collector
	collector := NewCollector(harness.GetCollectorAddr())
	locateCtx := context.Background()
	location, err := collector.LocateDaemon(locateCtx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}

	// Create Schedd instance
	schedd := NewSchedd(location.Name, location.Address)

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
	harness := SetupCondorHarness(t)

	// Wait for daemons to start
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}

	// Locate schedd using collector
	collector := NewCollector(harness.GetCollectorAddr())
	locateCtx := context.Background()
	location, err := collector.LocateDaemon(locateCtx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}

	// Create Schedd instance
	schedd := NewSchedd(location.Name, location.Address)

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
