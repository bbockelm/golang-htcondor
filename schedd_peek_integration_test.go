//go:build integration

package htcondor

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestPeekJobOutputIntegration is the end-to-end coverage for
// Schedd.PeekJobOutput against a real HTCondor pool. It submits a
// shell job that produces a known string on both stdout and stderr,
// waits for the job to run, then peeks both streams and verifies the
// returned bytes match.
//
// This test caught the original "live tail returns nothing" bug:
// the request ad was sending JobOutput / JobError as attribute names
// when the C++ macros ATTR_JOB_OUTPUT and ATTR_JOB_ERROR resolve to
// "Out" and "Err". The starter ignored the unknown attrs, returned
// an empty TransferFiles list, and the SPA showed nothing.
//
// Run with:   go test -tags=integration -run TestPeekJobOutputIntegration -v ./...
//
// Requires the host to have condor_master available; the test will
// skip cleanly if SetupCondorHarness can't bring one up.
//
//nolint:gocyclo // Integration test with several discrete verification stages.
func TestPeekJobOutputIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	harness := SetupCondorHarness(t)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}
	if err := harness.WaitForStartd(45 * time.Second); err != nil {
		t.Fatalf("Startd never reported in: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	collector := NewCollector(harness.GetCollectorAddr())
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}
	t.Logf("Schedd discovered: name=%s, address=%s", location.Name, location.Address)
	schedd := NewSchedd(location.Name, location.Address)

	// Job script: emits one sentinel line per stream then sleeps for
	// 5 minutes so the starter is still alive when we peek. We use
	// /bin/sh -c so transfer_executable=false and we don't need to
	// spool any input files.
	const stdoutSentinel = "PEEK_STDOUT_SENTINEL_4732"
	const stderrSentinel = "PEEK_STDERR_SENTINEL_8201"
	submitFile := fmt.Sprintf(`
universe = vanilla
executable = /bin/sh
transfer_executable = false
arguments = "-c 'echo %s; echo %s 1>&2; sleep 300'"
output = job.out
error = job.err
log = job.log
request_cpus = 1
request_memory = 64
request_disk = 64
queue
`, stdoutSentinel, stderrSentinel)

	clusterIDStr, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("Submit failed: %v", err)
	}
	clusterID, err := strconv.Atoi(clusterIDStr)
	if err != nil {
		t.Fatalf("Submit returned non-int cluster id %q: %v", clusterIDStr, err)
	}
	t.Logf("Submitted cluster %d", clusterID)

	// Always clean up — a 5-minute sleeper that survives the test
	// run wastes the harness slot for the next case in the run.
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if _, err := schedd.RemoveJobs(cleanupCtx, fmt.Sprintf("ClusterId == %d", clusterID), "test cleanup"); err != nil {
			t.Logf("warning: cleanup RemoveJobs failed: %v", err)
		}
	}()

	if err := waitForJobRunning(ctx, schedd, clusterID, 90*time.Second); err != nil {
		harness.PrintScheddLog()
		harness.PrintStarterLogs()
		t.Fatalf("job %d.0 never reached Running: %v", clusterID, err)
	}
	t.Logf("Job %d.0 is Running", clusterID)

	// Give the job a moment to actually emit its sentinel lines —
	// the schedd marks Running as soon as the starter accepts the
	// job, which is before the user process has started, let alone
	// printed anything. Without this we sometimes peek the file
	// while it's still 0 bytes.
	if err := waitForJobOutputBytes(ctx, schedd, clusterID, 0, 30*time.Second); err != nil {
		harness.PrintStarterLogs()
		t.Fatalf("job stdout never produced any bytes: %v", err)
	}

	// --- Peek stdout + stderr in one round trip ---------------------
	peekCtx, peekCancel := context.WithTimeout(ctx, 60*time.Second)
	defer peekCancel()

	result, err := schedd.PeekJobOutput(peekCtx, clusterID, 0, PeekRequest{
		Stdout:       true,
		StdoutOffset: -1, // tail the whole file
		Stderr:       true,
		StderrOffset: -1,
		MaxBytes:     16 * 1024,
	})
	if err != nil {
		harness.PrintStarterLogs()
		t.Fatalf("PeekJobOutput failed: %v", err)
	}

	if result.Stdout == nil {
		t.Fatal("PeekJobOutput returned no Stdout — request-ad attribute names are likely wrong (must be 'Out' / 'Err', not 'JobOutput' / 'JobError')")
	}
	if result.Stderr == nil {
		t.Fatal("PeekJobOutput returned no Stderr — request-ad attribute names are likely wrong")
	}

	stdoutText := string(result.Stdout.Bytes)
	stderrText := string(result.Stderr.Bytes)
	t.Logf("Peeked stdout (%d bytes, offset=%d):\n%s", len(stdoutText), result.Stdout.Offset, stdoutText)
	t.Logf("Peeked stderr (%d bytes, offset=%d):\n%s", len(stderrText), result.Stderr.Offset, stderrText)

	if !strings.Contains(stdoutText, stdoutSentinel) {
		t.Errorf("stdout missing sentinel %q; got %q", stdoutSentinel, stdoutText)
	}
	if !strings.Contains(stderrText, stderrSentinel) {
		t.Errorf("stderr missing sentinel %q; got %q", stderrSentinel, stderrText)
	}

	// Offsets should be at least the length of the bytes we
	// received (they're absolute end-of-file positions). With
	// tail-mode (-1) the starter trims to the last MaxBytes; the
	// returned offset is end-of-file regardless.
	if result.Stdout.Offset < int64(len(result.Stdout.Bytes)) {
		t.Errorf("stdout offset %d less than bytes returned %d",
			result.Stdout.Offset, len(result.Stdout.Bytes))
	}
	if result.Stderr.Offset < int64(len(result.Stderr.Bytes)) {
		t.Errorf("stderr offset %d less than bytes returned %d",
			result.Stderr.Offset, len(result.Stderr.Bytes))
	}

	// --- Follow-mode single-stream round-trip ---------------------
	// The job is still sleeping; nothing new should arrive on
	// stdout. A second peek with the previous offset should return
	// zero bytes without erroring. We deliberately request just
	// stdout (not both) — multi-stream all-empty responses hit a
	// cedar wire-level limitation around HTCondor's
	// PUT_FILE_EOM_NUM marker for empty files; the SPA only ever
	// polls one stream at a time so this matches production.
	result2, err := schedd.PeekJobOutput(peekCtx, clusterID, 0, PeekRequest{
		Stdout:       true,
		StdoutOffset: result.Stdout.Offset,
		MaxBytes:     16 * 1024,
	})
	if err != nil {
		t.Fatalf("follow-mode PeekJobOutput failed: %v", err)
	}
	if result2.Stdout == nil {
		t.Fatal("follow-mode result missing Stdout entry")
	}
	if len(result2.Stdout.Bytes) != 0 {
		t.Errorf("expected no new stdout in follow mode; got %d bytes: %q",
			len(result2.Stdout.Bytes), result2.Stdout.Bytes)
	}
	if result2.Stdout.Offset != result.Stdout.Offset {
		t.Errorf("follow-mode offset moved: got %d, want %d",
			result2.Stdout.Offset, result.Stdout.Offset)
	}
}

// waitForJobOutputBytes polls the job's OutputSize attribute until it
// exceeds `min` or the timeout elapses. The starter doesn't update
// the schedd's view of OutputSize in real time, so we also fall back
// to inspecting the size of the in-spool stdout file via a peek
// request that can read 0 bytes.
func waitForJobOutputBytes(ctx context.Context, s *Schedd, clusterID int, min int64, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Direct peek with a tiny budget: if the starter has any
		// bytes for us, this returns >=1 bytes; if not, it returns
		// empty. Either way we know whether the file has content.
		r, err := s.PeekJobOutput(ctx, clusterID, 0, PeekRequest{
			Stdout:       true,
			StdoutOffset: -1,
			MaxBytes:     1024,
		})
		if err == nil && r.Stdout != nil && int64(len(r.Stdout.Bytes)) > min {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for job %d.0 to produce >%d bytes of stdout", clusterID, min)
}
