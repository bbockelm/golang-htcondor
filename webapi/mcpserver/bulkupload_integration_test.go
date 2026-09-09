//go:build integration

package mcpserver

import (
	"context"
	"fmt"
	"os/exec"
	"os/user"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// The scenario from af-mcp-platform#268, against a real schedd.
//
// Cluster submitted with `queue 5`; one upload_job_input released proc 0
// and procs 1-4 stayed HELD on HoldReasonCode 16 until each got its own
// byte-identical upload. A bare cluster id should release all five in one
// call.
//
// This needs a real schedd because the thing under test is what the
// schedd does with the spool: a unit test can only check that we called
// SpoolJobFilesFromTar the number of times we meant to, which is not the
// same claim as "the procs left the hold".

// locateSchedd asks the collector where the schedd is.
//
// Not discoverScheddForTest: that trims the query string off the
// COLLECTOR's address, which drops the sock=schedd_... parameter that
// shared port uses to route to the right daemon. The result is the
// collector's own endpoint, and connecting to it to submit fails with
// "failed to read frame header: EOF" -- the wrong daemon on the far end,
// not an authentication problem.
func locateSchedd(t *testing.T, harness *htcondor.CondorTestHarness) *htcondor.Schedd {
	t.Helper()
	collector := htcondor.NewCollector(harness.GetCollectorAddr())
	loc, err := collector.LocateDaemon(context.Background(), "Schedd", "")
	if err != nil {
		t.Fatalf("locating the schedd: %v", err)
	}
	t.Logf("schedd %q at %s", loc.Name, loc.Address)
	return htcondor.NewSchedd(loc.Name, loc.Address)
}

func TestBulkUploadReleasesEveryProcOfACluster(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (forks a real HTCondor)")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not in PATH")
	}

	harness := htcondor.SetupCondorHarness(t)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("daemons failed to start: %v", err)
	}
	schedd := locateSchedd(t, harness)

	// The upload path is owner-scoped -- scopeToOwner reads the actor off
	// the context and refuses without one -- so the context needs an
	// authenticated user even though submit does not.
	ctx, cancel := context.WithTimeout(
		htcondor.WithAuthenticatedUser(context.Background(), currentUserForTest(t)),
		5*time.Minute)
	defer cancel()

	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{schedd: schedd, logger: logger}

	// More than bulkUploadConcurrency, so the fan-out actually runs in
	// waves against a real schedd. At 5 (one wave) the bound was never
	// exercised: every proc went in flight at once and a fan-out that
	// ignored its limit would have passed.
	//
	// These do not need to run -- the assertion is that none is left
	// held for spooling -- so 25 idle procs cost the harness nothing.
	const procs = 25
	// No transfer_executable = false: the point is that these procs are
	// held for spooling and need input before they can run.
	submitFile := fmt.Sprintf(`
universe = vanilla
executable = bulk.sh
arguments = $(Process)
transfer_input_files = bulk.sh
log = bulk_test.log
request_memory = 64
queue %d
`, procs)

	// Through the MCP tool, so this is the path the report came from --
	// and so the fan-out notice is exercised too.
	subRes, err := server.toolSubmitJob(ctx, map[string]interface{}{"submit_file": submitFile})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	subMeta := subRes.(map[string]interface{})["metadata"].(map[string]interface{})
	cluster, ok := subMeta["cluster_id"].(int)
	if !ok {
		t.Fatalf("no cluster_id in submit metadata: %+v", subMeta)
	}
	t.Logf("submitted cluster %d with %d procs", cluster, procs)

	// The submit result must say the upload is per proc. That notice is
	// the whole of proposal 1 in the issue, and the reason the surprise
	// happened was its absence.
	subText := subRes.(map[string]interface{})["content"].([]map[string]interface{})[0]["text"].(string)
	if !strings.Contains(subText, "PER PROC") {
		t.Errorf("submit result does not warn that spooling is per proc:\n%s", subText)
	}
	if !strings.Contains(subText, fmt.Sprintf("job_id=\"%d\"", cluster)) {
		t.Errorf("submit result does not offer the cluster-wide form:\n%s", subText)
	}

	// All procs start held for spooling. Asserted rather than assumed:
	// if a future change released them on submit, this test would be
	// exercising nothing.
	waitForHeldForSpooling(t, ctx, schedd, cluster, procs)

	// One call, bare cluster id.
	res, err := server.toolUploadJobInput(ctx, map[string]interface{}{
		"job_id": fmt.Sprintf("%d", cluster),
		"files": []interface{}{
			map[string]interface{}{
				"filename":      "bulk.sh",
				"data":          "#!/bin/sh\necho proc $1\n",
				"is_executable": true,
			},
		},
	})
	if err != nil {
		t.Fatalf("cluster-wide upload: %v", err)
	}

	meta := res.(map[string]interface{})["metadata"].(map[string]interface{})
	if got := meta["procs_spooled"]; got != procs {
		t.Errorf("procs_spooled = %v, want %d (metadata: %+v)", got, procs, meta)
	}
	if got := meta["procs_remaining"]; got != 0 {
		t.Errorf("procs_remaining = %v, want 0 (metadata: %+v)", got, meta)
	}

	// The claim that matters: every proc actually left the spool hold.
	// The metadata above only says what we tried.
	waitForNoneHeldForSpooling(t, ctx, schedd, cluster)
}

// A second call on an already-spooled cluster must be a no-op rather than
// an error: an agent that retries should not be told its request failed.
func TestBulkUploadOnASpooledClusterIsANoOp(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (forks a real HTCondor)")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not in PATH")
	}

	harness := htcondor.SetupCondorHarness(t)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("daemons failed to start: %v", err)
	}
	schedd := locateSchedd(t, harness)
	ctx, cancel := context.WithTimeout(
		htcondor.WithAuthenticatedUser(context.Background(), currentUserForTest(t)),
		5*time.Minute)
	defer cancel()
	logger, _ := logging.New(&logging.Config{OutputPath: "stderr"})
	server := &Server{schedd: schedd, logger: logger}

	subRes, err := server.toolSubmitJob(ctx, map[string]interface{}{"submit_file": `
universe = vanilla
executable = /bin/true
transfer_executable = false
log = noop_test.log
request_memory = 64
queue 2
`})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	cluster := subRes.(map[string]interface{})["metadata"].(map[string]interface{})["cluster_id"].(int)

	// Every remote submission is written into the queue held on code 16,
	// and releaseJobsWithEmptySpool clears the ones needing no input a
	// moment later. Uploading inside that window legitimately finds procs
	// held for spooling and spools them -- harmless, but it is not the
	// no-op path. Wait for the auto-release so the test asserts what it
	// means to.
	waitForNoneHeldForSpooling(t, ctx, schedd, cluster)
	res, err := server.toolUploadJobInput(ctx, map[string]interface{}{
		"job_id": fmt.Sprintf("%d", cluster),
		"files": []interface{}{
			map[string]interface{}{"filename": "unused.txt", "data": "x"},
		},
	})
	if err != nil {
		t.Fatalf("a cluster with nothing to spool should not be an error: %v", err)
	}
	meta := res.(map[string]interface{})["metadata"].(map[string]interface{})
	if meta["procs_spooled"] != 0 {
		t.Errorf("procs_spooled = %v, want 0", meta["procs_spooled"])
	}
}

func heldForSpooling(t *testing.T, ctx context.Context, schedd *htcondor.Schedd, cluster int) int {
	t.Helper()
	ads, _, err := schedd.QueryWithOptions(ctx,
		fmt.Sprintf("ClusterId == %d && JobStatus == 5 && HoldReasonCode == 16", cluster),
		&htcondor.QueryOptions{Projection: []string{"ClusterId", "ProcId"}, Limit: -1})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	return len(ads)
}

func waitForHeldForSpooling(t *testing.T, ctx context.Context, schedd *htcondor.Schedd, cluster, want int) {
	t.Helper()
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); {
		if n := heldForSpooling(t, ctx, schedd, cluster); n == want {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("cluster %d never had %d procs held for spooling (have %d)",
		cluster, want, heldForSpooling(t, ctx, schedd, cluster))
}

func waitForNoneHeldForSpooling(t *testing.T, ctx context.Context, schedd *htcondor.Schedd, cluster int) {
	t.Helper()
	for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline); {
		if heldForSpooling(t, ctx, schedd, cluster) == 0 {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("cluster %d still has %d procs held for spooling after a cluster-wide upload",
		cluster, heldForSpooling(t, ctx, schedd, cluster))
}

// currentUserForTest is the identity the harness's jobs are owned by:
// the test process's own user. The owner scope compares against the job
// ad's Owner, so anything else finds nothing and the test would look
// like a spooling failure.
func currentUserForTest(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatalf("looking up the current user: %v", err)
	}
	return u.Username
}
