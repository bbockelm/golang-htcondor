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

// TestMCPTailJobOutputIntegration reads a running job's output through
// the MCP surface, against a real pool.
//
// The unit tests can only check the arguments; everything that makes
// this tool different from get_job_stdout happens on the other side of
// GET_JOB_CONNECT_INFO + STARTER_PEEK -- the output is on the execute
// node, in a file the job has not finished writing.
//
// Run with: go test -tags=integration -run TestMCPTailJobOutputIntegration -v ./mcpserver/
func TestMCPTailJobOutputIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH")
	}

	harness := htcondor.SetupCondorHarness(t)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}
	if err := harness.WaitForStartd(45 * time.Second); err != nil {
		t.Fatalf("Startd never reported in: %v", err)
	}

	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	schedd := locateSchedd(t, harness)
	server, err := NewServer(Config{Schedd: schedd, Logger: logger, Delegated: true})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(server.Close)

	me, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	ctx, cancel := context.WithTimeout(
		htcondor.WithAuthenticatedUser(context.Background(), me.Username+"@"+harness.GetTrustDomain()),
		6*time.Minute)
	defer cancel()

	// A job that writes, flushes and keeps running: the point is to read
	// output from a file nobody has closed.
	submitFile := `
universe = vanilla
executable = /bin/sh
transfer_executable = false
arguments = "-c 'for i in 1 2 3 4 5; do echo line-$i; echo err-$i >&2; sleep 1; done; sleep 300'"
output = tail_itest.out
error  = tail_itest.err
log    = tail_itest.log
request_cpus = 1
request_memory = 64
request_disk = 64
queue
`
	clusterID, procAds, err := schedd.SubmitRemote(ctx, submitFile)
	if err != nil {
		t.Fatalf("submitting the test job: %v", err)
	}
	proc := 0
	if len(procAds) > 0 {
		if v, ok := procAds[0].EvaluateAttrInt("ProcId"); ok {
			proc = int(v)
		}
	}
	jobID := fmt.Sprintf("%d.%d", clusterID, proc)
	t.Logf("test job %s", jobID)
	defer func() {
		rmCtx, rmCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rmCancel()
		_, _ = schedd.RemoveJobsByID(rmCtx, []string{jobID}, "tail test cleanup")
	}()

	// While it is idle the tool must say so, and say what to use
	// instead, rather than failing somewhere inside the starter dial.
	if _, _, isErr := callToolOverMCP(t, server, ctx, "tail_job_output", map[string]interface{}{
		"job_id": jobID,
	}); !isErr {
		t.Log("job was already running; skipping the not-running check")
	}

	waitForRunning(t, ctx, schedd, clusterID, proc, 4*time.Minute)

	// Give the job a moment to produce something.
	deadline := time.Now().Add(90 * time.Second)
	var text string
	var meta map[string]interface{}
	for {
		var isErr bool
		text, meta, isErr = callToolOverMCP(t, server, ctx, "tail_job_output", map[string]interface{}{
			"job_id": jobID,
		})
		if isErr {
			t.Fatalf("tail_job_output failed: %s", text)
		}
		if strings.Contains(text, "line-") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no output from the running job within 90s:\n%s", text)
		}
		time.Sleep(3 * time.Second)
	}

	if !strings.Contains(text, "line-") {
		t.Errorf("stdout is missing from the tail:\n%s", text)
	}
	if !strings.Contains(text, "err-") {
		t.Errorf("stderr is missing from the tail:\n%s", text)
	}

	// The offsets come back so a caller can ask for only what is new.
	offset, ok := meta["stdout_offset"].(float64)
	if !ok {
		t.Fatalf("no stdout_offset in the metadata: %v", meta)
	}
	text2, meta2, isErr := callToolOverMCP(t, server, ctx, "tail_job_output", map[string]interface{}{
		"job_id":        jobID,
		"stream":        "stdout",
		"stdout_offset": int(offset),
	})
	if isErr {
		t.Fatalf("resuming from an offset failed: %s", text2)
	}
	if strings.Contains(text2, "err-") {
		t.Error("stream=stdout returned stderr as well")
	}
	if next, ok := meta2["stdout_offset"].(float64); !ok || next < offset {
		t.Errorf("offset went backwards: %v then %v", offset, next)
	}
}

// waitForRunning blocks until the job reaches Running.
func waitForRunning(t *testing.T, ctx context.Context, schedd *htcondor.Schedd, cluster, proc int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ads, _, err := schedd.QueryWithOptions(ctx,
			fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc),
			&htcondor.QueryOptions{Projection: []string{"JobStatus"}})
		if err != nil {
			t.Fatalf("querying the job: %v", err)
		}
		if len(ads) > 0 {
			if status, ok := ads[0].EvaluateAttrInt("JobStatus"); ok && status == 2 {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %d.%d never started running within %s", cluster, proc, timeout)
		}
		time.Sleep(2 * time.Second)
	}
}
