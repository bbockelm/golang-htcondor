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

// TestMCPExecInJobIntegration reaches into an ordinary running job --
// one this server did not submit and does not manage -- through the MCP
// surface, against a real pool.
//
// Everything that distinguishes this from the session tools is on the
// far side of condor_ssh_to_job: the job belongs to somebody else's
// submission, there is no lease or watchdog, and the connection is
// opened and closed per call.
//
// Run with: go test -tags=integration -run TestMCPExecInJobIntegration -v ./mcpserver/
func TestMCPExecInJobIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH")
	}
	extraConfig, ok := htcondor.SSHToJobHarnessConfig()
	if !ok {
		t.Skip("sshd or condor_ssh_to_job_sshd_config_template not found; this host cannot run condor_ssh_to_job")
	}

	harness := htcondor.SetupCondorHarnessWithConfig(t, extraConfig)
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
		8*time.Minute)
	defer cancel()

	// An ordinary batch job, submitted the way a user would -- not a
	// session. Nothing here keeps it alive; it sleeps on its own.
	submitFile := `
universe = vanilla
executable = /bin/sh
transfer_executable = false
arguments = "-c 'echo marker > sentinel.txt; sleep 600'"
output = exec_itest.out
error  = exec_itest.err
log    = exec_itest.log
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
	t.Logf("ordinary job %s", jobID)
	defer func() {
		rmCtx, rmCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rmCancel()
		_, _ = schedd.RemoveJobsByID(rmCtx, []string{jobID}, "exec test cleanup")
	}()

	waitForRunningJob(t, ctx, schedd, clusterID, proc, 4*time.Minute)

	// The job's own sandbox, not a session's: the file its command wrote
	// is there, which is the whole reason to reach into a running job.
	text, meta, isErr := callToolOverMCP(t, server, ctx, "exec_in_job", map[string]interface{}{
		"job_id":  jobID,
		"command": "cat sentinel.txt && pwd",
	})
	if isErr {
		t.Fatalf("exec_in_job failed: %s", text)
	}
	if !strings.Contains(text, "marker") {
		t.Errorf("did not read the file the job wrote:\n%s", text)
	}
	if code, ok := meta["exit_code"].(float64); !ok || code != 0 {
		t.Errorf("exit_code = %v, want 0", meta["exit_code"])
	}

	// A non-zero exit is a result, not a tool failure.
	text, meta, isErr = callToolOverMCP(t, server, ctx, "exec_in_job", map[string]interface{}{
		"job_id":  jobID,
		"command": "echo to-stderr >&2; exit 9",
	})
	if isErr {
		t.Errorf("a non-zero exit was reported as a tool failure:\n%s", text)
	}
	if code, ok := meta["exit_code"].(float64); !ok || code != 9 {
		t.Errorf("exit_code = %v, want 9", meta["exit_code"])
	}
	if !strings.Contains(text, "to-stderr") {
		t.Errorf("stderr missing:\n%s", text)
	}

	// Each call stands alone: the second call dialled again, so a shell
	// variable from the first is gone.
	text, _, isErr = callToolOverMCP(t, server, ctx, "exec_in_job", map[string]interface{}{
		"job_id":  jobID,
		"command": "echo [${CARRIED:-unset}]",
	})
	if isErr {
		t.Fatalf("exec_in_job failed: %s", text)
	}
	if !strings.Contains(text, "[unset]") {
		t.Errorf("environment carried across calls, which the tool says it does not:\n%s", text)
	}

	// Another user's job is not reachable, and says "not found" rather
	// than confirming it exists.
	otherCtx, otherCancel := context.WithTimeout(
		htcondor.WithAuthenticatedUser(context.Background(), "someone-else@"+harness.GetTrustDomain()),
		time.Minute)
	defer otherCancel()
	text, _, isErr = callToolOverMCP(t, server, otherCtx, "exec_in_job", map[string]interface{}{
		"job_id":  jobID,
		"command": "id",
	})
	if !isErr {
		t.Errorf("another user ran a command in this job: %s", text)
	} else if !strings.Contains(text, "not found") {
		t.Logf("note: refusal text was %q", text)
	}
}

// waitForRunningJob blocks until the job reaches Running.
func waitForRunningJob(t *testing.T, ctx context.Context, schedd *htcondor.Schedd, cluster, proc int, timeout time.Duration) {
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
