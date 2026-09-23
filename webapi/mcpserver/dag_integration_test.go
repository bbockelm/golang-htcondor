//go:build integration

package mcpserver

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// TestMCPSubmitDagIntegration runs a real DAGMan workflow, submitted the
// way a remote agent would: the whole workflow inline in one tool call,
// spooled to a schedd this process shares no working directory with.
//
// The point is the mechanism, not the graph. A two-node diamond tells us
// almost nothing on its own -- what it tells us is that every link in a
// chain of assumptions held:
//
//   - a scheduler-universe job survives remote submission with spooling,
//   - the schedd's spool rewrite left condor_dagman's absolute path alone
//     while moving Iwd to the spool directory,
//   - DAGMan found its .dag there and could parse it,
//   - the node jobs DAGMan submitted itself ran and produced output,
//   - and that output came back into the DAG's spool directory.
//
// Any one of those failing produces a DAG job that submits cleanly and
// then quietly does nothing, which is exactly the failure a unit test
// cannot see.
//
// Run with: go test -tags=integration -run TestMCPSubmitDagIntegration -v ./mcpserver/
func TestMCPSubmitDagIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH")
	}
	dagmanPath, err := exec.LookPath("condor_dagman")
	if err != nil {
		t.Skip("condor_dagman not found in PATH")
	}

	// DAGMAN_AVOID_SLASH_TMP is HTCondor's own testing-only knob for
	// exactly this situation (dagman_main.cpp: "DO NOT DOCUMENT this
	// testing-only knob"). DAGMan refuses to put its default node log
	// under /tmp -- the log has to be durable and visible to the schedd,
	// and /tmp is often neither -- and DAGMAN_USE_STRICT makes that
	// warning fatal. This harness puts its SPOOL in the system temp
	// directory, which on Linux is /tmp, so the workflow aborts before
	// parsing.
	//
	// This does not paper over a production problem: a real access point
	// keeps SPOOL somewhere like /var/lib/condor/spool, where the node
	// log belongs and the check never fires. It is the harness's choice
	// of directory, not anything this tool does, that trips it -- which
	// is why the workflow runs unchanged on macOS, where the temp
	// directory is under /var/folders.
	harness := htcondor.SetupCondorHarnessWithConfig(t, "DAGMAN_AVOID_SLASH_TMP = False\n")
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

	// The harness is a personal pool with its configuration somewhere
	// other than /etc/condor, so DAGMan needs CONDOR_CONFIG to find it.
	// This is the same knob a site uses when its access point is laid out
	// unusually (HTTP_API_DAGMAN_ENVIRONMENT), so the test exercises the
	// production path rather than a test-only shortcut.
	condorConfig := harness.GetConfigFile()
	if condorConfig == "" {
		t.Fatal("the harness has no config file; DAGMan would run against the wrong pool")
	}

	server, err := NewServer(Config{
		Schedd:            schedd,
		Logger:            logger,
		Delegated:         true,
		DagmanPath:        dagmanPath,
		DagmanEnvironment: map[string]string{"CONDOR_CONFIG": condorConfig},
	})
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
		10*time.Minute)
	defer cancel()

	// A chain, with the node descriptions inline so the workflow is one
	// self-contained file -- the shape the tool steers callers toward --
	// plus one separate .sub file, so the staging of a referenced file is
	// covered too.
	//
	// Each node writes its own marker rather than appending to a shared
	// file. An earlier version of this test had them append, and it passed
	// for the wrong reason: the harness runs its execute node on this
	// machine, so HTCondor skipped file transfer and every node appended to
	// the real spool directory. On any pool where the nodes actually
	// transfer, each would have started with an empty sandbox and clobbered
	// the file. should_transfer_files is now explicit for the same reason --
	// the test should exercise output coming BACK to the DAG's Iwd, which
	// is the mechanism in question, not a same-machine shortcut.
	//
	// Ordering is not asserted from file contents. DAGMan enforces the
	// graph, and it reports having done so: a non-zero exit means some node
	// failed or ran out of order, which waitForDagComplete already treats
	// as a failure.
	dag := `
SUBMIT-DESCRIPTION step {
    executable = /bin/sh
    transfer_executable = false
    should_transfer_files = YES
    when_to_transfer_output = ON_EXIT
    arguments = "-c 'echo ran > $(NodeName).done'"
    transfer_output_files = $(NodeName).done
    output = $(NodeName).out
    error  = $(NodeName).err
    log    = nodes.log
    request_cpus = 1
    request_memory = 64
    request_disk = 64
}
JOB A step
JOB B step
JOB C final.sub
VARS A NodeName="A"
VARS B NodeName="B"
PARENT A CHILD B
PARENT B CHILD C
`
	finalSub := `
executable = /bin/sh
transfer_executable = false
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
arguments = "-c 'echo ran > C.done'"
transfer_output_files = C.done
output = C.out
error  = C.err
log    = nodes.log
request_cpus = 1
request_memory = 64
request_disk = 64
queue
`

	text, meta, isErr := callToolOverMCP(t, server, ctx, "submit_dag", map[string]interface{}{
		"dag":        dag,
		"dag_name":   "diamond.dag",
		"batch_name": "mcp-dag-itest",
		"files":      map[string]interface{}{"final.sub": finalSub},
	})
	if isErr {
		t.Fatalf("submit_dag failed: %s", text)
	}
	t.Logf("submit_dag said:\n%s", text)

	clusterFloat, ok := meta["cluster_id"].(float64)
	if !ok {
		t.Fatalf("submit_dag returned no cluster_id: %v", meta)
	}
	cluster := int(clusterFloat)
	defer func() {
		rmCtx, rmCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rmCancel()
		_, _ = schedd.RemoveJobs(rmCtx, fmt.Sprintf("ClusterId == %d", cluster), "dag test cleanup")
	}()

	// Both the DAG and the separately-supplied submit file have to be in
	// the spool allow-set. A name missing from it is SKIPPED at spool
	// time rather than rejected, so this is the check that the computed
	// list -- not a hand-written one -- is what got sent.
	files, _ := meta["input_files"].([]interface{})
	var got []string
	for _, f := range files {
		got = append(got, fmt.Sprint(f))
	}
	for _, want := range []string{"diamond.dag", "final.sub"} {
		if !slices.Contains(got, want) {
			t.Errorf("input_files = %v, missing %s", got, want)
		}
	}

	// DAGMan writes its own diagnosis into the spool. Without this, a
	// failure here reports only that nothing happened, and the one file
	// that says why is discarded with the harness -- which cost a full
	// CI round trip the first time this went red.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		dumpCtx, dumpCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer dumpCancel()
		files := readSpoolDir(harness.GetSpoolDir(), cluster)
		if len(files) == 0 {
			// Falling back to the transfer covers the case where the
			// harness laid the spool out differently; reading the disk
			// is preferred because it works for a job that has already
			// finished, which a sandbox transfer may not.
			files = tryFetchSandbox(dumpCtx, schedd, cluster)
		}
		if len(files) == 0 {
			t.Logf("the workflow's spool could not be read, so DAGMan's own logs are unavailable")
			return
		}
		t.Logf("workflow spool contains: %v", keysOf(files))
		for _, name := range []string{"diamond.dagman.out", "diamond.lib.err", "diamond.lib.out"} {
			if body, ok := files[name]; ok && strings.TrimSpace(body) != "" {
				t.Logf("--- %s ---\n%s", name, tailLines(body, 40))
			}
		}
	})

	// DAGMan has to actually start. Until it does, the job is either held
	// for spooling or idle, and nothing distinguishes "about to run" from
	// "will never run" except waiting.
	waitForDagProgress(t, ctx, server, cluster, 5*time.Minute)

	// And it has to finish: the DAGMan job leaves the queue when the
	// workflow completes.
	waitForDagComplete(t, ctx, schedd, cluster, 8*time.Minute)

	// The proof that the workflow really ran is in its spool directory:
	// each node's output came back there. If DAGMan had started in the
	// wrong directory, or the node jobs' outputs had not returned to the
	// DAG's Iwd, none of these would be here.
	//
	// C is the one that matters most: its submit description was a
	// separately staged file rather than an inline block, so its presence
	// is what proves a referenced file reached the spool and DAGMan found
	// it there.
	sandbox := fetchSandbox(t, ctx, schedd, cluster)
	for _, node := range []string{"A", "B", "C"} {
		if _, ok := sandbox[node+".done"]; !ok {
			t.Errorf("node %s produced no output in the workflow's spool; files present: %v",
				node, keysOf(sandbox))
		}
	}
}

// TestMCPSubmitDagRefusesAnUnstartableWorkflowIntegration checks the
// refusal against a real schedd, because the value of refusing is that
// nothing reaches the queue. A unit test can see the error; only this can
// see that no cluster was created.
func TestMCPSubmitDagRefusesAnUnstartableWorkflowIntegration(t *testing.T) {
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
		2*time.Minute)
	defer cancel()

	before := countJobs(t, ctx, schedd)

	text, _, isErr := callToolOverMCP(t, server, ctx, "submit_dag", map[string]interface{}{
		"dag": "JOB A a.sub\nJOB B b.sub\nPARENT A CHILD B\nPARENT B CHILD A\n",
		"files": map[string]interface{}{
			"a.sub": "executable = /bin/true\nqueue\n",
			"b.sub": "executable = /bin/true\nqueue\n",
		},
	})
	if !isErr {
		t.Fatalf("a cyclic DAG was accepted: %s", text)
	}
	if !strings.Contains(text, "cycle") {
		t.Errorf("the refusal does not say the graph has a cycle: %s", text)
	}
	if after := countJobs(t, ctx, schedd); after != before {
		t.Errorf("the refusal still left something in the queue: %d jobs before, %d after", before, after)
	}
}

// waitForDagProgress waits until DAGMan has published node counts into
// its own job ad, which is the first moment it is provably running the
// workflow rather than merely queued.
func waitForDagProgress(t *testing.T, ctx context.Context, server *Server, cluster int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		text, meta, isErr := callToolOverMCP(t, server, ctx, "dag_status", map[string]interface{}{
			"job_id": fmt.Sprintf("%d", cluster),
		})
		if isErr {
			// The job leaving the queue this early means the workflow
			// failed outright; there is nothing to wait for.
			t.Fatalf("dag_status failed while waiting for DAGMan to start: %s", text)
		}
		last = text
		// A manager job that has already left Running without publishing
		// anything is never going to: it failed to start, or exited
		// immediately. Waiting out the window would cost five minutes to
		// learn what this call already knows.
		if status, ok := meta["job_status"].(float64); ok {
			switch int(status) {
			case 3, 4:
				t.Fatalf("the DAGMan job reached %s without ever publishing progress -- "+
					"it started and exited without running the workflow. Last status:\n%s",
					describeJobStatus(int(status)), last)
			case 5:
				// Spooling (code 16) clears on its own. Any other hold
				// does not, so waiting out the window would only cost
				// five minutes to learn what this call already knows.
				if code, ok := meta["hold_reason_code"].(float64); !ok || int(code) != 16 {
					t.Fatalf("the DAGMan job is held and will not start. Last status:\n%s", last)
				}
			}
		}
		if total, ok := meta["dag_nodestotal"].(float64); ok && total > 0 {
			t.Logf("DAGMan is running: %s", text)
			if total != 3 {
				t.Errorf("DAG_NodesTotal = %v, want 3 -- DAGMan parsed a different graph than we sent", total)
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context expired waiting for DAGMan to start; last status:\n%s", last)
		case <-time.After(5 * time.Second):
		}
	}
	t.Fatalf("DAGMan never published progress within %s; last status:\n%s", timeout, last)
}

// waitForDagComplete waits for the DAGMan job to reach Completed.
//
// It waits for a status, not for the job to disappear: SubmitRemote sets
// LeaveJobInQueue so a remotely-submitted job stays in the queue after it
// finishes, which is what makes its spool directory still there to
// retrieve. A test that waited for the job to vanish would time out on a
// workflow that succeeded.
func waitForDagComplete(t *testing.T, ctx context.Context, schedd *htcondor.Schedd, cluster int, timeout time.Duration) {
	t.Helper()
	constraint := fmt.Sprintf("ClusterId == %d", cluster)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ads, err := schedd.Query(ctx, constraint,
			[]string{"ClusterId", "JobStatus", "HoldReason", "HoldReasonCode", "ExitCode"})
		if err != nil {
			t.Fatalf("querying the DAGMan job: %v", err)
		}
		if len(ads) == 0 {
			t.Fatal("the DAGMan job left the queue entirely; its spool is gone and the workflow cannot be checked")
		}
		status, _ := ads[0].EvaluateAttrInt("JobStatus")
		switch status {
		case 4:
			if code, ok := ads[0].EvaluateAttrInt("ExitCode"); ok && code != 0 {
				t.Fatalf("DAGMan exited %d: the workflow failed", code)
			}
			return
		case 5:
			// A spooling hold clears on its own; anything else will not.
			if code, ok := ads[0].EvaluateAttrInt("HoldReasonCode"); !ok || code != 16 {
				reason, _ := ads[0].EvaluateAttrString("HoldReason")
				t.Fatalf("the DAGMan job went on hold and will not finish: %s", reason)
			}
		case 3:
			t.Fatal("the DAGMan job was removed")
		}
		select {
		case <-ctx.Done():
			t.Fatal("context expired waiting for the workflow to finish")
		case <-time.After(5 * time.Second):
		}
	}
	t.Fatalf("the workflow did not finish within %s", timeout)
}

// fetchSandbox retrieves a finished job's spool directory as a map of
// file name to contents.
func fetchSandbox(t *testing.T, ctx context.Context, schedd *htcondor.Schedd, cluster int) map[string]string {
	t.Helper()
	var buf bytes.Buffer
	errCh := schedd.ReceiveJobSandbox(ctx, fmt.Sprintf("ClusterId == %d", cluster), &buf)
	if err := <-errCh; err != nil {
		t.Fatalf("retrieving the workflow's spool: %v", err)
	}
	out := map[string]string{}
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reading the spool tar: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("reading %s from the spool tar: %v", hdr.Name, err)
		}
		out[path.Base(hdr.Name)] = string(body)
	}
	return out
}

func countJobs(t *testing.T, ctx context.Context, schedd *htcondor.Schedd) int {
	t.Helper()
	ads, err := schedd.Query(ctx, "true", []string{"ClusterId"})
	if err != nil {
		t.Fatalf("counting jobs: %v", err)
	}
	return len(ads)
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// tryFetchSandbox retrieves a job's spool without failing the test. It is
// for diagnosing a failure that has already happened, where a second
// error would only hide the first.
func tryFetchSandbox(ctx context.Context, schedd *htcondor.Schedd, cluster int) map[string]string {
	var buf bytes.Buffer
	if err := <-schedd.ReceiveJobSandbox(ctx, fmt.Sprintf("ClusterId == %d", cluster), &buf); err != nil {
		return nil
	}
	out := map[string]string{}
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if err != nil {
			return out
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return out
		}
		out[path.Base(hdr.Name)] = string(body)
	}
}

// tailLines returns the last n lines, so a long log does not bury the
// error that ended it.
func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// readSpoolDir reads a job's spool directory straight off disk.
//
// The harness runs the access point in this process's own filesystem, so
// the files DAGMan wrote are right there -- no transfer, and it works for
// a job that has already left the queue, which is exactly the case worth
// diagnosing.
func readSpoolDir(spool string, cluster int) map[string]string {
	dir := filepath.Join(spool, strconv.Itoa(cluster), "0",
		fmt.Sprintf("cluster%d.proc0.subproc0", cluster))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		out[e.Name()] = string(body)
	}
	return out
}
