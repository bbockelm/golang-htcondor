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

	// Fan out, then gather: the shape nearly every real workflow has, and
	// the one this tool's own description now teaches. Two producer nodes
	// share ONE inline submit description and are told apart only by VARS,
	// so the files they declare are macro-valued (`result_$(sample).txt`)
	// while the gather node names the literals it reads. The pre-submit
	// check has to see those as the same files -- it did not, and answered
	// a perfectly good workflow with three warnings that the files it
	// produces were missing.
	//
	// The gather node's description is a separately staged .sub file, so
	// the staging of a referenced file is covered too.
	//
	// Each node writes its own file rather than appending to a shared one.
	// An earlier version of this test had them append, and it passed for
	// the wrong reason: the harness runs its execute node on this machine,
	// so HTCondor skipped file transfer and every node appended to the real
	// spool directory. On any pool where the nodes actually transfer, each
	// would have started with an empty sandbox and clobbered the file.
	// should_transfer_files is explicit for the same reason -- the test
	// should exercise output coming BACK to the DAG's Iwd, which is the
	// mechanism in question, not a same-machine shortcut.
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
    arguments = "-c 'echo result-$(sample) > result_$(sample).txt'"
    transfer_output_files = result_$(sample).txt
    output = produce_$(sample).out
    error  = produce_$(sample).err
    log    = nodes.log
    request_cpus = 1
    request_memory = 64
    request_disk = 64
}
JOB produce_1 step
JOB produce_2 step
JOB COMBINE combine.sub
SCRIPT PRE produce_1 setup
VARS produce_1 sample="1"
VARS produce_2 sample="2"
PARENT produce_1 produce_2 CHILD COMBINE
SET_JOB_ATTR DagTestMarker = "set-from-dag"
ENV SET DAG_TEST_VAR=hello
`
	// A PRE script with no extension. DAGMan execs it out of the spool
	// directory, so it has to arrive with the execute bit set -- and the
	// rule that set it used to be "the name ends in .sh", which is the
	// one thing this file's name does not do. Staged 0644 it fails with
	// EACCES, reported as a node failure with no stated cause.
	preScript := "#!/bin/sh\nexit 0\n"

	// The gather node reads what the producers made, by name. Nothing
	// stages result_1.txt or result_2.txt: they exist only because the
	// workflow ran, and they reach this node because a node job's Iwd IS
	// the DAG's spool directory.
	combineSub := `
executable = /bin/sh
transfer_executable = false
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
arguments = "-c 'cat result_1.txt result_2.txt > combined.txt'"
transfer_input_files = result_1.txt, result_2.txt
transfer_output_files = combined.txt
output = combine.out
error  = combine.err
log    = nodes.log
request_cpus = 1
request_memory = 64
request_disk = 64
queue
`

	text, meta, isErr := callToolOverMCP(t, server, ctx, "submit_dag", map[string]interface{}{
		"dag":        dag,
		"dag_name":   "fanout.dag",
		"batch_name": "mcp-dag-itest",
		"files":      map[string]interface{}{"combine.sub": combineSub, "setup": preScript},
	})
	if isErr {
		t.Fatalf("submit_dag failed: %s", text)
	}
	t.Logf("submit_dag said:\n%s", text)

	// The live regression: the producers declare `result_$(sample).txt`
	// and the gather node names `result_1.txt`. Comparing those without
	// expanding the node's VARS reported each produced file as missing --
	// three warnings on a correct workflow, which is how a caller learns
	// to ignore the notes altogether.
	notes, _ := meta["notes"].([]interface{})
	for _, n := range notes {
		note := fmt.Sprint(n)
		if strings.Contains(note, "result_1.txt") || strings.Contains(note, "result_2.txt") {
			t.Errorf("the pre-submit check reported a file an ancestor produces: %s", note)
		}
	}

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
	for _, want := range []string{"fanout.dag", "combine.sub", "setup"} {
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
		for _, name := range []string{"fanout.dagman.out", "fanout.lib.err", "fanout.lib.out"} {
			if body, ok := files[name]; ok && strings.TrimSpace(body) != "" {
				t.Logf("--- %s ---\n%s", name, tailLines(body, 40))
			}
		}
	})

	// DAGMan has to actually start. Until it does, the job is either held
	// for spooling or idle, and nothing distinguishes "about to run" from
	// "will never run" except waiting.
	waitForDagProgress(t, ctx, server, cluster, 5*time.Minute)

	// SET_JOB_ATTR and ENV SET are honoured, and the proof is in the
	// manager job's own ad -- the only place either lands.
	//
	// Both were silently dropped before: the parser knew the keywords
	// and collected nothing, so a DAG that set an attribute its own
	// PRE/POST scripts or a site's policy expression depended on
	// submitted cleanly and behaved as if the line had not been written.
	// Nothing in the submit path would have noticed, which is why this
	// is checked against a real schedd rather than against the generated
	// submit file.
	checkDagManagerAttributes(t, ctx, schedd, cluster)

	// And it has to finish: the DAGMan job leaves the queue when the
	// workflow completes.
	//
	// The node jobs are watched while it runs rather than afterwards,
	// because a node job leaves the queue the moment it finishes. What
	// is being checked is the link between them and the manager --
	// DAGManJobId -- which is what get_job's workflow section points a caller at and
	// what OtherJobRemoveRequirements matches on, so nothing else in
	// this test would notice if DAGMan stopped setting it.
	sawNodeJobs := 0
	waitForDagComplete(t, ctx, schedd, cluster, 8*time.Minute, func() {
		ads, err := schedd.Query(ctx, fmt.Sprintf("DAGManJobId == %d", cluster),
			[]string{"ClusterId", "DAGNodeName"})
		if err == nil && len(ads) > sawNodeJobs {
			sawNodeJobs = len(ads)
		}
	})
	if sawNodeJobs == 0 {
		t.Error("no node job ever carried DAGManJobId == the manager's cluster; the workflow's jobs are " +
			"not attributable to it, which is what get_job's workflow section and the remove-the-whole-" +
			"workflow rule both depend on")
	}

	// The proof that the workflow really ran is in its spool directory:
	// each node's output came back there. If DAGMan had started in the
	// wrong directory, or the node jobs' outputs had not returned to the
	// DAG's Iwd, none of these would be here.
	sandbox := fetchSandbox(t, ctx, schedd, cluster)
	for _, name := range []string{"result_1.txt", "result_2.txt", "combined.txt"} {
		if _, ok := sandbox[name]; !ok {
			t.Errorf("%s is not in the workflow's spool; files present: %v", name, keysOf(sandbox))
		}
	}
	// combined.txt is the whole inter-stage flow in one file, and the
	// thing the tool's description now promises: two nodes wrote files
	// that came back to the DAG's directory, and a third read them from
	// there by name. Its CONTENTS are what proves it -- an empty
	// combined.txt would mean the gather node ran with neither input.
	//
	// COMBINE's submit description was a separately staged .sub file
	// rather than an inline block, so this also proves a referenced file
	// reached the spool and DAGMan found it there.
	combined := sandbox["combined.txt"]
	for _, marker := range []string{"result-1", "result-2"} {
		if !strings.Contains(combined, marker) {
			t.Errorf("combined.txt = %q, missing %q: the gather node did not get what the producers made",
				combined, marker)
		}
	}

	// Second phase, on the same harness: removing the workflow has to
	// remove the work.
	//
	// The manager job carries OtherJobRemoveRequirements = "DAGManJobId
	// =?= $(cluster)", and $(cluster) is a submit-file macro -- if it
	// expanded to nothing, or to the wrong thing, the expression would
	// still be accepted and every node job would be left running after
	// the workflow it belongs to was gone. Nothing observable at submit
	// time distinguishes the two, which is why this was broken without
	// anyone noticing: the only symptom is orphaned jobs on someone
	// else's access point.
	removeTakesTheNodeJobsWithIt(t, ctx, server, schedd)
}

// removeTakesTheNodeJobsWithIt submits a workflow whose one node sleeps,
// waits for that node to be RUNNING, removes the manager job through the
// tool a caller would use, and checks the node job goes with it.
func removeTakesTheNodeJobsWithIt(t *testing.T, ctx context.Context, server *Server, schedd *htcondor.Schedd) {
	t.Helper()
	dag := `
JOB sleeper {
    executable = /bin/sleep
    transfer_executable = false
    should_transfer_files = YES
    when_to_transfer_output = ON_EXIT
    arguments = "600"
    output = sleeper.out
    error  = sleeper.err
    log    = sleeper.log
    request_cpus = 1
    request_memory = 64
    request_disk = 64
}
`
	text, meta, isErr := callToolOverMCP(t, server, ctx, "submit_dag", map[string]interface{}{
		"dag":        dag,
		"dag_name":   "sleeper.dag",
		"batch_name": "mcp-dag-remove-itest",
	})
	if isErr {
		t.Fatalf("submit_dag failed: %s", text)
	}
	clusterFloat, ok := meta["cluster_id"].(float64)
	if !ok {
		t.Fatalf("submit_dag returned no cluster_id: %v", meta)
	}
	cluster := int(clusterFloat)
	defer func() {
		rmCtx, rmCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rmCancel()
		_, _ = schedd.RemoveJobs(rmCtx, fmt.Sprintf("ClusterId == %d || DAGManJobId == %d", cluster, cluster),
			"dag remove test cleanup")
	}()

	// Wait for the node job to be RUNNING. A node job that is merely
	// submitted proves nothing: the interesting case is the one where
	// work is in flight on an execute machine.
	nodeConstraint := fmt.Sprintf("DAGManJobId == %d", cluster)
	deadline := time.Now().Add(3 * time.Minute)
	running := false
	for time.Now().Before(deadline) && !running {
		ads, err := schedd.Query(ctx, nodeConstraint, []string{"ClusterId", "ProcId", "JobStatus"})
		if err != nil {
			t.Fatalf("querying the node job: %v", err)
		}
		for _, ad := range ads {
			if st, _ := ad.EvaluateAttrInt("JobStatus"); st == 2 {
				running = true
			}
		}
		if !running {
			time.Sleep(3 * time.Second)
		}
	}
	if !running {
		t.Fatal("the sleeping node job never started; there is nothing for the removal to have to clean up")
	}

	text, _, isErr = callToolOverMCP(t, server, ctx, "remove_job", map[string]interface{}{
		"job_id": fmt.Sprintf("%d.0", cluster),
		"reason": "dag removal test",
	})
	if isErr {
		t.Fatalf("remove_job on the DAGMan job failed: %s", text)
	}

	// The node job has to leave the queue on its own. The schedd acts on
	// OtherJobRemoveRequirements when the manager job is removed, so a
	// node job still in the queue a minute later is a workflow whose
	// removal did not remove the work.
	deadline = time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		ads, err := schedd.Query(ctx, nodeConstraint, []string{"ClusterId", "ProcId", "JobStatus"})
		if err != nil {
			t.Fatalf("querying the node job: %v", err)
		}
		left := true
		for _, ad := range ads {
			if st, _ := ad.EvaluateAttrInt("JobStatus"); st != 3 {
				left = false
			}
		}
		if left {
			return
		}
		time.Sleep(3 * time.Second)
	}
	ads, _ := schedd.Query(ctx, nodeConstraint, []string{"ClusterId", "ProcId", "JobStatus"})
	t.Errorf("removing the DAGMan job left %d node job(s) in the queue: the workflow is gone and its work "+
		"is still running (OtherJobRemoveRequirements did not match)", len(ads))
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
		text, meta, isErr := callToolOverMCP(t, server, ctx, "get_job", map[string]interface{}{
			"job_id": fmt.Sprintf("%d.0", cluster),
		})
		if isErr {
			// The job leaving the queue this early means the workflow
			// failed outright; there is nothing to wait for.
			t.Fatalf("get_job failed while waiting for DAGMan to start: %s", text)
		}
		last = text
		// The workflow's progress lives under "dag": get_job adds it for
		// a DAGMan manager job and for nothing else, so an empty object
		// here would mean the detection stopped recognizing one.
		dag, _ := meta["dag"].(map[string]interface{})
		if dag == nil {
			t.Fatalf("get_job returned no dag object for the DAGMan job -- the workflow section is not "+
				"being attached. Metadata: %v\nText:\n%s", meta, text)
		}
		// A manager job that has already left Running without publishing
		// anything is never going to: it failed to start, or exited
		// immediately. Waiting out the window would cost five minutes to
		// learn what this call already knows.
		if status, ok := dag["job_status"].(float64); ok {
			switch int(status) {
			case 3, 4:
				t.Fatalf("the DAGMan job reached %s without ever publishing progress -- "+
					"it started and exited without running the workflow. Last status:\n%s",
					describeJobStatus(int(status)), last)
			case 5:
				// Spooling (code 16) clears on its own. Any other hold
				// does not, so waiting out the window would only cost
				// five minutes to learn what this call already knows.
				if code, ok := dag["hold_reason_code"].(float64); !ok || int(code) != 16 {
					t.Fatalf("the DAGMan job is held and will not start. Last status:\n%s", last)
				}
			}
		}
		if total, ok := dag["dag_nodestotal"].(float64); ok && total > 0 {
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
// onPoll runs once per polling round, for a caller that needs to observe
// something that only exists WHILE the workflow runs.
func waitForDagComplete(t *testing.T, ctx context.Context, schedd *htcondor.Schedd, cluster int,
	timeout time.Duration, onPoll func()) {
	t.Helper()
	constraint := fmt.Sprintf("ClusterId == %d", cluster)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if onPoll != nil {
			onPoll()
		}
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

// checkDagManagerAttributes verifies that the DAG's SET_JOB_ATTR and ENV
// SET commands reached the manager job.
//
// The environment is asserted on the MANAGER, not on a node job, because
// node jobs do not inherit it: DAGMan submits them as ordinary jobs
// whose environment is whatever their own submit description says. What
// ENV SET buys is DAGMan's own environment, and through it the PRE/POST
// scripts DAGMan execs -- so the manager's Environment attribute is
// where the effect is, and the only place it can be observed.
func checkDagManagerAttributes(t *testing.T, ctx context.Context, schedd *htcondor.Schedd, cluster int) {
	t.Helper()
	ads, err := schedd.Query(ctx, fmt.Sprintf("ClusterId == %d", cluster),
		[]string{"ClusterId", "DagTestMarker", "Environment", "Env"})
	if err != nil {
		t.Fatalf("querying the DAGMan job for its attributes: %v", err)
	}
	if len(ads) == 0 {
		t.Fatalf("the DAGMan job %d.0 is not in the queue", cluster)
	}
	ad := ads[0]

	if marker, ok := ad.EvaluateAttrString("DagTestMarker"); !ok || marker != "set-from-dag" {
		expr, _ := ad.Lookup("DagTestMarker")
		t.Errorf("DagTestMarker = %v (string=%v), want \"set-from-dag\": SET_JOB_ATTR did not reach "+
			"the manager job's ad", expr, ok)
	}

	env, ok := ad.EvaluateAttrString("Environment")
	if !ok {
		env, ok = ad.EvaluateAttrString("Env")
	}
	if !ok {
		e, _ := ad.Lookup("Environment")
		t.Fatalf("the DAGMan job has no Environment string: %v", e)
	}
	if !strings.Contains(env, "DAG_TEST_VAR=hello") {
		t.Errorf("Environment = %q, missing DAG_TEST_VAR=hello: ENV SET did not reach the manager job", env)
	}
	// The generated environment is still intact: ENV SET adds to it.
	if !strings.Contains(env, "_CONDOR_DAGMAN_LOG=") {
		t.Errorf("Environment = %q lost _CONDOR_DAGMAN_LOG; ENV SET replaced it instead of merging", env)
	}
}
