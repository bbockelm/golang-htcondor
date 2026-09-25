//go:build integration

package httpserver

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"os/user"
	"path"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/dagman"
)

// TestJobDagIntegration runs real DAGMan workflows, spooled, and asks the
// endpoint to describe them.
//
// It asserts two things, and the first one is why the second one exists:
//
//  1. A spooled workflow's OWN .dag file never comes back from the
//     access point. TRANSFER_DATA on a spooled job is a changed-file
//     transfer, and a .dag that was staged as input and that DAGMan only
//     reads is never newer than the stage-in catalog. This subtest pins
//     that -- it is the premise the whole design rests on, it cannot be
//     asserted from unit tests, and an earlier version of this endpoint
//     was built on the assumption that it was false.
//
//  2. So the workflow is asked to publish itself instead: DOT and
//     NODE_STATUS_FILE, appended at submit time, make DAGMan write the
//     structure and the per-node state into the spool -- where, because
//     DAGMan created them during the run, the same changed-file transfer
//     does return them. The second workflow is instrumented exactly as
//     the submit path instruments one, and the endpoint reads it end to
//     end.
//
// Run with:
//
//	go test -tags=integration -run TestJobDag -timeout 20m -v ./httpserver/
func TestJobDagIntegration(t *testing.T) {
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

	// DAGMAN_AVOID_SLASH_TMP is HTCondor's own testing-only knob: DAGMan
	// refuses to put its default node log under /tmp, and this harness
	// puts SPOOL in the system temp directory, which on Linux is /tmp.
	// See the same note in mcpserver/dag_integration_test.go.
	harness := htcondor.SetupCondorHarnessWithConfig(t, "DAGMAN_AVOID_SLASH_TMP = False\n")
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}
	if err := harness.WaitForStartd(45 * time.Second); err != nil {
		t.Fatalf("Startd never reported in: %v", err)
	}

	collector := htcondor.NewCollector(harness.GetCollectorAddr())
	location, err := collector.LocateDaemon(context.Background(), "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}
	schedd := htcondor.NewSchedd(location.Name, location.Address)

	me, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	ctx, cancel := context.WithTimeout(
		htcondor.WithAuthenticatedUser(context.Background(), me.Username+"@"+harness.GetTrustDomain()),
		15*time.Minute)
	defer cancel()

	server, err := NewServer(Config{
		ListenAddr:               "127.0.0.1:0",
		ScheddName:               location.Name,
		ScheddAddr:               location.Address,
		UserHeader:               "X-Test-User",
		UserHeaderTrustAnyUnsafe: true, // single host, no proxy: the demo opt-in the other tests use
		SigningKeyPath:           harness.GetSigningKeyPath(),
		TrustDomain:              harness.GetTrustDomain(),
		UIDDomain:                harness.GetTrustDomain(),
		OAuth2DBPath:             harness.GetSpoolDir() + "/dag-graph-oauth2.db",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = server.Start() }()
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	baseURL := ""
	for i := 0; i < 100; i++ {
		if addr := server.GetAddr(); addr != "" {
			baseURL = "http://" + addr
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if baseURL == "" {
		t.Fatal("the API server never reported a listen address")
	}

	// getAs is the endpoint as some identity. The server runs with
	// UserHeader + UserHeaderTrustAnyUnsafe, so a second user costs one
	// header value -- and a second user is what the cache's
	// authorization has to be tested with.
	getAs := func(t *testing.T, as string, cluster int, query string) (int, DagGraphResponse, string) {
		t.Helper()
		url := fmt.Sprintf("%s/api/v1/jobs/%d.0/dag%s", baseURL, cluster, query)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("X-Test-User", as)
		resp, err := (&http.Client{Timeout: 3 * time.Minute}).Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var out DagGraphResponse
		if resp.StatusCode == http.StatusOK {
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatalf("decode %s: %v (body %s)", url, err, body)
			}
		}
		return resp.StatusCode, out, string(body)
	}
	get := func(t *testing.T, cluster int, query string) (int, DagGraphResponse, string) {
		t.Helper()
		return getAs(t, me.Username, cluster, query)
	}

	// Four producers share one submit description and one (empty) parent
	// set and all feed the gather node, so they occupy one position in
	// the workflow and must collapse to a single group; the gather node
	// is a second group with the first as its only parent. That is the
	// assertion this whole test exists to make on real data.
	const dagText = `
SUBMIT-DESCRIPTION step {
    executable = /bin/sh
    transfer_executable = false
    should_transfer_files = YES
    when_to_transfer_output = ON_EXIT
    arguments = "-c 'sleep 5; echo result-$(sample) > result_$(sample).txt'"
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
JOB produce_3 step
JOB produce_4 step
JOB COMBINE combine.sub
VARS produce_1 sample="1"
VARS produce_2 sample="2"
VARS produce_3 sample="3"
VARS produce_4 sample="4"
PARENT produce_1 produce_2 produce_3 produce_4 CHILD COMBINE
`
	const combineSub = `
executable = /bin/sh
transfer_executable = false
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
arguments = "-c 'cat result_1.txt result_2.txt result_3.txt result_4.txt > combined.txt'"
transfer_input_files = result_1.txt, result_2.txt, result_3.txt, result_4.txt
transfer_output_files = combined.txt
output = combine.out
error  = combine.err
log    = nodes.log
request_cpus = 1
request_memory = 64
request_disk = 64
queue
`

	submit := func(t *testing.T, dagName, body string) int {
		t.Helper()
		submitFile, err := dagman.SubmitFile(dagman.SubmitOptions{
			DagName:    dagName,
			DagmanPath: dagmanPath,
			// The spool allow-set is decided at submit time: a file the
			// job ad does not declare cannot be spooled afterwards. The
			// instrumented files are OUTPUTS and belong to neither list.
			InputFiles: []string{dagName, "combine.sub"},
			// The harness keeps its configuration somewhere other than
			// /etc/condor, so DAGMan needs to be told where the pool is.
			ExtraEnv: map[string]string{"CONDOR_CONFIG": harness.GetConfigFile()},
		})
		if err != nil {
			t.Fatalf("dagman.SubmitFile: %v", err)
		}
		cluster, procAds, err := schedd.SubmitRemote(ctx, submitFile)
		if err != nil {
			t.Fatalf("SubmitRemote: %v", err)
		}
		staged := fstest.MapFS{
			dagName:       &fstest.MapFile{Data: []byte(body), Mode: 0o644},
			"combine.sub": &fstest.MapFile{Data: []byte(combineSub), Mode: 0o644},
		}
		if err := schedd.SpoolJobFilesFromFS(ctx, procAds, staged); err != nil {
			t.Fatalf("SpoolJobFilesFromFS: %v", err)
		}
		t.Logf("submitted DAGMan manager %d.0 (%s)", cluster, dagName)
		t.Cleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cleanupCancel()
			_, _ = schedd.RemoveJobsByID(cleanupCtx, []string{fmt.Sprintf("%d.0", cluster)}, "test cleanup")
		})
		return cluster
	}

	// The instrumented one goes through exactly the call the submit path
	// makes, so this test breaks if that ever stops adding the commands.
	instrumented, instr := dagman.Instrument(dagText, "fanout.dag",
		map[string]string{"combine.sub": combineSub})
	for _, want := range []string{"DOT " + instr.DotFile, "NODE_STATUS_FILE " + instr.StatusFile} {
		if !strings.Contains(instrumented, want) {
			t.Fatalf("dagman.Instrument did not add %q:\n%s", want, instrumented)
		}
	}

	plain := submit(t, "plain.dag", dagText)
	visible := submit(t, "fanout.dag", instrumented)

	// (1) The premise. This is not a defect in the handler: the access
	// point has nothing to send.
	t.Run("SpooledDagIsNeverInTheTransfer", func(t *testing.T) {
		// Wait on the predicate the HANDLER uses, not on the file merely
		// existing. DAGMan creates plain.dagman.out immediately and writes
		// "Dag contains" a moment later, and dagmanPastStartup keys on the
		// latter -- so "the file is there" let this proceed seconds before
		// the endpoint would agree DAGMan had started, and the assertion
		// below got the "retry in a few seconds" 409 instead of the one it
		// is about. Calling dagmanPastStartup itself is what keeps the two
		// from drifting apart again.
		deadline := time.Now().Add(5 * time.Minute)
		for {
			files := tryFetchDagSandbox(ctx, schedd, plain)
			if dagmanPastStartup(files) {
				// DAGMan is running and its own log came back, so the
				// transfer is working. The .dag still did not.
				if _, ok := files["plain.dag"]; ok {
					t.Fatalf("a spooled job's .dag came back in the transfer; the changed-file rule no "+
						"longer holds and the reason this endpoint injects DOT and NODE_STATUS_FILE "+
						"has gone away. Files present: %v", sortedKeys(files))
				}
				t.Logf("as expected, the spool transfer holds %v and no plain.dag", sortedKeys(files))
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("DAGMan never got past startup; files present: %v", sortedKeys(files))
			}
			time.Sleep(5 * time.Second)
		}

		// ...and an uninstrumented workflow therefore has no graph to
		// read, which the endpoint has to say in those words rather than
		// as a generic failure.
		status, _, body := get(t, plain, "?refresh=1")
		if status != http.StatusConflict {
			t.Fatalf("status = %d, want 409 for a workflow that publishes nothing: %s", status, body)
		}
		if !strings.Contains(body, "declares no DOT") {
			t.Errorf("the 409 does not explain that the DAG declares no DOT command: %s", body)
		}
		if !strings.Contains(body, "instrumented") {
			t.Errorf("the 409 does not mention that workflows submitted here are instrumented: %s", body)
		}
	})

	// (2) The whole chain, on an instrumented workflow.
	var got DagGraphResponse
	t.Run("Structure", func(t *testing.T) {
		deadline := time.Now().Add(5 * time.Minute)
		for {
			status, resp, body := get(t, visible, "?refresh=1")
			if status == http.StatusOK {
				got = resp
				break
			}
			if time.Now().After(deadline) {
				// DAGMan writes its own diagnosis into the spool, and
				// without it a failure here reports only that nothing
				// happened.
				files := tryFetchDagSandbox(ctx, schedd, visible)
				t.Logf("the workflow's spool holds %v", sortedKeys(files))
				for name, text := range files {
					if strings.HasSuffix(name, ".dagman.out") || strings.HasSuffix(name, ".lib.err") {
						t.Logf("--- %s (tail) ---\n%s", name, lastLines(text, 40))
					}
				}
				t.Fatalf("the dag endpoint never succeeded: status %d, body %s", status, body)
			}
			t.Logf("dag endpoint not ready yet (status %d): %s", status, body)
			time.Sleep(5 * time.Second)
		}

		// The name is pinned by the OVERWRITE argument, but the reader
		// tolerates the numbered spelling an access point that ignores it
		// would produce, so the assertion does too.
		if got.DagFile != "fanout.dag" || !strings.HasPrefix(got.DotFile, instr.DotFile) {
			t.Errorf("dag_file/dot_file = %q/%q, want fanout.dag/%s", got.DagFile, got.DotFile, instr.DotFile)
		}
		if got.NodeCount != 5 {
			t.Errorf("node_count = %d, want 5", got.NodeCount)
		}
		if got.EdgeCount != 4 {
			t.Errorf("edge_count = %d, want 4", got.EdgeCount)
		}
		if got.ApproximateLayering {
			t.Errorf("a well-formed DAG reported approximate layering")
		}
		if len(got.Groups) != 2 {
			t.Fatalf("group_count = %d, want 2 (one fan-out, one gather): %+v", len(got.Groups), got.Groups)
		}
		fan, gather := got.Groups[0], got.Groups[1]
		if fan.Count != 4 {
			t.Errorf("the fan-out group holds %d nodes, want 4: %+v", fan.Count, fan)
		}
		if gather.Count != 1 || len(gather.ParentIDs) != 1 || gather.ParentIDs[0] != fan.ID {
			t.Errorf("the gather group is wrong: %+v (fan %s)", gather, fan.ID)
		}
		if len(got.Nodes) != 5 {
			t.Errorf("a 5-node workflow should list its nodes, got %d", len(got.Nodes))
		}
	})

	t.Run("State", func(t *testing.T) {
		if got.NodeCount == 0 {
			t.Skip("the structure never came back")
		}
		deadline := time.Now().Add(5 * time.Minute)
		var moved DagGraphResponse
		for {
			_, resp, _ := get(t, visible, "?refresh=1")
			fromStatusFile := 0
			for _, n := range resp.Nodes {
				if n.Source == dagSourceStatusFile && n.State != dagStateUnready && n.State != dagStateReady {
					fromStatusFile++
				}
			}
			if fromStatusFile > 0 {
				moved = resp
				t.Logf("state sources %v, %d nodes past ready according to DAGMan itself",
					resp.StateSources, fromStatusFile)
				break
			}
			if time.Now().After(deadline) {
				files := tryFetchDagSandbox(ctx, schedd, visible)
				t.Logf("the workflow's spool holds %v", sortedKeys(files))
				if body, ok := files[instr.StatusFile]; ok {
					t.Logf("--- %s (head) ---\n%s", instr.StatusFile, firstLines(body, 20))
				}
				for name, text := range files {
					if strings.HasSuffix(name, ".dagman.out") {
						t.Logf("--- %s (tail) ---\n%s", name, lastLines(text, 30))
					}
				}
				t.Fatalf("no node ever left the ready state according to the status file: sources %v, "+
					"status_file %q, %+v", resp.StateSources, resp.StatusFile, resp.Nodes)
			}
			time.Sleep(5 * time.Second)
		}

		// The status file is the authoritative source and it is the one
		// that has to have been read: it is the only thing that knows
		// about a node that is not a job.
		if !containsString(moved.StateSources, dagSourceStatusFile) {
			t.Errorf("state_sources = %v; the node status file did not contribute", moved.StateSources)
		}
		if moved.StatusFile != instr.StatusFile {
			t.Errorf("status_file = %q, want %s", moved.StatusFile, instr.StatusFile)
		}
		if moved.StatusFileTime == 0 {
			t.Errorf("the response does not say how old its node states are")
		}
		// The queue and the archive are still consulted, for the job ids
		// behind the states.
		if !containsString(moved.StateSources, dagSourceQueue) &&
			!containsString(moved.StateSources, dagSourceArchive) {
			t.Errorf("state_sources = %v; neither the queue nor the archive contributed", moved.StateSources)
		}
		for _, n := range moved.Nodes {
			if n.State == dagStateSubmitted && n.JobID == "" {
				t.Errorf("node %s is submitted but no source could name its job: %+v", n.Name, n)
			}
		}
	})

	t.Run("CachedLoad", func(t *testing.T) {
		if got.NodeCount == 0 {
			t.Skip("the structure never came back")
		}
		// A plain load must be served from the cache: the structure half
		// of this endpoint costs a whole-sandbox transfer, and an
		// ordinary page load must not pay it again within the state
		// freshness window.
		//
		// What that is asserted WITH matters. This subtest used to
		// compare node and group counts, which an implementation with no
		// cache at all satisfies -- the second transfer returns the same
		// workflow. The transfer counter is the thing only a cache holds
		// still.
		if _, _, body := get(t, visible, "?refresh=1"); body == "" {
			t.Fatalf("the seeding refresh returned nothing")
		}
		before := dagSandboxFetches.Load()

		start := time.Now()
		status, cached, body := get(t, visible, "")
		if status != http.StatusOK {
			t.Fatalf("cached load failed: %d %s", status, body)
		}
		if after := dagSandboxFetches.Load(); after != before {
			t.Errorf("an ordinary load started %d whole-sandbox transfer(s); it must be served "+
				"from the cache", after-before)
		}
		if cached.NodeCount != got.NodeCount || len(cached.Groups) != len(got.Groups) {
			t.Errorf("the cached structure disagrees with the fetched one: %d/%d nodes, %d/%d groups",
				cached.NodeCount, got.NodeCount, len(cached.Groups), len(got.Groups))
		}
		t.Logf("cached load took %v (transfers %d)", time.Since(start), dagSandboxFetches.Load())

		// ...and ?refresh=1 still costs one, or the counter above proves
		// nothing.
		if _, _, _ = get(t, visible, "?refresh=1"); dagSandboxFetches.Load() <= before {
			t.Errorf("?refresh=1 did not re-fetch the sandbox")
		}
	})

	// The authorization regression. A cache hit skips the sandbox
	// transfer, and the transfer is where the schedd checks the job's
	// owner (UserCheck2, per job, on a WRITE-registered command); the ad
	// read in front of it is NOT owner-checked for a token or
	// UserHeader caller, because bulkOwnerScope only scopes a browser
	// session. So before this was fixed, the second user here was handed
	// the first user's node names, edges, group labels and DAGMan status
	// details straight out of the cache, for up to the full hour.
	t.Run("AnotherUserIsNotServedTheCachedWorkflow", func(t *testing.T) {
		if got.NodeCount == 0 {
			t.Skip("the structure never came back")
		}
		// Warm the cache as the owner, so a hit is available to be
		// wrongly served.
		if status, _, body := get(t, visible, ""); status != http.StatusOK {
			t.Fatalf("the owner's own load failed: %d %s", status, body)
		}

		const other = "someone-else"
		if other == me.Username {
			t.Skip("the test's second identity is the owner")
		}
		before := dagSandboxFetches.Load()
		status, resp, body := getAs(t, other, visible, "")
		spent := dagSandboxFetches.Load() - before

		// The assertion is that the second user REACHED the schedd. A
		// cache hit is the whole bug: it answers without a transfer, and
		// the transfer is the only owner check on this path.
		if spent == 0 {
			t.Fatalf("a second user was served the first user's workflow out of the cache, with no "+
				"sandbox transfer and therefore no owner check: %d nodes, %d groups, dot file %q",
				resp.NodeCount, len(resp.Groups), resp.DotFile)
		}

		// What the schedd then decides is the schedd's policy, and this
		// harness's is wide open on purpose: QUEUE_ALL_USERS_TRUSTED is
		// True, ALLOW_* are *, and FS authentication resolves every
		// connection from this process to the local user whatever the
		// request header said. So a 200 here means the harness allowed
		// the transfer, not that the endpoint served a cached answer --
		// which is why the transfer count above is what is asserted. A
		// production schedd refuses this (UserCheck2, per job, on a
		// WRITE-registered command).
		t.Logf("the second user's request cost %d sandbox transfer(s) and the harness schedd "+
			"answered %d; the endpoint did not short-circuit it", spent, status)
		if status != http.StatusOK {
			for _, name := range []string{"produce_1", "produce_2", "COMBINE"} {
				if strings.Contains(body, name) {
					t.Errorf("the refusal leaks the workflow's node names (%q): %s", name, body)
				}
			}
		}
		// The owner's own entry survives the attempt.
		if status, again, body := get(t, visible, ""); status != http.StatusOK ||
			again.NodeCount != got.NodeCount {
			t.Errorf("the owner lost their cached workflow: %d %s", status, body)
		}
	})
}

// tryFetchDagSandbox retrieves a job's spool without failing the test: an
// early call is expected to come back with little or nothing in it.
func tryFetchDagSandbox(ctx context.Context, schedd *htcondor.Schedd, cluster int) map[string]string {
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

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// lastLines returns the last n lines, so a long log does not bury the
// error that ended it.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// firstLines returns the first n lines.
func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
