//go:build integration

package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/vscode"
)

// appsTestPool brings up a mini-pool and an httpserver in front of it,
// returning the server's address and the schedd.
//
// ssh-to-job is configured because the proxy test needs it; the
// lifecycle test does not, and pays only the config line.
func appsTestPool(t *testing.T) (addr string, harness *htcondor.CondorTestHarness, schedd *htcondor.Schedd) {
	t.Helper()

	extraConfig := ""
	for _, p := range []string{
		"/usr/lib/condor_ssh_to_job_sshd_config_template",
		"/usr/lib64/condor/condor_ssh_to_job_sshd_config_template",
		"/etc/condor/condor_ssh_to_job_sshd_config_template",
		"/usr/share/condor/condor_ssh_to_job_sshd_config_template",
	} {
		if _, err := os.Stat(p); err == nil {
			extraConfig = fmt.Sprintf("ENABLE_SSH_TO_JOB = True\nSSH_TO_JOB_SSHD = /usr/sbin/sshd\nSSH_TO_JOB_SSHD_CONFIG_TEMPLATE = %s\n", p)
			break
		}
	}
	// A build tree, which is where this gets developed. See the probe in
	// the core package's ssh integration test: looking only in packaged
	// locations meant the test skipped itself on the machines it was
	// written on.
	if extraConfig == "" {
		if master, err := exec.LookPath("condor_master"); err == nil {
			p := filepath.Join(filepath.Dir(filepath.Dir(master)), "lib", "condor_ssh_to_job_sshd_config_template")
			if _, serr := os.Stat(p); serr == nil {
				extraConfig = fmt.Sprintf("ENABLE_SSH_TO_JOB = True\nSSH_TO_JOB_SSHD = /usr/sbin/sshd\nSSH_TO_JOB_SSHD_CONFIG_TEMPLATE = %s\n", p)
			}
		}
	}

	harness = htcondor.SetupCondorHarnessWithConfig(t, extraConfig)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("daemons failed to start: %v", err)
	}
	if err := harness.WaitForStartd(45 * time.Second); err != nil {
		t.Fatalf("startd never reported in: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	location, err := htcondor.NewCollector(harness.GetCollectorAddr()).LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("locate schedd: %v", err)
	}
	schedd = htcondor.NewSchedd(location.Name, location.Address)

	server, err := NewServer(Config{
		ListenAddr:               "127.0.0.1:0",
		ScheddName:               location.Name,
		ScheddAddr:               location.Address,
		UserHeader:               "X-Test-User",
		UserHeaderTrustAnyUnsafe: true,
		SigningKeyPath:           harness.GetSigningKeyPath(),
		TrustDomain:              harness.GetTrustDomain(),
		UIDDomain:                harness.GetTrustDomain(),
		OAuth2DBPath:             filepath.Join(harness.GetSpoolDir(), "oauth2.db"),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = server.Start() }()
	time.Sleep(500 * time.Millisecond)
	addr = server.GetAddr()
	if addr == "" {
		t.Fatal("server has no address")
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer scancel()
		_ = server.Shutdown(sctx)
	})
	return addr, harness, schedd
}

func appsRequest(t *testing.T, method, url string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Test-User", testUser)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// TestAppsLifecycleIntegration drives create/list/get/delete against a
// real schedd.
//
// The job is never expected to RUN: it is a container-universe job and
// this pool has no container runtime, so it sits in the queue. That is
// the point -- it exercises the half that a unit test cannot reach (the
// schedd accepting the submit and the launcher actually spooling) while
// asserting the states stay honest about an app that has not started.
func TestAppsLifecycleIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	addr, _, schedd := appsTestPool(t)
	base := "http://" + addr + "/api/v1/apps"

	code, body := appsRequest(t, http.MethodPost, base, AppCreateRequest{
		Cpus: 1, MemoryMB: 128, DiskMB: 128,
		Image: "docker://example.invalid/code-server:test",
	})
	if code != http.StatusCreated {
		t.Fatalf("create: status %d body %s", code, body)
	}
	var created AppSummary
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("create response: %v (%s)", err, body)
	}
	if created.ID == "" || created.JobID == "" {
		t.Fatalf("create returned no handle: %+v", created)
	}
	if created.URL != "" {
		t.Errorf("a just-submitted app was given somewhere to open: %q", created.URL)
	}
	t.Logf("created app %s as job %s", created.ID, created.JobID)

	// The schedd must actually hold the job, which is what proves the
	// submit and the spool both landed rather than the handler simply
	// answering 201.
	cluster, proc, err := parseJobID(created.JobID)
	if err != nil {
		t.Fatalf("job id %q: %v", created.JobID, err)
	}
	qctx, qcancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer qcancel()
	ads, _, err := schedd.QueryWithOptions(qctx,
		fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc), nil)
	if err != nil {
		t.Fatalf("schedd query: %v", err)
	}
	if len(ads) != 1 {
		t.Fatalf("schedd holds %d ads for the app's job, want 1", len(ads))
	}

	// It appears in the caller's list, found by its batch name alone.
	code, body = appsRequest(t, http.MethodGet, base, nil)
	if code != http.StatusOK {
		t.Fatalf("list: status %d body %s", code, body)
	}
	var list AppListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("list response: %v (%s)", err, body)
	}
	found := false
	for _, a := range list.Apps {
		if a.ID == created.ID {
			found = true
			if a.State == appStateRunning || a.State == appStateStarting {
				t.Errorf("an app that cannot run reports %q", a.State)
			}
		}
	}
	if !found {
		t.Fatalf("the app is not in its owner's list: %+v", list.Apps)
	}

	// And individually.
	code, body = appsRequest(t, http.MethodGet, base+"/"+created.ID, nil)
	if code != http.StatusOK {
		t.Fatalf("get: status %d body %s", code, body)
	}
	var one AppSummary
	if err := json.Unmarshal(body, &one); err != nil {
		t.Fatalf("get response: %v (%s)", err, body)
	}
	if one.ID != created.ID || one.JobID != created.JobID {
		t.Errorf("get returned a different app: %+v", one)
	}

	// An id nobody owns is a 404, not somebody else's app.
	if code, _ := appsRequest(t, http.MethodGet, base+"/deadbeefdeadbeef", nil); code != http.StatusNotFound {
		t.Errorf("get of an unknown app = %d, want 404", code)
	}

	// Delete removes the job from the queue.
	code, body = appsRequest(t, http.MethodDelete, base+"/"+created.ID, nil)
	if code != http.StatusOK {
		t.Fatalf("delete: status %d body %s", code, body)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		dctx, dcancel := context.WithTimeout(context.Background(), 20*time.Second)
		ads, _, qerr := schedd.QueryWithOptions(dctx,
			fmt.Sprintf("ClusterId == %d && ProcId == %d && JobStatus != 3", cluster, proc), nil)
		dcancel()
		if qerr == nil && len(ads) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the app's job is still in the queue after delete (%d ads, err %v)", len(ads), qerr)
		}
		time.Sleep(2 * time.Second)
	}
}

// TestAppProxyServesHTTPOverAUnixSocketIntegration is the end-to-end
// assertion for the whole feature, over the transport a real app uses.
//
// It goes HTTP -> handler -> jobssh transport cache -> condor_ssh_to_job
// over CEDAR -> the sandbox -> a Unix socket -> the server -> back.
// Every unit test substitutes something for the middle of that; this one
// substitutes nothing, and it runs the REAL launcher script, so the
// socket addressing under test is the one production uses.
//
// The harness's scratch directory is long -- long enough to exceed
// sun_path on its own -- and that is the point rather than an obstacle.
// It is the shape of a glidein, an EP running inside a SLURM job, where
// execute/dir_N nests under the host batch system's own. A proxy that
// only worked with short paths would fail on exactly the pools this is
// for.
func TestAppProxyServesHTTPOverAUnixSocketIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found; skipping the proxy end-to-end test")
	}
	addr, harness, schedd := appsTestPool(t)

	const sentinel = "hello from inside the job"

	// A stand-in for code-server: it takes --socket, ignores the rest,
	// and serves HTTP over that socket. The launcher is the real one,
	// so it is the launcher that decides where the socket lives and
	// what address it publishes.
	toolDir := t.TempDir()
	fakeServerPath := filepath.Join(toolDir, "fake-code-server")
	fake := fmt.Sprintf(`#!%s
import http.server, socketserver, os, sys
args = sys.argv[1:]
sock = None
for i, a in enumerate(args):
    if a == "--socket" and i + 1 < len(args):
        sock = args[i + 1]
if not sock:
    sys.stderr.write("no --socket\n")
    sys.exit(2)
BODY = b"%s"
class H(http.server.BaseHTTPRequestHandler):
    def address_string(self):
        return "local"
    def do_GET(self):
        body = BODY + b" at " + self.path.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
try:
    os.unlink(sock)
except OSError:
    pass
class S(socketserver.UnixStreamServer):
    allow_reuse_address = True
with S(sock, H) as s:
    s.serve_forever()
`, python, sentinel)
	if err := os.WriteFile(fakeServerPath, []byte(fake), 0o700); err != nil { //nolint:gosec // G306: it is an executable
		t.Fatalf("write fake server: %v", err)
	}

	launcherPath := filepath.Join(toolDir, vscode.ExecutableName)
	launcher := vscode.LaunchScript(vscode.ScriptArgs{ServerCommand: fakeServerPath})
	if err := os.WriteFile(launcherPath, []byte(launcher), 0o700); err != nil { //nolint:gosec // G306: it is the job's executable
		t.Fatalf("write launcher: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	submitCtx, err := contextAsUser(ctx, harness, testUser)
	if err != nil {
		t.Fatalf("contextAsUser: %v", err)
	}

	submitFile := fmt.Sprintf(`
universe = vanilla
executable = %s
transfer_executable = false
output = server.out
error = server.err
log = server.log
request_cpus = 1
request_memory = 128
request_disk = 128
queue
`, launcherPath)

	cluster, _, err := schedd.SubmitRemote(submitCtx, submitFile)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	jobID := fmt.Sprintf("%d.0", cluster)
	t.Logf("submitted the in-job server as %s", jobID)

	deadline := time.Now().Add(2 * time.Minute)
	for {
		qctx, qcancel := context.WithTimeout(ctx, 20*time.Second)
		ads, _, qerr := schedd.QueryWithOptions(qctx,
			fmt.Sprintf("ClusterId == %d && ProcId == 0 && JobStatus == 2", cluster), nil)
		qcancel()
		if qerr == nil && len(ads) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the in-job server never started running")
		}
		time.Sleep(2 * time.Second)
	}
	t.Logf("job %s is running", jobID)

	// Report which of the launcher's two socket placements this
	// environment exercises, so a failure below can be read.
	//
	// Not a requirement, which an earlier version made it: the branch
	// taken depends on how deep the harness's scratch directory
	// happens to be, and CI's is 53 bytes where a developer Mac's is
	// over 100. Demanding the deep one failed the test for being in a
	// perfectly good environment. The deep branch is covered
	// deterministically by TestLaunchScriptWorksInADeepSandbox, which
	// builds its own over-long path on any platform; what this test is
	// for is that the whole chain works against a real pool.
	shell, err := schedd.OpenJobShell(ctx, cluster, 0, nil)
	if err != nil {
		t.Fatalf("opening a shell to check the sandbox path: %v", err)
	}
	sess, err := shell.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	scratchOut, err := sess.Output(`printf %s "$_CONDOR_SCRATCH_DIR"`)
	_ = sess.Close()
	_ = shell.Close()
	if err != nil {
		t.Fatalf("asking the job for its scratch directory: %v", err)
	}
	scratchLen := len(strings.TrimSpace(string(scratchOut)))
	sockLen := scratchLen + 1 + len(vscode.SocketName)
	placement := "a short directory outside it (the glidein shape)"
	if sockLen <= 100 {
		placement = "the sandbox itself"
	}
	t.Logf("sandbox scratch path is %d bytes, so the joined socket path would be %d: "+
		"this run exercises the socket living in %s", scratchLen, sockLen, placement)

	proxyBase := fmt.Sprintf("http://%s/api/v1/jobs/%s/proxy/unix/%s", addr, jobID, vscode.SocketName)

	// The bare prefix redirects to the trailing-slash form, or an app's
	// relative URLs resolve one path component too high.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	rreq, _ := http.NewRequestWithContext(ctx, http.MethodGet, proxyBase, nil)
	rreq.Header.Set("X-Test-User", testUser)
	rresp, err := noRedirect.Do(rreq)
	if err != nil {
		t.Fatalf("redirect probe: %v", err)
	}
	_ = rresp.Body.Close()
	if rresp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("bare prefix returned %d, want a redirect to the slash form", rresp.StatusCode)
	} else if loc := rresp.Header.Get("Location"); !strings.HasSuffix(loc, "/") {
		t.Errorf("redirect Location = %q, which does not end in a slash", loc)
	}

	// Retry: the job is running, but the server needs a moment to bind,
	// which is the window the app API reports as "starting".
	var gotBody string
	var gotStatus int
	deadline = time.Now().Add(90 * time.Second)
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, proxyBase+"/hello", nil)
		req.Header.Set("X-Test-User", testUser)
		resp, rerr := http.DefaultClient.Do(req)
		if rerr == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			gotStatus, gotBody = resp.StatusCode, string(b)
			if gotStatus == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("never reached the socket in the job: last status %d body %q err %v",
				gotStatus, gotBody, rerr)
		}
		time.Sleep(2 * time.Second)
	}

	if !strings.Contains(gotBody, sentinel) {
		t.Errorf("body = %q, want it to contain %q", gotBody, sentinel)
	}
	// The prefix is stripped: the server sees its own path, not ours.
	// Every app relies on this, since none of them can be told the path
	// they are served under.
	if !strings.Contains(gotBody, "at /hello") {
		t.Errorf("the server saw %q; the proxy did not strip its prefix", gotBody)
	}

	// A second request reuses the transport rather than paying another
	// schedd RPC, CEDAR handshake and sshd spawn.
	start := time.Now()
	req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, proxyBase+"/again", nil)
	req2.Header.Set("X-Test-User", testUser)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("second request status = %d", resp2.StatusCode)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the second request took %s; the transport is not being reused", elapsed)
	} else {
		t.Logf("second request served in %s from the cached transport", elapsed)
	}
}
