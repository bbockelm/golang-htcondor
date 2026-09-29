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

// TestAppProxyServesHTTPIntegration is the end-to-end assertion for the
// whole feature: a browser request reaching a server running inside a
// job.
//
// It goes HTTP -> handler -> jobssh transport cache -> condor_ssh_to_job
// over CEDAR -> the job's sandbox -> the server -> back. Every unit test
// for the proxy substitutes something for the middle of that; this one
// substitutes nothing.
//
// The server in the job listens on a TCP port rather than the Unix
// socket a real app would use, for one environmental reason: a Unix
// socket address is capped at ~104 bytes of sun_path, and this harness's
// scratch directory is long enough on macOS to exceed it on its own (see
// the core package's ssh integration test, which measures exactly that).
// The proxy code path is identical either way -- both end in
// jobssh.Cache.DialJob -- so the port form tests the chain without
// making the test unrunnable wherever EXECUTE happens to be deep.
func TestAppProxyServesHTTPIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found; skipping the proxy end-to-end test")
	}
	addr, harness, schedd := appsTestPool(t)

	const sentinel = "hello from inside the job"
	port := 35000 + (os.Getpid() % 900)

	scriptDir := t.TempDir()
	scriptPath := filepath.Join(scriptDir, "server.py")
	script := fmt.Sprintf(`import http.server, socketserver
BODY = b"%s"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = BODY + b" at " + self.path.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", %d), H) as s:
    s.serve_forever()
`, sentinel, port)
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatalf("write server script: %v", err)
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
arguments = %s
transfer_executable = false
output = server.out
error = server.err
log = server.log
request_cpus = 1
request_memory = 128
request_disk = 128
queue
`, python, scriptPath)

	cluster, _, err := schedd.SubmitRemote(submitCtx, submitFile)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	jobID := fmt.Sprintf("%d.0", cluster)
	t.Logf("submitted the in-job server as %s on port %d", jobID, port)

	// Wait for it to start; the proxy cannot reach a job with no starter.
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

	proxyBase := fmt.Sprintf("http://%s/api/v1/jobs/%s/proxy/%d", addr, jobID, port)

	// The bare prefix must redirect to the trailing-slash form, or an
	// app's relative URLs resolve one path component too high.
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

	// Now the real thing. Retry: the job is running, but python needs a
	// moment to bind, which is precisely the window the app API reports
	// as "starting" rather than as a failure.
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
			t.Fatalf("never reached the server in the job: last status %d body %q err %v",
				gotStatus, gotBody, rerr)
		}
		time.Sleep(2 * time.Second)
	}

	if !strings.Contains(gotBody, sentinel) {
		t.Errorf("body = %q, want it to contain %q", gotBody, sentinel)
	}
	// The prefix is stripped: the server sees its own path, not ours.
	// An app relies on this, since none of them can be told the path
	// they are served under.
	if !strings.Contains(gotBody, "at /hello") {
		t.Errorf("the server saw %q; the proxy did not strip its prefix", gotBody)
	}

	// A second request must reuse the transport rather than pay another
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
