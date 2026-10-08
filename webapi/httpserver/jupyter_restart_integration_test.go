//go:build integration

package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestJupyterSessionSurvivesAPIServerRestart runs a JupyterLab session as a
// real job in a real pool, restarts the API server over the same application
// database, and checks the session is still there and still usable.
//
// The job is the production one -- the generated launcher, the real helper
// binary, spooled the real way -- except that "jupyter" on the job's PATH is
// a stand-in that serves HTTP on the socket JupyterLab would have used.
// Installing JupyterLab is not what is under test, and would take minutes.
//
// The restart is a new Server and Handler over the same database file and on
// the same address the helper was told to dial. The old process's tunnel is
// cut the way a process exit cuts it: the listener goes first, then every
// connection, so the helper's redial finds nothing until the new server is up.
//
// Before the fix the stored session never learned its cluster id, so the new
// process adopted it as cluster 0, found no such job, and reaped it on the
// first list -- (a) fails.
func TestJupyterSessionSurvivesAPIServerRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not in PATH; skipping")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not in PATH; the stand-in JupyterLab needs it")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not in PATH; the helper is built by this test")
	}

	// --- the helper, built for this host, and a stand-in JupyterLab ---
	work := t.TempDir()
	helperBytes := buildJupyterHelperForTest(t, goTool, work)
	prevBytes, prevUniverse := jupyterHelperBytesFor, jupyterUniverse
	jupyterHelperBytesFor = func(goos, goarch string) ([]byte, error) {
		if goos != runtime.GOOS || goarch != runtime.GOARCH {
			return nil, fmt.Errorf("test helper is %s/%s, asked for %s/%s", runtime.GOOS, runtime.GOARCH, goos, goarch)
		}
		return helperBytes, nil
	}
	// Vanilla on every host: the test pool's execute node is this machine,
	// with no container runtime to speak of.
	jupyterUniverse = func() string { return "vanilla" }
	t.Cleanup(func() { jupyterHelperBytesFor, jupyterUniverse = prevBytes, prevUniverse })

	fakeBin := filepath.Join(work, "fakebin")
	if err := os.MkdirAll(fakeBin, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	//nolint:gosec // G306: the job runs it, so it has to be executable
	if err := os.WriteFile(filepath.Join(fakeBin, "jupyter"),
		[]byte("#!"+python+"\n"+fakeJupyterPy), 0o700); err != nil {
		t.Fatalf("write fake jupyter: %v", err)
	}

	// --- the pool ---
	harness := htcondor.SetupCondorHarness(t)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("daemons: %v", err)
	}
	if err := harness.WaitForStartd(45 * time.Second); err != nil {
		t.Fatalf("startd: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	collector := htcondor.NewCollector(harness.GetCollectorAddr())
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("locate schedd: %v", err)
	}

	// --- the first API server ---
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	baseURL := "http://" + addr
	cfg := Config{
		ListenAddr:               addr,
		ScheddName:               location.Name,
		ScheddAddr:               location.Address,
		UserHeader:               "X-Test-User",
		UserHeaderTrustAnyUnsafe: true,
		SigningKeyPath:           harness.GetSigningKeyPath(),
		TrustDomain:              harness.GetTrustDomain(),
		UIDDomain:                harness.GetTrustDomain(),
		// The durable application database both processes share.
		OAuth2DBPath: filepath.Join(work, "app.db"),
		// Puts the stand-in JupyterLab first on the job's PATH. The
		// launcher uses a jupyter it finds there rather than building one.
		InteractiveExtraSubmit: fmt.Sprintf("environment = \"PATH=%s:/usr/bin:/bin\"\n", fakeBin),
	}
	first := startJupyterTestServer(t, cfg, ln)

	client := &http.Client{Timeout: 30 * time.Second}
	created := jupyterIntegrationCreate(t, client, baseURL)
	t.Logf("created instance %s, cluster %s", created.InstanceID, created.ClusterID)
	defer func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		if uctx, err := contextAsUser(cctx, harness, testUser); err == nil {
			schedd := htcondor.NewSchedd(location.Name, location.Address)
			_, _ = schedd.RemoveJobs(uctx, "ClusterId == "+created.ClusterID, "test cleanup")
		}
	}()
	defer func() {
		if t.Failed() {
			harness.PrintScheddLog()
			harness.PrintStarterLogs()
		}
	}()

	// The job runs, the helper dials in, and a request reaches "JupyterLab".
	waitJupyterConnected(t, client, baseURL, created.InstanceID, 150*time.Second)
	if err := retryFor(30*time.Second, func() error {
		return jupyterProxyWorks(client, baseURL, created.InstanceID)
	}); err != nil {
		t.Fatalf("precondition: a proxied request does not work before the restart: %v", err)
	}

	// --- the restart ---
	first.crash(t)
	t.Log("first API server is gone; starting the second over the same database")
	ln2 := relisten(t, addr, 15*time.Second)
	second := startJupyterTestServer(t, cfg, ln2)
	defer second.crash(t)

	// (a) Still listed, under its job.
	list, err := jupyterIntegrationList(client, baseURL)
	if err != nil {
		t.Fatalf("list after the restart: %v", err)
	}
	var listed *JupyterInstanceSummary
	for i := range list {
		if list[i].InstanceID == created.InstanceID {
			listed = &list[i]
		}
	}
	if listed == nil {
		t.Fatalf("the session is not listed after the restart (listed %d others)", len(list))
	}
	if listed.ClusterID != created.ClusterID {
		t.Errorf("listed cluster %q, want %q", listed.ClusterID, created.ClusterID)
	}

	// (b) GET answers for it, with the right job.
	got, status, err := jupyterIntegrationGet(client, baseURL, created.InstanceID)
	if err != nil || status != http.StatusOK {
		t.Fatalf("GET after the restart: status %d, %v", status, err)
	}
	if got.ClusterID != created.ClusterID {
		t.Errorf("GET cluster %q, want %q", got.ClusterID, created.ClusterID)
	}
	if got.JobStatus != 2 {
		t.Errorf("GET job status %d, want 2 (Running)", got.JobStatus)
	}

	// (c) The helper redials with the token it was handed last time, and
	// requests flow again.
	waitJupyterConnected(t, client, baseURL, created.InstanceID, 90*time.Second)
	if err := retryFor(30*time.Second, func() error {
		return jupyterProxyWorks(client, baseURL, created.InstanceID)
	}); err != nil {
		t.Errorf("a proxied request does not work after the restart: %v", err)
	}
}

// fakeJupyterPy answers HTTP on --ServerApp.sock, which is all the tunnel
// needs from JupyterLab.
const fakeJupyterPy = `
import os, socketserver, sys
from http.server import BaseHTTPRequestHandler

sock = None
for arg in sys.argv[1:]:
    if arg.startswith("--ServerApp.sock="):
        sock = arg.split("=", 1)[1]
if not sock:
    sys.exit("no --ServerApp.sock")

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("fake-jupyter-OK path=%s" % self.path).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def address_string(self):
        return "uds"
    def log_message(self, *args):
        pass

class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

if os.path.exists(sock):
    os.unlink(sock)
Server(sock, Handler).serve_forever()
`

func buildJupyterHelperForTest(t *testing.T, goTool, dir string) []byte {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	out := filepath.Join(dir, "htcondor-jupyter-helper")
	//nolint:gosec // G204: the go found on PATH, building this module's own helper
	cmd := exec.CommandContext(context.Background(), goTool, "build", "-o", out, "./cmd/htcondor-jupyter-helper")
	cmd.Dir = filepath.Dir(wd) // the webapi module root
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the helper: %v\n%s", err, b)
	}
	b, err := os.ReadFile(out) //nolint:gosec // G304: the file this function just built
	if err != nil {
		t.Fatalf("read helper: %v", err)
	}
	return b
}

// jupyterTestServer is one API server process: the Server, and every
// connection it accepted, so that ending it can cut them all.
type jupyterTestServer struct {
	server *Server
	ln     *trackingListener
	once   sync.Once
}

func startJupyterTestServer(t *testing.T, cfg Config, ln net.Listener) *jupyterTestServer {
	t.Helper()
	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	tl := &trackingListener{Listener: ln}
	go func() { _ = server.ServeListener(tl, "http") }()
	if err := waitForServer("http://"+cfg.ListenAddr, 15*time.Second); err != nil {
		t.Fatalf("server did not start: %v", err)
	}
	return &jupyterTestServer{server: server, ln: tl}
}

// crash ends the server the way a process exit would for the helper: no new
// connections, and every existing one -- the hijacked tunnel included, which
// http.Server.Shutdown deliberately leaves alone -- cut.
func (s *jupyterTestServer) crash(t *testing.T) {
	t.Helper()
	s.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.ln.Close()
		_ = s.server.Shutdown(ctx)
		s.ln.closeAll()
	})
}

type trackingListener struct {
	net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func (l *trackingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		l.conns = append(l.conns, c)
		l.mu.Unlock()
	}
	return c, err
}

func (l *trackingListener) closeAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.conns {
		_ = c.Close()
	}
	l.conns = nil
}

// relisten binds addr again. The helper was told this address when its job
// was submitted, so the new server has to be on it.
func relisten(t *testing.T, addr string, timeout time.Duration) net.Listener {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
		if err == nil {
			return ln
		}
		if time.Now().After(deadline) {
			t.Fatalf("could not bind %s again: %v", addr, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func jupyterIntegrationDo(client *http.Client, method, url string, body io.Reader) (int, []byte, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, url, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("X-Test-User", testUser)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

func jupyterIntegrationCreate(t *testing.T, client *http.Client, baseURL string) JupyterCreateResponse {
	t.Helper()
	// Small enough for the test pool's one slot.
	status, body, err := jupyterIntegrationDo(client, http.MethodPost, baseURL+"/api/v1/jupyter/instances",
		strings.NewReader(`{"cpus":1,"memory_mb":256,"disk_mb":256}`))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, body)
	}
	var created JupyterCreateResponse
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	return created
}

func jupyterIntegrationList(client *http.Client, baseURL string) ([]JupyterInstanceSummary, error) {
	status, body, err := jupyterIntegrationDo(client, http.MethodGet, baseURL+"/api/v1/jupyter/instances", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", status, body)
	}
	var out struct {
		Instances []JupyterInstanceSummary `json:"instances"`
	}
	return out.Instances, json.Unmarshal(body, &out)
}

func jupyterIntegrationGet(client *http.Client, baseURL, id string) (JupyterInstanceSummary, int, error) {
	var out JupyterInstanceSummary
	status, body, err := jupyterIntegrationDo(client, http.MethodGet, baseURL+"/api/v1/jupyter/instances/"+id, nil)
	if err != nil {
		return out, 0, err
	}
	if status != http.StatusOK {
		return out, status, fmt.Errorf("%s", body)
	}
	return out, status, json.Unmarshal(body, &out)
}

// waitJupyterConnected waits for the helper to have dialed in, failing early
// on a session that has ended or a job that went on hold.
func waitJupyterConnected(t *testing.T, client *http.Client, baseURL, id string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last JupyterInstanceSummary
	for time.Now().Before(deadline) {
		got, status, err := jupyterIntegrationGet(client, baseURL, id)
		if status == http.StatusNotFound {
			t.Fatalf("the session is gone (404): %v", err)
		}
		if err == nil {
			last = got
			if got.Connected {
				return
			}
			// 16 is SpoolingInput: every spooled job sits there until its
			// input has landed, which is not the hold this is looking for.
			if got.JobStatus == 5 && got.HoldReasonCode != 16 {
				t.Fatalf("the job went on hold: %s", got.HoldReason)
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("the helper never connected within %s (last: connected=%v job_status=%d)",
		timeout, last.Connected, last.JobStatus)
}

func jupyterProxyWorks(client *http.Client, baseURL, id string) error {
	status, body, err := jupyterIntegrationDo(client, http.MethodGet,
		baseURL+"/api/v1/jupyter/instances/"+id+"/proxy/lab", nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK || !strings.Contains(string(body), "fake-jupyter-OK") {
		return fmt.Errorf("status %d: %s", status, truncateForError(string(body)))
	}
	return nil
}
