//go:build integration

package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/sharedportrouter"
	"github.com/gorilla/websocket"
)

// TestCCBSharedPortSSHToJobIntegration is the end-to-end proof for the API
// server's own inbound HTCondor port: a real pool, a real execute node
// reachable only through a Condor Connection Broker, a real running job, and a
// shell opened into it over the WebSocket bridge.
//
// The pool is arranged the way the deployment that motivated this one is. The
// startd and starter sit on a "private" network and register with the
// collector's built-in CCB server, so their advertised addresses carry a
// ccbid and nothing can reach them directly. The API server is given an
// inbound shared port and is NOT allowed to fall back to streaming -- which
// makes the test strict about what it proves: the broker in this harness is
// the C++ one, and if the shared-port path did not work there would be no
// other way through and the shell would never open.
//
// Routed > 0 at the end is the oracle. It can only be non-zero if the execute
// node dialed back to this process's shared port and the router matched it to
// the waiting dial, which is the whole feature. Without that assertion a
// regression that quietly reached the starter some other way would still pass.
//
// Run with: go test -tags=integration -run TestCCBSharedPortSSHToJob -v ./httpserver/
//
//nolint:gocyclo // Integration test with several discrete verification stages.
func TestCCBSharedPortSSHToJobIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not in PATH; skipping")
	}
	sshdPath := findSSHD()
	if sshdPath == "" {
		t.Skip("sshd not found in PATH or the usual sbin directories; skipping")
	}
	tmplPath := findSSHDConfigTemplate()
	if tmplPath == "" {
		t.Skip("condor_ssh_to_job_sshd_config_template not found; skipping")
	}

	// A fixed collector port: CCB_ADDRESS has to name the broker statically,
	// and the harness default (port 0) cannot be named.
	collectorPort := freeTCPPort(t)
	collectorAddr := fmt.Sprintf("127.0.0.1:%d", collectorPort)

	// USE_SHARED_PORT = False is load-bearing. Forcing CCB routing on a single
	// loopback host requires each daemon to have its own port; behind a shared
	// port every daemon lives at one directly-reachable address and the
	// private-network partitioning below has nothing to partition.
	extraConfig := fmt.Sprintf(`
ENABLE_SSH_TO_JOB = True
SSH_TO_JOB_SSHD = %s
SSH_TO_JOB_SSHD_CONFIG_TEMPLATE = %s

USE_SHARED_PORT = False
COLLECTOR_HOST = %s
CONDOR_VIEW_HOST = $(COLLECTOR_HOST)

# The collector's built-in CCB server is the broker. It is the C++ one, which
# in this harness predates streaming -- exactly the situation this feature
# exists for.
ENABLE_CCB_SERVER = True

# Put the execute side on its own network so it is CCB-routed: the startd and
# the starter register with the broker and advertise a ccbid, and a client
# that is not on NET_EXEC has to go through the broker to reach them.
PRIVATE_NETWORK_NAME = NET_DEFAULT
STARTD.PRIVATE_NETWORK_NAME = NET_EXEC
STARTER.PRIVATE_NETWORK_NAME = NET_EXEC
STARTD.CCB_ADDRESS = %s
STARTER.CCB_ADDRESS = %s
# The daemons and the collector start together; retry CCB registration quickly
# after the inevitable startup race rather than waiting out the 60s default.
CCB_RECONNECT_TIME = 2

STARTD_DEBUG = D_FULLDEBUG D_NETWORK
COLLECTOR_DEBUG = D_FULLDEBUG D_NETWORK

START = TRUE
SUSPEND = FALSE
PREEMPT = FALSE
KILL = FALSE
RUNBENCHMARKS = FALSE
`, sshdPath, tmplPath, collectorAddr, collectorAddr, collectorAddr)

	harness := htcondor.SetupCondorHarnessWithConfig(t, extraConfig)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("daemons failed to start: %v", err)
	}
	if err := harness.WaitForStartd(60 * time.Second); err != nil {
		harness.PrintCollectorLog()
		harness.PrintStartdLog()
		t.Fatalf("startd never reported in: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	collector := htcondor.NewCollector(harness.GetCollectorAddr())
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("locating schedd: %v", err)
	}
	schedd := htcondor.NewSchedd(location.Name, location.Address)

	// Confirm the premise before relying on it: if the startd is not actually
	// CCB-routed, everything below would pass by reaching it directly and the
	// test would prove nothing about the shared port.
	assertStartdIsCCBRouted(ctx, t, collector)

	// --- Submit a long-running job and wait for it to run -------------------

	submitFile := `
universe = vanilla
executable = /bin/sleep
transfer_executable = false
arguments = 600
output = job.out
error = job.err
log = job.log
request_cpus = 1
request_memory = 64
request_disk = 64
queue
`
	submitCtx, err := contextAsUser(ctx, harness, testUser)
	if err != nil {
		t.Fatalf("building a submit context for %s: %v", testUser, err)
	}
	clusterIDStr, err := schedd.Submit(submitCtx, submitFile)
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("submit: %v", err)
	}
	clusterID, err := strconv.Atoi(clusterIDStr)
	if err != nil {
		t.Fatalf("submit returned non-int cluster id %q: %v", clusterIDStr, err)
	}
	jobID := fmt.Sprintf("%d.0", clusterID)
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = schedd.RemoveJobs(cleanupCtx, fmt.Sprintf("ClusterId == %d", clusterID), "test cleanup")
	}()

	if err := waitForJobRunningHTTP(ctx, schedd, clusterID, 120*time.Second); err != nil {
		harness.PrintScheddLog()
		harness.PrintStarterLogs()
		t.Fatalf("job %s never reached Running: %v", jobID, err)
	}
	t.Logf("job %s is Running on a CCB-routed execute node", jobID)

	// --- Stand up the API server with its own inbound shared port -----------

	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	router, err := sharedportrouter.Start(sharedportrouter.Config{
		Listen: "127.0.0.1:0", // a concrete host, so the advertised address is derived
		Logger: logger.Slog(logging.DestinationHTTP),
	})
	if err != nil {
		t.Fatalf("starting the shared-port router: %v", err)
	}
	defer func() { _ = router.Close() }()
	t.Logf("API server shared port: %s", router.AdvertisedAddr())

	// Streaming off on purpose. The harness broker is too old for it anyway,
	// but saying so explicitly means a shared-port regression cannot be
	// covered up by a fallback that happens to work.
	ccbDialer := htcondor.NewCCBDialer(htcondor.CCBDialerConfig{
		Router:    router,
		Streaming: false,
		Logger:    logger.Slog(logging.DestinationHTTP),
	})

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
		CCB:                      ccbDialer,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = server.Start() }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	addr := waitForServerAddr(t, server, 10*time.Second)

	// --- Open a shell into the job over the WebSocket bridge ----------------

	wsURL := url.URL{
		Scheme:   "ws",
		Host:     addr,
		Path:     fmt.Sprintf("/api/v1/jobs/%s/ssh", jobID),
		RawQuery: "cols=120&rows=40",
	}
	hdr := http.Header{}
	hdr.Set("X-Test-User", testUser)

	dialer := websocket.Dialer{HandshakeTimeout: 60 * time.Second}
	wsConn, resp, err := dialer.DialContext(ctx, wsURL.String(), hdr)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			t.Logf("WS dial HTTP status: %s; body: %s", resp.Status, string(body))
		}
		t.Logf("shared-port router stats at failure: %+v", router.Stats())
		harness.PrintStarterLogs()
		t.Fatalf("WS dial failed -- the shell into the CCB-routed job never opened: %v", err)
	}
	defer func() { _ = wsConn.Close() }()

	const sentinel = "CCB_SHARED_PORT_OK_4242"
	if err := wsConn.WriteMessage(websocket.BinaryMessage, []byte("echo "+sentinel+"\n")); err != nil {
		t.Fatalf("WS write: %v", err)
	}

	var rx strings.Builder
	_ = wsConn.SetReadDeadline(time.Now().Add(45 * time.Second))
	for !strings.Contains(rx.String(), sentinel) {
		mt, payload, err := wsConn.ReadMessage()
		if err != nil {
			t.Fatalf("WS read: %v\nsaw so far: %q", err, rx.String())
		}
		if mt == websocket.BinaryMessage {
			rx.Write(payload)
		}
	}
	t.Logf("shell echoed the sentinel; the job is reachable -- by which path is the next check")

	closeJSON, _ := json.Marshal(wsControlMsg{Type: "close"})
	_ = wsConn.WriteMessage(websocket.TextMessage, closeJSON)

	// --- The oracle ---------------------------------------------------------

	stats := router.Stats()
	t.Logf("shared-port router stats: %+v", stats)
	if stats.Routed == 0 {
		t.Errorf("the router never routed a connection, so the shell reached the starter some "+
			"other way and this test proved nothing about the shared port: %+v", stats)
	}
	if stats.BadRequest > 0 || stats.UnknownID > 0 || stats.Undelivered > 0 {
		t.Errorf("the router saw connections it could not place: %+v", stats)
	}
}

// assertStartdIsCCBRouted fails the test unless the startd advertises a
// ccbid -- the premise the rest of the test rests on.
func assertStartdIsCCBRouted(ctx context.Context, t *testing.T, collector *htcondor.Collector) {
	t.Helper()
	loc, err := collector.LocateDaemon(ctx, "Startd", "")
	if err != nil {
		t.Fatalf("locating startd: %v", err)
	}
	if !strings.Contains(strings.ToUpper(loc.Address), "CCBID") {
		t.Fatalf("the startd advertises %q, which carries no ccbid: the pool is not CCB-routed, "+
			"so this test would pass by reaching the execute node directly", loc.Address)
	}
	t.Logf("startd is CCB-routed: %s", loc.Address)
}

// findSSHDConfigTemplate locates HTCondor's sshd config template. Its path is
// distro-dependent, and a developer build puts it somewhere none of the
// packaged locations name -- so derive candidates from where condor_master
// actually is before falling back to the packaged paths. Getting this wrong
// does not fail the test, it skips it, which is the worst outcome available.
func findSSHDConfigTemplate() string {
	const base = "condor_ssh_to_job_sshd_config_template"
	var candidates []string
	if master, err := exec.LookPath("condor_master"); err == nil {
		// .../sbin/condor_master -> .../lib, .../libexec, .../share/condor
		root := filepath.Dir(filepath.Dir(master))
		candidates = append(candidates,
			filepath.Join(root, "lib", base),
			filepath.Join(root, "lib64", "condor", base),
			filepath.Join(root, "libexec", base),
			filepath.Join(root, "share", "condor", base),
			filepath.Join(root, "etc", base),
		)
	}
	candidates = append(candidates,
		"/usr/lib/"+base,
		"/usr/lib64/condor/"+base,
		"/etc/condor/"+base,
		"/usr/share/condor/"+base,
	)
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// findSSHD locates the system sshd the starter will run on the execute node.
func findSSHD() string {
	if p, err := exec.LookPath("sshd"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// freeTCPPort returns a currently-free loopback port.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// waitForServerAddr polls until the server reports its bound address, instead
// of sleeping a fixed interval and hoping.
func waitForServerAddr(t *testing.T, server *Server, max time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if addr := server.GetAddr(); addr != "" {
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the API server never reported a listen address within %s", max)
	return ""
}
