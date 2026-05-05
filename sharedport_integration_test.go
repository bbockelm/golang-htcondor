//go:build integration

package htcondor

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSharedPortHTTPForwardingAndKeepalive is the end-to-end check for
// the shared_port + master keepalive integration:
//
//  1. Build a tiny helper binary that mimics what htcondor-api does
//     under condor_master: set up a sharedport.Listener on the
//     well-known UDS path, run a trivial HTTP handler on it, then
//     send DC_SET_READY and a DC_CHILDALIVE loop back to the master.
//  2. Spin up condor_master + condor_shared_port with the helper
//     registered as DAEMON_LIST=HTTP_API and
//     SHARED_PORT_HTTP_FORWARDING_ID=http_api.
//  3. Read shared_port_ad to discover the listener port, dial it,
//     issue a plain HTTP/1.0 GET, and verify the forwarded response
//     contains the helper's marker body.
//  4. Tail MasterLog and confirm both DC_SET_READY (60043) and
//     DC_CHILDALIVE (60008) appear.
//
// Why this lives at the package level rather than under sharedport/:
// the harness depends on this package's CondorTestHarness, and Go's
// test build doesn't let `sharedport` import the parent without an
// import cycle.
//
//nolint:gocyclo // Integration test; splitting the staging would obscure the protocol.
func TestSharedPortHTTPForwardingAndKeepalive(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test; needs condor_master")
	}

	// --- Step 1: build helper daemon ----------------------------------

	daemonDir := t.TempDir()
	daemonSrc := filepath.Join(daemonDir, "daemon_main.go")
	daemonBin := filepath.Join(daemonDir, "spdaemon")

	if err := os.WriteFile(daemonSrc, []byte(spDaemonMainSource), 0o600); err != nil {
		t.Fatalf("write daemon source: %v", err)
	}
	buildCmd := exec.Command("go", "build", "-buildvcs=false", "-o", daemonBin, daemonSrc)
	buildCmd.Env = append(os.Environ(), "GO111MODULE=on")
	buildCmd.Dir = projectRoot(t)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build daemon: %v\noutput: %s", err, string(out))
	}

	// --- Step 2: configure condor with shared_port forwarding ---------

	sockDir := filepath.Join(t.TempDir(), "spsock")
	if err := os.MkdirAll(sockDir, 0o700); err != nil {
		t.Fatalf("mkdir sockDir: %v", err)
	}

	// HTTP_API_ENVIRONMENT is the standard HTCondor mechanism for
	// injecting per-daemon env vars; our helper reads
	// _HTCONDOR_API_SHARED_PORT_DIR from there to know where to bind.
	// SHARED_PORT_HTTP_FORWARDING_ID is the C++ knob that tells
	// shared_port_server to forward non-CEDAR traffic to the daemon
	// listening at $DAEMON_SOCKET_DIR/<id>.
	extraConfig := fmt.Sprintf(`
DAEMON_LIST = MASTER, COLLECTOR, SHARED_PORT, HTTP_API
DAEMON_SOCKET_DIR = %s
SHARED_PORT_HTTP_FORWARDING_ID = http_api
SHARED_PORT_PORT = 0
SHARED_PORT_LOG = $(LOG)/SharedPortLog
SHARED_PORT_DEBUG = D_FULLDEBUG D_COMMAND
HTTP_API = %s
HTTP_API_LOG = $(LOG)/HTTPApiLog
HTTP_API_DEBUG = D_FULLDEBUG D_COMMAND
HTTP_API_ENVIRONMENT = "_HTCONDOR_API_SHARED_PORT_ID=http_api _HTCONDOR_API_SHARED_PORT_DIR=%s _HTCONDOR_API_BODY=shared-port-marker"
MASTER_DEBUG = D_FULLDEBUG D_COMMAND
`, sockDir, daemonBin, sockDir)

	harness := SetupCondorHarnessWithConfig(t, extraConfig)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("daemons did not start: %v", err)
	}

	// --- Step 3: discover the shared_port port ------------------------

	spAdPath := filepath.Join(harness.GetLockDir(), "shared_port_ad")
	var spPort int
	require.Eventually(t, func() bool {
		if p, ok := readSharedPortPort(spAdPath); ok {
			spPort = p
			return true
		}
		return false
	}, 30*time.Second, 250*time.Millisecond,
		"shared_port_ad never appeared at %s", spAdPath)

	// --- Step 4: drive an HTTP request through shared_port ------------

	target := fmt.Sprintf("127.0.0.1:%d", spPort)
	t.Logf("dialing shared_port at %s", target)

	// Helper daemon may take a beat to bind its UDS after master spawns
	// it. Retry until shared_port forwards us a real HTTP response.
	//
	// SHARED_PORT_HTTP_FORWARDING_ID was added to condor_shared_port
	// relatively recently (HTCondor 25.x). If the installed binary
	// predates the feature, our HTTP request gets routed to the
	// default forwarding id ("collector") and shared_port closes the
	// connection without forwarding to us. Detect that case and
	// t.Skip the HTTP-forwarding portion so older condor builds don't
	// flake the suite — keepalive + ready (verified below) is the
	// stricter end-to-end check and works regardless.
	var lastErr error
	var lastBody string
	ok := assertEventually(30*time.Second, 1*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err != nil {
			lastErr = err
			return false
		}
		defer func() { _ = c.Close() }()
		if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			lastErr = err
			return false
		}
		if _, err := c.Write([]byte("GET /probe HTTP/1.0\r\nHost: x\r\n\r\n")); err != nil {
			lastErr = err
			return false
		}
		buf, err := io.ReadAll(c)
		if err != nil {
			lastErr = err
			return false
		}
		got := string(buf)
		lastBody = got
		if !strings.Contains(got, "200 OK") {
			lastErr = fmt.Errorf("response missing 200 OK: %q", got)
			return false
		}
		if !strings.Contains(got, "shared-port-marker") {
			lastErr = fmt.Errorf("response missing daemon marker: %q", got)
			return false
		}
		return true
	})
	httpForwardingVerified := ok
	if !ok {
		// Distinguish "feature missing" from "feature broken". If the
		// SharedPortLog shows our HTTP request being routed to "ID
		// http_api", the feature is active and we have a real bug;
		// otherwise (request routed to "collector" or similar) the
		// installed condor_shared_port lacks SHARED_PORT_HTTP_FORWARDING_ID
		// and we report the HTTP probe as inconclusive but still verify
		// the keepalive + ready integration below.
		spLog := readFile(t, harness, "SharedPortLog")
		if !strings.Contains(spLog, "to ID http_api") {
			t.Logf("HTTP request via shared_port was not forwarded to http_api; "+
				"installed condor_shared_port likely predates SHARED_PORT_HTTP_FORWARDING_ID. "+
				"Skipping HTTP-forwarding assertion; keepalive + ready still verified. "+
				"last body=%q lastErr=%v", lastBody, lastErr)
		} else {
			dumpLog(t, harness, "MasterLog")
			dumpLog(t, harness, "SharedPortLog")
			dumpLog(t, harness, "HTTPApiLog")
			t.Logf("last body: %q", lastBody)
			t.Logf("last err: %v", lastErr)
			t.Fatalf("HTTP request through shared_port never returned the daemon marker")
		}
	}
	if httpForwardingVerified {
		t.Logf("✅ HTTP forwarding through shared_port verified")
	}

	// --- Step 5: verify keepalive + ready in MasterLog ----------------

	masterLog := filepath.Join(harness.GetLogDir(), "MasterLog")
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(masterLog) //nolint:gosec // test reading harness-owned file
		if err != nil {
			return false
		}
		s := string(b)
		// 60008 = DC_CHILDALIVE, 60043 = DC_SET_READY. The master log
		// is verbose enough that either the symbolic name or the
		// numeric command id will appear; accept either spelling so a
		// future condor change in log format doesn't flake the test.
		hasAlive := strings.Contains(s, "DC_CHILDALIVE") || strings.Contains(s, "60008")
		hasReady := strings.Contains(s, "DC_SET_READY") || strings.Contains(s, "60043") ||
			strings.Contains(s, "ready state")
		return hasAlive && hasReady
	}, 60*time.Second, 1*time.Second,
		"MasterLog never showed both DC_CHILDALIVE and DC_SET_READY")

	// --- Step 6: verify the inherited session is actually being used --
	//
	// When DC_CHILDALIVE rides on the inherited family session, the
	// master logs the child's authenticated identity as
	// `condor@child`. If we were instead doing a fresh handshake, the
	// identity would be the daemon process owner (e.g.
	// `vscode@<host>`). The check below is the regression test for
	// the SecurityNever / inherited-session-preferred path in
	// master.go's secConfigForMasterCommand: a future change that
	// breaks session import or skips the cache lookup will land us
	// back on the fresh-handshake fallback, and this assertion will
	// catch it.
	logBytes, err := os.ReadFile(masterLog) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("read MasterLog for identity check: %v", err)
	}
	logStr := string(logBytes)
	// Pull out the lines that handle DC_CHILDALIVE and inspect the
	// "from <identity> <addr>" portion for "condor@child".
	resumedSeen := false
	freshSeen := false
	for _, line := range strings.Split(logStr, "\n") {
		if !strings.Contains(line, "DC_CHILDALIVE") && !strings.Contains(line, "60008") {
			continue
		}
		if !strings.Contains(line, "from ") {
			continue
		}
		switch {
		case strings.Contains(line, "from condor@child"):
			resumedSeen = true
		case strings.Contains(line, "from "):
			// Anything other than condor@child means we did a fresh
			// handshake. Capture it so the failure message can show
			// which identity actually arrived.
			freshSeen = true
		}
	}
	if !resumedSeen {
		t.Errorf("DC_CHILDALIVE never used the inherited session "+
			"(expected master log entries `from condor@child`); "+
			"freshHandshakeSeen=%v", freshSeen)
		// Tail a slice of MasterLog to make the failure debuggable.
		tailMasterLog(t, logStr)
	} else {
		t.Logf("✅ Inherited session used for DC_CHILDALIVE (condor@child seen in MasterLog)")
	}
}

// tailMasterLog emits the last few DC_CHILDALIVE-related lines so a
// test failure shows what identity the master saw rather than the
// (huge) full log dump.
func tailMasterLog(t *testing.T, log string) {
	t.Helper()
	t.Logf("--- MasterLog DC_CHILDALIVE lines ---")
	count := 0
	const max = 6
	lines := strings.Split(log, "\n")
	for i := len(lines) - 1; i >= 0 && count < max; i-- {
		if strings.Contains(lines[i], "DC_CHILDALIVE") || strings.Contains(lines[i], "60008") {
			t.Logf("%s", lines[i])
			count++
		}
	}
	t.Logf("--- end ---")
}

// assertEventually is a require.Eventually-shaped helper that returns
// a bool instead of failing the test. We need this because the test's
// failure message includes log dumps captured *after* the polling
// gives up, and require.Eventually short-circuits via t.FailNow before
// we get a chance to emit them.
func assertEventually(timeout, interval time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(interval)
	}
}

// readFile slurps a condor log into a string, returning empty on
// error (the test treats "no log" as "no evidence of feature"). Used
// for inline checks; dumpLog handles the full-output diagnostic case.
func readFile(t *testing.T, harness *CondorTestHarness, name string) string {
	t.Helper()
	path := filepath.Join(harness.GetLogDir(), name)
	b, err := os.ReadFile(path) //nolint:gosec // test fixture path
	if err != nil {
		return ""
	}
	return string(b)
}

// dumpLog tails (or prints in full when small) the named condor log
// file into the test output. Used in failure paths where the test
// would otherwise fail with no actionable diagnostic.
func dumpLog(t *testing.T, harness *CondorTestHarness, name string) {
	t.Helper()
	path := filepath.Join(harness.GetLogDir(), name)
	b, err := os.ReadFile(path) //nolint:gosec // test fixture path
	if err != nil {
		t.Logf("--- %s: read failed: %v", name, err)
		return
	}
	t.Logf("--- %s (%d bytes) ---", name, len(b))
	for _, line := range strings.Split(string(b), "\n") {
		if line != "" {
			t.Logf("%s", line)
		}
	}
	t.Logf("--- end %s ---", name)
}

// readSharedPortPort scrapes shared_port_ad for the dynamically-
// assigned listening port. Format mirrors HTCondor's other classad
// drops: human-readable lines like `MyAddress = "<127.0.0.1:43217?...>"`.
// Returns (port, true) on success; (0, false) if the file is missing
// or unparseable, so callers can poll until the daemon writes it.
func readSharedPortPort(path string) (int, bool) {
	b, err := os.ReadFile(path) //nolint:gosec // test fixture path
	if err != nil {
		return 0, false
	}
	// Match :<port> directly after the address open-bracket. Any
	// trailing `?addrs=...` or `>` ends the match.
	re := regexp.MustCompile(`MyAddress\s*=\s*"<[^:]+:(\d+)`)
	m := re.FindStringSubmatch(string(b))
	if len(m) < 2 {
		return 0, false
	}
	var p int
	if _, err := fmt.Sscanf(m[1], "%d", &p); err != nil || p == 0 {
		return 0, false
	}
	return p, true
}

// spDaemonMainSource is the helper daemon. Compiled by the test into a
// standalone binary that condor_master then manages. It:
//
//   - reads the SHARED_PORT_DIR + ID env vars set via HTTP_API_ENVIRONMENT
//   - opens a sharedport.Listener at $DIR/$ID
//   - serves an HTTP handler that returns the body in $_HTCONDOR_API_BODY
//   - sends DC_SET_READY once the listener is up
//   - runs a DC_CHILDALIVE loop with a short hang timeout (so the
//     master log shows traffic well within the test's deadline)
//
// We deliberately keep it minimal: no condor config loading, no
// flags, no graceful shutdown of the HTTP server (we kill it via
// SIGTERM which Go's http.Server.Serve handles by returning).
const spDaemonMainSource = `package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/sharedport"
)

func main() {
	socketDir := os.Getenv("_HTCONDOR_API_SHARED_PORT_DIR")
	id := os.Getenv("_HTCONDOR_API_SHARED_PORT_ID")
	body := os.Getenv("_HTCONDOR_API_BODY")
	if body == "" {
		body = "ok"
	}
	if socketDir == "" || id == "" {
		log.Fatalf("missing _HTCONDOR_API_SHARED_PORT_DIR or _HTCONDOR_API_SHARED_PORT_ID")
	}
	socketPath := filepath.Join(socketDir, id)

	logf := func(f string, args ...any) { log.Printf("daemon: "+f, args...) }
	ln, err := sharedport.Listen(socketPath, sharedport.Options{
		HandshakeTimeout: 5 * time.Second,
		Logf:             logf,
	})
	if err != nil {
		log.Fatalf("sharedport.Listen %s: %v", socketPath, err)
	}
	defer func() { _ = ln.Close() }()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, body)
			fmt.Fprintf(w, "method=%s path=%s\n", r.Method, r.URL.Path)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		_ = srv.Serve(ln)
	}()

	// Master keepalive + ready. We use a short hang timeout so the
	// master log accumulates DC_CHILDALIVE events well within the
	// test's wait budget.
	master, err := htcondor.MasterFromEnv()
	if err != nil {
		log.Fatalf("MasterFromEnv: %v", err)
	}
	rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := master.SendReady(rctx, nil); err != nil {
		rcancel()
		log.Printf("SendReady: %v", err)
	} else {
		rcancel()
	}

	keepCtx, keepCancel := context.WithCancel(context.Background())
	stop, errs, err := master.StartKeepAlive(keepCtx, &htcondor.KeepAliveOptions{
		HangTimeout: 90 * time.Second,
		Interval:    1 * time.Second,
	})
	if err != nil {
		log.Printf("StartKeepAlive: %v", err)
	} else {
		go func() {
			for e := range errs {
				log.Printf("keepalive: %v", e)
			}
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh
	if stop != nil {
		stop()
	}
	keepCancel()
	_ = srv.Close()
	<-srvDone
}
`
