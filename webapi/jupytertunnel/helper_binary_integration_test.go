//go:build integration

package jupytertunnel

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestHelperBinaryEndToEnd runs the real htcondor-jupyter-helper binary as a
// subprocess (with --daemonize) against an httptest webapp and an HTTP
// server bound to a Unix domain socket. It validates the production paths
// that the unit-level TestEndToEnd doesn't cover:
//
//   - Token file is read and unlinked before the daemon connects.
//   - Stage 1 → stage 2 re-exec actually detaches and the parent exits 0.
//   - The detached daemon dials the websocket, sets up yamux, and serves
//     UDS proxy traffic.
//
// Run with: go test -tags=integration -run TestHelperBinaryEndToEnd ./jupytertunnel/
//
// Requires bin/htcondor-jupyter-helper to be built already
// (`make build-jupyter-helper`). The test will skip cleanly if the binary
// is missing or built for the wrong OS (linux-only, since the helper
// daemonizes via setsid which doesn't make sense on macOS test runs).
func TestHelperBinaryEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}

	helperBin := findHelperBinary(t)

	// --- "Jupyter" stand-in: HTTP on a UDS ---------------------------------
	tmp := t.TempDir()
	sockPath := filepath.Join(tmp, "jupyter.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer listener.Close()

	const sentinel = "fake-jupyter-OK"
	udsServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s path=%s", sentinel, r.URL.Path)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = udsServer.Serve(listener) }()
	defer udsServer.Close()

	// --- Webapp-side registry + httptest server ----------------------------
	reg, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/tunnel/")
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("upgrade: %v", err)
			return
		}
		inst, err := reg.AcceptTunnel(id, bearer, ws)
		if err != nil {
			t.Logf("AcceptTunnel: %v", err)
			_ = ws.Close()
			return
		}
		inst.Wait()
	})
	mux.HandleFunc("/proxy/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/proxy/")
		id, upstream := splitOnce(rest)
		inst, ok := reg.Lookup(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		reg.Proxy(inst, upstream, w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// --- Create instance, write token to a file, run the helper binary ---
	instID, token, err := reg.CreateInstance(CreateInstanceOptions{Owner: "tester"})
	if err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}

	tokenFile := filepath.Join(tmp, "token")
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	wsURL := strings.Replace(srv.URL, "http://", "ws://", 1) + "/tunnel/" + instID

	cmd := exec.Command(helperBin,
		"--upstream", wsURL,
		"--token-file", tokenFile,
		"--socket", sockPath,
		"--daemonize",
		"--log-file", filepath.Join(tmp, "helper.log"),
	)
	cmd.Stdout = newLineLogger(t, "helper.stdout")
	cmd.Stderr = newLineLogger(t, "helper.stderr")
	if err := cmd.Run(); err != nil {
		t.Fatalf("helper --daemonize exited %v\n--- log ---\n%s", err, readFile(filepath.Join(tmp, "helper.log")))
	}

	// Stage 1 has exited 0; the daemonized child is now alive somewhere.
	// Wait for the registry to observe the tunnel.
	if !waitFor(5*time.Second, func() bool {
		inst, ok := reg.Lookup(instID)
		if !ok {
			return false
		}
		inst.mu.Lock()
		defer inst.mu.Unlock()
		return inst.tunnel != nil
	}) {
		t.Fatalf("daemonized helper never registered\n--- helper log ---\n%s",
			readFile(filepath.Join(tmp, "helper.log")))
	}

	// Token file must be gone — the helper unlinks it before daemonizing.
	if _, err := os.Stat(tokenFile); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("token file should have been unlinked, but stat returned: %v", err)
	}

	// Sanity-check the proxy.
	resp, err := http.Get(srv.URL + "/proxy/" + instID + "/check")
	if err != nil {
		t.Fatalf("proxy GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), sentinel) {
		t.Errorf("proxy round-trip: status=%d body=%q", resp.StatusCode, body)
	}

	// Tear the tunnel down by closing the instance; the daemon will see
	// EOF on its websocket and exit. Look for it via the log file.
	reg.CloseInstance(instID)
	if !waitFor(5*time.Second, func() bool {
		// Whatever pid was spawned, it has long since detached. We can't
		// easily wait on it, but we can confirm the registry agrees the
		// tunnel is gone.
		_, ok := reg.Lookup(instID)
		return !ok
	}) {
		t.Errorf("registry did not finalize close")
	}
}

// findHelperBinary locates bin/htcondor-jupyter-helper relative to the
// module root (one level up from this package). Skips the test if missing
// or not built for linux (the daemon path uses Setsid).
func findHelperBinary(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// Module root is the parent of the jupytertunnel package dir.
	root := filepath.Dir(wd)
	bin := filepath.Join(root, "bin", "htcondor-jupyter-helper")
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("helper binary not found at %s; run `make build-jupyter-helper`", bin)
	}
	// We require the host OS to be linux; the helper's Setsid path is
	// linux-only (and the binary itself is built for linux/<arch>).
	out, _ := exec.Command("uname", "-s").Output()
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(string(out))), "linux") {
		t.Skipf("helper integration test runs on linux only (uname=%q)", strings.TrimSpace(string(out)))
	}
	return bin
}

func splitOnce(s string) (head, tail string) {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i], s[i:]
	}
	return s, "/"
}

// newLineLogger returns an io.Writer that t.Logf's each line. Useful for
// streaming a subprocess's stdio into the test output without losing it.
func newLineLogger(t *testing.T, prefix string) io.Writer {
	return &lineLogger{t: t, prefix: prefix}
}

type lineLogger struct {
	t      *testing.T
	prefix string
	buf    []byte
}

func (l *lineLogger) Write(p []byte) (int, error) {
	l.buf = append(l.buf, p...)
	for {
		i := strings.IndexByte(string(l.buf), '\n')
		if i < 0 {
			break
		}
		l.t.Logf("%s: %s", l.prefix, string(l.buf[:i]))
		l.buf = l.buf[i+1:]
	}
	return len(p), nil
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("(read %s: %v)", path, err)
	}
	return string(b)
}
