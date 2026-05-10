//go:build integration

package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/gorilla/websocket"
)

// TestHTTPSSHToJobIntegration drives the WebSocket SSH bridge end-to-end
// against a real HTCondor mini-pool:
//
//  1. SetupCondorHarness brings up master/collector/schedd/negotiator/startd.
//  2. We submit a long-running sleep job, wait for it to be Running.
//  3. We spin up the httpserver Handler with header-based auth.
//  4. We open a WebSocket to /api/v1/jobs/<id>/ssh.
//  5. We send keystrokes as binary frames, verify the echo'd bytes come back
//     in binary frames.
//  6. We send a resize control frame (verify no panic, no close).
//  7. We send {"type":"close"} and verify the server emits an exit text frame
//     and closes cleanly.
//
// Run with: go test -tags=integration -run TestHTTPSSHToJobIntegration -v ./httpserver/
//
//nolint:gocyclo // Integration test with several discrete verification stages.
func TestHTTPSSHToJobIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not in PATH; skipping")
	}
	if _, err := exec.LookPath("sshd"); err != nil {
		if _, err2 := exec.LookPath("/usr/sbin/sshd"); err2 != nil {
			t.Skip("sshd not in PATH or /usr/sbin; skipping")
		}
	}

	tmplCandidates := []string{
		"/usr/lib/condor_ssh_to_job_sshd_config_template",
		"/usr/lib64/condor/condor_ssh_to_job_sshd_config_template",
		"/etc/condor/condor_ssh_to_job_sshd_config_template",
		"/usr/share/condor/condor_ssh_to_job_sshd_config_template",
	}
	tmplPath := ""
	for _, p := range tmplCandidates {
		if _, statErr := os.Stat(p); statErr == nil {
			tmplPath = p
			break
		}
	}
	if tmplPath == "" {
		t.Skip("condor_ssh_to_job_sshd_config_template not found; skipping")
	}

	extraConfig := fmt.Sprintf(`
ENABLE_SSH_TO_JOB = True
SSH_TO_JOB_SSHD = /usr/sbin/sshd
SSH_TO_JOB_SSHD_CONFIG_TEMPLATE = %s
`, tmplPath)
	harness := htcondor.SetupCondorHarnessWithConfig(t, extraConfig)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}
	if err := harness.WaitForStartd(45 * time.Second); err != nil {
		t.Fatalf("Startd never reported in: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	collector := htcondor.NewCollector(harness.GetCollectorAddr())
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}
	t.Logf("Schedd: name=%s addr=%s", location.Name, location.Address)
	schedd := htcondor.NewSchedd(location.Name, location.Address)

	// Submit a long-running job. We use SubmitRemote so we get the integer
	// cluster id directly, matching what the WebSocket URL needs.
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
	// Use Submit (non-spooled) so the job lands in Idle and the negotiator
	// can match it without us needing to ship input via SPOOL_JOB_FILES.
	clusterIDStr, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("Submit: %v", err)
	}
	clusterID, err := strconv.Atoi(clusterIDStr)
	if err != nil {
		t.Fatalf("Submit returned non-int cluster id %q: %v", clusterIDStr, err)
	}
	jobID := fmt.Sprintf("%d.0", clusterID)
	t.Logf("Submitted %s", jobID)

	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = schedd.RemoveJobs(cleanupCtx, fmt.Sprintf("ClusterId == %d", clusterID), "test cleanup")
	}()

	if err := waitForJobRunningHTTP(ctx, schedd, clusterID, 90*time.Second); err != nil {
		harness.PrintScheddLog()
		harness.PrintStarterLogs()
		t.Fatalf("Job %s never reached Running: %v", jobID, err)
	}
	t.Logf("Job %s is Running", jobID)

	// --- Stand up the HTTP server -------------------------------------------

	passwordsDir := filepath.Join(harness.GetSpoolDir(), "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		t.Fatalf("mkdir passwords.d: %v", err)
	}
	signingKeyPath := filepath.Join(passwordsDir, "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(signingKeyPath, key, 0600); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	server, err := NewServer(Config{
		ListenAddr:               "127.0.0.1:0",
		ScheddName:               location.Name,
		ScheddAddr:               location.Address,
		UserHeader:               "X-Test-User",
		UserHeaderTrustAnyUnsafe: true, // demo opt-in: tests run on a single host with no proxy
		SigningKeyPath:           signingKeyPath,
		TrustDomain:              "test.htcondor.org",
		UIDDomain:                "test.htcondor.org",
		OAuth2DBPath:             filepath.Join(harness.GetSpoolDir(), "oauth2.db"),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = server.Start() }()
	time.Sleep(500 * time.Millisecond)
	addr := server.GetAddr()
	if addr == "" {
		t.Fatalf("server has no addr")
	}
	t.Logf("HTTP server: %s", addr)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	// --- Open the WebSocket -------------------------------------------------

	wsURL := url.URL{
		Scheme:   "ws",
		Host:     addr,
		Path:     fmt.Sprintf("/api/v1/jobs/%s/ssh", jobID),
		RawQuery: "cols=120&rows=40",
	}
	hdr := http.Header{}
	hdr.Set("X-Test-User", "testuser")

	// First, sanity-check the auth header by issuing a plain GET to a non-WS
	// endpoint. If this 401's, the handshake will too — for a clearer reason.
	probeReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s/api/v1/whoami", addr), nil)
	probeReq.Header.Set("X-Test-User", "testuser")
	probeResp, probeErr := http.DefaultClient.Do(probeReq)
	if probeErr != nil {
		t.Fatalf("auth-probe GET failed: %v", probeErr)
	}
	probeBody, _ := io.ReadAll(probeResp.Body)
	_ = probeResp.Body.Close()
	t.Logf("auth probe %s → %s: %s", probeReq.URL, probeResp.Status, string(probeBody))
	if probeResp.StatusCode != http.StatusOK {
		t.Fatalf("auth header not honored: probe returned %d", probeResp.StatusCode)
	}

	dialer := websocket.Dialer{HandshakeTimeout: 30 * time.Second}
	wsConn, resp, err := dialer.DialContext(ctx, wsURL.String(), hdr)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			t.Logf("WS dial HTTP status: %s; body: %s", resp.Status, string(body))
		} else {
			t.Logf("WS dial returned nil response (transport-level failure)")
		}
		harness.PrintStarterLogs()
		t.Fatalf("WS dial failed: %v", err)
	}
	defer func() { _ = wsConn.Close() }()

	// Set a generous read deadline so a stuck pipe doesn't hang the test.
	_ = wsConn.SetReadDeadline(time.Now().Add(45 * time.Second))

	// --- Step 1: send keystrokes, expect echo back --------------------------

	const sentinel = "WS_BRIDGE_OK_4242"
	cmd := []byte("echo " + sentinel + "\n")
	if err := wsConn.WriteMessage(websocket.BinaryMessage, cmd); err != nil {
		t.Fatalf("WS write: %v", err)
	}

	var rxBuf strings.Builder
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(rxBuf.String(), sentinel) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for sentinel; saw so far: %q", rxBuf.String())
		}
		mt, payload, err := wsConn.ReadMessage()
		if err != nil {
			t.Fatalf("WS read: %v\nsaw so far: %q", err, rxBuf.String())
		}
		switch mt {
		case websocket.BinaryMessage:
			rxBuf.Write(payload)
		case websocket.TextMessage:
			t.Logf("ctrl frame from server: %s", string(payload))
		}
	}
	t.Logf("Got sentinel; PTY echo received %d bytes", rxBuf.Len())

	// --- Step 2: send a resize control frame --------------------------------

	resize := wsControlMsg{Type: "resize", Cols: 200, Rows: 60}
	resizeJSON, _ := json.Marshal(resize)
	if err := wsConn.WriteMessage(websocket.TextMessage, resizeJSON); err != nil {
		t.Fatalf("WS write resize: %v", err)
	}
	// No ack expected; just confirm the connection is still alive by sending
	// another small command and reading at least one more frame.
	if err := wsConn.WriteMessage(websocket.BinaryMessage, []byte("true\n")); err != nil {
		t.Fatalf("WS write post-resize: %v", err)
	}
	_, _, err = wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("WS read after resize/echo: %v", err)
	}

	// --- Step 3: graceful close ---------------------------------------------

	closeMsg := wsControlMsg{Type: "close"}
	closeJSON, _ := json.Marshal(closeMsg)
	if err := wsConn.WriteMessage(websocket.TextMessage, closeJSON); err != nil {
		t.Fatalf("WS write close: %v", err)
	}

	// Drain remaining frames; expect to see an "exit" text frame before the
	// connection closes.
	sawExit := false
	_ = wsConn.SetReadDeadline(time.Now().Add(20 * time.Second))
	for {
		mt, payload, err := wsConn.ReadMessage()
		if err != nil {
			break
		}
		if mt == websocket.TextMessage {
			var ctrl wsControlMsg
			if jerr := json.Unmarshal(payload, &ctrl); jerr == nil && ctrl.Type == "exit" {
				sawExit = true
				t.Logf("exit frame: code=%d reason=%q", ctrl.Code, ctrl.Reason)
				break
			}
		}
	}
	if !sawExit {
		t.Errorf("expected exit text frame after close request")
	}
}

// waitForJobRunningHTTP polls the schedd until the job hits JobStatus 2
// (Running) or the deadline fires.
func waitForJobRunningHTTP(ctx context.Context, s *htcondor.Schedd, clusterID int, max time.Duration) error {
	deadline := time.Now().Add(max)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout after %v", max)
		}
		ads, err := s.Query(ctx, fmt.Sprintf("ClusterId == %d", clusterID), []string{"JobStatus", "HoldReason"})
		if err == nil && len(ads) > 0 {
			if statusExpr, ok := ads[0].Lookup("JobStatus"); ok {
				if v, verr := statusExpr.Eval(nil).IntValue(); verr == nil {
					switch v {
					case 2:
						return nil
					case 5:
						hold, _ := ads[0].EvaluateAttrString("HoldReason")
						return fmt.Errorf("job went on hold: %s", hold)
					case 3, 4:
						return fmt.Errorf("job in terminal state %d", v)
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
