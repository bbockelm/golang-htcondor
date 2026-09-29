//go:build integration

package htcondor

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSSHToJobIntegration submits a long-running sleep job under a real
// HTCondor pool, waits for it to reach the Running state, then drives
// condor_ssh_to_job over CEDAR + crypto/ssh and verifies it can:
//
//  1. Authenticate as the job owner using the schedd-minted session and the
//     starter's one-shot RSA keypair.
//  2. Execute a remote command and read its stdout.
//  3. Open a PTY-backed interactive shell and exchange data over it.
//  4. Forward a TCP connection to a port the job listens on (direct-tcpip).
//
// Run with:   go test -tags=integration -run TestSSHToJobIntegration -v ./...
//
// Requires the host to have condor_master + sshd available; the test will
// skip cleanly if either is missing.
//
//nolint:gocyclo // Integration test with several discrete verification stages.
func TestSSHToJobIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// condor_ssh_to_job needs the system sshd binary on the execute node.
	// In our harness the execute node is the same machine, so a missing
	// sshd means we can't possibly succeed — skip rather than fail.
	if _, err := exec.LookPath("sshd"); err != nil {
		if _, err2 := exec.LookPath("/usr/sbin/sshd"); err2 != nil {
			t.Skip("sshd not found in PATH or /usr/sbin; skipping ssh-to-job integration test")
		}
	}

	// ENABLE_SSH_TO_JOB defaults to True but we set it explicitly for clarity.
	// SSH_TO_JOB_SSHD points the starter at the system sshd if it isn't in
	// the default location (the harness runs as a non-root user).
	// Where the sshd config template lives is distro-dependent. Default
	// HTCondor expects /usr/lib/, but on AlmaLinux it's under
	// /usr/lib64/condor or /etc/condor. We probe at test time and override
	// SSH_TO_JOB_SSHD_CONFIG_TEMPLATE if needed.
	tmplCandidates := []string{
		"/usr/lib/condor_ssh_to_job_sshd_config_template",
		"/usr/lib64/condor/condor_ssh_to_job_sshd_config_template",
		"/etc/condor/condor_ssh_to_job_sshd_config_template",
		"/usr/share/condor/condor_ssh_to_job_sshd_config_template",
	}
	// A developer's HTCondor is a build tree, where the template sits in
	// release_dir/lib next to the sbin holding condor_master. Probing only
	// the packaged locations meant this test skipped itself on exactly the
	// machines it was being written on, and a skip reads as a pass.
	if masterPath, lookErr := exec.LookPath("condor_master"); lookErr == nil {
		root := filepath.Dir(filepath.Dir(masterPath))
		tmplCandidates = append(tmplCandidates,
			filepath.Join(root, "lib", "condor_ssh_to_job_sshd_config_template"))
	}
	tmplPath := ""
	for _, p := range tmplCandidates {
		if _, statErr := exec.Command("test", "-f", p).Output(); statErr == nil {
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
	harness := SetupCondorHarnessWithConfig(t, extraConfig)

	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}
	if err := harness.WaitForStartd(45 * time.Second); err != nil {
		t.Fatalf("Startd never reported in: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	collector := NewCollector(harness.GetCollectorAddr())
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("Failed to locate schedd: %v", err)
	}
	t.Logf("Schedd discovered: name=%s, address=%s", location.Name, location.Address)
	schedd := NewSchedd(location.Name, location.Address)

	// Long-running sleep job. Note: transfer_executable=false means HTCondor
	// uses /bin/sleep already on the execute node — we don't have to ship
	// anything via spool.
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
	// Use Submit (non-spooled) so the job goes straight to Idle and the
	// negotiator can match it. SubmitRemote leaves the job in
	// HoldReasonCode=16 "Spooling input data files" until input is shipped.
	clusterIDStr, err := schedd.Submit(ctx, submitFile)
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("Submit failed: %v", err)
	}
	clusterID, err := strconv.Atoi(clusterIDStr)
	if err != nil {
		t.Fatalf("Submit returned non-int cluster id %q: %v", clusterIDStr, err)
	}
	t.Logf("Submitted cluster %d", clusterID)

	// Always try to clean the job up at end of test, even on failure, so we
	// don't leave a 10-minute sleeper lurking in the pool.
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if _, err := schedd.RemoveJobs(cleanupCtx, fmt.Sprintf("ClusterId == %d", clusterID), "test cleanup"); err != nil {
			t.Logf("warning: cleanup RemoveJobs failed: %v", err)
		}
	}()

	if err := waitForJobRunning(ctx, schedd, clusterID, 90*time.Second); err != nil {
		harness.PrintScheddLog()
		harness.PrintStarterLogs()
		t.Fatalf("job %d.0 never reached Running: %v", clusterID, err)
	}
	t.Logf("Job %d.0 is Running", clusterID)

	// --- Step 1: Verify GetJobConnectInfo returns sane fields ------------------
	// The schedd briefly returns "retry_is_sensible" while it's waiting for
	// the startd to register the starter — that's the same race the C++
	// condor_ssh_to_job tool retries through. We retry similarly.
	info, err := getJobConnectInfoWithRetry(ctx, schedd, clusterID, 0, 60*time.Second)
	if err != nil {
		harness.PrintScheddLog()
		harness.PrintStarterLogs()
		t.Fatalf("GetJobConnectInfo failed: %v", err)
	}
	if info.StarterAddr == "" || info.ClaimID == "" {
		t.Fatalf("GetJobConnectInfo missing fields: %+v", info)
	}
	t.Logf("GetJobConnectInfo: starter=%s slot=%s version=%s",
		info.StarterAddr, info.RemoteHost, info.StarterVersion)

	// --- Step 2: Open SSH and run a non-interactive command --------------------

	openCtx, openCancel := context.WithTimeout(ctx, 60*time.Second)
	defer openCancel()
	client, err := info.OpenSSH(openCtx, nil)
	if err != nil {
		harness.PrintScheddLog()
		harness.PrintStarterLogs()
		t.Fatalf("OpenSSH failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	const sentinel = "ssh-to-job-OK-12345"
	out, err := sess.CombinedOutput("echo " + sentinel + " && pwd && whoami")
	_ = sess.Close()
	if err != nil {
		harness.PrintStarterLogs()
		t.Fatalf("remote command failed: %v\n--- output ---\n%s", err, string(out))
	}
	got := string(out)
	if !strings.Contains(got, sentinel) {
		t.Fatalf("did not see sentinel %q in remote output:\n%s", sentinel, got)
	}
	if !strings.Contains(got, "execute") && !strings.Contains(got, "scratch") {
		t.Logf("WARN: remote pwd does not look like a job sandbox; full output:\n%s", got)
	}
	t.Logf("Remote command output:\n%s", got)

	// --- Step 3: Open an interactive PTY shell, send a line, read the echo ----

	sess2, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession (PTY) failed: %v", err)
	}
	defer func() { _ = sess2.Close() }()

	if err := sess2.RequestPty("xterm-256color", 24, 80, nil); err != nil {
		t.Fatalf("RequestPty failed: %v", err)
	}
	stdin, err := sess2.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe failed: %v", err)
	}
	stdout, err := sess2.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe failed: %v", err)
	}
	if err := sess2.Shell(); err != nil {
		t.Fatalf("Shell failed: %v", err)
	}

	const ptySentinel = "PTY-WORKED-987"
	if _, err := stdin.Write([]byte("echo " + ptySentinel + "\nexit\n")); err != nil {
		t.Fatalf("write to PTY stdin failed: %v", err)
	}

	// Read stdout until we see the sentinel or timeout. PTY echoes both the
	// command we typed and its output, so the sentinel will appear at least
	// once for the echo of the typed command and once for the echo command's
	// stdout. We just need to see it; either occurrence proves the bridge.
	readDone := make(chan error, 1)
	var ptyOut strings.Builder
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := stdout.Read(buf)
			if n > 0 {
				ptyOut.Write(buf[:n])
				if strings.Contains(ptyOut.String(), ptySentinel) {
					readDone <- nil
					return
				}
			}
			if rerr != nil {
				readDone <- rerr
				return
			}
		}
	}()

	select {
	case rerr := <-readDone:
		if rerr != nil && !errors.Is(rerr, context.Canceled) && !strings.Contains(ptyOut.String(), ptySentinel) {
			t.Fatalf("PTY read failed before seeing sentinel: %v\noutput so far:\n%s", rerr, ptyOut.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("timed out waiting for PTY sentinel; output so far:\n%s", ptyOut.String())
	}
	t.Logf("PTY output (truncated): %q", truncate(ptyOut.String(), 200))

	// Wait for the shell to exit, but cap it: the shell may not flush in time.
	waitDone := make(chan error, 1)
	go func() { waitDone <- sess2.Wait() }()
	select {
	case err := <-waitDone:
		if err != nil {
			t.Logf("PTY session exit (non-fatal): %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Logf("PTY session did not exit in 10s; closing forcibly")
	}

	// --- Step 4: Forward a TCP port out of the sandbox (direct-tcpip) -------
	//
	// This is what carries a web IDE, a debugger, or anything else the job
	// listens on, and it is the one capability nothing else in this package
	// exercised. It is not obviously available: the sshd HTCondor generates
	// sets no AllowTcpForwarding, so OpenSSH's default of "yes" applies --
	// a default nobody wrote down, which a future edit of the template
	// could take away silently. A forward that stopped working would
	// surface as a hung editor, a long way from the cause.
	//
	// Note what a failure here means. "administratively prohibited" is
	// forwarding being disabled; "connect failed" is forwarding working and
	// nothing listening on the far side. They are not the same finding.
	python, perr := exec.LookPath("python3")
	if perr != nil {
		t.Skip("python3 not found; skipping the port-forward step")
	}

	const fwdSentinel = "DIRECT-TCPIP-OK"
	port := 34000 + (os.Getpid() % 1000)

	// The payload goes over base64 because condor_ssh_to_job_shell_setup
	// runs `eval ${SSH_ORIGINAL_COMMAND}` with the expansion UNQUOTED: the
	// command is word-split on IFS -- newlines included -- and rejoined
	// with spaces before eval re-parses it. A multi-line `python3 -c`
	// script arrives as one line and dies on the first indented block.
	// Anything sent through ssh-to-job must survive that round trip, so
	// keep it to a single line with no significant whitespace.
	script := fmt.Sprintf(`import socket
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",%d))
s.listen(8)
while True:
    c,_=s.accept(); c.sendall(b"%s\n"); c.close()
`, port, fwdSentinel)

	// An absolute interpreter path: the job's PATH is the starter's plus
	// /bin:/usr/bin (condor_ssh_to_job_shell_setup), which need not contain
	// the python3 this machine's developer has.
	listenerCmd := fmt.Sprintf(`%s -c "import base64;exec(base64.b64decode('%s'))"`,
		python, base64.StdEncoding.EncodeToString([]byte(script)))

	// Run it in the foreground of a session we hold open, rather than
	// backgrounding it. A nohup'd child is killed with the session's
	// process group when Run returns, and macOS has no setsid to escape
	// with.
	sess3, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession (listener) failed: %v", err)
	}
	defer func() { _ = sess3.Close() }()
	var listenerErr strings.Builder
	sess3.Stderr = &listenerErr
	listenerDone := make(chan error, 1)
	go func() { listenerDone <- sess3.Run(listenerCmd) }()

	// The listener needs a moment to bind, and Dial is the only way to ask.
	// Retry rather than sleeping a guessed interval: a fixed wait either
	// flakes on a slow machine or wastes time on a fast one.
	var fwd net.Conn
	deadline := time.Now().Add(30 * time.Second)
	for {
		fwd, err = client.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			break
		}
		select {
		case lerr := <-listenerDone:
			t.Fatalf("in-sandbox listener exited before it could be reached: %v\nstderr:\n%s", lerr, listenerErr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("direct-tcpip to 127.0.0.1:%d never succeeded: %v", port, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	defer func() { _ = fwd.Close() }()

	_ = fwd.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, rerr := bufio.NewReader(fwd).ReadString('\n')
	if rerr != nil {
		t.Fatalf("reading from forwarded port failed: %v", rerr)
	}
	if strings.TrimSpace(got) != fwdSentinel {
		t.Fatalf("forwarded port said %q, want %q", strings.TrimSpace(got), fwdSentinel)
	}
	t.Logf("direct-tcpip forward to 127.0.0.1:%d returned %q", port, strings.TrimSpace(got))
}

// getJobConnectInfoWithRetry retries GET_JOB_CONNECT_INFO while the schedd
// returns the "retry_is_sensible" race condition that occurs briefly after a
// job transitions to Running but before the startd reports the starter
// address. Any other error short-circuits.
func getJobConnectInfoWithRetry(ctx context.Context, s *Schedd, clusterID, procID int, max time.Duration) (*JobConnectInfo, error) {
	deadline := time.Now().Add(max)
	var lastErr error
	for {
		callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		info, err := s.GetJobConnectInfo(callCtx, clusterID, procID)
		cancel()
		if err == nil {
			return info, nil
		}
		lastErr = err
		// We treat "Failed to read/get address of starter" and explicit
		// "is not running" as transient — the schedd marks them retry-sensible.
		msg := err.Error()
		retryable := strings.Contains(msg, "Failed to read address of starter") ||
			strings.Contains(msg, "Failed to get address of starter") ||
			strings.Contains(msg, "is not running") ||
			strings.Contains(msg, "blocked fetching")
		if !retryable {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("GetJobConnectInfo retry exhausted after %v: %w", max, lastErr)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func waitForJobRunning(ctx context.Context, s *Schedd, clusterID int, max time.Duration) error {
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
						return fmt.Errorf("job already in terminal state %d", v)
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
