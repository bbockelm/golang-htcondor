//go:build integration

// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
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

	"golang.org/x/crypto/ssh"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"
)

// TestSSHGatewayIntegration drives the whole thing against a real pool:
// a real ssh client, a real device-code grant, a real schedd checking
// ownership, and a real sshd inside a real job.
//
// Everything else in this package's gateway tests uses a fake transport
// or a fake flow. This is the one that can tell us the CEDAR leg works,
// which is where the Jupyter proxy's problems actually were.
//
// The device approval is done by calling the storage directly, standing
// in for the human with the browser. Everything on either side of that
// -- the device authorization, the polling, the token, the introspection
// that resolves the account -- is the real path.
func TestSSHGatewayIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	for _, bin := range []string{"condor_master", "ssh"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not in PATH; skipping", bin)
		}
	}
	extraConfig, ok := htcondor.SSHToJobHarnessConfig()
	if !ok {
		t.Skip("ssh-to-job prerequisites (sshd, sshd config template) not found; skipping")
	}
	harness := htcondor.SetupCondorHarnessWithConfig(t, extraConfig)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("daemons: %v", err)
	}
	if err := harness.WaitForStartd(45 * time.Second); err != nil {
		t.Fatalf("startd never reported in: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	collector := htcondor.NewCollector(harness.GetCollectorAddr())
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("locate schedd: %v", err)
	}
	schedd := htcondor.NewSchedd(location.Name, location.Address)

	// Submitted AS testUser, because the schedd ownership-checks
	// GET_JOB_CONNECT_INFO and the gateway will be calling as whoever
	// the device grant resolved to.
	submitCtx, err := contextAsUser(ctx, harness, testUser)
	if err != nil {
		t.Fatalf("submit context: %v", err)
	}
	clusterIDStr, err := schedd.Submit(submitCtx, `
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
`)
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("submit: %v", err)
	}
	clusterID, err := strconv.Atoi(clusterIDStr)
	if err != nil {
		t.Fatalf("submit returned %q: %v", clusterIDStr, err)
	}
	jobID := fmt.Sprintf("%d.0", clusterID)
	t.Logf("submitted %s", jobID)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = schedd.RemoveJobs(c, fmt.Sprintf("ClusterId == %d", clusterID), "test cleanup")
	}()

	if err := waitForJobRunningHTTP(ctx, schedd, clusterID, 90*time.Second); err != nil {
		harness.PrintScheddLog()
		harness.PrintStarterLogs()
		t.Fatalf("job %s never ran: %v", jobID, err)
	}
	t.Logf("job %s is running", jobID)

	listenAddr, issuerURL := reserveAddr(t)
	server, err := NewServer(Config{
		ListenAddr:               listenAddr,
		OAuth2Issuer:             issuerURL,
		ScheddName:               location.Name,
		ScheddAddr:               location.Address,
		UserHeader:               "X-Test-User",
		UserHeaderTrustAnyUnsafe: true,
		SigningKeyPath:           harness.GetSigningKeyPath(),
		TrustDomain:              harness.GetTrustDomain(),
		UIDDomain:                harness.GetTrustDomain(),
		OAuth2DBPath:             filepath.Join(harness.GetSpoolDir(), "oauth2.db"),
		KEKFilePath:              writeKEK(t, t.TempDir()),
		EnableMCP:                true,
		SSHGatewayAddress:        "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	startErr := make(chan error, 1)
	go func() { startErr <- server.Start() }()
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(c)
	}()

	gwAddr := waitForGateway(t, server, startErr)
	gwPort, err := portOf(gwAddr)
	if err != nil {
		t.Fatalf("gateway address %q: %v", gwAddr, err)
	}
	t.Logf("gateway listening on %s", gwAddr)

	// Probe the device endpoint the gateway will call, before asking ssh
	// to do it. A failure here reaches the terminal only as "could not
	// start the login flow", which says nothing about why.
	probe := url.Values{}
	probe.Set("client_id", sshGatewayClientID)
	probe.Set("scope", strings.Join(sshGatewayScopes, " "))
	issuer := server.oauth2Provider.config.AccessTokenIssuer
	t.Logf("gateway issuer: %s", issuer)
	probeReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		issuer+"/mcp/oauth2/device/authorize", strings.NewReader(probe.Encode()))
	if err != nil {
		t.Fatalf("device-authorize probe request: %v", err)
	}
	probeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	probeResp, err := http.DefaultClient.Do(probeReq)
	if err != nil {
		t.Fatalf("device-authorize probe: %v", err)
	}
	probeBody, _ := io.ReadAll(probeResp.Body)
	_ = probeResp.Body.Close()
	t.Logf("device-authorize probe %s -> %s: %s", issuer, probeResp.Status, probeBody)
	if probeResp.StatusCode != http.StatusOK {
		t.Fatalf("the device endpoint the gateway drives is not usable: %s", probeBody)
	}

	// Stand in for the human at the browser.
	approved := make(chan string, 1)
	approveCtx, stopApproving := context.WithCancel(ctx)
	defer stopApproving()
	go approvePendingDeviceCodes(approveCtx, t, server.Handler, testUser, approved)

	// The real client. The username is the TARGET -- the job to reach --
	// not an identity; the identity is whatever the grant resolved to.
	//nolint:gosec // fixed argv; the binary is resolved by LookPath above
	cmd := exec.CommandContext(ctx, "ssh",
		// -F /dev/null so the developer's own ~/.ssh/config cannot reach
		// this. ControlMaster in particular is not a stylistic
		// difference: the mux layer swallows the reason a session
		// channel was refused and reports "Session open refused by
		// peer", which is exactly the diagnostic these tests exist for.
		"-F", "/dev/null",
		"-p", gwPort,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "PubkeyAuthentication=no",
		"-o", "PreferredAuthentications=keyboard-interactive",
		"-o", "IdentitiesOnly=yes",
		"-o", "LogLevel=ERROR",
		"-T",
		jobID+"@127.0.0.1",
		"echo gateway-reached-the-job && pwd",
	)
	out, sshErr := cmd.CombinedOutput()
	t.Logf("ssh exit=%v output:\n%s", sshErr, out)

	select {
	case code := <-approved:
		t.Logf("approved device code %s as %s", code, testUser)
	default:
		t.Error("no device code was ever presented for approval; the gateway never started a flow")
	}

	if sshErr != nil {
		harness.PrintScheddLog()
		harness.PrintStarterLogs()
		t.Fatalf("ssh through the gateway failed: %v", sshErr)
	}
	if !strings.Contains(string(out), "gateway-reached-the-job") {
		t.Fatalf("the command did not run inside the job:\n%s", out)
	}
	// The working directory proves it ran in the sandbox rather than
	// anywhere on the access point.
	if !strings.Contains(string(out), "dir_") && !strings.Contains(string(out), "execute") {
		t.Errorf("the shell does not look like it is in a job sandbox:\n%s", out)
	}
}

// TestSSHGatewayCreatesASessionOnDemand drives the other half of the
// target rule: any username that is not a job id names an interactive
// session, started if the caller has none.
//
// This is what a user gets from a bare `ssh gateway`, since the client
// sends their local login and nothing about it looks like a job id.
func TestSSHGatewayCreatesASessionOnDemand(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	for _, bin := range []string{"condor_master", "ssh"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not in PATH; skipping", bin)
		}
	}
	extraConfig, ok := htcondor.SSHToJobHarnessConfig()
	if !ok {
		t.Skip("ssh-to-job prerequisites (sshd, sshd config template) not found; skipping")
	}
	// A created session asks for the interactive defaults -- 1 CPU and
	// 1 GB each of memory and disk -- and the harness's slot is sized
	// from whatever the host reports, which on a laptop is not
	// necessarily enough. Sizing the slot here rather than shrinking
	// the request keeps the test honest about what the gateway
	// actually submits: a slot too small is a site's problem to
	// configure, and a test that quietly asked for less would not have
	// caught this at all.
	harness := htcondor.SetupCondorHarnessWithConfig(t, extraConfig+`
NUM_CPUS = 4
MEMORY = 8192
`)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("daemons: %v", err)
	}
	if err := harness.WaitForStartd(45 * time.Second); err != nil {
		t.Fatalf("startd never reported in: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	collector := htcondor.NewCollector(harness.GetCollectorAddr())
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("locate schedd: %v", err)
	}

	listenAddr, issuerURL := reserveAddr(t)
	server, err := NewServer(Config{
		ListenAddr:               listenAddr,
		OAuth2Issuer:             issuerURL,
		ScheddName:               location.Name,
		ScheddAddr:               location.Address,
		UserHeader:               "X-Test-User",
		UserHeaderTrustAnyUnsafe: true,
		SigningKeyPath:           harness.GetSigningKeyPath(),
		TrustDomain:              harness.GetTrustDomain(),
		UIDDomain:                harness.GetTrustDomain(),
		OAuth2DBPath:             filepath.Join(harness.GetSpoolDir(), "oauth2-ondemand.db"),
		KEKFilePath:              writeKEK(t, t.TempDir()),
		EnableMCP:                true,
		SSHGatewayAddress:        "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	startErr := make(chan error, 1)
	go func() { startErr <- server.Start() }()
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(c)
	}()

	gwAddr := waitForGateway(t, server, startErr)
	gwPort, err := portOf(gwAddr)
	if err != nil {
		t.Fatalf("gateway address %q: %v", gwAddr, err)
	}

	approveCtx, stopApproving := context.WithCancel(ctx)
	defer stopApproving()
	go approvePendingDeviceCodes(approveCtx, t, server.Handler, testUser, nil)

	defer func() {
		schedd := htcondor.NewSchedd(location.Name, location.Address)
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if sctx, err := contextAsUser(c, harness, testUser); err == nil {
			_, _ = schedd.RemoveJobs(sctx, "True", "test cleanup")
		}
	}()

	//nolint:gosec // fixed argv; the binary is resolved by LookPath above
	cmd := exec.CommandContext(ctx, "ssh",
		// -F /dev/null so the developer's own ~/.ssh/config cannot reach
		// this. ControlMaster in particular is not a stylistic
		// difference: the mux layer swallows the reason a session
		// channel was refused and reports "Session open refused by
		// peer", which is exactly the diagnostic these tests exist for.
		"-F", "/dev/null",
		"-p", gwPort,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "PubkeyAuthentication=no",
		"-o", "PreferredAuthentications=keyboard-interactive",
		"-o", "IdentitiesOnly=yes",
		// Not ERROR: the reason a session channel was refused is logged
		// at INFO, and that reason is the whole diagnostic when
		// creating a session goes wrong.
		"-o", "LogLevel=INFO",
		"-T",
		"+gwsession@127.0.0.1",
		"echo on-demand-session-reached",
	)
	out, sshErr := cmd.CombinedOutput()
	t.Logf("ssh exit=%v output:\n%s", sshErr, out)

	if sshErr != nil {
		logInteractiveSessions(ctx, t, server, testUser)
		harness.PrintScheddLog()
		t.Fatalf("ssh to a named session failed: %v", sshErr)
	}
	if !strings.Contains(string(out), "on-demand-session-reached") {
		t.Fatalf("the command did not run in the created session:\n%s", out)
	}

	// The session is a real one the rest of the API can see, not
	// something the gateway keeps to itself.
	// Server has its own mcpServer field (the HTTP one), which shadows
	// the Handler's. Named explicitly so this reaches the MCP server.
	mgr := server.Handler.mcpServer.InteractiveManager()
	if mgr == nil {
		t.Fatal("no interactive manager")
	}
	sessions, err := mgr.List(ctx, interactive.Caller{Actor: testUser, Owner: testUser})
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	found := false
	for _, s := range sessions {
		t.Logf("session %q job=%s status=%s", s.Name, s.JobID, s.Status)
		if s.Name == "gwsession" {
			found = true
		}
	}
	if !found {
		t.Error("the session the gateway created is not listed")
	}
}

// logInteractiveSessions dumps what the caller's sessions are doing.
//
// The ssh error on its own cannot tell "queued behind the negotiator"
// from "held" from "never submitted", and those want different fixes.
func logInteractiveSessions(ctx context.Context, t *testing.T, server *Server, account string) {
	t.Helper()
	mgr := server.Handler.mcpServer.InteractiveManager()
	if mgr == nil {
		t.Log("no interactive manager")
		return
	}
	sessions, err := mgr.List(ctx, interactive.Caller{Actor: account, Owner: account})
	if err != nil {
		t.Logf("listing sessions: %v", err)
		return
	}
	if len(sessions) == 0 {
		t.Log("the caller has no interactive sessions at all")
	}
	for _, s := range sessions {
		t.Logf("session %q job=%s status=%s(%d) hold=%q",
			s.Name, s.JobID, s.Status, s.JobStatus, s.HoldReason)
	}
}

// TestSSHGatewayRefusesSomeoneElsesJob checks that the schedd, not this
// code, is what stops a caller reaching a job they do not own -- the
// gateway deliberately does not second-guess it.
func TestSSHGatewayRefusesSomeoneElsesJob(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not in PATH; skipping")
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not in PATH; skipping")
	}

	harness := htcondor.SetupCondorHarness(t)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("daemons: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	collector := htcondor.NewCollector(harness.GetCollectorAddr())
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("locate schedd: %v", err)
	}

	listenAddr, issuerURL := reserveAddr(t)
	server, err := NewServer(Config{
		ListenAddr:               listenAddr,
		OAuth2Issuer:             issuerURL,
		ScheddName:               location.Name,
		ScheddAddr:               location.Address,
		UserHeader:               "X-Test-User",
		UserHeaderTrustAnyUnsafe: true,
		SigningKeyPath:           harness.GetSigningKeyPath(),
		TrustDomain:              harness.GetTrustDomain(),
		UIDDomain:                harness.GetTrustDomain(),
		OAuth2DBPath:             filepath.Join(harness.GetSpoolDir(), "oauth2-denied.db"),
		KEKFilePath:              writeKEK(t, t.TempDir()),
		EnableMCP:                true,
		SSHGatewayAddress:        "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	startErr := make(chan error, 1)
	go func() { startErr <- server.Start() }()
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(c)
	}()

	gwAddr := waitForGateway(t, server, startErr)
	gwPort, err := portOf(gwAddr)
	if err != nil {
		t.Fatalf("gateway address %q: %v", gwAddr, err)
	}

	approveCtx, stopApproving := context.WithCancel(ctx)
	defer stopApproving()
	go approvePendingDeviceCodes(approveCtx, t, server.Handler, "someone-else", nil)

	// A cluster id nobody owns, because nothing was submitted.
	//nolint:gosec // fixed argv; the binary is resolved by LookPath above
	cmd := exec.CommandContext(ctx, "ssh",
		// -F /dev/null so the developer's own ~/.ssh/config cannot reach
		// this. ControlMaster in particular is not a stylistic
		// difference: the mux layer swallows the reason a session
		// channel was refused and reports "Session open refused by
		// peer", which is exactly the diagnostic these tests exist for.
		"-F", "/dev/null",
		"-p", gwPort,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "PubkeyAuthentication=no",
		"-o", "PreferredAuthentications=keyboard-interactive",
		"-o", "IdentitiesOnly=yes",
		"-o", "LogLevel=ERROR",
		"-T",
		"999999.0@127.0.0.1",
		"echo should-not-run",
	)
	out, err := cmd.CombinedOutput()
	t.Logf("ssh exit=%v output:\n%s", err, out)

	if err == nil && strings.Contains(string(out), "should-not-run") {
		t.Fatal("a caller reached a job that does not exist")
	}
	// Authentication itself must have worked -- the refusal belongs to
	// the schedd, at channel-open, not to the login.
	if strings.Contains(string(out), "Permission denied") {
		t.Errorf("the login was refused; the refusal should come from the schedd at channel open:\n%s", out)
	}
}

// reserveAddr picks a free loopback port and hands back both the
// listen address and the issuer URL naming it.
//
// The gateway drives the device flow against the OAuth2 issuer, and the
// issuer has to be settled before the server starts, because the
// gateway starts with it. A ":0" listen address cannot work here: the
// issuer would have to be written after the port is known, and by then
// the gateway has already read it. This is also why an unconfigured
// deployment points at the hardcoded http://localhost:8080 default --
// see probeSSHGatewayIssuer.
func reserveAddr(t *testing.T) (listenAddr, issuer string) {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}
	return addr, "http://" + addr
}

// waitForGateway blocks until the gateway has bound its port, or the
// server gives up trying to start.
//
// Watching startErr matters: refusing to start is a designed outcome
// here -- no key file and no KEK means there is nowhere to keep a host
// key -- and without this the symptom is a bare "never bound a port"
// with the actual reason discarded in a goroutine.
func waitForGateway(t *testing.T, s *Server, startErr <-chan error) string {
	t.Helper()
	// Thirty seconds: the gateway binds during Start, so this covers a
	// slow machine rather than any real work.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if s.Handler != nil && s.sshGateway != nil {
			if addr := s.sshGateway.BoundAddr(); addr != "" {
				return addr
			}
		}
		select {
		case err := <-startErr:
			t.Fatalf("the server stopped before the gateway bound: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("the SSH gateway never bound a port")
	return ""
}

// writeKEK stages a master KEK so the gateway can mint and seal a host
// key in the application database -- the path a deployment without a
// staged key file takes.
func writeKEK(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "kek")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatalf("write kek: %v", err)
	}
	return path
}

// approvePendingDeviceCodes approves every device code that shows up,
// as subject. This is the human with the browser.
func approvePendingDeviceCodes(ctx context.Context, t *testing.T, h *Handler, subject string, approved chan<- string) {
	t.Helper()
	seen := map[string]bool{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}

		var userCode string
		err := h.db.QueryRowContext(ctx,
			`SELECT user_code FROM oauth2_device_codes WHERE status = 'pending' ORDER BY requested_at DESC LIMIT 1`).
			Scan(&userCode)
		if errors.Is(err, sql.ErrNoRows) || userCode == "" || seen[userCode] {
			continue
		}
		if err != nil {
			return
		}
		seen[userCode] = true

		session := newEmptySession()
		session.SetSubject(subject)
		if err := h.oauth2Provider.GetStorage().ApproveDeviceCodeSessionWithScopes(
			ctx, userCode, subject, session, sshGatewayScopes); err != nil {
			t.Logf("approving %s: %v", userCode, err)
			continue
		}
		if approved != nil {
			select {
			case approved <- userCode:
			default:
			}
		}
	}
}

// portOf pulls the port out of a listener address. net.SplitHostPort
// would do, but its host half is never wanted here and an unused
// return is one more thing to read past.
func portOf(addr string) (string, error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return "", fmt.Errorf("no port in %q", addr)
	}
	return addr[i+1:], nil
}

// TestSSHGatewayCertificateEndToEnd proves the whole certificate
// chain against a real pool: ask the endpoint for a certificate, then
// use it to reach a real job with a real ssh client, in BatchMode.
//
// BatchMode is the point. It refuses keyboard-interactive outright, so
// this path is the only way a script reaches a job -- and a run that
// never shows the device prompt is what proves no browser was
// involved.
func TestSSHGatewayCertificateEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	for _, bin := range []string{"condor_master", "ssh"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not in PATH; skipping", bin)
		}
	}
	extraConfig, ok := htcondor.SSHToJobHarnessConfig()
	if !ok {
		t.Skip("ssh-to-job prerequisites not found; skipping")
	}

	harness := htcondor.SetupCondorHarnessWithConfig(t, extraConfig)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("daemons: %v", err)
	}
	if err := harness.WaitForStartd(45 * time.Second); err != nil {
		t.Fatalf("startd never reported in: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	collector := htcondor.NewCollector(harness.GetCollectorAddr())
	location, err := collector.LocateDaemon(ctx, "Schedd", "")
	if err != nil {
		t.Fatalf("locate schedd: %v", err)
	}
	schedd := htcondor.NewSchedd(location.Name, location.Address)

	submitCtx, err := contextAsUser(ctx, harness, testUser)
	if err != nil {
		t.Fatalf("submit context: %v", err)
	}
	clusterIDStr, err := schedd.Submit(submitCtx, `
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
`)
	if err != nil {
		harness.PrintScheddLog()
		t.Fatalf("submit: %v", err)
	}
	clusterID, err := strconv.Atoi(clusterIDStr)
	if err != nil {
		t.Fatalf("submit returned %q: %v", clusterIDStr, err)
	}
	jobID := fmt.Sprintf("%d.0", clusterID)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = schedd.RemoveJobs(c, fmt.Sprintf("ClusterId == %d", clusterID), "test cleanup")
	}()
	if err := waitForJobRunningHTTP(ctx, schedd, clusterID, 90*time.Second); err != nil {
		harness.PrintScheddLog()
		t.Fatalf("job %s never ran: %v", jobID, err)
	}

	listenAddr, issuerURL := reserveAddr(t)
	server, err := NewServer(Config{
		ListenAddr:               listenAddr,
		OAuth2Issuer:             issuerURL,
		ScheddName:               location.Name,
		ScheddAddr:               location.Address,
		UserHeader:               "X-Test-User",
		UserHeaderTrustAnyUnsafe: true,
		SigningKeyPath:           harness.GetSigningKeyPath(),
		TrustDomain:              harness.GetTrustDomain(),
		UIDDomain:                harness.GetTrustDomain(),
		OAuth2DBPath:             filepath.Join(harness.GetSpoolDir(), "oauth2-cert.db"),
		KEKFilePath:              writeKEK(t, t.TempDir()),
		EnableMCP:                true,
		SSHGatewayAddress:        "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	startErr := make(chan error, 1)
	go func() { startErr <- server.Start() }()
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(c)
	}()

	gwAddr := waitForGateway(t, server, startErr)
	gwPort, err := portOf(gwAddr)
	if err != nil {
		t.Fatalf("gateway address %q: %v", gwAddr, err)
	}

	// A key that never leaves this test, and a certificate for it from
	// the real endpoint.
	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "id_ed25519")
	pubLine := writeUserKey(t, keyPath)

	certBody, err := json.Marshal(map[string]string{"public_key": pubLine})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	certReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		issuerURL+"/api/v1/ssh/certificate", bytes.NewReader(certBody))
	if err != nil {
		t.Fatalf("certificate request: %v", err)
	}
	certReq.Header.Set("X-Test-User", testUser)
	certReq.Header.Set("Content-Type", "application/json")
	certResp, err := http.DefaultClient.Do(certReq)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	certRaw, _ := io.ReadAll(certResp.Body)
	_ = certResp.Body.Close()
	if certResp.StatusCode != http.StatusOK {
		t.Fatalf("certificate endpoint returned %s: %s", certResp.Status, certRaw)
	}
	var issued struct {
		Certificate string `json:"certificate"`
		Principal   string `json:"principal"`
	}
	if err := json.Unmarshal(certRaw, &issued); err != nil {
		t.Fatalf("decode certificate: %v", err)
	}
	if issued.Principal != testUser {
		t.Fatalf("certificate principal = %q, want %q", issued.Principal, testUser)
	}
	if err := os.WriteFile(keyPath+"-cert.pub", []byte(issued.Certificate+"\n"), 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}

	//nolint:gosec // fixed argv; the binary is resolved by LookPath above
	cmd := exec.CommandContext(ctx, "ssh",
		"-F", "/dev/null",
		"-p", gwPort,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "IdentitiesOnly=yes",
		"-o", "LogLevel=ERROR",
		"-o", "BatchMode=yes",
		"-o", "PreferredAuthentications=publickey",
		"-i", keyPath,
		"-T",
		jobID+"@127.0.0.1",
		"echo certificate-reached-the-job",
	)
	out, sshErr := cmd.CombinedOutput()
	t.Logf("ssh exit=%v output:\n%s", sshErr, out)

	if sshErr != nil {
		harness.PrintScheddLog()
		t.Fatalf("a certificate did not reach the job in BatchMode: %v", sshErr)
	}
	if !strings.Contains(string(out), "certificate-reached-the-job") {
		t.Fatalf("the command did not run in the job:\n%s", out)
	}
	// No browser: the device prompt never appeared.
	if strings.Contains(string(out), "Sign in to") {
		t.Errorf("the certificate path fell back to the device flow:\n%s", out)
	}
}

// writeUserKey stages a private key and returns its public line.
func writeUserKey(t *testing.T, path string) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "gateway integration test")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}
