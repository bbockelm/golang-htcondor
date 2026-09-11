//go:build integration

//nolint:errcheck,noctx,gosec,errorlint // Integration test file with acceptable test patterns

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

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// A schedd restart changes its shared-port socket id. Everything the API
// server does afterwards has to go to the new one.
//
// This has bitten twice. The address updater does re-query the collector,
// but it treated a collector-discovered address as operator-pinned and
// refused to adopt the new one, so the process kept dialling a socket that
// no longer existed until something restarted it. See issue #308.
//
// The test asserts the three things that make the difference between
// "recovered" and "stuck":
//
//	(a) the socket really did change,
//	(b) the server noticed and adopted the new address, and
//	(c) both the REST API and the MCP endpoint still reach the schedd.
//
// (c) is the one that matters: the address can be updated in one place and
// stale in another, which is exactly how MCP kept a schedd handle the REST
// side had already replaced.
func TestScheddRestartIsDiscoveredAndBothAPIsRecover(t *testing.T) {
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	tempDir, err := os.MkdirTemp("", "htcondor-schedd-restart-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketDir, err := os.MkdirTemp("/tmp", "htc_rst_sock_*")
	if err != nil {
		t.Fatalf("Failed to create socket directory: %v", err)
	}
	defer os.RemoveAll(socketDir)

	defer func() {
		if t.Failed() {
			printHTCondorLogs(tempDir, t)
		}
	}()

	passwordsDir := filepath.Join(tempDir, "passwords.d")
	if err := os.MkdirAll(passwordsDir, 0700); err != nil {
		t.Fatalf("Failed to create passwords.d: %v", err)
	}
	poolKeyPath := filepath.Join(passwordsDir, "POOL")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 11)
	}
	if err := os.WriteFile(poolKeyPath, key, 0600); err != nil {
		t.Fatalf("Failed to write signing key: %v", err)
	}

	const trustDomain = "test.htcondor.org"
	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDir, socketDir, passwordsDir, trustDomain, t); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	os.Setenv("CONDOR_CONFIG", configFile)
	defer os.Unsetenv("CONDOR_CONFIG")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	condorMaster, err := startCondorMaster(ctx, configFile, tempDir)
	if err != nil {
		t.Fatalf("Failed to start condor_master: %v", err)
	}
	defer stopCondorMaster(condorMaster, t)
	if err := waitForCondor(tempDir, 60*time.Second, t); err != nil {
		t.Fatalf("Condor failed to start: %v", err)
	}

	collectorAddr, err := getCollectorAddress(tempDir, 30*time.Second)
	if err != nil {
		t.Fatalf("Failed to get collector address: %v", err)
	}
	collector := htcondor.NewCollector(collectorAddr)

	// Discover the schedd exactly as the daemon's main() does: ask the
	// collector, then hand the answer to the server as ScheddAddr. That
	// ordering is the bug's habitat -- the server cannot tell a
	// discovered address from one an operator pinned.
	scheddName, scheddAddr := discoverScheddNameAndAddress(t, collector, 60*time.Second)
	t.Logf("discovered schedd %q at %s", scheddName, scheddAddr)

	listener, baseURL := listenLocal(t)
	server, err := NewServer(Config{
		ListenAddr:     listener.Addr().String(),
		ScheddName:     scheddName,
		ScheddAddr:     scheddAddr,
		Collector:      collector,
		SigningKeyPath: poolKeyPath,
		TrustDomain:    trustDomain,
		UIDDomain:      trustDomain,
		EnableMCP:      true,
		// The server detects a dead socket on its periodic ping and
		// re-discovers from there. A short cadence keeps the test off
		// the one-minute address-updater tick without reaching into
		// the server to trigger recovery by hand -- recovering on its
		// own is the property under test.
		PingInterval: 2 * time.Second,
		OAuth2DBPath: filepath.Join(tempDir, "oauth2.db"),
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.ServeListener(listener, "http") }()
	defer server.Shutdown(context.Background())
	if err := waitForServer(baseURL, 15*time.Second); err != nil {
		t.Fatalf("server did not start: %v", err)
	}

	now := time.Now().Unix()
	token, err := security.GenerateJWT(passwordsDir, "POOL",
		"alice@"+trustDomain, trustDomain, now, now+3600, []string{"READ", "WRITE"})
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	client := &http.Client{Timeout: 30 * time.Second}

	// Precondition: both APIs work before the restart. Without this the
	// test could "pass" against a server that never worked at all.
	if err := retryFor(30*time.Second, func() error { return restQueryWorks(client, baseURL, token) }); err != nil {
		t.Fatalf("precondition failed: REST does not work before the restart: %v", err)
	}
	if err := retryFor(30*time.Second, func() error { return mcpQueryWorks(client, baseURL, token) }); err != nil {
		t.Fatalf("precondition failed: MCP does not work before the restart: %v", err)
	}

	beforeAddr := server.getSchedd().Address()
	beforeSock := scheddSharedPortInfo(beforeAddr).SharedPortID
	if beforeSock == "" {
		t.Fatalf("no shared-port socket id in %q; this test cannot observe a restart without one", beforeAddr)
	}
	t.Logf("before: sock=%s addr=%s", beforeSock, beforeAddr)

	// (a) Restart the schedd onto a different socket, and confirm the
	// address really changed.
	//
	// A schedd restarted under a live master comes back on the socket it
	// had, so simply bouncing it would leave the address identical and
	// the rest of this test would prove nothing. The master passes each
	// daemon its shared-port socket name, and takes extra arguments for
	// a daemon from <SUBSYS>_ARGS, so naming the socket there reproduces
	// what a real restart does to the address while leaving the schedd's
	// name -- which is what discovery matches on -- alone.
	newSock := fmt.Sprintf("schedd_moved_%d", time.Now().UnixNano()%100000)
	t.Logf("restarting the schedd onto sock=%s", newSock)
	appendCondorConfig(t, configFile, fmt.Sprintf("\nSCHEDD_ARGS = -sock %s\n", newSock))
	runCondorTool(t, "condor_reconfig", "-master")
	runCondorTool(t, "condor_restart", "-fast", "-schedd")

	afterSock := waitForNewScheddSock(t, tempDir, beforeSock, 150*time.Second)
	t.Logf("after:  sock=%s", afterSock)
	if afterSock == beforeSock {
		t.Fatal("the socket id did not change, so the rest of this test proves nothing")
	}

	// (b) The server notices on its own and adopts the new address.
	deadline := time.Now().Add(90 * time.Second)
	var adopted string
	for time.Now().Before(deadline) {
		adopted = server.getSchedd().Address()
		if scheddSharedPortInfo(adopted).SharedPortID == afterSock {
			break
		}
		time.Sleep(time.Second)
	}
	if got := scheddSharedPortInfo(adopted).SharedPortID; got != afterSock {
		t.Fatalf("the server never adopted the new address: still sock=%s after the schedd moved to sock=%s; "+
			"every schedd RPC from here on goes to a socket that no longer exists (addr=%s)",
			got, afterSock, adopted)
	}
	t.Logf("server adopted sock=%s", afterSock)

	// (c) Both APIs still reach the schedd.
	if err := retryFor(30*time.Second, func() error { return restQueryWorks(client, baseURL, token) }); err != nil {
		t.Errorf("REST does not work after the restart: %v", err)
	}
	if err := retryFor(30*time.Second, func() error { return mcpQueryWorks(client, baseURL, token) }); err != nil {
		t.Errorf("MCP does not work after the restart: %v", err)
	}
}

// restQueryWorks runs a job query through the REST API.
func restQueryWorks(client *http.Client, baseURL, token string) error {
	req, _ := http.NewRequest("GET", baseURL+"/api/v1/jobs?limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", resp.StatusCode, truncateForError(string(body)))
	}
	return nil
}

// mcpQueryWorks runs a job query through the MCP endpoint. It uses a tool
// that talks to the schedd, so a stale address fails here even when the
// endpoint itself is up.
func mcpQueryWorks(client *http.Client, baseURL, token string) error {
	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "query_jobs",
			"arguments": map[string]any{"limit": 1},
		},
	})
	req, _ := http.NewRequest("POST", baseURL+"/mcp/message", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", resp.StatusCode, truncateForError(string(body)))
	}
	var out struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("decode %q: %w", truncateForError(string(body)), err)
	}
	if len(out.Error) > 0 {
		return fmt.Errorf("jsonrpc error: %s", out.Error)
	}
	// A tool that cannot reach the schedd answers 200 with isError set;
	// treating that as success is how a stale MCP handle would hide.
	if out.Result.IsError {
		text := ""
		if len(out.Result.Content) > 0 {
			text = out.Result.Content[0].Text
		}
		return fmt.Errorf("tool reported an error: %s", truncateForError(text))
	}
	return nil
}

// waitForNewScheddSock waits for the schedd's address file to advertise a
// socket id different from the one given, and returns the new one.
func waitForNewScheddSock(t *testing.T, tempDir, oldSock string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		addr, err := getScheddAddress(tempDir, 2*time.Second)
		if err == nil {
			last = scheddSharedPortInfo(addr).SharedPortID
			if last != "" && last != oldSock {
				return last
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("the schedd's socket id never changed from %s (last seen %q) within %s",
		oldSock, last, timeout)
	return ""
}

func retryFor(timeout time.Duration, fn func() error) error {
	deadline := time.Now().Add(timeout)
	var err error
	for time.Now().Before(deadline) {
		if err = fn(); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return err
}

func truncateForError(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

// getCollectorAddress reads the collector's address file, the same way
// getScheddAddress reads the schedd's.
func getCollectorAddress(localDir string, timeout time.Duration) (string, error) {
	path := filepath.Join(localDir, "log", ".collector_address")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "$") {
					return line, nil
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", fmt.Errorf("timeout finding collector address")
}

// discoverScheddNameAndAddress asks the collector what schedd it knows
// about. The name matters: the address updater re-queries by name, so a
// test that invented one would never see an update.
func discoverScheddNameAndAddress(t *testing.T, collector *htcondor.Collector, timeout time.Duration) (string, string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		qctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		ads, _, err := collector.QueryAdsWithOptions(qctx, "ScheddAd", "", nil)
		cancel()
		if err == nil && len(ads) > 0 {
			name, okN := ads[0].EvaluateAttrString("Name")
			addr, okA := ads[0].EvaluateAttrString("MyAddress")
			if okN && okA && name != "" && addr != "" {
				return name, addr
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatal("the collector never advertised a schedd")
	return "", ""
}

// appendCondorConfig adds overrides after the shared mini-pool config, so
// they win.
func appendCondorConfig(t *testing.T, configFile, extra string) {
	t.Helper()
	f, err := os.OpenFile(configFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open config: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(extra); err != nil {
		t.Fatalf("append config: %v", err)
	}
}

// runCondorTool runs an HTCondor CLI against the test pool.
func runCondorTool(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = os.Environ() // CONDOR_CONFIG is already set for this process
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
	t.Logf("%s %v: %s", name, args, strings.TrimSpace(string(out)))
}
