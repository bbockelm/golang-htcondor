//go:build integration

//nolint:errcheck,noctx,gosec,errorlint,govet // Integration test file with acceptable test patterns
package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"

	"github.com/bbockelm/golang-htcondor/webapi/mcpserver"
)

// TestMCPForwardedTokenNoCrossTalk is the live guard against one MCP
// caller's request running as another. Two users present their own
// HTCondor IDTOKENs to /mcp/message; each must see only their own jobs.
//
// The failure it exists to catch is not in this repo's own logic: cedar
// keys its client session cache by {SecurityTag, address, command}, and
// with an empty tag by {address, command} alone. Every forwarded-token
// caller talks to the same schedd with the same commands, so an untagged
// session established for alice is resumable by bob's request — which
// then executes with alice's identity on the schedd. The handler tags
// each caller's sessions with a digest of their bearer; this test proves
// the isolation end to end rather than by inspection.
//
// Authentication is TOKEN-only here on purpose. With HTCondor's usual
// FS,TOKEN order the daemon would authenticate as the process user
// regardless of the token, both callers would map to the same identity,
// and the test would pass without proving anything.
func TestMCPForwardedTokenNoCrossTalk(t *testing.T) {
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	tempDir, err := os.MkdirTemp("", "htcondor-mcp-crosstalk-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketDir, err := os.MkdirTemp("/tmp", "htc_xt_sock_*")
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
		key[i] = byte(i * 7)
	}
	if err := os.WriteFile(poolKeyPath, key, 0600); err != nil {
		t.Fatalf("Failed to write signing key: %v", err)
	}

	const trustDomain = "test.htcondor.org"

	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDir, socketDir, passwordsDir, trustDomain, t); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	// Override the shared config's FS,TOKEN with TOKEN only, so the
	// token is what decides identity, and let the schedd hold jobs owned
	// by users that do not exist on this host.
	overrides := fmt.Sprintf(`
# --- cross-talk test overrides ---
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = TOKEN
SEC_CLIENT_AUTHENTICATION_METHODS = TOKEN
SEC_READ_AUTHENTICATION_METHODS = TOKEN
SEC_WRITE_AUTHENTICATION_METHODS = TOKEN
UID_DOMAIN = %s
TRUST_DOMAIN = %s
QUEUE_ALL_USERS_TRUSTED = True
`, trustDomain, trustDomain)
	cf, err := os.OpenFile(configFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("Failed to open config for overrides: %v", err)
	}
	if _, err := cf.WriteString(overrides); err != nil {
		t.Fatalf("Failed to append overrides: %v", err)
	}
	cf.Close()

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
	scheddAddr, err := getScheddAddress(tempDir, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to get schedd address: %v", err)
	}

	// Port 0: the kernel picks a free port and GetAddr reports it once
	// the listener is up. A fixed port makes the test fail when
	// something else on the machine (or a parallel run of this suite)
	// already holds it.
	server, err := NewServer(Config{
		ListenAddr:     "127.0.0.1:0",
		ScheddName:     "local",
		ScheddAddr:     scheddAddr,
		SigningKeyPath: poolKeyPath,
		TrustDomain:    trustDomain,
		UIDDomain:      trustDomain,
		EnableMCP:      true,
		OAuth2DBPath:   filepath.Join(tempDir, "oauth2.db"),
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Start() }()
	defer server.Shutdown(context.Background())

	baseURL := waitForServerAddr(t, server, 15*time.Second)
	if err := waitForServer(baseURL, 15*time.Second); err != nil {
		t.Fatalf("server did not start: %v", err)
	}
	t.Logf("API server listening at %s", baseURL)

	client := &http.Client{Timeout: 30 * time.Second}

	mintToken := func(user string) string {
		t.Helper()
		now := time.Now().Unix()
		tok, err := security.GenerateJWT(passwordsDir, "POOL",
			user+"@"+trustDomain, trustDomain, now, now+900,
			[]string{"READ", "WRITE"})
		if err != nil {
			t.Fatalf("GenerateJWT(%s): %v", user, err)
		}
		return tok
	}

	aliceToken := mintToken("alice")
	bobToken := mintToken("bob")

	// Each user submits their own job through the MCP tool, which is the
	// path under test: the submit goes to the schedd over a session this
	// handler establishes on their behalf.
	aliceCluster := submitJobAsUser(t, client, baseURL, aliceToken, "alice")
	bobCluster := submitJobAsUser(t, client, baseURL, bobToken, "bob")
	if aliceCluster == bobCluster {
		t.Fatalf("both users got cluster %d; the schedd did not treat them as separate submissions", aliceCluster)
	}
	t.Logf("alice submitted cluster %d, bob submitted cluster %d", aliceCluster, bobCluster)

	// Interleave the queries. Alice queries after bob's request has
	// established its own session: if sessions were shared, this is where
	// alice's query would run as bob (or vice versa).
	t.Run("alice sees only her own job", func(t *testing.T) {
		assertOwnJobsOnly(t, client, baseURL, aliceToken, aliceCluster, bobCluster)
	})
	t.Run("bob sees only his own job", func(t *testing.T) {
		assertOwnJobsOnly(t, client, baseURL, bobToken, bobCluster, aliceCluster)
	})
	t.Run("alice still sees only her own job after bob's request", func(t *testing.T) {
		assertOwnJobsOnly(t, client, baseURL, aliceToken, aliceCluster, bobCluster)
	})
}

// waitForServerAddr blocks until the server has bound its listener and
// returns its base URL. Start() binds asynchronously, so GetAddr is
// empty for a moment after the goroutine is launched.
func waitForServerAddr(t *testing.T, server *Server, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if addr := server.GetAddr(); addr != "" {
			return "http://" + addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server did not bind a listener within %s", timeout)
	return ""
}

// submitJobAsUser submits a trivial job through submit_job with the
// given bearer and returns its cluster id.
func submitJobAsUser(t *testing.T, client *http.Client, baseURL, token, user string) int {
	t.Helper()
	params, _ := json.Marshal(map[string]interface{}{
		"name": "submit_job",
		"arguments": map[string]interface{}{
			"submit_file": "executable = /bin/true\ntransfer_executable = False\n" +
				"log = " + user + ".log\nqueue",
		},
	})
	resp := sendMCPRequest(t, client, baseURL, token, mcpserver.MCPMessage{
		JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params,
	})
	if resp.Error != nil {
		t.Fatalf("submit_job as %s failed: %v", user, resp.Error.Message)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("submit_job as %s: no result map: %+v", user, resp.Result)
	}
	metadata, ok := result["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("submit_job as %s: no metadata: %+v", user, result)
	}
	cluster, ok := metadata["cluster_id"].(float64)
	if !ok {
		t.Fatalf("submit_job as %s: no cluster_id: %+v", user, metadata)
	}
	return int(cluster)
}

// assertOwnJobsOnly checks that the caller holding this bearer sees
// their own cluster and not the other user's, through both an
// owner-scoped listing and a direct by-id fetch.
func assertOwnJobsOnly(t *testing.T, client *http.Client, baseURL, token string, ownCluster, otherCluster int) {
	t.Helper()

	// query_jobs self-scopes to the caller.
	params, _ := json.Marshal(map[string]interface{}{
		"name": "query_jobs",
		"arguments": map[string]interface{}{
			"constraint": "true",
			"projection": []string{"ClusterId", "ProcId", "Owner"},
			"limit":      100,
		},
	})
	resp := sendMCPRequest(t, client, baseURL, token, mcpserver.MCPMessage{
		JSONRPC: "2.0", ID: 2, Method: "tools/call", Params: params,
	})
	if resp.Error != nil {
		t.Fatalf("query_jobs failed: %v", resp.Error.Message)
	}
	listing := toolText(t, resp.Result)
	if !strings.Contains(listing, fmt.Sprintf(`"ClusterId":%d`, ownCluster)) {
		t.Errorf("caller does not see their own cluster %d: %s", ownCluster, listing)
	}
	if strings.Contains(listing, fmt.Sprintf(`"ClusterId":%d`, otherCluster)) {
		t.Errorf("CROSS-TALK: caller sees the other user's cluster %d: %s", otherCluster, listing)
	}

	// get_job on the other user's job must not return it.
	params, _ = json.Marshal(map[string]interface{}{
		"name":      "get_job",
		"arguments": map[string]interface{}{"job_id": fmt.Sprintf("%d.0", otherCluster)},
	})
	resp = sendMCPRequest(t, client, baseURL, token, mcpserver.MCPMessage{
		JSONRPC: "2.0", ID: 3, Method: "tools/call", Params: params,
	})
	if resp.Error == nil {
		got, _ := json.Marshal(resp.Result)
		t.Errorf("CROSS-TALK: get_job returned the other user's job %d.0: %s", otherCluster, got)
	}

	// ...while the caller's own job is reachable, so the check above is
	// not passing merely because get_job never works.
	params, _ = json.Marshal(map[string]interface{}{
		"name":      "get_job",
		"arguments": map[string]interface{}{"job_id": fmt.Sprintf("%d.0", ownCluster)},
	})
	resp = sendMCPRequest(t, client, baseURL, token, mcpserver.MCPMessage{
		JSONRPC: "2.0", ID: 4, Method: "tools/call", Params: params,
	})
	if resp.Error != nil {
		t.Fatalf("caller cannot fetch their own job %d.0: %v", ownCluster, resp.Error.Message)
	}
	if own := toolText(t, resp.Result); !strings.Contains(own, fmt.Sprintf(`"ClusterId": %d`, ownCluster)) {
		t.Errorf("get_job returned something other than the caller's job %d.0: %s", ownCluster, own)
	}
}

// toolText pulls the text out of an MCP tool result. The tool payload is
// a string inside the JSON-RPC result, so asserting against the
// re-marshaled result would search escaped JSON instead of the content.
func toolText(t *testing.T, result interface{}) string {
	t.Helper()
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("tool result is not an object: %+v", result)
	}
	content, ok := m["content"].([]interface{})
	if !ok || len(content) == 0 {
		t.Fatalf("tool result has no content: %+v", m)
	}
	first, ok := content[0].(map[string]interface{})
	if !ok {
		t.Fatalf("tool content is not an object: %+v", content[0])
	}
	text, _ := first["text"].(string)
	return text
}
