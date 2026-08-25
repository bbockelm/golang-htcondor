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
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"

	"github.com/bbockelm/golang-htcondor/webapi/mcpserver"
)

// TestMCPQueryJobsOwnerScopeUnderFSAuth reproduces the deployment the
// owner-scoping tools actually run in, which the existing cross-talk
// test deliberately configures away.
//
// That test forces TOKEN-only authentication, with this comment: "With
// HTCondor's usual FS,TOKEN order the daemon would authenticate as the
// process user regardless of the token, both callers would map to the
// same identity, and the test would pass without proving anything." The
// same sentence describes an access point: the API daemon runs there as
// a service account, FS is offered before TOKEN, and so every caller's
// connection to the schedd authenticates as that account no matter whose
// bearer arrived.
//
// Two things then compound, and neither is visible under TOKEN-only:
//
//  1. The actor is resolved by asking the schedd who this connection is
//     (actorForSession → schedd.Ping). Under FS that answers with the
//     service account, so query_jobs scopes to the daemon rather than to
//     the caller.
//
//  2. The schedd drops owner scoping entirely for a queue superuser:
//     "if (owner.empty() || isQueueSuperUser(...)) my_jobs_expr = NULL"
//     (condor_schedd.V6/schedd.cpp). The service account is a superuser
//     — PERSONAL_CONDOR_IS_SUPER_USER adds the process user, and a real
//     AP lists condor in QUEUE_SUPER_USERS — so MyJobs is discarded and
//     Requirements is left as the caller's bare constraint.
//
// The result is fail-open: constraint "true" returns every user's jobs,
// with Cmd, Iwd and Arguments, to any authenticated caller. This test
// asserts the property the tool documents — a caller sees only their own
// jobs — under that configuration.
func TestMCPQueryJobsOwnerScopeUnderFSAuth(t *testing.T) {
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	tempDir, err := os.MkdirTemp("", "htcondor-mcp-ownerscope-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketDir, err := os.MkdirTemp("/tmp", "htc_os_sock_*")
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
		key[i] = byte(i*11 + 3)
	}
	if err := os.WriteFile(poolKeyPath, key, 0600); err != nil {
		t.Fatalf("Failed to write signing key: %v", err)
	}

	const trustDomain = "test.htcondor.org"

	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDir, socketDir, passwordsDir, trustDomain, t); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// The shared config already offers FS,TOKEN — the access-point
	// ordering. What is added here is only what lets one schedd hold
	// jobs belonging to users who have no account on this host, which is
	// how a submit portal's queue looks.
	me, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	overrides := fmt.Sprintf(`
# --- owner-scope test overrides ---
UID_DOMAIN = %s
TRUST_DOMAIN = %s
QUEUE_ALL_USERS_TRUSTED = True
SCHEDD_DEBUG = D_COMMAND D_VERBOSE
`, trustDomain, trustDomain)
	cf, err := os.OpenFile(configFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("Failed to open config for overrides: %v", err)
	}
	if _, err := cf.WriteString(overrides); err != nil {
		t.Fatalf("Failed to append overrides: %v", err)
	}
	cf.Close()
	t.Logf("daemon runs as %q; PERSONAL_CONDOR_IS_SUPER_USER makes that a queue superuser", me.Username)

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

	listener, baseURL := listenLocal(t)
	server, err := NewServer(Config{
		ListenAddr:     listener.Addr().String(),
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
	go func() { serverErr <- server.ServeListener(listener, "http") }()
	defer server.Shutdown(context.Background())

	if err := waitForServer(baseURL, 15*time.Second); err != nil {
		t.Fatalf("server did not start: %v", err)
	}

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

	// Seed one job per user. Both submissions run over the daemon's
	// service-account connection, so the queue ends up holding jobs
	// owned by two users neither of whom is that account — the submit
	// portal shape, and the one where "show me my jobs" has to mean
	// something other than "show me this connection's jobs".
	aliceCluster := submitJobOwnedBy(t, tempDir, configFile, "alice")
	bobCluster := submitJobOwnedBy(t, tempDir, configFile, "bob")
	if aliceCluster == bobCluster {
		t.Fatalf("both submissions returned cluster %d", aliceCluster)
	}
	t.Logf("alice owns cluster %d, bob owns cluster %d", aliceCluster, bobCluster)

	// Guard the setup: if the seeding did not actually produce two
	// different owners, the scoping assertions below would pass for the
	// wrong reason.
	assertJobOwner(t, client, baseURL, aliceToken, aliceCluster, "alice")
	assertJobOwner(t, client, baseURL, bobToken, bobCluster, "bob")

	// Which identity the daemon believes it is acting as. /api/v1/whoami
	// reports what the schedd attributed this connection to, which is the
	// same answer actorForSession scopes queries by — so this names the
	// first of the two compounding causes rather than leaving it inferred.
	t.Logf("schedd attributes alice's connection to: %s", whoamiAs(t, client, baseURL, aliceToken))
	t.Logf("schedd attributes bob's connection to:   %s", whoamiAs(t, client, baseURL, bobToken))

	// Both halves matter. Asserting only that the other user's job is
	// absent would pass just as well if the query returned nothing at
	// all — which is exactly what scoping to the wrong identity
	// produces, and it would look like success here while hiding every
	// caller's own jobs in production.
	t.Run("alice sees her own jobs and not bob's", func(t *testing.T) {
		listing := queryJobsAs(t, client, baseURL, aliceToken, "true")
		if strings.Contains(listing, fmt.Sprintf(`"ClusterId":%d`, bobCluster)) {
			t.Errorf("FAIL-OPEN: alice's query_jobs returned bob's cluster %d.\n%s", bobCluster, listing)
		}
		if !strings.Contains(listing, fmt.Sprintf(`"ClusterId":%d`, aliceCluster)) {
			t.Errorf("FAIL-CLOSED: alice's query_jobs did not return her own cluster %d.\n%s", aliceCluster, listing)
		}
	})

	t.Run("bob sees his own jobs and not alice's", func(t *testing.T) {
		listing := queryJobsAs(t, client, baseURL, bobToken, "true")
		if strings.Contains(listing, fmt.Sprintf(`"ClusterId":%d`, aliceCluster)) {
			t.Errorf("FAIL-OPEN: bob's query_jobs returned alice's cluster %d.\n%s", aliceCluster, listing)
		}
		if !strings.Contains(listing, fmt.Sprintf(`"ClusterId":%d`, bobCluster)) {
			t.Errorf("FAIL-CLOSED: bob's query_jobs did not return his own cluster %d.\n%s", bobCluster, listing)
		}
	})
}

// submitJobOwnedBy puts one job owned by the named user into the queue
// and returns its cluster id.
//
// It shells out to condor_submit rather than going through submit_job:
// the fixture must not depend on the code under test, and this is a
// faithful stand-in for how a submit portal creates a job on someone
// else's behalf. +Owner is honored because QUEUE_ALL_USERS_TRUSTED is
// set and the submitting identity is a queue superuser.
func submitJobOwnedBy(t *testing.T, dir, configFile, owner string) int {
	t.Helper()
	subFile := filepath.Join(dir, owner+".sub")
	body := "executable = /bin/sleep\narguments = 600\n" +
		"transfer_executable = False\n" +
		"+Owner = \"" + owner + "\"\n" +
		"log = " + filepath.Join(dir, owner+".log") + "\n" +
		"queue\n"
	if err := os.WriteFile(subFile, []byte(body), 0600); err != nil {
		t.Fatalf("writing %s: %v", subFile, err)
	}

	cmd := exec.Command("condor_submit", "-terse", subFile)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("condor_submit for %s failed: %v\n%s", owner, err, out)
	}
	// -terse prints "<first> - <last>", e.g. "3.0 - 3.0".
	first, _, ok := strings.Cut(strings.TrimSpace(string(out)), " ")
	if !ok {
		first = strings.TrimSpace(string(out))
	}
	clusterStr, _, _ := strings.Cut(first, ".")
	cluster, err := strconv.Atoi(clusterStr)
	if err != nil {
		t.Fatalf("could not read a cluster id from condor_submit output %q: %v", out, err)
	}
	return cluster
}

// queryJobsAs runs query_jobs with the given bearer and returns the
// rendered listing.
func queryJobsAs(t *testing.T, client *http.Client, baseURL, token, constraint string) string {
	t.Helper()
	params, _ := json.Marshal(map[string]interface{}{
		"name": "query_jobs",
		"arguments": map[string]interface{}{
			"constraint": constraint,
			"projection": []string{"ClusterId", "ProcId", "Owner", "Cmd"},
			"limit":      100,
		},
	})
	resp := sendMCPRequest(t, client, baseURL, token, mcpserver.MCPMessage{
		JSONRPC: "2.0", ID: 2, Method: "tools/call", Params: params,
	})
	if resp.Error != nil {
		t.Fatalf("query_jobs failed: %v", resp.Error.Message)
	}
	return toolText(t, resp.Result)
}

// assertJobOwner fails the test if the seeded job is not owned by the
// expected user, so a scoping assertion can never pass because the
// fixture was wrong.
func assertJobOwner(t *testing.T, client *http.Client, baseURL, token string, cluster int, wantOwner string) {
	t.Helper()
	listing := queryJobsAs(t, client, baseURL, token, fmt.Sprintf("ClusterId == %d", cluster))
	if !strings.Contains(listing, fmt.Sprintf(`"Owner":"%s"`, wantOwner)) &&
		!strings.Contains(listing, fmt.Sprintf(`"Owner": "%s"`, wantOwner)) {
		t.Fatalf("setup: cluster %d is not owned by %q: %s", cluster, wantOwner, listing)
	}
}

// whoamiAs reports the identity the daemon resolves for this bearer.
func whoamiAs(t *testing.T, client *http.Client, baseURL, token string) string {
	t.Helper()
	req, _ := http.NewRequest("GET", baseURL+"/api/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf("(whoami failed: %v)", err)
	}
	defer resp.Body.Close()
	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	out, _ := json.Marshal(body)
	return string(out)
}
