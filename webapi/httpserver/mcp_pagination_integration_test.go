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
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"

	htcondor "github.com/bbockelm/golang-htcondor"

	"github.com/bbockelm/golang-htcondor/webapi/mcpserver"
)

// TestMCPQueryJobsRefusesToPageTheSchedd is the contract that replaced
// paging a schedd: it does not happen, and the caller is told why.
//
// The reported bug was that a page_token had no effect and the same page
// came back forever. Making it work turned out to be the wrong fix. The
// schedd's job queue is a hash table with no order to resume from, so a
// page is an arbitrary subset of the matches and a cursor over one
// either repeats it or silently skips what it missed. Imposing an order
// means sorting every match, which means fetching every match — and
// there is no index either: filter_iterator walks the whole table
// evaluating the constraint on every ad, so each page costs a full queue
// scan. Walking a queue in P pages costs the schedd P full scans where
// reading it once costs one. Pagination against a schedd is more load
// than the thing it exists to avoid.
//
// So: no token is ever issued, a supplied one is refused, and the
// response says what to do instead. Pagination lives on the htcondordb
// mirror, which resumes a storage cursor against a snapshot.
func TestMCPQueryJobsRefusesToPageTheSchedd(t *testing.T) {
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	tempDir, err := os.MkdirTemp("", "htcondor-mcp-pagination-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketDir, err := os.MkdirTemp("/tmp", "htc_pg_sock_*")
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
		key[i] = byte(i*5 + 1)
	}
	if err := os.WriteFile(poolKeyPath, key, 0600); err != nil {
		t.Fatalf("Failed to write signing key: %v", err)
	}

	const trustDomain = "test.htcondor.org"

	configFile := filepath.Join(tempDir, "condor_config")
	if err := writeMiniCondorConfig(configFile, tempDir, socketDir, passwordsDir, trustDomain, t); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	overrides := fmt.Sprintf(`
# --- pagination test overrides ---
UID_DOMAIN = %s
TRUST_DOMAIN = %s
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
	// Bind the process-global rate limiter to THIS test's config rather
	// than inheriting whatever a previously-run test left cached. The
	// reload defer is registered first so LIFO runs it after the
	// environment is restored.
	defer htcondor.ReloadDefaultConfig()
	defer os.Unsetenv("CONDOR_CONFIG")
	htcondor.ReloadDefaultConfig()

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

	// More jobs than one page holds, so the answer is genuinely cut
	// short and the "what now?" guidance is the only way forward.
	const (
		jobCount = 5
		pageSize = 2
	)
	owner := currentOSUser(t)
	for i := 0; i < jobCount; i++ {
		submitJobOwnedBy(t, tempDir, configFile, owner)
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
	go func() { _ = server.ServeListener(listener, "http") }()
	defer server.Shutdown(context.Background())

	if err := waitForServer(baseURL, 15*time.Second); err != nil {
		t.Fatalf("server did not start: %v", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	now := time.Now().Unix()
	token, err := security.GenerateJWT(passwordsDir, "POOL",
		owner+"@"+trustDomain, trustDomain, now, now+900, []string{"READ", "WRITE"})
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	t.Run("a truncated answer offers no token", func(t *testing.T) {
		clusters, next, text := queryJobsPage(t, client, baseURL, token, pageSize, "")
		if len(clusters) != pageSize {
			t.Fatalf("expected the limit of %d jobs, got %d (%v)", pageSize, len(clusters), clusters)
		}
		if next != "" {
			t.Errorf("the schedd path handed out the page token %q; following it is the reported loop", next)
		}
		// A dead end with no explanation is how the reported bug felt
		// from the outside. The response has to say what to do instead.
		for _, want := range []string{"limit", "aggregate_jobs", "arrow"} {
			if !strings.Contains(text, want) {
				t.Errorf("truncated answer does not mention %q:\n%s", want, text)
			}
		}
	})

	// The tool answers into a model's context, so a caller asking for
	// everything gets the ceiling rather than everything.
	t.Run("an unlimited request is capped, not obeyed", func(t *testing.T) {
		clusters, _, _ := queryJobsPage(t, client, baseURL, token, -1, "")
		if len(clusters) > mcpserver.MaxToolResults {
			t.Errorf("unlimited request returned %d jobs, past the ceiling of %d",
				len(clusters), mcpserver.MaxToolResults)
		}
		if len(clusters) != jobCount {
			t.Errorf("unlimited request returned %d of the %d queued jobs", len(clusters), jobCount)
		}
	})

	t.Run("a supplied token is refused, not ignored", func(t *testing.T) {
		// A token minted the old way. Silently ignoring it is what made
		// the original bug invisible: the caller looped, believing it
		// was making progress.
		stale := htcondor.EncodePageToken(1, 0)
		_, _, text := queryJobsPageExpectingError(t, client, baseURL, token, pageSize, stale)
		if !strings.Contains(text, "paginate") && !strings.Contains(text, "pagination") {
			t.Errorf("the refusal does not explain itself:\n%s", text)
		}
	})
}

// queryJobsPage runs one query_jobs call and returns the cluster ids on
// that page plus the token for the next one.
// queryJobsPage runs one query_jobs call and returns the cluster ids it
// listed, any continuation token, and the rendered text.
func queryJobsPage(t *testing.T, client *http.Client, baseURL, token string, limit int, pageToken string) ([]int, string, string) {
	t.Helper()
	args := map[string]interface{}{
		"constraint": "true",
		"projection": []string{"ClusterId", "ProcId", "Owner"},
		"limit":      limit,
	}
	if pageToken != "" {
		args["page_token"] = pageToken
	}
	params, _ := json.Marshal(map[string]interface{}{"name": "query_jobs", "arguments": args})
	resp := sendMCPRequest(t, client, baseURL, token, mcpserver.MCPMessage{
		JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params,
	})
	if resp.Error != nil {
		t.Fatalf("query_jobs failed: %v", resp.Error.Message)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("query_jobs: no result map: %+v", resp.Result)
	}
	metadata, _ := result["metadata"].(map[string]interface{})
	next, _ := metadata["next_page_token"].(string)

	text := toolText(t, result)
	return clustersInListing(t, text), next, text
}

// clustersInListing pulls the ClusterId values out of a rendered
// listing, in the order they appear.
func clustersInListing(t *testing.T, listing string) []int {
	t.Helper()
	var out []int
	const marker = `"ClusterId":`
	for rest := listing; ; {
		i := strings.Index(rest, marker)
		if i < 0 {
			return out
		}
		rest = rest[i+len(marker):]
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		if end == 0 {
			continue
		}
		n, err := strconv.Atoi(rest[:end])
		if err != nil {
			t.Fatalf("unparseable ClusterId in listing: %q", rest[:end])
		}
		out = append(out, n)
	}
}

// currentOSUser is the account condor_submit will stamp on the seeded
// jobs, and therefore the identity the walk has to be scoped to.
func currentOSUser(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	return u.Username
}

// removeClusterForGap deletes one seeded cluster from the middle of the
// queue and drops it from the expected set, leaving a hole in the
// ClusterId numbering for the walk to cross.
func removeClusterForGap(t *testing.T, configFile string, want map[int]int) {
	t.Helper()
	clusters := make([]int, 0, len(want))
	for c := range want {
		clusters = append(clusters, c)
	}
	sort.Ints(clusters)
	// Never the dense cluster: the gap and the fat-cluster cases are
	// both worth exercising, so removing one to make the other would
	// halve what this test covers.
	victim := clusters[0]
	for _, c := range clusters {
		if want[c] == 1 {
			victim = c
			break
		}
	}

	cmd := exec.Command("condor_rm", strconv.Itoa(victim))
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("condor_rm %d: %v\n%s", victim, err, out)
	}
	delete(want, victim)
	total := 0
	for _, n := range want {
		total += n
	}
	t.Logf("removed cluster %d to leave a gap; expecting %d jobs across %d clusters", victim, total, len(want))
}

// queueLine renders the submit file's queue statement, optionally with a
// proc count so one cluster can hold many jobs.
func queueLine(procs []int) string {
	if len(procs) == 0 || procs[0] <= 1 {
		return "queue\n"
	}
	return fmt.Sprintf("queue %d\n", procs[0])
}

// queryJobsPageExpectingError runs a query_jobs call that should be
// refused, and returns the refusal. A call that unexpectedly succeeds is
// the failure: silently ignoring a page token is what let the original
// bug loop unnoticed.
func queryJobsPageExpectingError(t *testing.T, client *http.Client, baseURL, token string, limit int, pageToken string) ([]int, string, string) {
	t.Helper()
	params, _ := json.Marshal(map[string]interface{}{
		"name": "query_jobs",
		"arguments": map[string]interface{}{
			"constraint": "true",
			"projection": []string{"ClusterId", "ProcId", "Owner"},
			"limit":      limit,
			"page_token": pageToken,
		},
	})
	resp := sendMCPRequest(t, client, baseURL, token, mcpserver.MCPMessage{
		JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params,
	})
	if resp.Error == nil {
		t.Fatalf("a page token against the schedd was accepted rather than refused: %+v", resp.Result)
	}
	return nil, "", resp.Error.Message
}
