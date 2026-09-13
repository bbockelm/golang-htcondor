//go:build integration

package mcpserver

import (
	"context"
	"encoding/json"
	"os/exec"
	"os/user"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// TestMCPInteractiveSessionIntegration drives the interactive-session
// tools the way a client does — JSON-RPC tools/call into
// Server.HandleMessage — against a real HTCondor pool and a real job
// sandbox.
//
// Why at this layer and not at the Manager's:
// webapi/interactive's integration test already proves the engine
// works (sessions start, commands run, heartbeats hold a slot, the
// watchdog reclaims it). None of that says the TOOL works. Between the
// two sit the things that actually break an MCP feature on first
// contact:
//
//   - dispatch: a tool can be listed and not routed, or routed and not
//     listed, and neither shows up at compile time;
//   - arguments: the JSON a model sends has to survive the trip into
//     CreateSpec/ExecRequest with its types intact;
//   - identity: every tool here refuses without an authenticated
//     caller, and the owner it derives from that caller has to match
//     the Owner the schedd stamps on the job — a mapping no unit test
//     can check, because it takes a real schedd to say what Owner is;
//   - failure shape: a tool that fails returns a RESULT carrying
//     isError, not a JSON-RPC error. A model reads the text either
//     way; a test calling the Go function directly sees neither.
//
// Run with: go test -tags=integration -run TestMCPInteractiveSessionIntegration -v ./mcpserver/
//
//nolint:gocyclo // Integration test with several discrete verification stages.
func TestMCPInteractiveSessionIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH")
	}
	extraConfig, ok := htcondor.SSHToJobHarnessConfig()
	if !ok {
		t.Skip("sshd or condor_ssh_to_job_sshd_config_template not found; this host cannot run condor_ssh_to_job")
	}

	harness := htcondor.SetupCondorHarnessWithConfig(t, extraConfig)
	if err := harness.WaitForDaemons(); err != nil {
		t.Fatalf("Daemons failed to start: %v", err)
	}
	if err := harness.WaitForStartd(45 * time.Second); err != nil {
		t.Fatalf("Startd never reported in: %v", err)
	}

	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}

	// Build the server through NewServer, not by filling in a struct:
	// the session manager is wired inside it, and a test that hand-
	// assembles a Server proves nothing about how the daemon assembles
	// one. Delegated mirrors running behind HTTP, where every call is
	// on behalf of somebody else.
	server, err := NewServer(Config{
		Schedd:    locateSchedd(t, harness),
		Logger:    logger,
		Delegated: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(server.Close)

	// The identity the schedd will authenticate this process as, in the
	// qualified form the HTTP transport puts on the context. The tools
	// have to strip the domain to get the job's Owner; if that mapping
	// is wrong every call returns "no interactive session named ...",
	// and only a real schedd can say whether it is right.
	me, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	actor := me.Username + "@" + harness.GetTrustDomain()
	ctx, cancel := context.WithTimeout(htcondor.WithAuthenticatedUser(context.Background(), actor), 8*time.Minute)
	defer cancel()
	t.Logf("calling as %q (expecting job Owner %q)", actor, me.Username)

	const session = "mcp-itest"

	// ---- Stage 1: the tools are listed through the real entry point --
	listed := listToolsOverMCP(t, server, ctx)
	for _, name := range []string{
		"interactive_session_start",
		"interactive_session_exec",
		"interactive_session_list",
		"interactive_session_stop",
	} {
		if !listed[name] {
			t.Errorf("tools/list does not advertise %s", name)
		}
	}

	// ---- Stage 2: start a session -----------------------------------
	text, meta, isErr := callToolOverMCP(t, server, ctx, "interactive_session_start", map[string]interface{}{
		"session":   session,
		"memory_mb": 256,
		"disk_mb":   256,
	})
	if isErr {
		t.Fatalf("interactive_session_start failed: %s", text)
	}
	if got, _ := meta["session"].(string); got != session {
		t.Errorf("metadata session = %q, want %q", got, session)
	}
	jobID, _ := meta["job_id"].(string)
	if jobID == "" {
		t.Fatal("start returned no job_id")
	}
	t.Logf("session %q is job %s", session, jobID)

	// Always release the slot, even if a later stage fails.
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(htcondor.WithAuthenticatedUser(context.Background(), actor), time.Minute)
		defer stopCancel()
		_, _, _ = callToolOverMCP(t, server, stopCtx, "interactive_session_stop", map[string]interface{}{"session": session})
	}()

	// ---- Stage 3: run a command in it -------------------------------
	//
	// The arguments go in as JSON numbers, which is what a model sends
	// and what the int coercion has to survive.
	text, meta, isErr = callToolOverMCP(t, server, ctx, "interactive_session_exec", map[string]interface{}{
		"session":         session,
		"command":         "echo hello-from-mcp && pwd",
		"timeout_seconds": 60,
		"wait_seconds":    240,
	})
	if isErr {
		t.Fatalf("interactive_session_exec failed: %s", text)
	}
	if !strings.Contains(text, "hello-from-mcp") {
		t.Errorf("exec output does not contain the echoed text:\n%s", text)
	}
	if !strings.Contains(text, "exit code 0") {
		t.Errorf("exec output does not report a zero exit:\n%s", text)
	}
	if code, ok := meta["exit_code"].(float64); !ok || code != 0 {
		t.Errorf("metadata exit_code = %v, want 0", meta["exit_code"])
	}

	// ---- Stage 4: a failing command is a result, not an error -------
	text, meta, isErr = callToolOverMCP(t, server, ctx, "interactive_session_exec", map[string]interface{}{
		"session": session,
		"command": "echo to-stderr >&2; exit 7",
	})
	if isErr {
		t.Errorf("a command exiting non-zero was reported as a tool failure:\n%s", text)
	}
	if code, ok := meta["exit_code"].(float64); !ok || code != 7 {
		t.Errorf("metadata exit_code = %v, want 7", meta["exit_code"])
	}
	if !strings.Contains(text, "to-stderr") {
		t.Errorf("stderr missing from the result:\n%s", text)
	}

	// ---- Stage 5: the session is listed as ready --------------------
	text, meta, isErr = callToolOverMCP(t, server, ctx, "interactive_session_list", map[string]interface{}{})
	if isErr {
		t.Fatalf("interactive_session_list failed: %s", text)
	}
	if !strings.Contains(text, session) {
		t.Errorf("list does not mention %q:\n%s", session, text)
	}
	sessions, _ := meta["sessions"].([]interface{})
	found := false
	for _, raw := range sessions {
		row, _ := raw.(map[string]interface{})
		if name, _ := row["session"].(string); name == session {
			found = true
			if status, _ := row["status"].(string); status != "ready" {
				t.Errorf("session status = %q, want ready", status)
			}
		}
	}
	if !found {
		t.Errorf("session %q missing from list metadata: %v", session, sessions)
	}

	// ---- Stage 6: an unauthenticated caller is refused --------------
	//
	// The tools derive the caller from the context the transport
	// populates. If that plumbing breaks, every call fails this way —
	// which is the shape "it didn't work out of the box" usually takes.
	anonCtx, anonCancel := context.WithTimeout(context.Background(), time.Minute)
	defer anonCancel()
	text, _, isErr = callToolOverMCP(t, server, anonCtx, "interactive_session_list", map[string]interface{}{})
	if !isErr {
		t.Errorf("an unauthenticated caller was served: %s", text)
	} else if !strings.Contains(strings.ToLower(text), "authentication") {
		t.Errorf("refusal does not say authentication is the problem: %s", text)
	}

	// ---- Stage 7: another user cannot reach this session ------------
	otherCtx, otherCancel := context.WithTimeout(
		htcondor.WithAuthenticatedUser(context.Background(), "someone-else@"+harness.GetTrustDomain()), time.Minute)
	defer otherCancel()
	text, _, isErr = callToolOverMCP(t, server, otherCtx, "interactive_session_exec", map[string]interface{}{
		"session":      session,
		"command":      "id",
		"wait_seconds": 5,
	})
	if !isErr {
		t.Errorf("another user ran a command in this session: %s", text)
	} else if !strings.Contains(text, "no interactive session named") {
		t.Logf("note: refusal text was %q", text)
	}

	// ---- Stage 8: stop releases it ----------------------------------
	text, _, isErr = callToolOverMCP(t, server, ctx, "interactive_session_stop", map[string]interface{}{"session": session})
	if isErr {
		t.Fatalf("interactive_session_stop failed: %s", text)
	}

	deadline := time.Now().Add(90 * time.Second)
	for {
		text, _, isErr = callToolOverMCP(t, server, ctx, "interactive_session_list", map[string]interface{}{})
		if isErr {
			t.Fatalf("interactive_session_list failed after stop: %s", text)
		}
		if !strings.Contains(text, session) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("session %q still listed 90s after stop:\n%s", session, text)
		}
		time.Sleep(3 * time.Second)
	}
}

// listToolsOverMCP asks for the catalog through the JSON-RPC entry
// point and returns the tool names it advertises.
func listToolsOverMCP(t *testing.T, server *Server, ctx context.Context) map[string]bool {
	t.Helper()
	resp := server.HandleMessage(ctx, &MCPMessage{JSONRPC: "2.0", ID: 1, Method: "tools/list"})
	if resp.Error != nil {
		t.Fatalf("tools/list: %v", resp.Error)
	}
	var parsed struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	remarshal(t, resp.Result, &parsed)
	names := map[string]bool{}
	for _, tool := range parsed.Tools {
		names[tool.Name] = true
	}
	return names
}

// callToolOverMCP performs one tools/call and unpacks what a client
// would see: the text a model reads, the structured metadata, and
// whether the call reported a tool failure.
func callToolOverMCP(t *testing.T, server *Server, ctx context.Context, name string, args map[string]interface{}) (string, map[string]interface{}, bool) {
	t.Helper()
	params, err := json.Marshal(map[string]interface{}{"name": name, "arguments": args})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	resp := server.HandleMessage(ctx, &MCPMessage{JSONRPC: "2.0", ID: 2, Method: "tools/call", Params: params})
	if resp.Error != nil {
		// A JSON-RPC error means the request never reached a tool —
		// an unknown method or unparseable params, i.e. a bug in this
		// test or in dispatch, not a tool-level failure.
		t.Fatalf("%s returned a protocol error: %v", name, resp.Error)
	}
	var parsed struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Metadata map[string]interface{} `json:"metadata"`
		IsError  bool                   `json:"isError"`
	}
	remarshal(t, resp.Result, &parsed)

	var text strings.Builder
	for _, c := range parsed.Content {
		text.WriteString(c.Text)
	}
	return text.String(), parsed.Metadata, parsed.IsError
}

// remarshal round-trips a result through JSON, so the test reads what
// a client receives on the wire rather than the Go value behind it.
func remarshal(t *testing.T, from interface{}, into interface{}) {
	t.Helper()
	raw, err := json.Marshal(from)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("unmarshal result: %v\n%s", err, raw)
	}
}
