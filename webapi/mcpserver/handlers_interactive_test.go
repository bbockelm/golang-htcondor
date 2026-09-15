package mcpserver

import (
	"context"
	"encoding/json"
	"os/user"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"
)

func newTestServerWithInteractive(t *testing.T) *Server {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	s := &Server{
		schedd: htcondor.NewSchedd("test_schedd", "localhost:9618"),
		logger: logger,
	}
	mgr, err := interactive.NewManager(interactive.Options{
		Schedd:  func() interactive.ScheddClient { return s.schedd },
		Logger:  logger,
		LogDest: logging.DestinationMCP,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(mgr.Close)
	s.interactive = mgr
	return s
}

// TestInteractiveToolsAreListedAndDispatchable walks the same path a
// client does: the tool has to appear in tools/list AND resolve in
// handleCallTool. A tool registered in only one of the two is invisible
// or unreachable, and neither failure shows up at compile time.
func TestInteractiveToolsAreListedAndDispatchable(t *testing.T) {
	s := newTestServerWithInteractive(t)
	ctx := context.Background()

	listed := map[string]bool{}
	result := s.handleListTools(ctx, nil)
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal tools/list: %v", err)
	}
	var parsed struct {
		Tools []struct {
			Name        string                 `json:"name"`
			Description string                 `json:"description"`
			InputSchema map[string]interface{} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal tools/list: %v", err)
	}
	for _, tool := range parsed.Tools {
		listed[tool.Name] = true
		if strings.HasPrefix(tool.Name, "interactive_") && tool.Description == "" {
			t.Errorf("tool %s has no description; a model cannot tell when to use it", tool.Name)
		}
	}

	for _, name := range []string{
		"interactive_session_start",
		"interactive_session_exec",
		"interactive_session_list",
		"interactive_session_stop",
	} {
		if !listed[name] {
			t.Errorf("tool %s is not in tools/list", name)
		}
		params, err := json.Marshal(map[string]interface{}{
			"name":      name,
			"arguments": map[string]interface{}{},
		})
		if err != nil {
			t.Fatal(err)
		}
		// Every tool must at least be dispatched. What happens next
		// depends on the transport, which the next two tests pin.
		_, err = s.handleCallTool(ctx, params)
		if err != nil && strings.Contains(err.Error(), "unknown tool") {
			t.Errorf("%s is listed but not dispatched: %v", name, err)
		}
	}
}

// TestInteractiveCallerRefusedWhenDelegated: behind HTTP, every call is
// on somebody's behalf, so a caller the transport could not identify
// has to be refused rather than served as this daemon's own user.
func TestInteractiveCallerRefusedWhenDelegated(t *testing.T) {
	s := newTestServerWithInteractive(t)
	s.delegated = true

	for _, name := range []string{
		"interactive_session_start",
		"interactive_session_exec",
		"interactive_session_list",
		"interactive_session_stop",
	} {
		params, err := json.Marshal(map[string]interface{}{
			"name":      name,
			"arguments": map[string]interface{}{"session": "s", "command": "true"},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.handleCallTool(context.Background(), params)
		if err == nil {
			t.Errorf("%s served an unidentifiable caller", name)
			continue
		}
		if !strings.Contains(err.Error(), "authentication required") {
			t.Errorf("%s refused for the wrong reason: %v", name, err)
		}
	}
}

// TestInteractiveCallerIsTheLocalUserOverStdio: run from a shell, the
// server IS the user -- it holds their credentials and the schedd
// authenticates it as them. Refusing there made all four tools unusable
// on stdio while still advertising them in tools/list.
func TestInteractiveCallerIsTheLocalUserOverStdio(t *testing.T) {
	s := newTestServerWithInteractive(t)
	s.delegated = false

	caller, err := s.interactiveCaller(context.Background())
	if err != nil {
		t.Fatalf("stdio caller was refused: %v", err)
	}
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	if caller.Owner != me.Username || caller.Actor != me.Username {
		t.Errorf("caller = %+v, want the local user %q", caller, me.Username)
	}
}

// TestInteractiveScopeClassification: an unclassified tool is treated
// as a write, which is the safe direction -- but listing sessions is a
// read, and classifying it as a write would make it unavailable to a
// read-scoped client for no reason.
func TestInteractiveScopeClassification(t *testing.T) {
	if !IsReadOnlyTool("interactive_session_list") {
		t.Error("interactive_session_list is not classified read-only")
	}
	for _, name := range []string{"interactive_session_start", "interactive_session_exec", "interactive_session_stop"} {
		if IsReadOnlyTool(name) {
			t.Errorf("%s is classified read-only; a read-scoped token could run commands inside a job", name)
		}
	}
}

// TestInteractiveToolsRequireSessionName pins the sessionless
// contract: the handle is an argument, never connection state.
func TestInteractiveToolsRequireSessionName(t *testing.T) {
	required := map[string][]string{
		"interactive_session_start": {"session"},
		"interactive_session_exec":  {"session", "command"},
		"interactive_session_stop":  {"session"},
		"interactive_session_list":  nil,
	}
	for _, tool := range interactiveTools() {
		want, ok := required[tool.Name]
		if !ok {
			t.Errorf("unexpected interactive tool %q", tool.Name)
			continue
		}
		body, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			Required   []string                          `json:"required"`
			Properties map[string]map[string]interface{} `json:"properties"`
		}
		if err := json.Unmarshal(body, &schema); err != nil {
			t.Fatal(err)
		}
		if strings.Join(schema.Required, ",") != strings.Join(want, ",") {
			t.Errorf("%s required = %v, want %v", tool.Name, schema.Required, want)
		}
		for _, name := range want {
			if _, ok := schema.Properties[name]; !ok {
				t.Errorf("%s declares %q required but does not define it", tool.Name, name)
			}
		}
	}
}

func TestInteractiveCallerSplitsDomain(t *testing.T) {
	s := newTestServerWithInteractive(t)
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.example.com")
	caller, err := s.interactiveCaller(ctx)
	if err != nil {
		t.Fatalf("interactiveCaller: %v", err)
	}
	if caller.Actor != "alice@uid.example.com" || caller.Owner != "alice" {
		t.Errorf("caller = %+v, want actor alice@uid.example.com / owner alice", caller)
	}

	// Admins get no exemption here: a session is a live shell in
	// somebody's job, not a query result.
	s.adminUsers = map[string]struct{}{"root@uid.example.com": {}}
	adminCtx := htcondor.WithAuthenticatedUser(context.Background(), "root@uid.example.com")
	adminCaller, err := s.interactiveCaller(adminCtx)
	if err != nil {
		t.Fatalf("interactiveCaller(admin): %v", err)
	}
	if adminCaller.Owner != "root" {
		t.Errorf("admin caller owner = %q, want root", adminCaller.Owner)
	}
}

func TestFormatExecResult(t *testing.T) {
	out := formatExecResult(&interactive.ExecResult{
		ExitCode: 2,
		Stdout:   "one\ntwo\n",
		Stderr:   "",
		Duration: 1500 * time.Millisecond,
	})
	if !strings.Contains(out, "exit code 2") {
		t.Errorf("exit code missing from:\n%s", out)
	}
	if !strings.Contains(out, "one\ntwo\n") {
		t.Errorf("stdout missing from:\n%s", out)
	}
	// An empty stream is reported, not dropped: a missing section
	// reads as a truncated answer.
	if !strings.Contains(out, "stderr:\n(no output)") {
		t.Errorf("empty stderr not reported:\n%s", out)
	}

	timedOut := formatExecResult(&interactive.ExecResult{TimedOut: true, Stdout: "partial\n", Duration: time.Minute})
	if !strings.Contains(timedOut, "timed out") {
		t.Errorf("timeout not reported:\n%s", timedOut)
	}
	if !strings.Contains(timedOut, "partial") {
		t.Errorf("partial output dropped on timeout:\n%s", timedOut)
	}

	truncated := formatExecResult(&interactive.ExecResult{Stdout: "x", StdoutTruncated: true})
	if !strings.Contains(truncated, "truncated") {
		t.Errorf("truncation not reported:\n%s", truncated)
	}
}

func TestIntArgAcceptsStringNumbers(t *testing.T) {
	args := map[string]interface{}{"a": float64(5), "b": "7", "c": " 9 ", "d": "later", "e": nil}
	for key, want := range map[string]int{"a": 5, "b": 7, "c": 9, "d": 3, "e": 3, "missing": 3} {
		if got := intArg(args, key, 3); got != want {
			t.Errorf("intArg(%q) = %d, want %d", key, got, want)
		}
	}
}

// TestStartAdvertisesRequirementsAndSubmitLines: an argument a model
// cannot see is an argument it will not use. These two exist because a
// session that cannot say where it runs is not much use on a
// heterogeneous pool.
func TestStartAdvertisesRequirementsAndSubmitLines(t *testing.T) {
	for _, tool := range interactiveTools() {
		if tool.Name != "interactive_session_start" {
			continue
		}
		body, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			Properties map[string]map[string]interface{} `json:"properties"`
		}
		if err := json.Unmarshal(body, &schema); err != nil {
			t.Fatal(err)
		}
		for _, arg := range []string{"requirements", "submit_lines"} {
			prop, ok := schema.Properties[arg]
			if !ok {
				t.Errorf("interactive_session_start does not advertise %q", arg)
				continue
			}
			desc, _ := prop["description"].(string)
			if desc == "" {
				t.Errorf("%q has no description; a model cannot tell what belongs there", arg)
			}
		}
		// The refusal is part of the contract, so say so where it is read.
		desc, _ := schema.Properties["submit_lines"]["description"].(string)
		if !strings.Contains(desc, "refused") {
			t.Errorf("submit_lines does not mention that session-defining commands are refused: %q", desc)
		}
		return
	}
	t.Fatal("interactive_session_start is not in the catalog")
}
