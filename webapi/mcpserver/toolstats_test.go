package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/logging"
)

// fakeRecorder captures what the dispatcher reports.
type fakeRecorder struct {
	mu   sync.Mutex
	seen []recorded
}

type recorded struct {
	tool, user, client, outcome string
	d                           time.Duration
}

func (f *fakeRecorder) Record(tool, user, client, outcome string, d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, recorded{tool, user, client, outcome, d})
}

func (f *fakeRecorder) only(t *testing.T) recorded {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.seen) != 1 {
		t.Fatalf("recorded %d calls, want 1: %+v", len(f.seen), f.seen)
	}
	return f.seen[0]
}

func testLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	return l
}

func statsServer(t *testing.T, rec *fakeRecorder) *Server {
	t.Helper()
	s := &Server{stats: rec, clients: newClientRegistry(), logger: testLogger(t)}
	return s
}

// A tool that does not exist is counted under its own outcome, with the
// name the caller used: a stale catalogue and a hallucinated tool name
// both show up here, and neither is a tool that ran and failed.
func TestDispatcherRecordsAnUnknownToolUnderItsOwnOutcome(t *testing.T) {
	rec := &fakeRecorder{}
	s := statsServer(t, rec)
	params, _ := json.Marshal(map[string]interface{}{"name": "no_such_tool"})

	if _, err := s.handleCallTool(context.Background(), params); err == nil {
		t.Fatal("an unknown tool was dispatched successfully")
	}
	got := rec.only(t)
	if got.tool != "no_such_tool" {
		t.Errorf("tool = %q; the name the caller used is the signal", got.tool)
	}
	if got.outcome != toolstatsOutcomeUnknownTool {
		t.Errorf("outcome = %q, want %q", got.outcome, toolstatsOutcomeUnknownTool)
	}
}

// A real tool that runs and fails is an error, and is counted with the
// duration it burned before failing.
func TestDispatcherRecordsARealFailureAsAnError(t *testing.T) {
	rec := &fakeRecorder{}
	s := statsServer(t, rec)
	// submit_job rejects a call with no submit_file before it needs a
	// schedd, so this exercises the outcome path without a pool.
	params, _ := json.Marshal(map[string]interface{}{
		"name": "submit_job", "arguments": map[string]interface{}{},
	})
	if _, err := s.handleCallTool(context.Background(), params); err == nil {
		t.Fatal("submit_job with no submit file succeeded")
	}
	got := rec.only(t)
	if got.tool != "submit_job" {
		t.Errorf("tool = %q", got.tool)
	}
	if got.outcome != toolstatsOutcomeError {
		t.Errorf("outcome = %q, want %q", got.outcome, toolstatsOutcomeError)
	}
}

// A tool refused by configuration is NOT an error: it says something
// about the deployment, not about the call, and a dashboard that
// conflated them would report a policy decision as a malfunction.
func TestDispatcherRecordsARefusalSeparatelyFromAnError(t *testing.T) {
	rec := &fakeRecorder{}
	// Built through NewServer so the config wiring is under test too:
	// a ToolStats that never reached the Server would make every other
	// assertion here vacuous.
	s, err := NewServer(Config{
		ScheddName:    "test",
		ScheddAddr:    "127.0.0.1:9618",
		DisabledTools: "exec_in_job",
		ToolStats:     rec,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	params, _ := json.Marshal(map[string]interface{}{"name": "exec_in_job"})
	if _, err := s.handleCallTool(context.Background(), params); err == nil {
		t.Fatal("a disabled tool was dispatched")
	}
	if got := rec.only(t); got.outcome != toolstatsOutcomeRefused {
		t.Errorf("outcome = %q, want %q", got.outcome, toolstatsOutcomeRefused)
	}
}

// Params that do not parse never named a tool. Counting them would put
// protocol faults in the same table as tool results.
func TestDispatcherRecordsNothingForUnparseableParams(t *testing.T) {
	rec := &fakeRecorder{}
	s := statsServer(t, rec)
	if _, err := s.handleCallTool(context.Background(), json.RawMessage("{{{")); err == nil {
		t.Fatal("malformed params were accepted")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.seen) != 0 {
		t.Errorf("recorded %+v for a call that named no tool", rec.seen)
	}
}

// The client identity comes from the session's initialize when there is
// one, and from the transport's User-Agent when there is not.
func TestClientIdentityPrefersInitializeOverTheUserAgent(t *testing.T) {
	rec := &fakeRecorder{}
	s := statsServer(t, rec)
	s.clients.Remember("sess-1", "claude-code/2.1")

	ctx := WithSessionID(context.Background(), "sess-1")
	ctx = WithClientInfo(ctx, "go-http-client-1.1")
	params, _ := json.Marshal(map[string]interface{}{"name": "no_such_tool"})
	_, _ = s.handleCallTool(ctx, params)

	if got := rec.only(t); got.client != "claude-code/2.1" {
		t.Errorf("client = %q; the User-Agent beat the harness's own declaration", got.client)
	}
}

func TestClientIdentityFallsBackToTheUserAgent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		session string
		want    string
	}{
		// stdio has no session at all.
		{"no session", "", "python-httpx-0.27"},
		// A restart loses the registry while clients keep their ids.
		{"a session this process never saw", "sess-unknown", "python-httpx-0.27"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &fakeRecorder{}
			s := statsServer(t, rec)
			ctx := WithSessionID(context.Background(), tc.session)
			ctx = WithClientInfo(ctx, "python-httpx-0.27")
			params, _ := json.Marshal(map[string]interface{}{"name": "no_such_tool"})
			_, _ = s.handleCallTool(ctx, params)
			if got := rec.only(t); got.client != tc.want {
				t.Errorf("client = %q, want %q", got.client, tc.want)
			}
		})
	}
}

// A server built without a recorder must not panic on every call.
func TestNoRecorderIsSafe(t *testing.T) {
	s := &Server{clients: newClientRegistry(), logger: testLogger(t)}
	params, _ := json.Marshal(map[string]interface{}{"name": "no_such_tool"})
	if _, err := s.handleCallTool(context.Background(), params); err == nil {
		t.Fatal("an unknown tool was dispatched successfully")
	}
}

func TestClientInfoFromInitialize(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params string
		want   string
	}{
		{"name and version", `{"clientInfo":{"name":"Claude Code","version":"2.1.0"}}`, "claude-code/2.1.0"},
		{"name only", `{"clientInfo":{"name":"cursor"}}`, "cursor"},
		// clientInfo is optional in the MCP schema and plenty of
		// clients omit it; that is not an error.
		{"absent", `{"protocolVersion":"2024-11-05"}`, ""},
		{"empty params", ``, ""},
		{"malformed", `{{{`, ""},
		{"name is only punctuation", `{"clientInfo":{"name":"///"}}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := clientInfoFromInitialize(json.RawMessage(tc.params)); got != tc.want {
				t.Errorf("clientInfoFromInitialize = %q, want %q", got, tc.want)
			}
		})
	}
}

// A label value has to be printable and bounded: it is echoed into the
// Prometheus exposition format, and it comes from the caller.
func TestNormalizeClientNameSanitizes(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Claude Code", "claude-code"},
		{"python-httpx/0.27", "python-httpx-0.27"},
		{`evil"label`, "evillabel"},
		{"with\nnewline", "withnewline"},
		{"   ", ""},
		{"", ""},
	} {
		if got := NormalizeClientName(tc.in, ""); got != tc.want {
			t.Errorf("NormalizeClientName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	long := NormalizeClientName(strings.Repeat("a", 500), strings.Repeat("9", 500))
	if len(long) > 80 {
		t.Errorf("a 1000-character client name produced a %d-character label", len(long))
	}
	for _, r := range long {
		if r == '"' || r == '\n' || r == '\\' {
			t.Errorf("label %q contains a character the exposition format would have to escape", long)
		}
	}
}

// The registry is keyed by a value the CLIENT chooses, so it is capped.
func TestClientRegistryIsBounded(t *testing.T) {
	r := newClientRegistry()
	r.max = 3
	for i := 0; i < 50; i++ {
		r.Remember(string(rune('a'+i%26))+string(rune('0'+i/26)), "harness")
	}
	r.mu.Lock()
	n := len(r.entries)
	r.mu.Unlock()
	if n > 3 {
		t.Errorf("registry holds %d entries, want at most 3", n)
	}
}

// An idle session is swept, but an active one must not be swept out
// from under itself just because it has been connected a long time.
func TestClientRegistrySweepsOnlyIdleSessions(t *testing.T) {
	now := time.Now()
	r := newClientRegistry()
	r.ttl = time.Hour
	r.now = func() time.Time { return now }

	r.Remember("busy", "harness-a")
	r.Remember("idle", "harness-b")

	// Half an hour on, the busy session is used again.
	now = now.Add(30 * time.Minute)
	if got := r.Lookup("busy"); got != "harness-a" {
		t.Fatalf("Lookup(busy) = %q", got)
	}

	// Past the idle one's TTL but not the busy one's; a write triggers
	// the sweep.
	now = now.Add(45 * time.Minute)
	r.Remember("new", "harness-c")

	if got := r.Lookup("busy"); got != "harness-a" {
		t.Errorf("an active session was swept: Lookup(busy) = %q", got)
	}
	if got := r.Lookup("idle"); got != "" {
		t.Errorf("an idle session outlived its TTL: Lookup(idle) = %q", got)
	}
}

// The outcome strings are spelled in two packages. They are a contract
// with the stored rows, which outlive any rename.
func TestOutcomeConstantsMatchTheStoredStrings(t *testing.T) {
	for got, want := range map[string]string{
		toolstatsOutcomeOK:      "ok",
		toolstatsOutcomeError:   "error",
		toolstatsOutcomeRefused: "refused",
	} {
		if got != want {
			t.Errorf("outcome constant = %q, want %q", got, want)
		}
	}
}
