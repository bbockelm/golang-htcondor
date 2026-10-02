package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/toolstats"
)

// postMCPWith sends one JSON-RPC message and returns the recorder, so a
// test can read both the body and the response headers.
func postMCPWith(t *testing.T, s *Server, body, sessionID, userAgent string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+forwardedHTCondorToken(t, testTrustDomain))
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

// TestTheServerAssignsASessionIdAtInitialize is the bug.
//
// In streamable HTTP the SERVER assigns the session id: a client cannot
// send one on initialize because it does not have one yet. This server
// only ever read the header, so initialize always arrived with an empty
// session, the clientInfo it carries was remembered against nothing,
// and every subsequent call fell back to the User-Agent -- the value
// this feature exists to avoid relying on.
func TestTheServerAssignsASessionIdAtInitialize(t *testing.T) {
	s := newMCPTransportServer(t, false)
	t.Cleanup(func() { s.StopToolStats() })

	rec := postMCPWith(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":`+
			`{"protocolVersion":"2024-11-05","clientInfo":{"name":"Claude Code","version":"2.1.0"}}}`,
		"", "node/20.0")

	if rec.Code != http.StatusOK {
		t.Fatalf("initialize returned %d", rec.Code)
	}
	sid := rec.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("the server assigned no session id, so no client can ever send one back")
	}
	if len(sid) < 16 {
		t.Errorf("session id %q is too short to be unguessable", sid)
	}
}

// With the id the server handed out, a tool call is attributed to the
// harness the client declared -- not to its HTTP library.
func TestAToolCallIsAttributedToTheDeclaredHarness(t *testing.T) {
	s := newMCPTransportServer(t, false)
	t.Cleanup(func() { s.StopToolStats() })

	rec := postMCPWith(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":`+
			`{"protocolVersion":"2024-11-05","clientInfo":{"name":"Claude Code","version":"2.1.0"}}}`,
		"", "node/20.0")
	sid := rec.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("no session id was assigned")
	}

	postMCPWith(t, s,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":`+
			`{"name":"definitely_not_a_tool","arguments":{}}}`,
		sid, "node/20.0")

	var got string
	for k, e := range s.toolStats.Snapshot() {
		if k.Tool == "definitely_not_a_tool" && e.Calls > 0 {
			got = k.Client
		}
	}
	if got != "claude-code/2.1.0" {
		t.Errorf("client = %q, want claude-code/2.1.0; the declared harness lost to the User-Agent", got)
	}
}

// A client that sends no clientInfo, or whose session this process has
// forgotten, still gets counted -- against its User-Agent.
func TestTheUserAgentRemainsTheFallback(t *testing.T) {
	s := newMCPTransportServer(t, false)
	t.Cleanup(func() { s.StopToolStats() })

	postMCPWith(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`+
			`{"name":"definitely_not_a_tool","arguments":{}}}`,
		"a-session-this-process-never-saw", "python-httpx/0.27")

	var got string
	for k, e := range s.toolStats.Snapshot() {
		if k.Tool == "definitely_not_a_tool" && e.Calls > 0 {
			got = k.Client
		}
	}
	if got != "python-httpx-0.27" {
		t.Errorf("client = %q, want python-httpx-0.27", got)
	}
}

// The id a client already holds is never replaced, or the session would
// change under it on every request.
func TestAnExistingSessionIdIsLeftAlone(t *testing.T) {
	s := newMCPTransportServer(t, false)
	t.Cleanup(func() { s.StopToolStats() })

	rec := postMCPWith(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`,
		"client-chose-this", "")
	if got := rec.Header().Get("Mcp-Session-Id"); got != "" {
		t.Errorf("the server overrode a session the client already had: %q", got)
	}
}

// Two initialises must not collide, or two clients share one attribution.
func TestAssignedSessionIdsAreUnique(t *testing.T) {
	s := newMCPTransportServer(t, false)
	t.Cleanup(func() { s.StopToolStats() })

	seen := map[string]bool{}
	for i := 0; i < 25; i++ {
		rec := postMCPWith(t, s,
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`,
			"", "")
		sid := rec.Header().Get("Mcp-Session-Id")
		if sid == "" || seen[sid] {
			t.Fatalf("session id %q repeated or empty on attempt %d", sid, i)
		}
		seen[sid] = true
	}
}

// Assigning a session must not disturb the initialize response itself.
func TestInitializeStillAnswersNormally(t *testing.T) {
	s := newMCPTransportServer(t, false)
	t.Cleanup(func() { s.StopToolStats() })

	rec := postMCPWith(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":`+
			`{"protocolVersion":"2024-11-05","clientInfo":{"name":"cursor","version":"0.4"}}}`,
		"", "")
	var resp struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	if resp.Result["protocolVersion"] == nil || resp.Result["serverInfo"] == nil {
		t.Errorf("initialize result is malformed: %+v", resp.Result)
	}
}

// The store still has to exist for any of this to be observable.
func TestSessionIdentityDoesNotRequireAStore(t *testing.T) {
	s := newMCPTransportServer(t, false)
	t.Cleanup(func() { s.StopToolStats() })
	s.toolStats = nil
	rec := postMCPWith(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`,
		"", "")
	if rec.Code != http.StatusOK {
		t.Errorf("initialize without a store returned %d", rec.Code)
	}
}

var _ = toolstats.OutcomeOK
