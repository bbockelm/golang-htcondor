package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

// A tool that ran and failed must come back as a RESULT carrying
// isError, not as a JSON-RPC error.
//
// This is the difference between the user seeing "job submission failed:
// <what the schedd said>" and seeing "Error occurred during tool
// execution". Clients treat a JSON-RPC error as a protocol fault and
// surface it opaquely -- the model never sees the text -- so returning
// the diagnosis that way threw it away exactly when it was needed.
func TestToolExecutionFailureIsAResultNotAProtocolError(t *testing.T) {
	s := newTestServerForErrors(t)

	params, err := json.Marshal(map[string]interface{}{
		"name":      "submit_job",
		"arguments": map[string]interface{}{}, // no submit_file: the tool errors
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	resp := s.HandleMessage(context.Background(), &MCPMessage{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  params,
	})

	if resp.Error != nil {
		t.Fatalf("a tool failure came back as a JSON-RPC error (%d: %s); "+
			"clients render that opaquely", resp.Error.Code, resp.Error.Message)
	}
	if resp.Result == nil {
		t.Fatal("no result and no error")
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is %T, want a map", resp.Result)
	}
	if isErr, _ := result["isError"].(bool); !isErr {
		t.Errorf("isError = %v, want true", result["isError"])
	}

	text := contentText(t, result)
	// The point of the change: the actual reason has to be in there.
	if !strings.Contains(text, "submit_file is required") {
		t.Errorf("the tool's own message did not survive: %q", text)
	}
	if !strings.Contains(text, "submit_job") {
		t.Errorf("the failing tool is not named: %q", text)
	}
	// And the trace id, so a user can hand it to an administrator.
	if !strings.Contains(text, "mcp-") {
		t.Errorf("no trace id in the message shown to the user: %q", text)
	}
}

// A malformed request is a different thing and stays a JSON-RPC error:
// no tool ran, so there is no tool result to return.
func TestMalformedRequestsStayProtocolErrors(t *testing.T) {
	s := newTestServerForErrors(t)

	cases := []struct {
		name   string
		params string
	}{
		{"unparseable params", `{"name":`},
		{"unknown tool", `{"name":"no_such_tool","arguments":{}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := s.HandleMessage(context.Background(), &MCPMessage{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "tools/call",
				Params:  json.RawMessage(tc.params),
			})
			if resp.Error == nil {
				t.Fatalf("want a JSON-RPC error, got result %v", resp.Result)
			}
			if resp.Result != nil {
				t.Errorf("both error and result set: %v", resp.Result)
			}
		})
	}
}

// The id in the log and the id shown to the user have to be the SAME
// value, or it cannot be used to find anything.
func TestTraceIDIsStableAcrossTheCall(t *testing.T) {
	s := newTestServerForErrors(t)

	var seen string
	// A tool call observes the id through the context; the caller sees
	// it in the error text. Compare the two.
	ctx := context.Background()
	params, _ := json.Marshal(map[string]interface{}{
		"name":      "submit_job",
		"arguments": map[string]interface{}{},
	})
	resp := s.HandleMessage(ctx, &MCPMessage{
		JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params,
	})
	result, _ := resp.Result.(map[string]interface{})
	text := contentText(t, result)

	i := strings.Index(text, "mcp-")
	if i < 0 {
		t.Fatalf("no trace id in %q", text)
	}
	seen = text[i : i+len("mcp-")+10]
	if len(seen) != len("mcp-")+10 {
		t.Errorf("trace id looks malformed: %q", seen)
	}

	// Two calls must not share one.
	resp2 := s.HandleMessage(ctx, &MCPMessage{
		JSONRPC: "2.0", ID: 2, Method: "tools/call", Params: params,
	})
	result2, _ := resp2.Result.(map[string]interface{})
	if strings.Contains(contentText(t, result2), seen) {
		t.Error("two calls produced the same trace id")
	}
}

func TestProtocolErrorClassification(t *testing.T) {
	if !isProtocolError(protocolErrorf("bad params")) {
		t.Error("a protocolErrorf must classify as a protocol error")
	}
	if !isProtocolError(fmt.Errorf("wrapped: %w", protocolErrorf("bad params"))) {
		t.Error("wrapping must not lose the classification")
	}
	if isProtocolError(errors.New("the schedd refused the job")) {
		t.Error("an ordinary error must NOT classify as a protocol error; " +
			"that would send tool failures back down the opaque path")
	}
	if isProtocolError(nil) {
		t.Error("nil is not a protocol error")
	}
}

// Arguments carry submit files, credentials and constraints naming other
// users. Only the keys may be logged.
func TestArgKeysDoesNotLeakValues(t *testing.T) {
	keys := argKeys(map[string]interface{}{
		"submit_file": "executable = /bin/secret\nqueue",
		"constraint":  `Owner == "someone-else"`,
	})
	if len(keys) != 2 || keys[0] != "constraint" || keys[1] != "submit_file" {
		t.Fatalf("keys = %v, want sorted names only", keys)
	}
	for _, k := range keys {
		if strings.Contains(k, "/bin/secret") || strings.Contains(k, "someone-else") {
			t.Errorf("a value leaked into the log keys: %q", k)
		}
	}
	if argKeys(nil) != nil {
		t.Error("no arguments should log no keys")
	}
}

func TestSessionIDContext(t *testing.T) {
	ctx := WithSessionID(context.Background(), "sess-123")
	if got := SessionIDFromContext(ctx); got != "sess-123" {
		t.Errorf("session id = %q", got)
	}
	// An absent header must not put an empty value on the context.
	if got := SessionIDFromContext(WithSessionID(context.Background(), "")); got != "" {
		t.Errorf("empty session id = %q", got)
	}
	if got := SessionIDFromContext(context.Background()); got != "" {
		t.Errorf("bare context session id = %q", got)
	}
}

func contentText(t *testing.T, result map[string]interface{}) string {
	t.Helper()
	content, ok := result["content"].([]map[string]interface{})
	if !ok {
		t.Fatalf("content is %T, want []map[string]interface{}", result["content"])
	}
	var b strings.Builder
	for _, c := range content {
		s, _ := c["text"].(string)
		b.WriteString(s)
	}
	return b.String()
}

// newTestServerForErrors builds a server whose schedd is unreachable.
// That is fine for these tests: they exercise how a failure is REPORTED,
// and submit_job rejects a missing submit_file before it ever dials.
func newTestServerForErrors(t *testing.T) *Server {
	t.Helper()
	s, err := NewServer(Config{
		ScheddName: "test",
		ScheddAddr: "127.0.0.1:9618",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

// A failing tool call has to leave a log line. Before this, it left
// none: an administrator asked "what went wrong?" had literally nothing
// to read, which is how a broken submit became unexplainable.
func TestFailingToolCallIsLogged(t *testing.T) {
	buf := logging.NewBuffer(100, slog.LevelDebug)
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	logging.AttachBuffer(logger, buf)

	s, err := NewServer(Config{
		ScheddName: "test",
		ScheddAddr: "127.0.0.1:9618",
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	params, _ := json.Marshal(map[string]interface{}{
		"name":      "submit_job",
		"arguments": map[string]interface{}{},
	})
	ctx := WithSessionID(context.Background(), "sess-abc")
	resp := s.HandleMessage(ctx, &MCPMessage{
		JSONRPC: "2.0", ID: 7, Method: "tools/call", Params: params,
	})

	result, _ := resp.Result.(map[string]interface{})
	shownText := contentText(t, result)

	var failure *logging.BufferEntry
	for _, e := range buf.Entries(100) {
		if e.Message == "MCP tool call failed" {
			entry := e
			failure = &entry
			break
		}
	}
	if failure == nil {
		var got []string
		for _, e := range buf.Entries(100) {
			got = append(got, e.Message)
		}
		t.Fatalf("no failure log line; buffer held %v", got)
	}

	if failure.Fields["tool"] != "submit_job" {
		t.Errorf("tool field = %q", failure.Fields["tool"])
	}
	if failure.Fields["session_id"] != "sess-abc" {
		t.Errorf("session_id field = %q, want sess-abc", failure.Fields["session_id"])
	}
	if !strings.Contains(failure.Fields["error"], "submit_file is required") {
		t.Errorf("error field lost the reason: %q", failure.Fields["error"])
	}

	// The id in the log and the id the user was shown must match, or it
	// cannot be used to find anything.
	traceID := failure.Fields["trace_id"]
	if traceID == "" {
		t.Fatal("no trace_id on the log line")
	}
	if !strings.Contains(shownText, traceID) {
		t.Errorf("the log's trace id %q is not in what the user saw: %q", traceID, shownText)
	}
}
