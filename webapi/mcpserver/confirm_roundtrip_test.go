package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The whole round trip, driven by the SDK's own client.
//
// These are the tests that would have caught the mistake this feature
// was nearly built on. The obvious implementation calls
// ServerSession.Elicit from inside the tool and blocks; against a
// 2026-07-28 client the SDK refuses that outright -- "cannot be sent
// while serving a request" -- so the gate would have asked nobody and
// failed every gated call, on exactly the newest clients. Nothing short
// of driving a real client finds that.
//
// What they assert is not the Go plumbing but the user-visible
// behaviour: the question reaches the person, their yes lets the call
// proceed, and their no stops it.

func confirmRoundTripServer(t *testing.T, submitOver int) *httptest.Server {
	t.Helper()
	s, err := NewServer(Config{
		ScheddName:        "test",
		ScheddAddr:        "127.0.0.1:9618",
		ConfirmSubmitOver: submitOver,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(s.SDKHTTPHandler(verifierFor([]string{"mcp:read", "mcp:write"})))
	t.Cleanup(ts.Close)
	return ts
}

// bigSubmit asks for n jobs and passes the submit lint, so the only
// thing that can stop it before the schedd is the gate.
func bigSubmit(n string) map[string]any {
	return map[string]any{
		"submit_file": "executable = /bin/sleep\ntransfer_executable = False\narguments = 60\nqueue " + n + "\n",
	}
}

// answeringClient is a client that answers questions with the given
// action, counting what it was asked and keeping the last question.
func answeringClient(action string, asked *atomic.Int64, seen *atomic.Value) *mcp.Client {
	return mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, &mcp.ClientOptions{
		ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			asked.Add(1)
			if req.Params != nil && seen != nil {
				seen.Store(req.Params.Message)
			}
			return &mcp.ElicitResult{Action: action}, nil
		},
	})
}

func connectAt(t *testing.T, ts *httptest.Server, client *mcp.Client, version string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   ts.URL,
		HTTPClient: &http.Client{Transport: bearerRoundTripper{}},
	}, &mcp.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		t.Fatalf("a %s client could not connect: %v", version, err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

// A person is asked, says yes, and the call proceeds.
//
// "Proceeds" here means it gets as far as the schedd and fails to reach
// one, which is the strongest available evidence that the gate let it
// past: a gate still holding it would have produced its own refusal
// instead.
func TestRoundTripApprovalReachesTheSchedd(t *testing.T) {
	ts := confirmRoundTripServer(t, 50)
	var asked atomic.Int64
	var message atomic.Value
	sess := connectAt(t, ts, answeringClient("accept", &asked, &message), protocolVersionV2)

	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "submit_job", Arguments: bigSubmit("500"),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	if asked.Load() != 1 {
		t.Fatalf("the person was asked %d times, want exactly 1", asked.Load())
	}
	msg, _ := message.Load().(string)
	if !strings.Contains(msg, "500") {
		t.Errorf("the question did not say how many jobs: %q", msg)
	}

	text := sdkResultText(res)
	if strings.Contains(text, "HTTP_API_MCP_CONFIRM_SUBMIT_OVER") {
		t.Fatalf("the call was refused by the gate after the person approved it: %s", text)
	}
	if !res.IsError {
		t.Fatalf("expected the submission to fail with no schedd to submit to, got: %s", text)
	}
}

// The same call, and the person says no. Nothing is submitted and the
// model is told the person decided.
func TestRoundTripDeclineStopsTheCall(t *testing.T) {
	ts := confirmRoundTripServer(t, 50)
	var asked atomic.Int64
	sess := connectAt(t, ts, answeringClient("decline", &asked, nil), protocolVersionV2)

	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "submit_job", Arguments: bigSubmit("500"),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if asked.Load() != 1 {
		t.Fatalf("the person was asked %d times, want exactly 1", asked.Load())
	}
	if !res.IsError {
		t.Fatal("a declined submission was reported as a success")
	}
	text := sdkResultText(res)
	if !strings.Contains(text, "declined") {
		t.Errorf("the result does not say the person declined: %s", text)
	}
	if strings.Contains(text, "connect") {
		t.Errorf("a declined submission still reached the schedd: %s", text)
	}
}

// Under the threshold nobody is interrupted. A gate that asked about
// routine work would be one people learn to click through.
func TestRoundTripUnderTheThresholdAsksNobody(t *testing.T) {
	ts := confirmRoundTripServer(t, 50)
	var asked atomic.Int64
	sess := connectAt(t, ts, answeringClient("accept", &asked, nil), protocolVersionV2)

	if _, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "submit_job", Arguments: bigSubmit("10"),
	}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if asked.Load() != 0 {
		t.Errorf("a 10-job submission interrupted the person %d times", asked.Load())
	}
}

// A client that declares no elicitation support is refused, not waved
// through. This is the fail-closed half, over the wire: the server has
// no way to ask, so it does not act.
func TestRoundTripClientWithoutElicitationIsRefused(t *testing.T) {
	ts := confirmRoundTripServer(t, 50)
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	sess := connectAt(t, ts, client, protocolVersionV2)

	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "submit_job", Arguments: bigSubmit("500"),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatal("a 500-job submission went through a client that cannot be asked")
	}
	text := sdkResultText(res)
	if !strings.Contains(text, "HTTP_API_MCP_CONFIRM_SUBMIT_OVER") {
		t.Fatalf("the call failed for some reason other than the gate: %s", text)
	}
	if strings.Contains(text, "connect") {
		t.Errorf("the submission reached the schedd despite the gate: %s", text)
	}
}

// With no threshold set -- the default -- the feature is not merely off,
// it is invisible: nothing asks, whatever the size.
func TestRoundTripDefaultAsksNobody(t *testing.T) {
	ts := confirmRoundTripServer(t, 0)
	var asked atomic.Int64
	sess := connectAt(t, ts, answeringClient("accept", &asked, nil), protocolVersionV2)

	if _, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "submit_job", Arguments: bigSubmit("100000"),
	}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if asked.Load() != 0 {
		t.Errorf("an unconfigured server asked the person %d times", asked.Load())
	}
}

// A client older than the 2026-07-28 protocol is REFUSED, not asked.
//
// This is a limitation, pinned here because it is invisible from the
// code and surprising. The server serves MCP statelessly, so an older
// client's capabilities -- declared once, during an initialize whose
// session is gone by the time the tool call arrives -- are not available
// to the handler: the SDK synthesizes an InitializeParams carrying the
// protocol version and no capabilities at all. The server cannot know
// whether this client could present a question, and the spec forbids
// sending one to a client that has not said it can.
//
// Fail-closed is the only safe reading of "I cannot tell". An operator
// enabling these thresholds is enabling a gate that, for older clients,
// is a flat refusal, and that is a thing to know before turning it on
// rather than after.
//
// If a later SDK makes an older client's capabilities readable in
// stateless mode, this is the test that should start failing.
func TestRoundTripOlderProtocolClientIsRefusedNotAsked(t *testing.T) {
	ts := confirmRoundTripServer(t, 50)
	var asked atomic.Int64
	sess := connectAt(t, ts, answeringClient("accept", &asked, nil), "2025-06-18")

	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "submit_job", Arguments: bigSubmit("500"),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if asked.Load() != 0 {
		t.Fatalf("an older client was asked %d times; if the SDK now carries its capabilities, the gate can ask it", asked.Load())
	}
	if !res.IsError {
		t.Fatal("a 500-job submission went through an older client unasked")
	}
	text := sdkResultText(res)
	if !strings.Contains(text, "HTTP_API_MCP_CONFIRM_SUBMIT_OVER") {
		t.Fatalf("the call failed for some reason other than the gate: %s", text)
	}
	// The refusal has to say WHY, and the why here is the client's age:
	// telling this user to enable elicitation would send them hunting
	// for a setting that would not help.
	if !strings.Contains(text, "2026-07-28") {
		t.Errorf("the refusal does not tell the user their client is too old: %s", text)
	}
	if strings.Contains(text, "connect") {
		t.Errorf("the submission reached the schedd despite the gate: %s", text)
	}
}

func sdkResultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}
