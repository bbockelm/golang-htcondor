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

// A client that declares no elicitation support is NOT blocked.
//
// The gate asks whoever can be asked and gets out of the way of whoever
// cannot. Refusing instead would make these settings unusable at a site
// whose users are on clients that cannot present a question: the
// thresholds would not gate bulk work, they would forbid it.
//
// What this costs is stated plainly in the docs and logged at WARN on
// every skip, because an operator who sets a threshold here does not
// thereby have a limit.
func TestRoundTripClientWithoutElicitationIsNotBlocked(t *testing.T) {
	ts := confirmRoundTripServer(t, 50)
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	sess := connectAt(t, ts, client, protocolVersionV2)

	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "submit_job", Arguments: bigSubmit("500"),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	// It reaches the schedd and fails to find one, which is what a
	// submission that was not gated looks like here.
	text := sdkResultText(res)
	if !res.IsError || !strings.Contains(text, "connect") {
		t.Fatalf("the submission did not reach the schedd: %s", text)
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

// A client older than the 2026-07-28 protocol is not asked, and is not
// blocked either.
//
// The reason it cannot be asked is worth knowing and is invisible from
// the code: this server answers MCP statelessly, so an older client's
// capabilities -- declared once, during a handshake whose session is
// gone by the time the tool call arrives -- are not available to the
// handler. The SDK synthesizes an InitializeParams carrying the
// protocol version and nothing else, so the server cannot tell whether
// this client could present a question, and the spec forbids sending
// one to a client that has not said it can.
//
// So for these clients the threshold does nothing at all. That is the
// behaviour to understand before turning it on: at a site still on
// older clients, setting a threshold buys a log line and no gate.
//
// If a later SDK makes an older client's capabilities readable in
// stateless mode, this is the test that should start failing -- at
// which point these clients start being asked.
func TestRoundTripOlderProtocolClientIsNeitherAskedNorBlocked(t *testing.T) {
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
	text := sdkResultText(res)
	if !res.IsError || !strings.Contains(text, "connect") {
		t.Fatalf("an older client's submission did not reach the schedd: %s", text)
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
