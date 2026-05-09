package chat

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeTool is a tiny chat.Tool implementation tests can register
// to assert what the engine forwards to it.
type fakeTool struct {
	name        string
	confirm     bool
	clientSide  bool
	lastInput   json.RawMessage
	lastActor   string
	calls       int
	returnValue string
	returnErr   error
}

func (f *fakeTool) Name() string                 { return f.name }
func (f *fakeTool) Description() string          { return "test " + f.name }
func (f *fakeTool) InputSchema() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }
func (f *fakeTool) ClientSide() bool             { return f.clientSide }
func (f *fakeTool) RequiresConfirmation() bool   { return f.confirm }
func (f *fakeTool) Execute(_ context.Context, actor string, in json.RawMessage) (string, error) {
	f.calls++
	f.lastActor = actor
	f.lastInput = in
	if f.returnErr != nil {
		return "", f.returnErr
	}
	if f.returnValue == "" {
		return `{"ok":true}`, nil
	}
	return f.returnValue, nil
}

// TestResolvePendingApprovalsExecutesApproved is the core
// confirmation-flow test: when the conversation history has an
// assistant tool_use that's in the approved set AND there's no
// matching tool_result in the next user turn, the engine executes
// the tool and splices a synthetic tool_result into the history
// before forwarding to Anthropic.
//
// Anthropic's wire-protocol rule (every tool_use must have a
// tool_result in the immediately-following user turn) is what
// drives this behavior. Without splicing the engine would forward
// a malformed history and Anthropic would 400. The test asserts
// (a) the tool's Execute is called, (b) the actor is propagated,
// (c) the resulting message slice has a tool_result block where
// expected.
func TestResolvePendingApprovalsExecutesApproved(t *testing.T) {
	tool := &fakeTool{name: "remove_job", confirm: true, returnValue: `{"removed":1}`}
	engine := NewEngine(nil /* anthropic client unused */, []Tool{tool})

	// Hand-craft an Anthropic-shape history with an unfinished
	// tool_use waiting for a tool_result.
	msgs := []AnthropicMessage{
		{Role: "user", Content: []AnthropicContentBlock{{Type: "text", Text: "remove cluster 1"}}},
		{Role: "assistant", Content: []AnthropicContentBlock{
			{Type: "tool_use", ID: "tu_1", Name: "remove_job", Input: json.RawMessage(`{"cluster_id":1,"proc_id":0}`)},
		}},
		{Role: "user", Content: []AnthropicContentBlock{{Type: "text", Text: "Approved."}}},
	}
	approved := map[string]bool{"tu_1": true}

	// The writer needs *something* http-shaped; httptest.ResponseRecorder works.
	w := NewWriter(httptest.NewRecorder())
	defer w.Close()

	out := engine.resolvePendingApprovals(context.Background(), w, "alice", msgs, approved)

	// (a) tool was executed exactly once
	if tool.calls != 1 {
		t.Errorf("tool called %d times, want 1", tool.calls)
	}
	// (b) actor was propagated
	if tool.lastActor != "alice" {
		t.Errorf("tool received actor=%q, want alice", tool.lastActor)
	}
	// (b2) input was forwarded verbatim
	var input map[string]any
	_ = json.Unmarshal(tool.lastInput, &input)
	if input["cluster_id"] != float64(1) || input["proc_id"] != float64(0) {
		t.Errorf("tool received input %v, want {cluster_id:1, proc_id:0}", input)
	}

	// (c) splicing: the user turn at index 2 should now have a
	// tool_result block prepended with the tool's return value.
	if len(out) < 3 {
		t.Fatalf("output has %d messages, want >= 3", len(out))
	}
	userTurn := out[2]
	if userTurn.Role != "user" {
		t.Fatalf("expected user turn at index 2, got %q", userTurn.Role)
	}
	var foundResult *AnthropicContentBlock
	for i := range userTurn.Content {
		if userTurn.Content[i].Type == "tool_result" && userTurn.Content[i].ToolUseID == "tu_1" {
			foundResult = &userTurn.Content[i]
			break
		}
	}
	if foundResult == nil {
		t.Fatalf("tool_result for tu_1 not spliced into user turn; content=%+v", userTurn.Content)
	}
	if foundResult.IsError {
		t.Errorf("expected non-error tool_result, got is_error=true")
	}
	if !strings.Contains(foundResult.Content, `"removed":1`) {
		t.Errorf("tool_result content missing return payload: %q", foundResult.Content)
	}
}

// TestResolvePendingApprovalsLeavesUnapprovedAlone confirms that
// tool_use blocks NOT in the approved set are not executed and the
// history isn't touched. Anthropic will reject those (and the SPA
// will see the tool-approval-request via the engine's main loop on
// the next round), but that's the desired outcome — the engine
// doesn't side-execute tool_uses behind the user's back.
func TestResolvePendingApprovalsLeavesUnapprovedAlone(t *testing.T) {
	tool := &fakeTool{name: "remove_job", confirm: true}
	engine := NewEngine(nil, []Tool{tool})

	msgs := []AnthropicMessage{
		{Role: "user", Content: []AnthropicContentBlock{{Type: "text", Text: "remove"}}},
		{Role: "assistant", Content: []AnthropicContentBlock{
			{Type: "tool_use", ID: "tu_unapproved", Name: "remove_job"},
		}},
	}
	approved := map[string]bool{} // empty

	w := NewWriter(httptest.NewRecorder())
	defer w.Close()

	out := engine.resolvePendingApprovals(context.Background(), w, "alice", msgs, approved)
	if tool.calls != 0 {
		t.Errorf("tool called %d times, want 0 (unapproved)", tool.calls)
	}
	if len(out) != len(msgs) {
		t.Errorf("history length changed from %d to %d (expected unchanged)", len(msgs), len(out))
	}
}

// TestResolvePendingApprovalsSkipsAlreadyResolved confirms the
// engine doesn't double-execute when the user turn already carries
// a tool_result for the tool_use — that's the normal happy path
// where Anthropic emitted tool_use + we executed it + we sent the
// tool_result on a previous round. Re-running would be a bug.
func TestResolvePendingApprovalsSkipsAlreadyResolved(t *testing.T) {
	tool := &fakeTool{name: "remove_job", confirm: true}
	engine := NewEngine(nil, []Tool{tool})

	msgs := []AnthropicMessage{
		{Role: "assistant", Content: []AnthropicContentBlock{
			{Type: "tool_use", ID: "tu_done", Name: "remove_job"},
		}},
		{Role: "user", Content: []AnthropicContentBlock{
			{Type: "tool_result", ToolUseID: "tu_done", Content: `{"old":"result"}`},
		}},
	}
	approved := map[string]bool{"tu_done": true} // approved but already done

	w := NewWriter(httptest.NewRecorder())
	defer w.Close()

	_ = engine.resolvePendingApprovals(context.Background(), w, "alice", msgs, approved)
	if tool.calls != 0 {
		t.Errorf("tool re-executed despite existing tool_result; calls=%d", tool.calls)
	}
}

// TestNewWriterEmitsSSEHeaders is a small smoke check that the
// writer sets the headers DefaultChatTransport expects when it
// asserts the upstream is an SSE stream.
func TestNewWriterEmitsSSEHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	w := NewWriter(rec)
	w.WriteText("hi")
	w.Close()

	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/event-stream") {
		t.Errorf("Content-Type=%q, want text/event-stream prefix", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q, want no-store", got)
	}
	body := rec.Body.String()
	// Each event should be `data: {...}\n\n`. Spot-check that the
	// text-start + text-delta pair shows up.
	if !strings.Contains(body, `"type":"text-start"`) {
		t.Errorf("missing text-start chunk in body: %q", body)
	}
	if !strings.Contains(body, `"type":"text-delta"`) || !strings.Contains(body, `"delta":"hi"`) {
		t.Errorf("missing text-delta chunk: %q", body)
	}
}

// TestWriterToolApprovalSequence pins the wire shape of the
// confirmation gate: tool-input-start, tool-input-available,
// tool-approval-request, in that order, all carrying the same
// toolCallId so the SPA can correlate.
func TestWriterToolApprovalSequence(t *testing.T) {
	rec := httptest.NewRecorder()
	w := NewWriter(rec)
	w.WriteConfirmationRequest("tu_42", "remove_job", json.RawMessage(`{"cluster_id":42}`))
	w.Close()

	body := rec.Body.String()
	idxStart := strings.Index(body, `"type":"tool-input-start"`)
	idxAvail := strings.Index(body, `"type":"tool-input-available"`)
	idxApproval := strings.Index(body, `"type":"tool-approval-request"`)
	if idxStart < 0 || idxAvail < 0 || idxApproval < 0 {
		t.Fatalf("missing chunk types in body: %q", body)
	}
	if idxStart >= idxAvail || idxAvail >= idxApproval {
		t.Errorf("chunks out of order; start=%d available=%d approval=%d",
			idxStart, idxAvail, idxApproval)
	}
	if !strings.Contains(body, `"toolCallId":"tu_42"`) {
		t.Errorf("toolCallId missing from chunks: %q", body)
	}
	if !strings.Contains(body, `"approvalId":"tu_42"`) {
		t.Errorf("approvalId missing from approval-request: %q", body)
	}
	// httptest.ResponseRecorder doesn't automatically check headers
	// were set before WriteHeader — we just make sure they're in
	// the recorder.
	_ = http.StatusOK
}
