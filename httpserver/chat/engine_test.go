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
	pages       []string
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
func (f *fakeTool) AvailablePages() []string     { return f.pages }
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
	engine := NewEngine(nil /* anthropic client unused */, []Tool{tool}, nil, "")

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
	engine := NewEngine(nil, []Tool{tool}, nil, "")

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
	engine := NewEngine(nil, []Tool{tool}, nil, "")

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

// TestWriterEmitsStepBoundaries pins the step-boundary protocol the
// AI-SDK auto-resubmit predicate relies on. Without start-step /
// finish-step chunks, lastAssistantMessageIsCompleteWithToolCalls
// inspects the entire accumulated assistant message and considers any
// turn ending in text after a resolved tool call as "complete with
// tool calls" — fires another /api/v1/chat POST forever.
func TestWriterEmitsStepBoundaries(t *testing.T) {
	rec := httptest.NewRecorder()
	w := NewWriter(rec)
	w.WriteStepStart()
	w.WriteText("hi")
	w.WriteStepFinish()
	w.Close()

	body := rec.Body.String()
	if !strings.Contains(body, `"type":"start-step"`) {
		t.Errorf("missing start-step chunk in body: %q", body)
	}
	if !strings.Contains(body, `"type":"finish-step"`) {
		t.Errorf("missing finish-step chunk in body: %q", body)
	}
	idxStart := strings.Index(body, `"type":"start-step"`)
	idxFinish := strings.Index(body, `"type":"finish-step"`)
	if idxStart >= idxFinish {
		t.Errorf("step boundaries out of order: start=%d finish=%d body=%q",
			idxStart, idxFinish, body)
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

// TestEngineFiltersToolsByPage is the core multi-page guarantee:
// when a request arrives with Page="submit", a tool tagged ["jobs"]
// must NOT appear in the schema sent to Anthropic (and vice versa).
// Untagged tools are universal and stay visible everywhere. The
// failure mode this protects against is the LLM seeing — and
// invoking — a UI-mutation tool whose target component isn't even
// mounted on the current page.
func TestEngineFiltersToolsByPage(t *testing.T) {
	jobsOnly := &fakeTool{name: "set_filter", pages: []string{"jobs"}}
	submitOnly := &fakeTool{name: "set_template_body", pages: []string{"submit"}}
	universal := &fakeTool{name: "doc_search"} // pages nil = everywhere

	engine := NewEngine(nil, []Tool{jobsOnly, submitOnly, universal}, nil, "")

	cases := []struct {
		page        string
		wantTools   []string
		bannedTools []string
	}{
		{
			page:        "jobs",
			wantTools:   []string{"set_filter", "doc_search"},
			bannedTools: []string{"set_template_body"},
		},
		{
			page:        "submit",
			wantTools:   []string{"set_template_body", "doc_search"},
			bannedTools: []string{"set_filter"},
		},
		{
			// Empty page is "no filtering" — legacy callers without
			// the Page field still see every tool. This is intentional;
			// strict filtering kicks in only when a real page id arrives.
			page:      "",
			wantTools: []string{"set_filter", "set_template_body", "doc_search"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.page, func(t *testing.T) {
			tools, schemas := engine.toolsForPage(tc.page)
			gotNames := make(map[string]bool, len(tools))
			for _, tool := range tools {
				gotNames[tool.Name()] = true
			}
			for _, want := range tc.wantTools {
				if !gotNames[want] {
					t.Errorf("page=%q: missing tool %q from filter result", tc.page, want)
				}
			}
			for _, banned := range tc.bannedTools {
				if gotNames[banned] {
					t.Errorf("page=%q: banned tool %q leaked through filter", tc.page, banned)
				}
			}
			// Tool slice and schema slice must stay aligned (the
			// engine sends `schemas` to Anthropic and dispatches by
			// `tools`; a misalignment would dispatch wrong tools).
			if len(tools) != len(schemas) {
				t.Errorf("page=%q: tools=%d schemas=%d (must match)",
					tc.page, len(tools), len(schemas))
			}
			for i := range tools {
				if tools[i].Name() != schemas[i].Name {
					t.Errorf("page=%q: index %d tool=%q schema=%q (out of sync)",
						tc.page, i, tools[i].Name(), schemas[i].Name)
				}
			}
		})
	}
}

// TestSystemPromptComposition pins the system-prompt assembly:
// the base preamble is always present, the per-page suffix is
// included only when the page key is in the engine's instruction
// map, and the operator addendum (if non-empty) appears last so
// site rules trump everything above. Verifying these positionally
// matters because the LLM weighs later prompt content as a higher
// priority — a regression that puts operator rules above page
// help would silently change behavior at every site.
func TestSystemPromptComposition(t *testing.T) {
	pageInstr := map[string]string{
		"jobs":   "JOBS_INSTRUCTIONS_MARKER",
		"submit": "SUBMIT_INSTRUCTIONS_MARKER",
	}
	engine := NewEngine(nil, nil, pageInstr, "OPERATOR_RULES_MARKER")

	t.Run("known page includes its suffix and the operator addendum", func(t *testing.T) {
		got := engine.systemPromptForPage("jobs", nil, "")
		if !strings.Contains(got, "JOBS_INSTRUCTIONS_MARKER") {
			t.Errorf("missing jobs suffix in prompt:\n%s", got)
		}
		if strings.Contains(got, "SUBMIT_INSTRUCTIONS_MARKER") {
			t.Errorf("submit suffix leaked into jobs prompt:\n%s", got)
		}
		if !strings.Contains(got, "OPERATOR_RULES_MARKER") {
			t.Errorf("missing operator addendum:\n%s", got)
		}
		// Operator rules must follow the page suffix — otherwise
		// site policy would be overridden by per-page guidance.
		if strings.Index(got, "JOBS_INSTRUCTIONS_MARKER") >
			strings.Index(got, "OPERATOR_RULES_MARKER") {
			t.Errorf("operator addendum appears BEFORE the page suffix; expected after")
		}
	})

	t.Run("unknown page falls back to base+addendum only", func(t *testing.T) {
		got := engine.systemPromptForPage("unknown_xyz", nil, "")
		if strings.Contains(got, "JOBS_INSTRUCTIONS_MARKER") ||
			strings.Contains(got, "SUBMIT_INSTRUCTIONS_MARKER") {
			t.Errorf("unknown page leaked a known page's suffix:\n%s", got)
		}
		if !strings.Contains(got, "OPERATOR_RULES_MARKER") {
			t.Errorf("unknown page should still include operator addendum:\n%s", got)
		}
	})

	t.Run("empty operator addendum produces no operator block", func(t *testing.T) {
		bare := NewEngine(nil, nil, pageInstr, "")
		got := bare.systemPromptForPage("jobs", nil, "")
		if strings.Contains(got, "Site operator instructions") {
			t.Errorf("bare engine emitted operator block despite empty addendum:\n%s", got)
		}
	})

	t.Run("page context is injected and respects the cap", func(t *testing.T) {
		got := engine.systemPromptForPage("jobs", nil, "job_id=1.0\nstatus=Running")
		if !strings.Contains(got, "Page context:") {
			t.Errorf("missing 'Page context:' header in prompt:\n%s", got)
		}
		if !strings.Contains(got, "job_id=1.0") {
			t.Errorf("missing page-context body in prompt:\n%s", got)
		}
		// Page context must come AFTER the page-specific instructions
		// — a future regression that swaps the order would cause the
		// page guidance to override the per-request facts.
		if strings.Index(got, "JOBS_INSTRUCTIONS_MARKER") > strings.Index(got, "Page context:") {
			t.Errorf("page context should appear AFTER the page-instructions block")
		}

		// Cap enforcement: a 4 KiB string must be truncated to the
		// engine's cap with a "[truncated]" marker. Without the cap
		// a runaway caller could pin gigantic strings into the
		// system prompt.
		huge := strings.Repeat("A", 4096)
		clamped := engine.systemPromptForPage("jobs", nil, huge)
		if !strings.Contains(clamped, "[truncated]") {
			t.Errorf("huge page context should be marked truncated:\n%s", clamped)
		}
	})
}
