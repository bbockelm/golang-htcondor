package chat

import (
	"encoding/json"
	"testing"
)

// TestMessagesToAnthropicSplitsAroundCompletedTool pins the central
// v6 reshape: a single assistant UIMessage holding [pre-call text,
// completed tool, post-result text] must split into THREE Anthropic
// messages — assistant(text+tool_use), user(tool_result), assistant
// (post-result text). Previously the engine packed everything into
// one assistant turn and Anthropic 400'd because the trailing text
// implied "model continued past the tool call without seeing a
// result".
func TestMessagesToAnthropicSplitsAroundCompletedTool(t *testing.T) {
	in := []RequestMessage{
		{Role: "user", Parts: []RequestMessagePart{
			{Type: "text", Text: "How much memory are my jobs using?"},
		}},
		{Role: "assistant", Parts: []RequestMessagePart{
			{Type: "text", Text: "I'll check your jobs."},
			{
				Type:       "tool-query_jobs",
				ToolCallID: "tu_1",
				State:      "output-available",
				Input:      json.RawMessage(`{"limit":50}`),
				Output:     json.RawMessage(`{"count":2,"jobs":[]}`),
			},
			{Type: "text", Text: "I see 2 running jobs."},
		}},
		{Role: "user", Parts: []RequestMessagePart{
			{Type: "text", Text: "help?"},
		}},
	}

	got := messagesToAnthropic(in)

	// Expect:
	//   0: user("How much memory…")
	//   1: assistant(text "I'll check…", tool_use)
	//   2: user(tool_result)
	//   3: assistant(text "I see 2…")
	//   4: user("help?")
	if len(got) != 5 {
		t.Fatalf("got %d messages, want 5: %+v", len(got), got)
	}

	// Turn 1: assistant ending in tool_use (no trailing text).
	if got[1].Role != "assistant" {
		t.Fatalf("turn 1 role=%q, want assistant", got[1].Role)
	}
	if len(got[1].Content) != 2 {
		t.Fatalf("turn 1 should have 2 blocks (text + tool_use), got %d: %+v", len(got[1].Content), got[1].Content)
	}
	if got[1].Content[1].Type != "tool_use" || got[1].Content[1].ID != "tu_1" {
		t.Errorf("turn 1 must end in tool_use(tu_1); got %+v", got[1].Content[1])
	}

	// Turn 2: user with tool_result IMMEDIATELY after tool_use.
	if got[2].Role != "user" || len(got[2].Content) != 1 {
		t.Fatalf("turn 2 should be user with 1 tool_result; got %+v", got[2])
	}
	tr := got[2].Content[0]
	if tr.Type != "tool_result" || tr.ToolUseID != "tu_1" {
		t.Errorf("turn 2 tool_result mismatch: %+v", tr)
	}

	// Turn 3: assistant with the post-result text only — no leftover
	// tool_use blocks at the end.
	if got[3].Role != "assistant" || len(got[3].Content) != 1 ||
		got[3].Content[0].Type != "text" || got[3].Content[0].Text != "I see 2 running jobs." {
		t.Errorf("turn 3 should be assistant(text only); got %+v", got[3])
	}

	// Turn 4: user prose — must NOT be merged with the synthetic
	// tool_result user turn (they're separated by an assistant turn).
	if got[4].Role != "user" || len(got[4].Content) != 1 ||
		got[4].Content[0].Text != "help?" {
		t.Errorf("turn 4 should be user(\"help?\"); got %+v", got[4])
	}
}

// TestMessagesToAnthropicToolWithoutOutput pins the still-pending
// case: a tool part with state input-available (or approval-
// requested) carries no output yet, so the assistant turn just ends
// with the tool_use and no synthetic user turn is emitted. The
// engine's resolvePendingApprovals fills in the result before the
// model sees it.
func TestMessagesToAnthropicToolWithoutOutput(t *testing.T) {
	in := []RequestMessage{
		{Role: "assistant", Parts: []RequestMessagePart{
			{Type: "text", Text: "About to remove…"},
			{
				Type:       "tool-remove_job",
				ToolCallID: "tu_pending",
				State:      "input-available",
				Input:      json.RawMessage(`{"cluster_id":7}`),
			},
		}},
	}
	got := messagesToAnthropic(in)
	if len(got) != 1 {
		t.Fatalf("want 1 message (assistant only, no tool_result yet); got %d: %+v", len(got), got)
	}
	if got[0].Role != "assistant" || len(got[0].Content) != 2 {
		t.Fatalf("turn 0 shape mismatch: %+v", got[0])
	}
	if got[0].Content[1].Type != "tool_use" || got[0].Content[1].ID != "tu_pending" {
		t.Errorf("turn 0 must end in tool_use; got %+v", got[0].Content[1])
	}
}

// TestMessagesToAnthropicSkipsInputStreaming confirms that tool parts
// whose args haven't finished streaming don't get forwarded.
func TestMessagesToAnthropicSkipsInputStreaming(t *testing.T) {
	in := []RequestMessage{
		{Role: "assistant", Parts: []RequestMessagePart{
			{Type: "tool-query_jobs", ToolCallID: "tu_x", State: "input-streaming"},
		}},
	}
	got := messagesToAnthropic(in)
	if len(got) != 0 {
		t.Errorf("input-streaming part should be skipped; got %d messages: %+v", len(got), got)
	}
}

// TestMessagesToAnthropicErrorOutput pins the error path: a tool part
// in state output-error yields is_error=true with the errorText as
// content, so the model can recover.
func TestMessagesToAnthropicErrorOutput(t *testing.T) {
	in := []RequestMessage{
		{Role: "assistant", Parts: []RequestMessagePart{
			{
				Type:       "tool-hold_job",
				ToolCallID: "tu_err",
				State:      "output-error",
				Input:      json.RawMessage(`{"cluster_id":99}`),
				ErrorText:  "permission denied",
			},
		}},
	}
	got := messagesToAnthropic(in)
	if len(got) != 2 {
		t.Fatalf("want 2 messages (assistant tool_use + user tool_result); got %d: %+v", len(got), got)
	}
	tr := got[1].Content[0]
	if !tr.IsError || tr.Content != "permission denied" {
		t.Errorf("error tool_result mismatch: %+v", tr)
	}
}

// TestMessagesToAnthropicInterruptedToolBackfill pins the recovery
// path for the "client-side tool stalled, user typed next message
// before it finished" scenario. The previous assistant turn ended
// with a tool_use carrying no output; the SPA includes that
// unresolved part in the next POST alongside the user's follow-up
// prose. Without backfill Anthropic 400s with "tool_use without
// tool_result". With backfill we splice a synthetic interrupted
// tool_result so the model can recover and respond to the prose.
func TestMessagesToAnthropicInterruptedToolBackfill(t *testing.T) {
	in := []RequestMessage{
		{Role: "user", Parts: []RequestMessagePart{{Type: "text", Text: "why isn't this running?"}}},
		{Role: "assistant", Parts: []RequestMessagePart{
			{Type: "text", Text: "Let me check the match analysis."},
			{
				Type:       "tool-get_match_analysis",
				ToolCallID: "tu_stalled",
				State:      "input-available",
				Input:      json.RawMessage(`{}`),
				// no Output — the client-side hook never resolved
			},
		}},
		{Role: "user", Parts: []RequestMessagePart{{Type: "text", Text: "hello?"}}},
	}
	got := messagesToAnthropic(in)

	// Find the user turn that follows the assistant tool_use; it
	// should now START with a synthetic tool_result for tu_stalled,
	// followed by the original "hello?" text.
	var found bool
	for _, m := range got {
		if m.Role != "user" || len(m.Content) < 2 {
			continue
		}
		first := m.Content[0]
		if first.Type == "tool_result" && first.ToolUseID == "tu_stalled" && first.IsError {
			found = true
			// And the original user text must still be in there.
			haveText := false
			for _, b := range m.Content {
				if b.Type == "text" && b.Text == "hello?" {
					haveText = true
					break
				}
			}
			if !haveText {
				t.Errorf("synthetic tool_result was injected but original user prose was lost: %+v", m)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected synthetic tool_result for tu_stalled to be prepended to the next user turn; got %+v", got)
	}
}

// TestMessagesToAnthropicNoBackfillWhenPending pins the negative case:
// when the assistant's tool_use is the last message in history (no
// follow-up user turn yet — i.e. waiting for client-side or approval
// resolution), we must NOT fabricate a result. The engine's main loop
// or resolvePendingApprovals owns those paths.
func TestMessagesToAnthropicNoBackfillWhenPending(t *testing.T) {
	in := []RequestMessage{
		{Role: "user", Parts: []RequestMessagePart{{Type: "text", Text: "remove cluster 1"}}},
		{Role: "assistant", Parts: []RequestMessagePart{
			{
				Type:       "tool-remove_job",
				ToolCallID: "tu_pending",
				State:      "input-available",
				Input:      json.RawMessage(`{"cluster_id":1}`),
			},
		}},
	}
	got := messagesToAnthropic(in)
	// Sanity: assistant tool_use is last; no synthetic tool_result.
	if len(got) != 2 {
		t.Fatalf("got %d messages, want 2: %+v", len(got), got)
	}
	for _, m := range got {
		for _, b := range m.Content {
			if b.Type == "tool_result" {
				t.Errorf("synthetic tool_result invented when none of the next-message conditions applied: %+v", b)
			}
		}
	}
}

// TestMessagesToAnthropicConsecutiveToolsBatchSplit pins the multi-
// tool case: when the assistant called two tools back-to-back, the
// flatten produces two assistant→user(result) pairs (one per tool).
// Adjacent same-role messages get merged elsewhere; here we just
// verify the per-tool boundary is preserved so each tool_use has its
// own immediately-following tool_result.
func TestMessagesToAnthropicConsecutiveToolsBatchSplit(t *testing.T) {
	in := []RequestMessage{
		{Role: "assistant", Parts: []RequestMessagePart{
			{
				Type: "tool-query_jobs", ToolCallID: "A",
				State: "output-available", Output: json.RawMessage(`{"a":1}`),
			},
			{
				Type: "tool-query_jobs", ToolCallID: "B",
				State: "output-available", Output: json.RawMessage(`{"b":2}`),
			},
		}},
	}
	got := messagesToAnthropic(in)
	// Expect: assistant(tool_use A) → user(result A) → assistant
	// (tool_use B) → user(result B). 4 messages, alternating roles.
	if len(got) != 4 {
		t.Fatalf("want 4 messages; got %d: %+v", len(got), got)
	}
	if got[0].Role != "assistant" || got[0].Content[len(got[0].Content)-1].ID != "A" {
		t.Errorf("turn 0 mismatch: %+v", got[0])
	}
	if got[1].Role != "user" || got[1].Content[0].ToolUseID != "A" {
		t.Errorf("turn 1 mismatch: %+v", got[1])
	}
	if got[2].Role != "assistant" || got[2].Content[len(got[2].Content)-1].ID != "B" {
		t.Errorf("turn 2 mismatch: %+v", got[2])
	}
	if got[3].Role != "user" || got[3].Content[0].ToolUseID != "B" {
		t.Errorf("turn 3 mismatch: %+v", got[3])
	}
}
