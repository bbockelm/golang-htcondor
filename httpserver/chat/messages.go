package chat

import (
	"encoding/json"
	"strings"
)

// RequestMessage is one turn from the AI-SDK v6 `useChat()` payload.
// The browser sends every turn on every POST so the server stays
// stateless. Content is loosely-typed because the AI SDK packs
// "parts" of various kinds into the same array — text and tool
// invocations — and we only need to reshape them for Anthropic.
type RequestMessage struct {
	ID    string               `json:"id,omitempty"`
	Role  string               `json:"role"` // "user" | "assistant"
	Parts []RequestMessagePart `json:"parts,omitempty"`
}

// RequestMessagePart is one element inside RequestMessage.Parts.
//
// AI SDK v6 packs each tool invocation into a single part whose Type
// is "tool-<toolName>" and whose lifecycle is tracked via State:
//
//	input-streaming         — args still streaming; ignore on server
//	input-available         — args complete; emit tool_use to model
//	input-approval-required — paused for user confirmation
//	output-available        — result back; emit tool_use + tool_result
//	output-error            — tool failed; emit tool_use + tool_result(err)
//
// The same part holds Input (model args) and Output (executed result)
// once the lifecycle progresses, so we split it back into Anthropic's
// separate tool_use / tool_result blocks at flatten-time.
type RequestMessagePart struct {
	Type       string `json:"type"`
	Text       string `json:"text,omitempty"`
	ToolCallID string `json:"toolCallId,omitempty"`

	State     string          `json:"state,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	Output    json.RawMessage `json:"output,omitempty"`
	ErrorText string          `json:"errorText,omitempty"`
}

// toolPartName returns the tool name encoded in a tool part's Type
// ("tool-<name>" → "<name>"). Empty when the part is not a tool part.
func (p RequestMessagePart) toolPartName() string {
	if !p.isToolPart() {
		return ""
	}
	return strings.TrimPrefix(p.Type, "tool-")
}

// isToolPart reports whether the part is a v6 tool invocation part.
func (p RequestMessagePart) isToolPart() bool {
	return strings.HasPrefix(p.Type, "tool-")
}

// hasToolOutput reports whether a tool part carries an executed
// result that should be replayed to the model as a tool_result.
func (p RequestMessagePart) hasToolOutput() bool {
	return p.State == "output-available" || p.State == "output-error" ||
		len(p.Output) > 0 || p.ErrorText != ""
}

// messagesToAnthropic flattens the AI-SDK message stream into
// Anthropic's stricter shape. Two rules drive the reshape:
//
//  1. Roles strictly alternate user/assistant; consecutive same-role
//     messages get merged.
//  2. Every assistant tool_use must be followed (immediately) by a
//     user-role message carrying a matching tool_result, with no
//     post-tool assistant content in the same turn — Anthropic
//     interprets text after tool_use as "model continued past the
//     call without seeing the result" and rejects the request.
//
// AI SDK v6 packs the entire model trajectory (pre-call text, tool
// invocation, post-result text) into one assistant UIMessage's parts
// list. We split each such message into the canonical
// assistant→user(tool_result)→assistant sequence Anthropic expects.
func messagesToAnthropic(in []RequestMessage) []AnthropicMessage {
	out := make([]AnthropicMessage, 0, len(in))
	for _, m := range in {
		switch m.Role {
		case "user":
			content := partsToAnthropicUser(m)
			if len(content) == 0 {
				continue
			}
			out = appendMessage(out, AnthropicMessage{Role: "user", Content: content})
		case "assistant":
			for _, sub := range splitAssistantMessage(m) {
				out = appendMessage(out, sub)
			}
		default:
			// Unknown role — drop. Forward-compat: don't break the
			// turn when the SDK adds a new role kind.
		}
	}
	return backfillInterruptedTools(out)
}

// backfillInterruptedTools handles the "user kept typing while a
// client-side tool was still in flight" case. The SPA sends the full
// history on every POST; if a previous assistant turn ended in a
// tool_use that the client never resolved (e.g. fetch-query stalled,
// user lost patience and typed a follow-up), the next user turn
// arrives without a matching tool_result. Anthropic rejects that with
// a 400 — every tool_use must have a tool_result in the next message.
//
// We synthesize an interrupted-by-user tool_result at the head of the
// trailing user turn so the model sees "the call didn't finish" and
// can move on. This only fires when there IS a user turn following
// the unfinished assistant tool_use; a tool_use that's the genuinely-
// last message (e.g. waiting for approval) is left alone for
// resolvePendingApprovals to handle.
func backfillInterruptedTools(msgs []AnthropicMessage) []AnthropicMessage {
	for i := 0; i+1 < len(msgs); i++ {
		if msgs[i].Role != "assistant" {
			continue
		}
		var pending []string
		for _, b := range msgs[i].Content {
			if b.Type == "tool_use" && b.ID != "" {
				pending = append(pending, b.ID)
			}
		}
		if len(pending) == 0 {
			continue
		}
		next := &msgs[i+1]
		if next.Role != "user" {
			// Two consecutive assistant messages would already be
			// merged by appendMessage; if it's something else, the
			// history is shaped weirder than our flatten produces
			// and we can't safely splice.
			continue
		}
		matched := map[string]bool{}
		for _, b := range next.Content {
			if b.Type == "tool_result" && b.ToolUseID != "" {
				matched[b.ToolUseID] = true
			}
		}
		var injected []AnthropicContentBlock
		for _, id := range pending {
			if matched[id] {
				continue
			}
			injected = append(injected, AnthropicContentBlock{
				Type:      "tool_result",
				ToolUseID: id,
				Content:   "tool call was interrupted by the user before it finished; no result is available",
				IsError:   true,
			})
		}
		if len(injected) > 0 {
			next.Content = append(injected, next.Content...)
		}
	}
	return msgs
}

// appendMessage handles Anthropic's "no two consecutive same-role
// messages" rule by merging content into the last entry when the
// roles match.
func appendMessage(dst []AnthropicMessage, msg AnthropicMessage) []AnthropicMessage {
	if n := len(dst); n > 0 && dst[n-1].Role == msg.Role {
		dst[n-1].Content = append(dst[n-1].Content, msg.Content...)
		return dst
	}
	return append(dst, msg)
}

// partsToAnthropicUser converts a user-role message into Anthropic
// content blocks. User turns hold prose; tool-result blocks land on
// user turns only as a synthetic spillover from prior assistant
// messages (see partsToAnthropicAssistant).
func partsToAnthropicUser(m RequestMessage) []AnthropicContentBlock {
	out := make([]AnthropicContentBlock, 0, len(m.Parts))
	for _, p := range m.Parts {
		switch {
		case p.Type == "text":
			if p.Text != "" {
				out = append(out, AnthropicContentBlock{Type: "text", Text: p.Text})
			}
		case p.isToolPart() && p.hasToolOutput():
			// Defensive: some clients pack executed tool results on
			// user turns. Accept and forward.
			out = append(out, toolResultBlock(p))
		}
	}
	return out
}

// splitAssistantMessage turns a v6 assistant UIMessage into the
// sequence of Anthropic messages that represent the same conversation
// trajectory. A single v6 message can describe multiple Anthropic
// turns when the model called a tool mid-response: the parts list
// holds [pre-call text, tool_use, post-result text] in chronological
// order, but Anthropic requires those to be three separate messages
// (assistant → user(tool_result) → assistant).
//
// The walk accumulates blocks into a pending assistant turn and
// flushes whenever it encounters a tool part with output: the pending
// turn (text + the tool_use) becomes the assistant message, the
// output becomes a synthetic user message with the tool_result, and a
// new pending turn captures everything that follows. Tool parts
// without output (input-available, approval-requested, etc.) just
// emit a tool_use; the next v6 message will carry the resolution.
func splitAssistantMessage(m RequestMessage) []AnthropicMessage {
	var out []AnthropicMessage
	var pending []AnthropicContentBlock
	flushAssistant := func() {
		if len(pending) > 0 {
			out = append(out, AnthropicMessage{Role: "assistant", Content: pending})
			pending = nil
		}
	}
	for _, p := range m.Parts {
		switch {
		case p.Type == "text":
			if p.Text != "" {
				pending = append(pending, AnthropicContentBlock{Type: "text", Text: p.Text})
			}
		case p.isToolPart():
			// Skip parts where args aren't ready. Anything from
			// input-available onward is fine to send to the model.
			if p.State == "input-streaming" {
				continue
			}
			name := p.toolPartName()
			if name == "" || p.ToolCallID == "" {
				continue
			}
			pending = append(pending, AnthropicContentBlock{
				Type:  "tool_use",
				ID:    p.ToolCallID,
				Name:  name,
				Input: rawOrEmptyObject(p.Input),
			})
			if p.hasToolOutput() {
				flushAssistant()
				out = append(out, AnthropicMessage{
					Role:    "user",
					Content: []AnthropicContentBlock{toolResultBlock(p)},
				})
			}
		default:
			// Unknown part type — drop. Forward-compat for SDK bumps.
		}
	}
	flushAssistant()
	return out
}

// toolResultBlock renders a v6 tool part's output half into a
// tool_result content block. State output-error is converted to
// is_error=true with errorText as the content.
func toolResultBlock(p RequestMessagePart) AnthropicContentBlock {
	isErr := p.State == "output-error" || p.ErrorText != ""
	var content string
	switch {
	case isErr && p.ErrorText != "":
		content = p.ErrorText
	case len(p.Output) > 0:
		content = string(p.Output)
	}
	return AnthropicContentBlock{
		Type:      "tool_result",
		ToolUseID: p.ToolCallID,
		Content:   content,
		IsError:   isErr,
	}
}

// rawOrEmptyObject normalizes a possibly-empty json.RawMessage so
// the model never sees a literal empty value where it expects an
// object input.
func rawOrEmptyObject(r json.RawMessage) json.RawMessage {
	if len(r) == 0 {
		return json.RawMessage(`{}`)
	}
	return r
}
