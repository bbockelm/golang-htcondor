package chat

import (
	"encoding/json"
	"fmt"
)

// RequestMessage is one turn from the AI-SDK `useChat()` payload.
// The browser sends every turn on every POST so the server stays
// stateless. Content is loosely-typed because the AI SDK packs
// "parts" of various kinds into the same array — text, tool calls,
// tool results — and we only need to reshape them for Anthropic.
type RequestMessage struct {
	ID    string               `json:"id,omitempty"`
	Role  string               `json:"role"` // "user" | "assistant" | "tool"
	Parts []RequestMessagePart `json:"parts,omitempty"`
	// Content is the AI SDK v3 fallback for plain-text messages
	// (older clients). When Parts is empty we treat Content as a
	// single text part.
	Content string `json:"content,omitempty"`
}

// RequestMessagePart is one element inside RequestMessage.Parts.
// AI SDK part types we care about:
//
//	type=="text"            → Text is set
//	type=="tool-call"       → ToolCallID / ToolName / Args set (assistant)
//	type=="tool-result"     → ToolCallID / Result set (user, post-tool)
//
// Everything else is ignored on the request side (we don't echo
// anything back from the SPA that isn't actionable).
type RequestMessagePart struct {
	Type       string          `json:"type"`
	Text       string          `json:"text,omitempty"`
	ToolCallID string          `json:"toolCallId,omitempty"`
	ToolName   string          `json:"toolName,omitempty"`
	Args       json.RawMessage `json:"args,omitempty"`
	// Result is the JSON value the client-side tool returned. The
	// AI SDK encodes it as an arbitrary value; we forward as-is.
	Result json.RawMessage `json:"result,omitempty"`
	// IsError flags a tool result that failed (the engine forwards
	// it to Anthropic with is_error=true so the model can recover).
	IsError bool `json:"isError,omitempty"`
}

// messagesToAnthropic flattens the AI-SDK message stream into
// Anthropic's stricter shape. The two main rules Anthropic enforces:
//
//  1. Roles strictly alternate user/assistant. Two consecutive
//     same-role messages are rejected.
//  2. Tool results live inside a user-role message as
//     content_block.type=="tool_result".
//
// AI SDK uses an explicit role="tool" for tool-result turns; we
// rewrite those to user-role content blocks here so the wire shape
// is what Anthropic expects.
func messagesToAnthropic(in []RequestMessage) ([]AnthropicMessage, error) {
	out := make([]AnthropicMessage, 0, len(in))
	for _, m := range in {
		switch m.Role {
		case "user":
			content := partsToAnthropicUser(m)
			if len(content) == 0 {
				// Empty user turn — skip rather than send a zero-content
				// message which Anthropic rejects.
				continue
			}
			out = appendMessage(out, AnthropicMessage{Role: "user", Content: content})
		case "assistant":
			content, err := partsToAnthropicAssistant(m)
			if err != nil {
				return nil, err
			}
			if len(content) == 0 {
				continue
			}
			out = appendMessage(out, AnthropicMessage{Role: "assistant", Content: content})
		case "tool":
			// AI SDK v3 sometimes renders tool results as their own
			// role=="tool" message. Anthropic wants them folded into
			// a user turn — coalesce.
			content := partsToToolResults(m)
			if len(content) == 0 {
				continue
			}
			out = appendMessage(out, AnthropicMessage{Role: "user", Content: content})
		default:
			// Unknown role — drop. Forward-compat with future AI SDK
			// extensions; we'd rather drop than break the turn.
		}
	}
	return out, nil
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
// content blocks. Falls back to RequestMessage.Content when Parts is
// empty — AI SDK older callers send plain strings.
func partsToAnthropicUser(m RequestMessage) []AnthropicContentBlock {
	if len(m.Parts) == 0 {
		if m.Content == "" {
			return nil
		}
		return []AnthropicContentBlock{{Type: "text", Text: m.Content}}
	}
	out := make([]AnthropicContentBlock, 0, len(m.Parts))
	for _, p := range m.Parts {
		switch p.Type {
		case "text":
			if p.Text != "" {
				out = append(out, AnthropicContentBlock{Type: "text", Text: p.Text})
			}
		case "tool-result":
			out = append(out, toolResultBlock(p))
		}
	}
	return out
}

// partsToAnthropicAssistant converts an assistant-role message,
// preserving tool-call shape so Anthropic can match results to calls
// on later turns. AI SDK encodes tool-calls as a separate part with
// the same toolCallId the eventual tool-result references.
func partsToAnthropicAssistant(m RequestMessage) ([]AnthropicContentBlock, error) {
	if len(m.Parts) == 0 {
		if m.Content == "" {
			return nil, nil
		}
		return []AnthropicContentBlock{{Type: "text", Text: m.Content}}, nil
	}
	out := make([]AnthropicContentBlock, 0, len(m.Parts))
	for _, p := range m.Parts {
		switch p.Type {
		case "text":
			if p.Text != "" {
				out = append(out, AnthropicContentBlock{Type: "text", Text: p.Text})
			}
		case "tool-call":
			args := p.Args
			if len(args) == 0 {
				args = json.RawMessage("{}")
			}
			out = append(out, AnthropicContentBlock{
				Type:  "tool_use",
				ID:    p.ToolCallID,
				Name:  p.ToolName,
				Input: args,
			})
		case "tool-result":
			// Some clients (and our protocol writer when forwarding
			// server-executed results) attach the tool-result to the
			// assistant message, but Anthropic insists tool_result
			// live in user-role messages. The flattener at the
			// caller will move this on the next turn — for now we
			// drop it from the assistant turn rather than emit an
			// invalid message.
		default:
			return nil, fmt.Errorf("chat: unknown assistant part type %q", p.Type)
		}
	}
	return out, nil
}

// partsToToolResults pulls just the tool-result entries from a
// role=="tool" message, used by the coalescing branch in
// messagesToAnthropic.
func partsToToolResults(m RequestMessage) []AnthropicContentBlock {
	out := make([]AnthropicContentBlock, 0, len(m.Parts))
	for _, p := range m.Parts {
		if p.Type == "tool-result" {
			out = append(out, toolResultBlock(p))
		}
	}
	return out
}

// toolResultBlock renders one AI-SDK tool-result part into
// Anthropic's tool_result content block. The Result field is
// arbitrary JSON; we serialize it to a string because Anthropic's
// content-string field doesn't accept structured content for
// tool_result blocks (the model parses the string itself).
func toolResultBlock(p RequestMessagePart) AnthropicContentBlock {
	resultStr := ""
	if len(p.Result) > 0 {
		resultStr = string(p.Result)
	}
	return AnthropicContentBlock{
		Type:      "tool_result",
		ToolUseID: p.ToolCallID,
		Content:   resultStr,
		IsError:   p.IsError,
	}
}
