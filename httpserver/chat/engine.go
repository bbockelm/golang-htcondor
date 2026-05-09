package chat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Tool is the server-side interface every chat tool must satisfy.
// The engine consults Schema to advertise the tool to the LLM and
// calls Execute when the LLM emits a tool_use referencing this name.
//
// Execute receives the authenticated user identity in `actor` so each
// implementation can enforce its own scoping (e.g. inject Owner ==
// actor into a job-query constraint). The string return is the JSON
// payload the LLM will see as the tool result; if it contains
// non-JSON, the engine wraps it as { "result": <string> }. Errors
// surface to the LLM as a tool_result with is_error=true so the
// model can recover (or apologize) rather than crashing the turn.
type Tool interface {
	Name() string
	Description() string
	InputSchema() json.RawMessage
	// ClientSide reports whether this tool runs in the browser. The
	// engine handles client-side tools differently: it forwards the
	// tool_use to the SPA and pauses until the SPA sends back a
	// tool_result on the next request.
	ClientSide() bool
	// RequiresConfirmation reports whether the engine should pause
	// for user approval before executing. Always false for read-only
	// or client-side tools; true for write actions (hold/release/
	// remove). The frontend renders an Approve / Reject UI for these.
	RequiresConfirmation() bool
	Execute(ctx context.Context, actor string, input json.RawMessage) (string, error)
}

// Request is one /api/v1/chat call. Messages is the full conversation
// history (browser sends every turn so the server is stateless). Each
// message's content is the AI-SDK shape — see request_message.go.
//
// PreApprovedToolUseIDs lists the tool_use ids the user has
// explicitly approved this turn. When the engine encounters a
// confirmation-required tool whose id is NOT in this set, it pauses
// and emits a confirmation prompt instead of executing.
type Request struct {
	Messages              []RequestMessage `json:"messages"`
	PreApprovedToolUseIDs []string         `json:"approved_tool_use_ids,omitempty"`
	// AutoApprove names tool kinds the user has flagged as "always
	// run without prompting" (e.g. ["release","hold"]). Same shape
	// as Tool.Name(); the engine checks membership before honoring
	// RequiresConfirmation.
	AutoApprove []string `json:"auto_approve,omitempty"`
}

// Engine drives one chat turn end-to-end. Construct with NewEngine
// once at startup and reuse — it's safe for concurrent calls because
// every Stream invocation owns its own state.
type Engine struct {
	client     *AnthropicClient
	tools      map[string]Tool
	toolSchema []AnthropicTool
	system     string
}

// NewEngine builds an engine over the supplied LLM client and tool
// registry. The system prompt is generated from the registered tool
// list so adding a tool doesn't require a prompt edit.
func NewEngine(client *AnthropicClient, tools []Tool) *Engine {
	registry := make(map[string]Tool, len(tools))
	schemas := make([]AnthropicTool, 0, len(tools))
	for _, t := range tools {
		registry[t.Name()] = t
		schemas = append(schemas, AnthropicTool{
			Name:        t.Name(),
			Description: t.Description(),
			InputSchema: t.InputSchema(),
		})
	}
	return &Engine{
		client:     client,
		tools:      registry,
		toolSchema: schemas,
		system:     buildSystemPrompt(tools),
	}
}

// Tool returns a tool by name, or nil. Used by the HTTP handler so
// it can recognize a confirmation continuation pointing at a tool
// the engine knows about.
func (e *Engine) Tool(name string) Tool {
	if e == nil {
		return nil
	}
	return e.tools[name]
}

// Stream runs one chat turn, possibly looping internally to dispatch
// server-side tool calls until the assistant produces a final text
// reply or hands off a client-side tool. Output is a sequence of
// AI-SDK protocol parts written via the Writer.
//
// `actor` is the authenticated username; tools use it for owner
// scoping. The engine never lets a tool see anything else.
//
// Stream returns when the assistant's turn ends OR when a client-side
// tool needs the browser's help (the browser's next POST will
// include the resolved tool_result and the conversation continues).
func (e *Engine) Stream(ctx context.Context, w *Writer, actor string, req Request) error {
	approved := stringSet(req.PreApprovedToolUseIDs)
	autoApprove := stringSet(req.AutoApprove)

	// Convert browser-shape messages to Anthropic-shape, dropping any
	// fields the LLM doesn't need to see.
	msgs, err := messagesToAnthropic(req.Messages)
	if err != nil {
		return fmt.Errorf("convert messages: %w", err)
	}

	// Resolve any pending approvals. When the SPA sends us
	// PreApprovedToolUseIDs, the user has clicked Approve on a
	// destructive tool whose tool_use block is sitting in the
	// previous assistant turn with no matching tool_result. Anthropic
	// rejects such histories, so we splice a synthetic tool_result
	// into the right place by executing the tool now. Same actor
	// scoping as a normal server-side execution path.
	msgs = e.resolvePendingApprovals(ctx, w, actor, msgs, approved)

	// Loop: dispatch to the LLM, feed back any server-side tool
	// results, repeat until the LLM produces a final answer or asks
	// for a client-side tool.
	const maxToolHops = 8 // belt-and-braces against runaway loops
	for hop := 0; hop < maxToolHops; hop++ {
		events := e.client.Stream(ctx, e.system, msgs, e.toolSchema, "")

		// Collect the assistant turn's content blocks as we see
		// them; the LLM might emit text + tool_use in the same turn.
		assistantContent := []AnthropicContentBlock{}
		needsTool := false
		stopReason := ""

	eventLoop:
		for ev := range events {
			switch ev.Kind {
			case "text_delta":
				w.WriteText(ev.Text)
				// Append/extend the trailing text block so we can
				// preserve assistant turn shape on the next hop.
				if n := len(assistantContent); n > 0 && assistantContent[n-1].Type == "text" {
					assistantContent[n-1].Text += ev.Text
				} else {
					assistantContent = append(assistantContent, AnthropicContentBlock{
						Type: "text",
						Text: ev.Text,
					})
				}
			case "tool_use":
				assistantContent = append(assistantContent, AnthropicContentBlock{
					Type:  "tool_use",
					ID:    ev.ToolUseID,
					Name:  ev.ToolName,
					Input: ev.ToolInput,
				})
				needsTool = true
			case "message_stop":
				stopReason = ev.StopReason
				break eventLoop
			case "error":
				w.WriteError(ev.Err.Error())
				return ev.Err
			}
		}

		// Append the assistant turn to history regardless of branch.
		if len(assistantContent) > 0 {
			msgs = append(msgs, AnthropicMessage{
				Role:    "assistant",
				Content: assistantContent,
			})
		}

		if !needsTool {
			// stop_reason=end_turn or max_tokens — assistant is done.
			if stopReason == "max_tokens" {
				w.WriteText("\n\n[turn truncated: max tokens reached; ask me to continue]")
			}
			return nil
		}

		// Execute every tool_use the assistant emitted; gather the
		// results into one user-turn content array Anthropic
		// expects.
		toolResults := []AnthropicContentBlock{}
		clientHandoff := false

		for _, blk := range assistantContent {
			if blk.Type != "tool_use" {
				continue
			}
			tool := e.tools[blk.Name]
			if tool == nil {
				toolResults = append(toolResults, errorToolResult(blk.ID,
					fmt.Sprintf("unknown tool %q", blk.Name)))
				continue
			}

			// Client-side tool: forward the tool_use to the browser
			// and end this stream. The browser will execute and POST
			// the result back, and we'll resume from there.
			if tool.ClientSide() {
				w.WriteToolCall(blk.ID, blk.Name, blk.Input)
				clientHandoff = true
				continue
			}

			// Confirmation gate. If the tool requires confirmation
			// AND it's not pre-approved AND not in the auto-approve
			// set, pause and let the SPA render an approval card.
			if tool.RequiresConfirmation() &&
				!approved[blk.ID] &&
				!autoApprove[blk.Name] {
				w.WriteConfirmationRequest(blk.ID, blk.Name, blk.Input)
				clientHandoff = true
				continue
			}

			// Server-side execution. Emit the tool-input chunks first
			// so the UI can render a "calling <tool>..." indicator;
			// without these the user sees only the result with no
			// context for what produced it.
			w.WriteToolCall(blk.ID, blk.Name, blk.Input)
			res, err := tool.Execute(ctx, actor, blk.Input)
			if err != nil {
				toolResults = append(toolResults, errorToolResult(blk.ID, err.Error()))
				w.WriteToolError(blk.ID, blk.Name, err.Error())
				continue
			}
			toolResults = append(toolResults, AnthropicContentBlock{
				Type:      "tool_result",
				ToolUseID: blk.ID,
				Content:   res,
			})
			w.WriteToolResult(blk.ID, blk.Name, res)
		}

		if clientHandoff {
			// We fired off at least one tool_use to the browser; the
			// next round-trip carries the results. End the stream.
			return nil
		}

		// Loop again with the tool results as the next user turn.
		if len(toolResults) > 0 {
			msgs = append(msgs, AnthropicMessage{
				Role:    "user",
				Content: toolResults,
			})
		}
	}

	w.WriteError("tool-call loop exceeded the safety limit; ask me a simpler question")
	return errors.New("chat: maxToolHops exceeded")
}

// resolvePendingApprovals walks the supplied message history and,
// for each tool_use block in an assistant turn that lacks a matching
// tool_result in the immediately-following user turn, checks whether
// the tool_use_id is in `approved`. If so, executes the tool
// server-side (with the same owner-scoping every other server tool
// path uses) and splices the resulting tool_result into the user
// turn. Tool_use blocks whose id is NOT in `approved` are left
// alone — they may belong to a different conversation branch (or
// the user is still deciding) and Anthropic will surface them as
// the same `tool_use without tool_result` error the SPA already
// recovers from by showing the approval card.
//
// On execution success, the engine emits the same WriteToolResult
// chunks to the SPA stream that a synchronous server-side execution
// would produce, so the UI shows "✓ remove_job" inline.
func (e *Engine) resolvePendingApprovals(
	ctx context.Context,
	w *Writer,
	actor string,
	msgs []AnthropicMessage,
	approved map[string]bool,
) []AnthropicMessage {
	if len(approved) == 0 || len(msgs) == 0 {
		return msgs
	}
	for i := 0; i < len(msgs); i++ {
		if msgs[i].Role != "assistant" {
			continue
		}
		// Collect tool_use IDs in this assistant turn.
		var pending []AnthropicContentBlock
		for _, b := range msgs[i].Content {
			if b.Type == "tool_use" {
				pending = append(pending, b)
			}
		}
		if len(pending) == 0 {
			continue
		}
		// Identify which IDs are already resolved by an existing
		// tool_result in the immediately-following user turn.
		resolved := map[string]bool{}
		nextUser := -1
		if i+1 < len(msgs) && msgs[i+1].Role == "user" {
			nextUser = i + 1
			for _, b := range msgs[nextUser].Content {
				if b.Type == "tool_result" && b.ToolUseID != "" {
					resolved[b.ToolUseID] = true
				}
			}
		}
		// For each tool_use that's both approved AND unresolved,
		// execute server-side and gather the synthetic results.
		var newResults []AnthropicContentBlock
		for _, blk := range pending {
			if resolved[blk.ID] || !approved[blk.ID] {
				continue
			}
			tool := e.tools[blk.Name]
			if tool == nil {
				newResults = append(newResults, errorToolResult(blk.ID,
					fmt.Sprintf("approval refers to unknown tool %q", blk.Name)))
				continue
			}
			// Emit the tool-input chunks to the SPA so the UI shows
			// "calling X…" as if this were a fresh execution.
			w.WriteToolCall(blk.ID, blk.Name, blk.Input)
			res, err := tool.Execute(ctx, actor, blk.Input)
			if err != nil {
				newResults = append(newResults, errorToolResult(blk.ID, err.Error()))
				w.WriteToolError(blk.ID, blk.Name, err.Error())
				continue
			}
			newResults = append(newResults, AnthropicContentBlock{
				Type:      "tool_result",
				ToolUseID: blk.ID,
				Content:   res,
			})
			w.WriteToolResult(blk.ID, blk.Name, res)
		}
		if len(newResults) == 0 {
			continue
		}
		// Splice the synthetic tool_results into the next user turn,
		// or insert a fresh user turn if there isn't one yet.
		if nextUser >= 0 {
			msgs[nextUser].Content = append(newResults, msgs[nextUser].Content...)
		} else {
			injected := AnthropicMessage{Role: "user", Content: newResults}
			// Insert at i+1.
			msgs = append(msgs[:i+1], append([]AnthropicMessage{injected}, msgs[i+1:]...)...)
		}
	}
	return msgs
}

// errorToolResult is a small helper for the "tool barfed" path. The
// LLM gets is_error=true so it can apologize / try a different
// approach instead of crashing the turn.
func errorToolResult(id, msg string) AnthropicContentBlock {
	return AnthropicContentBlock{
		Type:      "tool_result",
		ToolUseID: id,
		Content:   msg,
		IsError:   true,
	}
}

// buildSystemPrompt assembles the system message we send on every
// turn. We keep it short and operator-evergreen: the LLM doesn't
// need to know the operator's name or pool, just that it's helping
// a single authenticated user investigate / manage their own jobs
// and that the server enforces owner scoping irrespective of what
// the LLM tries.
func buildSystemPrompt(tools []Tool) string {
	var b strings.Builder
	b.WriteString(`You are a HTCondor assistant embedded in an HTC user's job-management UI.
Your job is to help the user investigate and act on THEIR OWN jobs in the local pool.
Be concise — terminal users don't need filler.

Owner scoping: every tool you call is silently scoped to the authenticated user.
You CANNOT see or act on other users' jobs even if asked. If the user asks you to,
explain that and suggest an alternative.

Available tools:
`)
	for _, t := range tools {
		fmt.Fprintf(&b, "  - %s: %s\n", t.Name(), t.Description())
	}
	b.WriteString(`
Today's date: ` + time.Now().UTC().Format("2006-01-02") + `.
`)
	return b.String()
}

// stringSet builds a tiny membership map from a slice; nil-safe.
func stringSet(xs []string) map[string]bool {
	if len(xs) == 0 {
		return nil
	}
	out := make(map[string]bool, len(xs))
	for _, x := range xs {
		out[x] = true
	}
	return out
}
