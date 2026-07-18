package chat

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// Writer serializes engine output as the AI-SDK v6 UI-message-stream
// format `useChat()` reads via DefaultChatTransport. The on-wire shape
// is plain SSE (`data: {json}\n\n`) where each event's payload is one
// UIMessageChunk — the typed union from `ai` v6's TypeScript surface.
//
// We emit a small subset of chunk types:
//
//	text-start / text-delta / text-end          — assistant prose
//	tool-input-start                             — opening a tool call
//	tool-input-available                         — tool call's args complete
//	tool-output-available / tool-output-error    — server-executed result
//	tool-approval-request                        — destructive-tool confirm
//	error                                        — terminal error
//
// Buffered writer + flusher pinning ensures text characters reach the
// browser as they're produced; the SDK's stream parser doesn't
// require any padding or keep-alives.
type Writer struct {
	mu       sync.Mutex
	w        *bufio.Writer
	rc       *http.ResponseController
	textOpen bool   // tracks whether a text-start has been emitted without a matching text-end
	textID   string // current text part id; valid only while textOpen is true
}

// NewWriter wraps an http.ResponseWriter for the chat handler. Sets
// the SSE response headers if not already present.
//
// IMPORTANT: we use http.NewResponseController(rw) instead of the
// classic `rw.(http.Flusher)` type assertion. The Go server pipes
// every request through wrapping middleware (accessLogMiddleware's
// responseWriter, metrics' statusRecorder, etc.) that captures status
// codes and byte counts by embedding http.ResponseWriter. None of
// those wrappers re-implement the Flusher interface explicitly — and
// a direct type assertion fails on an embedded-interface wrapper, so
// `flusher` would be nil and our Flush calls would be no-ops. Result:
// every text-delta sits in Go's chunked-encoding buffer until the
// response ends, so the entire turn appears at once in the browser
// no matter how slow the upstream LLM streamed.
//
// http.NewResponseController (Go 1.20+) walks the Unwrap() chain to
// find a real Flusher, so as long as every wrapper exposes Unwrap()
// — which they do — we always get a working flush. Belt-and-braces:
// see ../server.go and ../metrics.go for the wrappers.
func NewWriter(rw http.ResponseWriter) *Writer {
	if rw.Header().Get("Content-Type") == "" {
		rw.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	}
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Connection", "keep-alive")
	rw.Header().Set("x-vercel-ai-ui-message-stream", "v1")

	w := bufio.NewWriter(rw)
	return &Writer{w: w, rc: http.NewResponseController(rw)}
}

// WriteStepStart emits a start-step chunk. The AI-SDK on the client
// uses these as boundaries between LLM "turns" within a single
// streaming assistant message: lastAssistantMessageIsCompleteWithTool
// Calls (the auto-resubmit predicate) only inspects parts AFTER the
// most recent step-start. Without these, a turn that emits both a
// (resolved) tool call AND trailing text gets misclassified as
// "complete with tool calls" — the predicate fires forever and the
// chat loops on /api/v1/chat with no progress.
//
// Pair with WriteStepFinish around each LLM call. Subsequent re-
// submits accumulate into the same assistant message client-side, so
// the step boundaries are what tells them apart.
func (w *Writer) WriteStepStart() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.finishTextLocked()
	w.writeChunkLocked(map[string]any{
		"type": "start-step",
	})
}

// WriteStepFinish emits a finish-step chunk balancing a prior
// WriteStepStart. The SDK uses it to flush per-step state (active
// text/reasoning parts); it doesn't push a part itself. Safe to skip,
// but emitting matches the SDK's server-side conventions.
func (w *Writer) WriteStepFinish() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.finishTextLocked()
	w.writeChunkLocked(map[string]any{
		"type": "finish-step",
	})
}

// WriteText emits an incremental text delta. The first call
// implicitly emits a text-start; subsequent calls just emit deltas.
// Call FinishText (or Close) to balance with text-end.
func (w *Writer) WriteText(s string) {
	if s == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.textOpen {
		w.textID = "msg_" + randomID(8)
		w.writeChunkLocked(map[string]any{
			"type": "text-start",
			"id":   w.textID,
		})
		w.textOpen = true
	}
	w.writeChunkLocked(map[string]any{
		"type":  "text-delta",
		"id":    w.textID,
		"delta": s,
	})
}

// FinishText emits the matching text-end for any open text part.
// Idempotent. Called automatically by Close, but the engine calls
// it explicitly between assistant turns and tool dispatches so the
// UI can render distinct message segments rather than one giant
// streaming blob.
func (w *Writer) FinishText() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.finishTextLocked()
}

func (w *Writer) finishTextLocked() {
	if !w.textOpen {
		return
	}
	w.writeChunkLocked(map[string]any{
		"type": "text-end",
		"id":   w.textID,
	})
	w.textOpen = false
	w.textID = ""
}

// WriteToolCall emits the tool-input-start + tool-input-available
// pair. The two-step shape is the SDK's protocol (the start exists
// for streaming arg deltas, which we don't bother with — we always
// have the complete input in hand).
//
// providerExecuted controls whether the SDK fires `onToolCall` on
// the client when the tool-input-available chunk arrives:
//
//	false — we're announcing a CLIENT-SIDE tool. The SPA is expected
//	        to execute it via its hooks bag and post the result back
//	        via addToolResult. onToolCall MUST fire.
//	true  — we're announcing a SERVER-SIDE tool. We're just informing
//	        the UI so it can render a "calling X..." indicator;
//	        execution is happening server-side and the result chunk
//	        follows shortly. onToolCall MUST NOT fire — if it did, the
//	        SPA's handler would see an unknown-tool name and reply
//	        with an error result that races the actual server result.
//
// The SDK's tool-input-available handler skips onToolCall when
// providerExecuted is truthy (see ai/dist/index.mjs ~5669:
// `if (onToolCall && !chunk.providerExecuted)`).
func (w *Writer) WriteToolCall(toolCallID, toolName string, args json.RawMessage, providerExecuted bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.finishTextLocked()
	startChunk := map[string]any{
		"type":       "tool-input-start",
		"toolCallId": toolCallID,
		"toolName":   toolName,
	}
	availChunk := map[string]any{
		"type":       "tool-input-available",
		"toolCallId": toolCallID,
		"toolName":   toolName,
		"input":      jsonRaw(args),
	}
	if providerExecuted {
		startChunk["providerExecuted"] = true
		availChunk["providerExecuted"] = true
	}
	w.writeChunkLocked(startChunk)
	w.writeChunkLocked(availChunk)
}

// WriteToolResult emits the result of a server-executed tool. The
// SDK keeps it in the message history; the assistant references it
// on the next turn.
//
// toolName is accepted but currently unused on the wire — the SDK
// correlates results to calls via toolCallId. Kept on the
// signature so the call sites read symmetrically with WriteToolCall
// / WriteToolError, and so a future SDK that wants the name on the
// result chunk can be wired in without churning every caller.
func (w *Writer) WriteToolResult(toolCallID, _ /*toolName*/, result string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.finishTextLocked()
	w.writeChunkLocked(map[string]any{
		"type":       "tool-output-available",
		"toolCallId": toolCallID,
		"output":     jsonStringOrRaw(result),
	})
}

// WriteToolError emits a tool-output-error so the SDK can render
// the failure inline and the LLM gets is_error=true on the next
// turn. toolName unused on the wire; see WriteToolResult.
func (w *Writer) WriteToolError(toolCallID, _ /*toolName*/, msg string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.finishTextLocked()
	w.writeChunkLocked(map[string]any{
		"type":       "tool-output-error",
		"toolCallId": toolCallID,
		"errorText":  msg,
	})
}

// WriteConfirmationRequest emits a tool-input-available followed by
// a tool-approval-request. The SDK's `addToolApprovalResponse`
// helper on the React side completes the round-trip — when the user
// clicks Approve, the SPA POSTs back with the approval response,
// and the engine's next call sees the tool-use ID in
// PreApprovedToolUseIDs.
//
// The approvalId we send here is the same as the toolCallId so the
// frontend can correlate without an extra map.
func (w *Writer) WriteConfirmationRequest(toolCallID, toolName string, args json.RawMessage) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.finishTextLocked()
	// providerExecuted=true on the input chunks for two reasons:
	//   1. The tool will be executed server-side (after user approval),
	//      not in the browser. Without this flag the SDK fires
	//      onToolCall on the client when tool-input-available lands;
	//      our handler has no entry for the destructive tool and
	//      replies with an "unknown client-side tool" error that
	//      races the actual server result.
	//   2. The auto-resubmit predicate (lastAssistantMessageIsComplete-
	//      WithToolCalls) filters OUT providerExecuted parts, so a
	//      pending approval-requested destructive tool doesn't gate
	//      the predicate. Other client-side tools in the same turn
	//      (e.g. set_filter) can still drive auto-resubmit when ready.
	w.writeChunkLocked(map[string]any{
		"type":             "tool-input-start",
		"toolCallId":       toolCallID,
		"toolName":         toolName,
		"providerExecuted": true,
	})
	w.writeChunkLocked(map[string]any{
		"type":             "tool-input-available",
		"toolCallId":       toolCallID,
		"toolName":         toolName,
		"input":            jsonRaw(args),
		"providerExecuted": true,
	})
	w.writeChunkLocked(map[string]any{
		"type":       "tool-approval-request",
		"approvalId": toolCallID,
		"toolCallId": toolCallID,
	})
}

// WriteError emits a terminal error chunk. Caller should return
// after this — the stream is over.
func (w *Writer) WriteError(msg string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.finishTextLocked()
	w.writeChunkLocked(map[string]any{
		"type":      "error",
		"errorText": msg,
	})
}

// WriteFinish balances any open text part. Optional but well-
// behaved; the SDK uses message boundaries to drop the typing
// indicator.
//
// stopReason is preserved for log breadcrumbs in protocol.go's
// signature but no longer threaded into the wire format — the SDK
// no longer carries a finish-reason chunk.
func (w *Writer) WriteFinish(_ string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.finishTextLocked()
}

// Close flushes any buffered output and closes any open text part.
// Defer this from the handler — engine doesn't own the writer.
func (w *Writer) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.finishTextLocked()
	_ = w.w.Flush()
}

// writeChunkLocked is the single internal serializer. Caller must
// hold w.mu.
func (w *Writer) writeChunkLocked(chunk map[string]any) {
	encoded, err := json.Marshal(chunk)
	if err != nil {
		// Encoding can really only fail on a malformed value we
		// passed in; emit a fixed error frame and move on.
		_, _ = io.WriteString(w.w, "data: {\"type\":\"error\",\"errorText\":\"internal: failed to encode chat record\"}\n\n")
		_ = w.w.Flush()
		_ = w.rc.Flush()
		return
	}
	_, _ = io.WriteString(w.w, "data: ")
	_, _ = w.w.Write(encoded)
	_, _ = io.WriteString(w.w, "\n\n")
	_ = w.w.Flush()
	_ = w.rc.Flush()
}

// jsonRaw normalizes a possibly-empty json.RawMessage so the SDK
// never sees a literal empty value where it expects an object.
func jsonRaw(r json.RawMessage) any {
	if len(r) == 0 {
		return map[string]any{}
	}
	return r
}

// jsonStringOrRaw returns the result either as a parsed JSON value
// (when the tool returned valid JSON) or wrapped in a string
// envelope. The SDK accepts both shapes; the parsed form is more
// useful in the assistant turn because the model can inspect it
// structurally.
func jsonStringOrRaw(s string) any {
	if s == "" {
		return map[string]any{}
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err == nil {
		return v
	}
	return map[string]string{"result": s}
}

// randomID returns 2*n hex chars of cryptographic randomness, used
// to tag text parts so the SDK can group deltas correctly. We don't
// rely on it for security — purely an SDK ergonomic.
func randomID(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is essentially impossible; fall back
		// to a stable string rather than crash the chat turn.
		return fmt.Sprintf("fallback%x", n)
	}
	return hex.EncodeToString(buf)
}
