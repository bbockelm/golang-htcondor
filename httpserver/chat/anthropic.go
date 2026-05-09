// Package chat provides the LLM-backed chat endpoint that powers the
// "Ask about your jobs" surface in the SPA. It is deliberately small:
// one HTTP endpoint, one LLM provider (Anthropic), a tool registry
// scoped to the authenticated user, and a streaming protocol that
// matches what Vercel's AI SDK `useChat()` hook expects on the wire.
//
// The package is shaped around a single Engine value the HTTP handler
// constructs once and reuses for every request.  Engine.Stream takes
// a fully-formed Request (incoming messages + per-tool-call results
// the frontend has already settled) and returns an event stream of
// AI-SDK protocol parts that the handler relays to the browser
// verbatim. The Engine never reads the *http.Request directly — the
// handler does that and converts to a chat.Request, so this package
// stays independent of the HTTP server's session machinery.
package chat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// AnthropicAPIVersion pins the Anthropic Messages API version we
// negotiate. Anthropic dates major changes; bumping this is an
// explicit operator decision.
const AnthropicAPIVersion = "2023-06-01"

// DefaultAnthropicURL is the upstream endpoint when the operator
// hasn't pointed HTTP_API_LLM_API_URL at a proxy.
const DefaultAnthropicURL = "https://api.anthropic.com/v1/messages"

// DefaultAnthropicModel is the model used when the chat request
// doesn't override it. Sonnet is the standard "good enough at
// reasoning, cheap enough at scale" middle.
const DefaultAnthropicModel = "claude-sonnet-4-5"

// MaxTokens caps how much the LLM can emit per turn. Tool-heavy
// flows can take a few thousand tokens of reasoning + tool args; 4096
// is comfortable headroom while still bounding worst-case spend.
const MaxTokens = 4096

// AnthropicClient is the minimal HTTP wrapper around Anthropic's
// Messages API. We hand-roll instead of importing a Go SDK because
// the surface we use is small (one endpoint, streaming) and a fresh
// dep adds non-trivial code to vet.
type AnthropicClient struct {
	apiKey string // "Bearer-equivalent" — sent as x-api-key
	url    string // Operator-overridable; defaults to DefaultAnthropicURL
	model  string // Default model when Request.Model is empty
	httpDo func(*http.Request) (*http.Response, error)
}

// AnthropicConfig configures the client. APIKeyFile is the on-disk
// path to a file holding the API key — the bytes are never expected
// to live in HTCondor config (which is publicly readable on the host).
// Empty APIKey + empty APIKeyFile = chat disabled.
type AnthropicConfig struct {
	// APIKeyFile is the path the chat handler reads on every server
	// start to load the Anthropic API key. Mode 0600/0400 enforced.
	APIKeyFile string

	// URL overrides the upstream endpoint. Use for self-hosted proxies
	// (e.g. an LLM gateway with audit logging or a cache). Empty = use
	// DefaultAnthropicURL.
	URL string

	// Model overrides the default Anthropic model identifier. Empty =
	// DefaultAnthropicModel.
	Model string

	// HTTPClient is the http.Client to dispatch with. nil = a stock
	// client with a 60-second per-request timeout.
	HTTPClient *http.Client
}

// NewAnthropicClient loads the API key from disk and returns a ready
// client. Returns nil, nil when no key is configured — that's the
// "chat disabled" path; callers must check.
//
// Refuses to read the key file with mode bits set for group or other
// (`stat --printf=%a key` should be `600` or `400`). Same security
// posture as seal.LoadMasterKEKFromFile.
func NewAnthropicClient(cfg AnthropicConfig) (*AnthropicClient, error) {
	if strings.TrimSpace(cfg.APIKeyFile) == "" {
		return nil, nil
	}
	info, err := os.Stat(cfg.APIKeyFile)
	if err != nil {
		return nil, fmt.Errorf("chat: stat api key file %s: %w", cfg.APIKeyFile, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("chat: api key file %s is a directory", cfg.APIKeyFile)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("chat: api key file %s has world/group perms (mode %#o); must be 0600 or 0400", cfg.APIKeyFile, perm)
	}
	raw, err := os.ReadFile(cfg.APIKeyFile) //nolint:gosec // path is operator-controlled
	if err != nil {
		return nil, fmt.Errorf("chat: read api key file: %w", err)
	}
	apiKey := strings.TrimRight(string(raw), "\r\n\t ")
	if apiKey == "" {
		return nil, fmt.Errorf("chat: api key file %s is empty", cfg.APIKeyFile)
	}

	endpoint := cfg.URL
	if endpoint == "" {
		endpoint = DefaultAnthropicURL
	}
	// Sanity-check the URL early so a typo blows up at startup, not
	// on the first chat request.
	if _, err := url.Parse(endpoint); err != nil {
		return nil, fmt.Errorf("chat: invalid LLM URL %q: %w", endpoint, err)
	}

	model := cfg.Model
	if model == "" {
		model = DefaultAnthropicModel
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 120 * time.Second}
	}
	return &AnthropicClient{
		apiKey: apiKey,
		url:    endpoint,
		model:  model,
		httpDo: httpClient.Do,
	}, nil
}

// Model returns the default model id this client was configured with.
// Useful in handler logs.
func (c *AnthropicClient) Model() string { return c.model }

// URL returns the configured endpoint URL (after defaults applied).
// Useful in handler logs to confirm which upstream is in use.
func (c *AnthropicClient) URL() string { return c.url }

// anthropicMessageRequest is the on-wire shape we POST.
type anthropicMessageRequest struct {
	Model     string             `json:"model"`
	System    string             `json:"system,omitempty"`
	Messages  []AnthropicMessage `json:"messages"`
	MaxTokens int                `json:"max_tokens"`
	Stream    bool               `json:"stream"`
	Tools     []AnthropicTool    `json:"tools,omitempty"`
}

// AnthropicMessage is one turn in the conversation. Content is
// polymorphic — for text-only turns it's a single TextBlock; turns
// that carry tool results from the previous round include
// ToolResultBlock entries; assistant turns can carry ToolUseBlock.
//
// We expose the typed shape rather than json.RawMessage so the
// engine can construct messages without per-call JSON gymnastics.
type AnthropicMessage struct {
	Role    string                  `json:"role"` // "user" or "assistant"
	Content []AnthropicContentBlock `json:"content"`
}

// AnthropicContentBlock is one element inside a message's content
// array. Type discriminates the union:
//   - "text"        → Text is set
//   - "tool_use"    → ID, Name, Input set (assistant proposes a tool call)
//   - "tool_result" → ToolUseID, Content (string) set (user replies with the result)
type AnthropicContentBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   string          `json:"content,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
}

// AnthropicTool is the tool schema we hand the model. InputSchema is
// a JSON Schema describing the tool's arguments — we let callers
// build it once per tool registry construction.
type AnthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// StreamEvent is one parsed Anthropic SSE event the engine emits to
// its caller. We surface a small fixed set of types (the others —
// "ping", "message_start", etc. — are absorbed internally) so the
// engine code stays linear.
type StreamEvent struct {
	// Kind discriminates the event:
	//   "text_delta"    — incremental text from the assistant
	//   "tool_use"      — a complete tool_use block (gathered from input_json_delta deltas)
	//   "message_stop"  — assistant turn finished; StopReason is set
	//   "error"         — terminal error; Err is set
	Kind       string
	Text       string          // "text_delta"
	ToolUseID  string          // "tool_use"
	ToolName   string          // "tool_use"
	ToolInput  json.RawMessage // "tool_use"
	StopReason string          // "message_stop": "end_turn", "tool_use", "max_tokens"
	Err        error           // "error"
}

// Stream POSTs the conversation to Anthropic with stream=true, parses
// the SSE event stream, and emits a flattened sequence of StreamEvent
// values on the returned channel. The channel is closed when the
// upstream connection closes; consumers typically iterate with `for ev
// := range ch`.
//
// Cancel by canceling the supplied context — the underlying HTTP
// request is cancelable and the read loop honors ctx.Done.
//
// Error handling: terminal errors (HTTP error from Anthropic, parse
// failure, network drop) are emitted as a final {Kind:"error"} event
// before the channel closes, never returned out-of-band. Callers
// don't need a separate err-check codepath.
func (c *AnthropicClient) Stream(ctx context.Context, system string, msgs []AnthropicMessage, tools []AnthropicTool, model string) <-chan StreamEvent {
	out := make(chan StreamEvent, 8)
	if model == "" {
		model = c.model
	}

	go func() {
		defer close(out)

		body, err := json.Marshal(anthropicMessageRequest{
			Model:     model,
			System:    system,
			Messages:  msgs,
			MaxTokens: MaxTokens,
			Stream:    true,
			Tools:     tools,
		})
		if err != nil {
			out <- StreamEvent{Kind: "error", Err: fmt.Errorf("encode request: %w", err)}
			return
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
		if err != nil {
			out <- StreamEvent{Kind: "error", Err: fmt.Errorf("build request: %w", err)}
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", c.apiKey)
		req.Header.Set("anthropic-version", AnthropicAPIVersion)
		req.Header.Set("Accept", "text/event-stream")

		resp, err := c.httpDo(req)
		if err != nil {
			out <- StreamEvent{Kind: "error", Err: fmt.Errorf("dispatch: %w", err)}
			return
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			// Read up to 4 KiB of the body for the error message —
			// Anthropic's error JSON is small and human-readable.
			detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			out <- StreamEvent{Kind: "error", Err: fmt.Errorf("anthropic %s: %s", resp.Status, strings.TrimSpace(string(detail)))}
			return
		}

		// Walk the SSE stream. Each event is one or more "field: value"
		// lines terminated by a blank line; we care about the data:
		// field, which holds a JSON object describing the event.
		readSSE(ctx, resp.Body, out)
	}()

	return out
}

// readSSE is the inner SSE reader. Pulled out for testability and to
// keep Stream's goroutine readable. Anthropic emits one JSON object
// per `data:` line; events come in a documented sequence per turn:
//
//	message_start → content_block_start (text or tool_use) → content_block_delta* → content_block_stop
//	  → … repeat per content block …
//	→ message_delta (carries stop_reason) → message_stop
//
// We compress that into the four StreamEvent kinds the engine cares
// about. tool_use blocks accumulate their input over a series of
// input_json_delta events and emit a single StreamEvent on
// content_block_stop.
func readSSE(ctx context.Context, body io.Reader, out chan<- StreamEvent) {
	reader := bufio.NewReader(body)

	// Per-block state. Anthropic gives each block an index; we only
	// ever have one in-flight at a time within a message, so a
	// scalar map indexed by id is overkill — we just track the
	// current open block.
	var (
		curKind     string // "text" or "tool_use"
		curToolID   string
		curToolName string
		curToolBuf  bytes.Buffer
		stopReason  string
	)

	for {
		select {
		case <-ctx.Done():
			out <- StreamEvent{Kind: "error", Err: ctx.Err()}
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if errors.Is(err, io.EOF) {
			out <- StreamEvent{Kind: "message_stop", StopReason: stopReason}
			return
		}
		if err != nil {
			out <- StreamEvent{Kind: "error", Err: fmt.Errorf("read sse: %w", err)}
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" || !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}

		var evt sseEvent
		if err := json.Unmarshal([]byte(payload), &evt); err != nil {
			out <- StreamEvent{Kind: "error", Err: fmt.Errorf("parse sse data: %w", err)}
			return
		}

		switch evt.Type {
		case "content_block_start":
			curKind = evt.ContentBlock.Type
			curToolID = evt.ContentBlock.ID
			curToolName = evt.ContentBlock.Name
			curToolBuf.Reset()
		case "content_block_delta":
			switch evt.Delta.Type {
			case "text_delta":
				if evt.Delta.Text != "" {
					out <- StreamEvent{Kind: "text_delta", Text: evt.Delta.Text}
				}
			case "input_json_delta":
				curToolBuf.WriteString(evt.Delta.PartialJSON)
			}
		case "content_block_stop":
			if curKind == "tool_use" {
				// COPY the buffered input bytes — bytes.Buffer.Bytes()
				// aliases the buffer's backing array, and we're about
				// to Reset() the buffer (and the next content_block
				// will write fresh deltas into the same memory). The
				// channel is buffered, so by the time the engine
				// consumes this event the slice would otherwise have
				// been overwritten with the *next* tool's input —
				// json.Marshal then fails with "internal: failed to
				// encode chat record" because the bytes are mangled.
				input := json.RawMessage(append([]byte(nil), curToolBuf.Bytes()...))
				if len(input) == 0 {
					input = json.RawMessage("{}")
				}
				out <- StreamEvent{
					Kind:      "tool_use",
					ToolUseID: curToolID,
					ToolName:  curToolName,
					ToolInput: input,
				}
			}
			curKind = ""
			curToolID = ""
			curToolName = ""
			curToolBuf.Reset()
		case "message_delta":
			if evt.Delta.StopReason != "" {
				stopReason = evt.Delta.StopReason
			}
		case "message_stop":
			out <- StreamEvent{Kind: "message_stop", StopReason: stopReason}
			return
		case "error":
			msg := "anthropic stream error"
			if evt.Error.Message != "" {
				msg = evt.Error.Message
			}
			out <- StreamEvent{Kind: "error", Err: fmt.Errorf("%s: %s", evt.Error.Type, msg)}
			return
		}
	}
}

// sseEvent is the parsed shape of a single Anthropic SSE event. We
// keep it loose — fields not present on every event type are tagged
// omitempty in the wire format.
type sseEvent struct {
	Type         string `json:"type"`
	ContentBlock struct {
		Type string `json:"type"`
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"content_block"`
	Delta struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		PartialJSON string `json:"partial_json"`
		StopReason  string `json:"stop_reason"`
	} `json:"delta"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}
