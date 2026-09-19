package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Serving the tools over the upstream MCP SDK instead of the hand-rolled
// JSON-RPC dispatcher and HTTP transport.
//
// What is worth keeping here is the tools: their schemas, the owner-scope
// wrapper, the error taxonomy and the HTCondor knowledge in them. What is not
// worth keeping is a protocol implementation that has to track a spec someone
// else already tracks -- the built-in one still answers "2024-11-05".
//
// No tool is rewritten. Tool.InputSchema is `any` in the SDK, so the
// hand-written JSON Schema maps register verbatim, and AddTool's low-level
// form hands back raw arguments, which is what handleCallTool already takes.
// The SDK owns the wire and nothing else.

// sdkImplementation is how this server identifies itself over the SDK
// transport. Unchanged from the built-in one so a client cannot tell which
// transport answered by the name.
var sdkImplementation = &mcp.Implementation{Name: "htcondor-mcp", Version: "0.1.0"}

// sdkServerFor builds a server whose catalogue is what these scopes may see.
//
// Registering the filtered catalogue rather than everything is what makes the
// catalogue and the call gate the same fact: a tool this caller may not see is
// not registered, so the SDK answers "unknown tool" rather than the server
// consulting a second allowlist that can disagree with the first.
func (s *Server) sdkServerFor(scopes []string) *mcp.Server {
	instructions := ""
	if v := s.instructions.Load(); v != nil {
		instructions = *v
	}
	srv := mcp.NewServer(sdkImplementation, &mcp.ServerOptions{Instructions: instructions})
	for _, t := range s.toolsFor(WithGrantedScopes(context.Background(), scopes)) {
		srv.AddTool(
			&mcp.Tool{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema},
			s.sdkToolHandler(t.Name),
		)
	}
	return srv
}

// sdkToolHandler adapts one tool to the SDK's raw handler signature.
func (s *Server) sdkToolHandler(name string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ctx, stop := withClientGoneCancel(ctx)
		defer stop()

		args := req.Params.Arguments
		if len(args) == 0 {
			args = json.RawMessage(`{}`)
		}
		params, err := json.Marshal(struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}{Name: name, Arguments: args})
		if err != nil {
			return nil, err
		}

		// The error taxonomy has to come along, and it is the part of this
		// adapter most easily got wrong: a tool that ran and failed must come
		// back as a RESULT carrying isError, not as a JSON-RPC error. A
		// client surfaces a protocol error as an opaque failure, so the model
		// never sees the diagnosis -- exactly when it needs it. Returning err
		// for everything, which is the obvious adapter, silently degrades
		// every tool failure into "something went wrong".
		//
		// The trace id is minted here rather than inside handleCallTool so
		// the error result and the log line carry the same value.
		traceID := newTraceID()
		ctx = withTraceID(ctx, traceID)

		result, err := s.handleCallTool(ctx, params)
		switch {
		case err == nil:
			return toSDKResult(result)
		case isProtocolError(err):
			// Malformed request: no tool ran, so there is no tool result.
			return nil, err
		default:
			return toSDKResult(toolErrorResult(name, traceID, err))
		}
	}
}

// toSDKResult converts a handler's result into the SDK's typed result. The
// handlers already emit MCP content blocks, so this is a re-marshal rather
// than a translation.
func toSDKResult(result interface{}) (*mcp.CallToolResult, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshalling the tool result: %w", err)
	}
	var out mcp.CallToolResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("converting the tool result: %w", err)
	}
	return &out, nil
}

// --- the client going away -------------------------------------------------

// The SDK detaches a tool's context from the HTTP request's, so a client that
// vanishes -- crashed, network gone, user closed the tab -- no longer cancels
// the work it asked for. Measured: the built-in transport cancels in about
// 0.1s; under the SDK's stateless transport the tool runs to completion.
//
// notifications/cancelled covers a client that is still there and changes its
// mind, but not one that cannot speak, and stateless mode has no server->client
// channel at all. Left alone this holds real resources: an abandoned
// exec_in_job keeps an interactive slot for its whole timeout.
//
// Context VALUES do survive the detachment even though cancellation does not,
// so the request's own Done channel is carried across as a value and rebound
// to a cancel here. sdkHTTPMiddleware is the half that puts it there.

type clientGoneKey struct{}

// withClientGone records the HTTP request's cancellation for the tool handler.
func withClientGone(ctx context.Context, gone <-chan struct{}) context.Context {
	return context.WithValue(ctx, clientGoneKey{}, gone)
}

// withClientGoneCancel returns a context cancelled when the client goes away,
// restoring what the built-in transport gets from the request context.
//
// With no channel recorded -- a direct call, or a test constructing the server
// itself -- this is the identity, so a tool is never cancelled by the absence
// of the signal.
func withClientGoneCancel(ctx context.Context) (context.Context, context.CancelFunc) {
	gone, _ := ctx.Value(clientGoneKey{}).(<-chan struct{})
	if gone == nil {
		return ctx, func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-gone:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// sdkHTTPMiddleware carries the request's cancellation into the tool handlers.
func sdkHTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(withClientGone(r.Context(), r.Context().Done())))
	})
}
