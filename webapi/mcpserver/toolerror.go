package mcpserver

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

// Tool failures and how they reach the caller.
//
// MCP draws a line the first version of this server did not. A JSON-RPC
// error means "the request itself was malformed" -- unparseable params,
// a tool that does not exist. A tool that ran and failed is a normal
// result carrying isError, with the reason in its content.
//
// The distinction matters because clients treat them differently: a
// JSON-RPC error is a protocol fault, so a client reports it as an
// opaque failure and the model never sees the text. Returning "job
// submission failed: <what the schedd said>" as a protocol error
// therefore threw the diagnosis away and showed the user "Error
// occurred during tool execution" instead.

// protocolError marks an error as a fault in the request rather than in
// the work the tool tried to do. Only these become JSON-RPC errors.
type protocolError struct{ err error }

func (e *protocolError) Error() string { return e.err.Error() }
func (e *protocolError) Unwrap() error { return e.err }

// protocolErrorf builds an error the dispatcher will report as JSON-RPC.
func protocolErrorf(format string, args ...interface{}) error {
	return &protocolError{err: fmt.Errorf(format, args...)}
}

// isProtocolError reports whether err is a malformed request rather than
// a tool that ran and failed.
func isProtocolError(err error) bool {
	var pe *protocolError
	return errors.As(err, &pe)
}

// traceIDKey carries the per-call trace id so a tool deep in the stack
// can put it on its own log lines.
type traceIDKey struct{}

// sessionIDKey carries the client's MCP session id, set by the HTTP
// transport. Empty over stdio, which has no session concept.
type sessionIDKey struct{}

// WithSessionID records the client's MCP session id on the context so
// tool-call logs can be correlated across requests from one client.
func WithSessionID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, sessionIDKey{}, id)
}

// SessionIDFromContext returns the MCP session id, or "" if unset.
func SessionIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(sessionIDKey{}).(string)
	return id
}

func withTraceID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, traceIDKey{}, id)
}

// TraceIDFromContext returns the current tool call's trace id, or "" if
// there is none.
func TraceIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(traceIDKey{}).(string)
	return id
}

// newTraceID mints the identifier that ties a log line to what the user
// was shown. It is deliberately short: someone reads it off a chat
// transcript and types it into a grep.
//
// A failure to read the CSPRNG is not worth failing the call over -- the
// trace id is an aid, not a credential -- so it degrades to a fixed
// marker that is still greppable and is obviously not unique.
func newTraceID() string {
	b := make([]byte, 5)
	if _, err := cryptorand.Read(b); err != nil {
		return "mcp-norand"
	}
	return "mcp-" + hex.EncodeToString(b)
}

// toolErrorResult renders a tool failure the way MCP expects: a normal
// result whose content explains what went wrong, flagged with isError so
// the client knows the tool did not succeed.
//
// The trace id is repeated in the text because this string is the only
// part of the exchange a user can see. Without it, "it failed" in a chat
// window cannot be tied to anything in the server log.
func toolErrorResult(tool, traceID string, err error) map[string]interface{} {
	text := fmt.Sprintf("Tool %q failed: %v", tool, err)
	if traceID != "" {
		text += fmt.Sprintf("\n\n(server trace id: %s -- an administrator can find this in the API server log)", traceID)
	}
	return map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": text},
		},
		"isError": true,
	}
}
