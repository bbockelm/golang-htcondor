package mcpserver

import (
	"context"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// ToolStatsRecorder is told about every tool call.
//
// An interface rather than a concrete dependency so this package does
// not import the storage layer: mcpserver is also embedded by the stdio
// server, which has no database, no /metrics endpoint and no reason to
// carry either.
//
// Implementations must be safe for concurrent use and must not block --
// this is called on the request path, after the tool has returned but
// before its result reaches the caller.
type ToolStatsRecorder interface {
	Record(tool, user, client, outcome string, d time.Duration)
}

// recordToolCall reports one finished tool call.
//
// Resolving the client here rather than at the transport keeps the
// fallback order in one place:
//
//  1. what this session declared at initialize (MCP's own answer),
//  2. what the transport could see about the request (the User-Agent),
//  3. nothing, recorded as unknown.
//
// Step 2 is not a poor relation: a restarted server has forgotten every
// registration while its clients keep using their session ids, some
// clients send no clientInfo, and the SDK transport answers initialize
// itself so nothing is ever remembered there. All ordinary, none of
// them a reason to lose the call.
//
// The stdio server records nothing at all -- it is built with no
// recorder, having no database to persist to and no /metrics to serve
// -- so neither step runs there.
func (s *Server) recordToolCall(ctx context.Context, tool, outcome string, d time.Duration) {
	if s.stats == nil || tool == "" {
		return
	}
	client := s.clients.Lookup(SessionIDFromContext(ctx))
	if client == "" {
		client = ClientInfoFromContext(ctx)
	}
	s.stats.Record(tool, htcondor.GetAuthenticatedUserFromContext(ctx), client, outcome, d)
}

// The outcome strings, duplicated from the toolstats package rather
// than imported: see the ToolStatsRecorder comment on why this package
// does not depend on it. They are a wire contract between the two and
// are pinned by a test that fails if either side renames one.
const (
	toolstatsOutcomeOK      = "ok"
	toolstatsOutcomeError   = "error"
	toolstatsOutcomeRefused = "refused"
	// toolstatsOutcomeUnknownTool is a call naming a tool this server
	// does not have.
	toolstatsOutcomeUnknownTool = "unknown_tool"
)
