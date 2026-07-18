package mcpserver

import (
	"context"
	"fmt"
	"strings"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// scopeToOwner wraps an LLM-supplied ClassAd constraint with an owner
// filter so a tool call against the schedd can never operate on
// another user's jobs. Mirrors the wrapper used by the chat-side
// LLM tools at httpserver/handlers_chat_tools.go:scopeToOwner.
//
// Returns (constraint, ok) where ok==false means the caller is
// unauthenticated (no `actor` on context). Tool handlers should
// refuse the request in that case rather than fall back to "no
// filter" — the server enforces "must be authenticated" at the
// transport layer, but defense-in-depth here means a future
// transport bug doesn't accidentally let an unauthenticated request
// through.
//
// Admin callers (caller's authenticated user is in Server.adminUsers)
// get the constraint as-is. The audit recommendation was that
// admins skip this wrapper so they can do cross-user troubleshooting
// (e.g. "find every held job", "remove all jobs in the stale
// queue"); normal users always get owner-scoped.
func (s *Server) scopeToOwner(ctx context.Context, llmConstraint string) (string, bool) {
	actor := htcondor.GetAuthenticatedUserFromContext(ctx)
	if actor == "" {
		return "", false
	}
	if s.isAdmin(actor) {
		return strings.TrimSpace(llmConstraint), true
	}
	owner := fmt.Sprintf("Owner == %s", classadStringLit(actor))
	c := strings.TrimSpace(llmConstraint)
	if c == "" {
		return owner, true
	}
	return fmt.Sprintf("(%s) && (%s)", owner, c), true
}

// isAdmin reports whether the given authenticated username is in the
// configured admin list. Match is exact against
// htcondor.GetAuthenticatedUserFromContext (typically
// "user@uid.domain"). Returns false when adminUsers is unset.
func (s *Server) isAdmin(authenticatedUser string) bool {
	if s == nil || len(s.adminUsers) == 0 {
		return false
	}
	_, ok := s.adminUsers[authenticatedUser]
	return ok
}

// classadStringLit quotes a string as a ClassAd string literal,
// escaping internal double quotes and backslashes. Same shape as the
// chat-side helper; duplicated here to keep mcpserver free of the
// httpserver package import (which would create a cycle).
func classadStringLit(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
