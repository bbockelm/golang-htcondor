package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/PelicanPlatform/classad/classad"

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
	owner := fmt.Sprintf("Owner == %s", classadStringLit(ownerFromActor(actor)))
	c := strings.TrimSpace(llmConstraint)
	if c == "" {
		return owner, true
	}
	// Combine safely. Splicing the raw untrusted constraint into "(owner) && (c)"
	// does NOT confine it: a crafted c escapes the AND via '||' precedence and
	// unbalanced parentheses (e.g. c = `true) || (true` yields
	// `(owner) && (true) || (true)`, which parses as `... || true` = every job).
	// Re-serialize c through the ClassAd parser: the round-tripped form is always
	// balanced, so the enclosing parens confine it. An input that will not parse
	// is dropped (owner-only) rather than trusted -- fail closed.
	safe, err := classadBalanced(c)
	if err != nil {
		return owner, true
	}
	return fmt.Sprintf("(%s) && (%s)", owner, safe), true
}

// classadBalanced parses an untrusted ClassAd boolean expression and returns its
// re-serialized (fully parenthesized, balanced) form, so it can be safely spliced
// as one operand of a larger expression. It errors on anything that does not
// parse as a single complete expression -- which is exactly how an owner-scope
// bypass attempt (unbalanced parens to escape an enclosing &&) is rejected.
func classadBalanced(constraint string) (string, error) {
	expr, err := classad.ParseExpr(constraint)
	if err != nil {
		return "", err
	}
	return expr.String(), nil
}

// ownerFromActor maps an authenticated actor to the value HTCondor
// stores in a job's Owner attribute: the bare username. An actor is
// often fully qualified — "alice@uid.domain" is what the schedd maps a
// CEDAR peer to, and what an IDTOKEN's `sub` looks like — while Owner
// never is, so comparing the two verbatim would match no jobs at all.
// Admin matching deliberately keeps the qualified form (see isAdmin):
// it is an identity check, not a job-ownership one.
func ownerFromActor(actor string) string {
	name, _, found := strings.Cut(actor, "@")
	if !found {
		return actor
	}
	return name
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
