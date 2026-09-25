package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// OwnerScope is what a tool call was confined to, so a handler can both
// apply it and say what it applied.
//
// Saying so matters as much as doing it. The caller is a language model,
// and a listing that silently covers every user reads exactly like one
// that covers its own -- which is how a session ends up being told there
// are ten thousand held jobs by one tool and none by another, with
// nothing in either answer to explain the difference.
type OwnerScope struct {
	// Owner is the identity the call was confined to, empty for an
	// unconfined admin call.
	Owner string
	// AllUsers is true when the call covers every user's jobs.
	AllUsers bool
}

// Note renders the scope for the caller. Every read tool appends it, so
// the answer always carries the question it actually answered.
func (o OwnerScope) Note() string {
	if o.AllUsers {
		return "[scope: ALL users' jobs -- you are an MCP admin, so this is not limited to your own]"
	}
	return fmt.Sprintf("[scope: only jobs owned by %q]", o.Owner)
}

// ownerScope resolves who a call is for and whether it is confined.
// ok==false means the caller could not be identified.
func (s *Server) ownerScope(ctx context.Context, tier privTier) (OwnerScope, bool) {
	actor := htcondor.GetAuthenticatedUserFromContext(ctx)
	if actor == "" {
		return OwnerScope{}, false
	}
	if s.allowsAllUsers(ctx, actor, tier) {
		return OwnerScope{AllUsers: true}, true
	}
	return OwnerScope{Owner: ownerFromActor(actor)}, true
}

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
func (s *Server) scopeToOwner(ctx context.Context, llmConstraint string, tier privTier) (string, bool) {
	actor := htcondor.GetAuthenticatedUserFromContext(ctx)
	if actor == "" {
		return "", false
	}
	if s.allowsAllUsers(ctx, actor, tier) {
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

// selfScopedQueryOptions returns the query options that confine a schedd
// query to the caller's own jobs, and false when there is no
// authenticated caller to confine it to.
//
// The primary confinement is the schedd's: FetchMyJobs sends
// QUERY_JOB_ADS_WITH_AUTH, so the schedd filters on the identity it
// authenticated rather than on any owner name we supply. Callers pair it
// with scopeToOwner's constraint, which confines the same query
// client-side. Two mechanisms for one rule is deliberate — this one was
// silently doing nothing until ApplyDefaults stopped dropping FetchOpts,
// and a confinement that can degrade to "no filter" without a symptom
// wants a second one behind it that fails closed instead.
//
// Admins are exempt, as with scopeToOwner: no self-scoping, so
// cross-user troubleshooting still works.
func (s *Server) selfScopedQueryOptions(ctx context.Context, base *htcondor.QueryOptions) (*htcondor.QueryOptions, bool) {
	actor := htcondor.GetAuthenticatedUserFromContext(ctx)
	if actor == "" {
		return nil, false
	}

	opts := &htcondor.QueryOptions{}
	if base != nil {
		copied := *base
		opts = &copied
	}
	if s.allowsAllUsers(ctx, actor, tierRead) {
		return opts, true
	}
	opts.FetchOpts |= htcondor.FetchMyJobs
	opts.Owner = ownerFromActor(actor)
	return opts, true
}

// ownerFromActor maps an authenticated actor to the value HTCondor
// stores in a job's Owner attribute: the bare username. An actor is
// often fully qualified — "alice@uid.domain" is what the schedd maps a
// CEDAR peer to, and what an IDTOKEN's `sub` looks like — while Owner
// never is, so comparing the two verbatim would match no jobs at all.
//
// The split is at the LAST "@", because "@" is legal in a Linux
// username and SSSD hands out names that contain one:
// "foo@bar@uid.domain" is the user "foo@bar" in the domain
// "uid.domain". Splitting at the first "@" would scope that user's
// queries to the non-existent owner "foo".
//
// Admin matching deliberately keeps the qualified form (see isAdmin):
// it is an identity check, not a job-ownership one.
func ownerFromActor(actor string) string {
	i := strings.LastIndex(actor, "@")
	if i < 0 {
		return actor
	}
	return actor[:i]
}

// privTier is which cross-user privilege a call needs. Reading every
// user's jobs and changing every user's jobs are different powers, and
// conflating them meant anyone who could run a cross-user query could
// also remove somebody else's jobs.
//
// There is deliberately no default. Every call site names its tier, so
// classifying a new tool is a decision a reviewer sees rather than
// something a zero value makes silently.
type privTier int

const (
	// tierRead covers queries: seeing other users' jobs, history and
	// epochs. Granted by the mcp:admin scope or by MCP_ADMIN_USERS.
	tierRead privTier = iota
	// tierMutate covers acting on another user's jobs -- removal, hold,
	// release, edit. Granted ONLY by the mcp:superuser scope.
	tierMutate
)

func (t privTier) String() string {
	if t == tierMutate {
		return "mutate"
	}
	return "read"
}

// Scopes carrying each tier. They are granted at login from the
// operator's group configuration, the same path mcp:read and mcp:write
// already take, so a privilege rides in the token and is visible to
// whoami rather than being re-derived per call.
const (
	scopeMCPAdmin     = "mcp:admin"
	scopeMCPSuperuser = "mcp:superuser"
)

// allowsAllUsers reports whether this caller may act outside their own
// jobs at the given tier.
//
// MCP_ADMIN_USERS grants the read tier only, and only where the caller's
// transport supplied no scopes at all. It used to grant both tiers, and
// narrowing it is a real reduction for a deployment that relied on the
// old behaviour -- which is why the server logs a warning at startup
// when the list is configured and no superuser group is, rather than
// letting a removal simply start being refused one day.
func (s *Server) allowsAllUsers(ctx context.Context, authenticatedUser string, tier privTier) bool {
	if s == nil || authenticatedUser == "" {
		return false
	}
	switch tier {
	case tierMutate:
		return hasScope(ctx, scopeMCPSuperuser)
	default:
		if hasScope(ctx, scopeMCPAdmin) {
			return true
		}
		// The list does not override a token that withheld the scope.
		//
		// mcp:admin is rendered UNCHECKED on the consent form precisely
		// so that granting it is a deliberate act (see the note in
		// oauth2_sso.go). Falling back to a subject list here undid that
		// for exactly the people the box was written for: an operator
		// who left it unchecked got a token without the scope and
		// cross-user reads anyway, with nothing but whoami to say so.
		//
		// A token is the ceiling; a subject list is not allowed to raise
		// it. This is what the mutate tier above has always done, and
		// the two tiers disagreeing was the accident.
		if scopedTransport(ctx) {
			return false
		}
		_, ok := s.adminUsers[authenticatedUser]
		return ok
	}
}

// scopedTransport reports whether the caller arrived over a transport
// that stated a scope set.
//
// This is what separates "the token withheld mcp:admin" from "nothing
// here has scopes to withhold". The HTTP MCP transport always attaches
// the granted set, so a nil set means stdio, where the process IS the
// user and MCP_ADMIN_USERS remains the only way to grant the read tier.
func scopedTransport(ctx context.Context) bool {
	return grantedScopesFromContext(ctx) != nil
}

// hasScope reports whether the caller's granted scopes include name.
//
// A transport that supplies no scopes at all (the stdio server, where
// the process IS the user) yields false, so the explicit MCP_ADMIN_USERS
// list remains the way to grant the read tier there.
func hasScope(ctx context.Context, name string) bool {
	for _, s := range grantedScopesFromContext(ctx) {
		if s == name {
			return true
		}
	}
	return false
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

// ownerScopedConstraint ANDs an owner restriction onto a caller-supplied
// constraint, unconditionally and with no admin exemption.
//
// This is the only owner scoping that actually binds a job query. The
// obvious-looking alternative — QueryOptions.FetchOpts = FetchMyJobs
// with QueryOptions.Owner set — does not, because it delegates the
// decision to the schedd, which is free to ignore it:
//
//   - "Me" on the request ad is a suggestion. The schedd overrides it
//     with the identity it authenticated the CONNECTION as, which for a
//     service acting on behalf of users is the service account.
//   - A queue superuser gets owner filtering dropped altogether:
//     "if (owner.empty() || isQueueSuperUser(...)) my_jobs_expr = NULL"
//     (condor_schedd.V6/schedd.cpp). Access-point service accounts are
//     routinely superusers, and a submit portal has to be one to submit
//     for other users — so this is the normal deployment, not an edge.
//
// Both leave "show me my jobs" meaning "show me everything", which is
// fail-open. A constraint the schedd merely evaluates cannot be
// reinterpreted that way. FetchMyJobs stays set alongside this as
// defense in depth.
func ownerScopedConstraint(owner, constraint string) (string, error) {
	if owner == "" {
		return "", fmt.Errorf("no authenticated owner to scope to")
	}
	scope := fmt.Sprintf("Owner == %s", classadStringLit(owner))
	c := strings.TrimSpace(constraint)
	if c == "" || strings.EqualFold(c, "true") {
		return scope, nil
	}
	// Re-serialize the caller's constraint before splicing it in: raw
	// concatenation does not confine it, since `||` binds looser than
	// `&&` and an unbalanced input like `true) || (true` escapes the
	// enclosing AND and matches every job.
	safe, err := classadBalanced(c)
	if err != nil {
		return "", fmt.Errorf("constraint is not a valid ClassAd expression: %w", err)
	}
	return fmt.Sprintf("(%s) && (%s)", scope, safe), nil
}

// fetchOptsFor keeps the schedd-side hint aligned with the constraint.
// FetchMyJobs narrows to the connection's authenticated identity, which
// is right for a confined call and wrong for an admin's deliberately
// unconfined one.
func fetchOptsFor(scope OwnerScope) htcondor.QueryFetchOpts {
	if scope.AllUsers {
		return htcondor.FetchNormal
	}
	return htcondor.FetchMyJobs
}
