package mcpserver

import (
	"context"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

func tierServer(adminUsers ...string) *Server {
	set := map[string]struct{}{}
	for _, u := range adminUsers {
		set[u] = struct{}{}
	}
	return &Server{adminUsers: set}
}

func tierCtx(actor string, scopes ...string) context.Context {
	ctx := htcondor.WithAuthenticatedUser(context.Background(), actor)
	if len(scopes) > 0 {
		ctx = WithGrantedScopes(ctx, scopes)
	}
	return ctx
}

// The whole point of the split: being able to SEE every user's jobs must
// not carry the ability to CHANGE them. Before this, one list granted
// both, so anyone who could run a cross-user query could also remove
// somebody else's jobs.
func TestReadTierDoesNotGrantMutation(t *testing.T) {
	s := tierServer("root@uid.domain")
	ctx := tierCtx("root@uid.domain")

	// Read tier: the constraint passes through untouched.
	if got, ok := s.scopeToOwner(ctx, "JobStatus == 5", tierRead); !ok || got != "JobStatus == 5" {
		t.Errorf("read tier should be unconfined for an MCP_ADMIN_USERS member: got %q ok=%v", got, ok)
	}

	// Mutate tier: confined to their own jobs despite being listed.
	got, ok := s.scopeToOwner(ctx, "JobStatus == 5", tierMutate)
	if !ok {
		t.Fatal("the caller is authenticated; scoping must succeed")
	}
	if !strings.Contains(got, `Owner == "root"`) {
		t.Errorf("MCP_ADMIN_USERS must NOT grant cross-user mutation; got %q", got)
	}
}

func TestSuperuserScopeGrantsMutation(t *testing.T) {
	s := tierServer() // not in MCP_ADMIN_USERS at all
	ctx := tierCtx("carol@uid.domain", "mcp:read", "mcp:write", scopeMCPSuperuser)

	if got, ok := s.scopeToOwner(ctx, "JobStatus == 5", tierMutate); !ok || got != "JobStatus == 5" {
		t.Errorf("mcp:superuser should be unconfined for mutation: got %q ok=%v", got, ok)
	}
}

// mcp:admin is the group-granted equivalent of the MCP_ADMIN_USERS list.
func TestAdminScopeGrantsReadOnly(t *testing.T) {
	s := tierServer()
	ctx := tierCtx("dave@uid.domain", scopeMCPAdmin)

	if got, ok := s.scopeToOwner(ctx, "true", tierRead); !ok || got != "true" {
		t.Errorf("mcp:admin should be unconfined for reads: got %q ok=%v", got, ok)
	}
	got, _ := s.scopeToOwner(ctx, "true", tierMutate)
	if !strings.Contains(got, `Owner == "dave"`) {
		t.Errorf("mcp:admin must not grant mutation; got %q", got)
	}
}

// A caller with neither is confined at both tiers.
func TestPlainUserConfinedAtBothTiers(t *testing.T) {
	s := tierServer()
	ctx := tierCtx("erin@uid.domain", "mcp:read", "mcp:write")

	for _, tier := range []privTier{tierRead, tierMutate} {
		got, ok := s.scopeToOwner(ctx, "true", tier)
		if !ok {
			t.Fatalf("%s: authenticated caller must scope", tier)
		}
		if !strings.Contains(got, `Owner == "erin"`) {
			t.Errorf("%s tier: a plain user must be confined; got %q", tier, got)
		}
	}
}

// An unauthenticated caller is refused at both tiers rather than falling
// back to an unconfined constraint.
func TestUnauthenticatedRefusedAtBothTiers(t *testing.T) {
	s := tierServer("root@uid.domain")
	for _, tier := range []privTier{tierRead, tierMutate} {
		if _, ok := s.scopeToOwner(context.Background(), "true", tier); ok {
			t.Errorf("%s tier: an unauthenticated caller must be refused", tier)
		}
	}
}

// ownerScope must agree with scopeToOwner at each tier. They are
// consulted by different tools, and a disagreement would mean the note
// shown to the caller described a confinement the tool did not apply.
func TestOwnerScopeAgreesPerTier(t *testing.T) {
	s := tierServer("root@uid.domain")
	ctx := tierCtx("root@uid.domain")

	readScope, ok := s.ownerScope(ctx, tierRead)
	if !ok || !readScope.AllUsers {
		t.Errorf("read tier should report all users: %+v ok=%v", readScope, ok)
	}
	mutScope, ok := s.ownerScope(ctx, tierMutate)
	if !ok {
		t.Fatal("mutate tier should still resolve")
	}
	if mutScope.AllUsers {
		t.Error("mutate tier must not report all users for an MCP_ADMIN_USERS member")
	}
	if mutScope.Owner != "root" {
		t.Errorf("mutate tier owner = %q, want root", mutScope.Owner)
	}
}

// selfScopedQueryOptions is a read path and must follow the read tier.
func TestSelfScopedQueryOptionsFollowsReadTier(t *testing.T) {
	s := tierServer("root@uid.domain")
	opts, ok := s.selfScopedQueryOptions(tierCtx("root@uid.domain"), nil)
	if !ok {
		t.Fatal("admin caller should be accepted")
	}
	if opts.FetchOpts&htcondor.FetchMyJobs != 0 {
		t.Error("a read-tier admin must not be confined to their own jobs")
	}
}

// Scopes only count when the transport supplied them. A stdio server
// passes none, so the explicit list stays the way to grant the read tier
// there -- and nothing accidentally grants the mutate tier.
func TestNoScopesMeansNoSuperuser(t *testing.T) {
	s := tierServer("root@uid.domain")
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "root@uid.domain")

	if !s.allowsAllUsers(ctx, "root@uid.domain", tierRead) {
		t.Error("the explicit list must still grant the read tier with no scopes present")
	}
	if s.allowsAllUsers(ctx, "root@uid.domain", tierMutate) {
		t.Error("no scopes must mean no mutate tier")
	}
}

// The bug this file did not catch: an MCP_ADMIN_USERS member whose token
// does NOT carry mcp:admin was given cross-user reads anyway.
//
// mcp:admin is rendered unchecked on the consent form so that granting
// it is deliberate. Leaving it unchecked has to mean something, and the
// subject list was quietly overriding it. Every case above used a
// scopeless context, which is why this went unnoticed.
func TestAdminListDoesNotOverrideAScopeBearingToken(t *testing.T) {
	s := tierServer("root@uid.domain")
	// A real OAuth caller: scopes present, mcp:admin deliberately absent.
	ctx := tierCtx("root@uid.domain", "mcp:read", "mcp:write")

	got, ok := s.scopeToOwner(ctx, "JobStatus == 5", tierRead)
	if !ok {
		t.Fatal("the caller is authenticated; scoping must succeed")
	}
	if !strings.Contains(got, `Owner == "root"`) {
		t.Errorf("MCP_ADMIN_USERS overrode a token that withheld %s; got %q", scopeMCPAdmin, got)
	}
}

// The stdio path is what the list exists for and must keep working:
// that transport states no scopes, so there is nothing to withhold.
func TestAdminListStillAppliesWithoutScopes(t *testing.T) {
	s := tierServer("root@uid.domain")
	ctx := tierCtx("root@uid.domain") // no scopes at all

	if got, ok := s.scopeToOwner(ctx, "JobStatus == 5", tierRead); !ok || got != "JobStatus == 5" {
		t.Errorf("MCP_ADMIN_USERS should still grant the read tier over stdio: got %q ok=%v", got, ok)
	}
}

// Holding the scope works whether or not the caller is also listed.
func TestAdminScopeWorksForAListedUserToo(t *testing.T) {
	s := tierServer("root@uid.domain")
	ctx := tierCtx("root@uid.domain", "mcp:read", scopeMCPAdmin)

	if got, ok := s.scopeToOwner(ctx, "JobStatus == 5", tierRead); !ok || got != "JobStatus == 5" {
		t.Errorf("the %s scope should be unconfined: got %q ok=%v", scopeMCPAdmin, got, ok)
	}
}

// A token that granted NOTHING is still a token: it stated its scope set
// and that set is empty. Only a transport that states no set at all --
// stdio -- falls back to the list. Without this the distinction would be
// "is the slice empty", which an empty grant would satisfy.
func TestAnEmptyGrantIsStillAScopeBearingToken(t *testing.T) {
	s := tierServer("root@uid.domain")
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "root@uid.domain")
	ctx = WithGrantedScopes(ctx, []string{}) // present, and empty

	if !scopedTransport(ctx) {
		t.Fatal("an empty-but-present scope set must count as scope-bearing")
	}
	got, ok := s.scopeToOwner(ctx, "JobStatus == 5", tierRead)
	if !ok {
		t.Fatal("the caller is authenticated; scoping must succeed")
	}
	if !strings.Contains(got, `Owner == "root"`) {
		t.Errorf("an empty grant was treated as stdio; got %q", got)
	}
}

// whoami must not claim a grant the rule refuses. Reporting "listed in
// MCP_ADMIN_USERS" next to admin=false is how an operator concludes the
// list is broken rather than that the scope is missing.
func TestWhoamiExplainsWhyTheListDidNotApply(t *testing.T) {
	s := tierServer("root@uid.domain")
	ctx := tierCtx("root@uid.domain", "mcp:read", "mcp:write")

	adminVia, _ := s.privilegeProvenance(ctx, "root@uid.domain")
	if s.allowsAllUsers(ctx, "root@uid.domain", tierRead) {
		t.Fatal("precondition: this caller should not be admin")
	}
	for _, want := range []string{scopeMCPAdmin, "MCP_ADMIN_USERS", "HTTP_API_MCP_ADMIN_GROUP"} {
		if !strings.Contains(adminVia, want) {
			t.Errorf("admin_via = %q; it should mention %q so the operator knows what to do", adminVia, want)
		}
	}
}
