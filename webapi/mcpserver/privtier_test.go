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
