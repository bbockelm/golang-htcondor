package mcpserver

import (
	"context"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestEveryToolAgreesOnScope. query_jobs used to scope unconditionally
// while every other tool let an MCP admin through, so one session was
// told by query_jobs that it owned nothing while aggregate_jobs counted
// the whole pool -- a contradiction with nothing in either answer to
// explain it. Two tools cannot disagree about whose jobs a session is
// looking at.
func TestEveryToolAgreesOnScope(t *testing.T) {
	admin := &Server{adminUsers: map[string]struct{}{"root@uid.domain": {}}}
	adminCtx := htcondor.WithAuthenticatedUser(context.Background(), "root@uid.domain")
	userCtx := htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.domain")

	scope, ok := admin.ownerScope(adminCtx)
	if !ok || !scope.AllUsers {
		t.Fatalf("an admin should be unconfined: %+v ok=%v", scope, ok)
	}
	// And the same policy the other tools reach through scopeToOwner.
	if got, ok := admin.scopeToOwner(adminCtx, "JobStatus == 5"); !ok || got != "JobStatus == 5" {
		t.Errorf("scopeToOwner confined an admin (%q); the two helpers must agree", got)
	}

	scope, ok = admin.ownerScope(userCtx)
	if !ok || scope.AllUsers || scope.Owner != "alice" {
		t.Fatalf("a normal user must be confined to their own jobs: %+v", scope)
	}
	if got, _ := admin.scopeToOwner(userCtx, ""); !strings.Contains(got, `Owner == "alice"`) {
		t.Errorf("scopeToOwner did not confine a normal user: %q", got)
	}

	// An unidentified caller is neither.
	if _, ok := admin.ownerScope(context.Background()); ok {
		t.Error("an unidentified caller must not resolve to a scope")
	}
}

// TestScopeIsStatedInTheAnswer is the other half. Which scope was
// applied has to be visible, not inferred: a listing that silently
// covers every user reads exactly like one that covers its own, and the
// caller is a language model with no other way to tell.
func TestScopeIsStatedInTheAnswer(t *testing.T) {
	all := OwnerScope{AllUsers: true}.Note()
	if !strings.Contains(all, "ALL users") || !strings.Contains(all, "admin") {
		t.Errorf("an unconfined answer must say so plainly: %q", all)
	}
	mine := OwnerScope{Owner: "alice"}.Note()
	if !strings.Contains(mine, "alice") {
		t.Errorf("a confined answer must name the owner: %q", mine)
	}
	if all == mine {
		t.Error("the two scopes must be distinguishable")
	}
}

// TestFetchMyJobsFollowsTheScope: FetchMyJobs narrows to the
// connection's identity, so leaving it on for an admin would silently
// re-narrow a listing the constraint deliberately left wide -- the
// schedd-side half of the same inconsistency.
func TestFetchMyJobsFollowsTheScope(t *testing.T) {
	if got := fetchOptsFor(OwnerScope{AllUsers: true}); got != htcondor.FetchNormal {
		t.Errorf("an admin call must not carry FetchMyJobs: %v", got)
	}
	if got := fetchOptsFor(OwnerScope{Owner: "alice"}); got != htcondor.FetchMyJobs {
		t.Errorf("a confined call should keep FetchMyJobs as defence in depth: %v", got)
	}
}

// TestToolDescriptionsStateTheDefault: the description is the only place
// a model learns the scope before it calls, and "Owner-scoped" was
// untrue for admins.
func TestToolDescriptionsStateTheDefault(t *testing.T) {
	s := &Server{}
	res, ok := s.handleListTools(context.Background(), nil).(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected tool listing shape: %T", s.handleListTools(context.Background(), nil))
	}
	tools, ok := res["tools"].([]Tool)
	if !ok {
		t.Fatalf("unexpected tools field: %T", res["tools"])
	}
	for _, tool := range tools {
		switch tool.Name {
		case "query_jobs", "aggregate_jobs", "query_history_db", "query_jobs_as_of":
			if !strings.Contains(tool.Description, "YOUR OWN jobs") {
				t.Errorf("%s does not state the default scope:\n%s", tool.Name, tool.Description)
			}
			if !strings.Contains(tool.Description, "states which scope") {
				t.Errorf("%s does not say the answer names its scope:\n%s", tool.Name, tool.Description)
			}
		}
	}
}
