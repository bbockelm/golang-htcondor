package mcpserver

import (
	"context"
	"errors"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestScopeToOwnerRefusesMalformedConstraint: a constraint that does not parse is refused
// with its own error, not narrowed to the caller's own jobs. Narrowing turned a typo in a
// remove_jobs constraint into "remove every job I own".
func TestScopeToOwnerRefusesMalformedConstraint(t *testing.T) {
	s := scopeTestServer(t, true)
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.domain")
	for _, tier := range []privTier{tierRead, tierMutate} {
		got, err := s.scopeToOwner(ctx, `JobStatus == `, tier)
		if err == nil {
			t.Fatalf("tier %v: malformed constraint scoped to %q, want a refusal", tier, got)
		}
		if errors.Is(err, errScopeUnauthenticated) {
			t.Errorf("tier %v: malformed constraint reported as unauthenticated: %v", tier, err)
		}
	}
}

// TestRemoveJobsRefusesMalformedConstraint: remove_jobs with a constraint that does not
// parse must fail before anything reaches the schedd.
func TestRemoveJobsRefusesMalformedConstraint(t *testing.T) {
	s := scopeTestServer(t, true) // its schedd address has no listener
	ctx := htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.domain")
	_, err := s.toolRemoveJobs(ctx, map[string]interface{}{"constraint": `Owner == "alice" &&`})
	if err == nil {
		t.Fatal("remove_jobs accepted a malformed constraint")
	}
	if !strings.Contains(err.Error(), "not a valid ClassAd expression") {
		t.Errorf("remove_jobs error = %v, want the constraint refused before the schedd is contacted", err)
	}
}

// TestSingleJobMutateScopeStdioStillUnscoped: over stdio (not delegated, no actor) the id
// clause still goes out as it is; only the unauthenticated refusal is waived there.
func TestSingleJobMutateScopeStdioStillUnscoped(t *testing.T) {
	s := scopeTestServer(t, false)
	got, err := s.singleJobMutateScope(context.Background(), "ClusterId == 1 && ProcId == 0")
	if err != nil || got != "ClusterId == 1 && ProcId == 0" {
		t.Fatalf("stdio single-job scope = %q, %v; want the clause unchanged", got, err)
	}
}
