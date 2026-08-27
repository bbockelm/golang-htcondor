package mcpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"

	htcondor "github.com/bbockelm/golang-htcondor"
)

func scopeTestServer(t *testing.T, delegated bool) *Server {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return &Server{
		// An address nothing listens on: these cases must be decided
		// before any query goes out, so reaching the schedd at all is
		// itself the failure.
		schedd:    htcondor.NewSchedd("test_schedd", "127.0.0.1:1"),
		logger:    logger,
		delegated: delegated,
	}
}

// TestQueryJobsRefusesUnidentifiedCallerWhenDelegated is the fail-closed
// half of the reported information disclosure.
//
// Behind HTTP the daemon acts for remote callers, so a query it cannot
// attribute to one has no owner to scope by. Left to FetchMyJobs alone
// the schedd decides, and on an access point it decides "everything" —
// the connection is the service account and a queue superuser gets owner
// filtering dropped. Refusing is the only answer that cannot widen.
func TestQueryJobsRefusesUnidentifiedCallerWhenDelegated(t *testing.T) {
	s := scopeTestServer(t, true)

	_, err := s.toolQueryJobs(context.Background(), map[string]interface{}{"constraint": "true"})
	if err == nil {
		t.Fatal("a delegated query_jobs with no identifiable caller must refuse")
	}
	if !strings.Contains(err.Error(), "uthentication required") {
		t.Errorf("the refusal should say what is missing, got: %v", err)
	}
}

// TestQueryJobsRunsForTheLocalUserWhenNotDelegated is the other half:
// run from a user's shell over stdio, the process IS the user and the
// schedd sees them on the connection, so FetchMyJobs means what
// condor_q means by it. Refusing there would break the CLI to fix a
// problem it does not have.
//
// The call is expected to fail — nothing is listening on the schedd
// address — but it must fail trying to reach the schedd, not by
// refusing up front.
func TestQueryJobsRunsForTheLocalUserWhenNotDelegated(t *testing.T) {
	s := scopeTestServer(t, false)

	_, err := s.toolQueryJobs(context.Background(), map[string]interface{}{"constraint": "true"})
	if err == nil {
		t.Fatal("expected the query to fail against an unreachable schedd")
	}
	if strings.Contains(err.Error(), "uthentication required") {
		t.Errorf("stdio mode must not require a resolved caller identity, got: %v", err)
	}
}

// TestQueryJobsScopesByConstraintNotJustFetchOpts: an identified caller
// gets the owner restriction in the constraint, where the schedd can
// only evaluate it. Asserting on QueryOptions alone would not catch the
// bug — FetchMyJobs was already set throughout the fail-open.
func TestQueryJobsScopesByConstraintNotJustFetchOpts(t *testing.T) {
	scoped, err := ownerScopedConstraint(ownerFromActor("alice@example.org"), "JobStatus == 1")
	if err != nil {
		t.Fatalf("ownerScopedConstraint: %v", err)
	}
	if !strings.Contains(scoped, `Owner == "alice"`) {
		t.Errorf("the constraint carries no owner restriction: %q", scoped)
	}
	if scopeAdmits(t, scoped, "bob") {
		t.Errorf("the scoped constraint admits another user: %q", scoped)
	}
}
