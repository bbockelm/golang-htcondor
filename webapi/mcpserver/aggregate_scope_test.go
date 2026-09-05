package mcpserver

import (
	"context"
	"os"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// aggregate_jobs used to confine its schedd query with a hardcoded
// FetchMyJobs. That sends QUERY_JOB_ADS_WITH_AUTH, so the schedd filters
// on the identity it authenticated -- and this server authenticates as
// the end user, so the answer covered only that user's own jobs.
//
// Admins are exempt from owner scoping everywhere else, including in the
// constraint aggregate_jobs itself builds via scopeToOwner. Applying the
// schedd-side filter to them anyway meant an admin counting held jobs
// pool-wide got their OWN held jobs: a flat zero beside a queue holding
// thousands, with nothing to indicate the answer had been narrowed.
func TestAggregateUsesTheSharedScopingRatherThanAHardcodedFilter(t *testing.T) {
	src, err := os.ReadFile("handlers_htcondordb.go")
	if err != nil {
		t.Fatalf("reading source: %v", err)
	}
	// Comments are stripped first: the function's own comment has to be
	// free to name the thing it must not do, and an assertion that
	// cannot survive its own explanation is not much of an assertion.
	fn := stripComments(functionBody(t, string(src), "func (s *Server) aggregateJobsFromSchedd"))

	if strings.Contains(fn, "FetchOpts:") || strings.Contains(fn, "FetchMyJobs") {
		t.Errorf("aggregateJobsFromSchedd sets a fetch option directly:\n%s\n"+
			"scoping belongs to selfScopedQueryOptions, which exempts admins; "+
			"setting FetchMyJobs here confines them too", fn)
	}
	if !strings.Contains(fn, "selfScopedQueryOptions(") {
		t.Error("aggregateJobsFromSchedd does not use selfScopedQueryOptions, " +
			"so it does not get the admin exemption every other tool honours")
	}
}

// The options that path now asks for, spelled out: an admin is
// unconfined, a normal user is confined by both mechanisms.
func TestAggregateScopingOptionsByRole(t *testing.T) {
	s := scopeTestServer(t, true)
	admin := scopeTestServer(t, true)
	admin.adminUsers = map[string]struct{}{"root@uid.domain": {}}

	t.Run("a normal user is confined", func(t *testing.T) {
		ctx := htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.domain")
		opts, ok := s.selfScopedQueryOptions(ctx, nil)
		if !ok {
			t.Fatal("an authenticated caller must be scopeable")
		}
		if opts.FetchOpts&htcondor.FetchMyJobs == 0 {
			t.Error("a normal user must keep the schedd-side filter")
		}
		if opts.Owner != "alice" {
			t.Errorf("Owner = %q, want the bare username", opts.Owner)
		}
	})

	t.Run("an admin is not", func(t *testing.T) {
		ctx := htcondor.WithAuthenticatedUser(context.Background(), "root@uid.domain")
		opts, ok := admin.selfScopedQueryOptions(ctx, nil)
		if !ok {
			t.Fatal("an admin must be scopeable")
		}
		if opts.FetchOpts&htcondor.FetchMyJobs != 0 {
			t.Error("an admin must NOT get the schedd-side filter; that is the bug " +
				"that made a pool-wide count return only the admin's own jobs")
		}
		if opts.Owner != "" {
			t.Errorf("Owner = %q, want empty for an admin", opts.Owner)
		}
	})

	// No actor, no scoping: refuse rather than fall back to "no filter".
	t.Run("an unidentified caller is refused", func(t *testing.T) {
		if _, ok := s.selfScopedQueryOptions(context.Background(), nil); ok {
			t.Error("an unauthenticated caller must not be scopeable")
		}
	})
}

// The constraint half is admin-exempt too, and always was; this pins the
// pair so a future change cannot fix one and leave the other.
func TestAggregateConstraintIsAdminExempt(t *testing.T) {
	admin := scopeTestServer(t, true)
	admin.adminUsers = map[string]struct{}{"root@uid.domain": {}}

	ctx := htcondor.WithAuthenticatedUser(context.Background(), "root@uid.domain")
	got, ok := admin.scopeToOwner(ctx, "JobStatus == 5")
	if !ok {
		t.Fatal("admin must be allowed")
	}
	if got != "JobStatus == 5" {
		t.Errorf("constraint = %q, want it untouched for an admin", got)
	}

	user := scopeTestServer(t, true)
	uctx := htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.domain")
	got, _ = user.scopeToOwner(uctx, "JobStatus == 5")
	if !strings.Contains(got, `Owner == "alice"`) {
		t.Errorf("a normal user's constraint is not owner-scoped: %q", got)
	}
}

// functionBody returns the source of the named function, from its
// declaration to the closing brace in column 0.
func functionBody(t *testing.T, src, decl string) string {
	t.Helper()
	i := strings.Index(src, decl)
	if i < 0 {
		t.Fatalf("function %q not found", decl)
	}
	rest := src[i:]
	if j := strings.Index(rest, "\n}\n"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// stripComments removes whole-line // comments, so a source assertion
// reads the code rather than the prose around it.
func stripComments(src string) string {
	var kept []string
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}
