package mcpserver

import (
	"context"
	"fmt"
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

// --- truncation ---

func aggRows(n int) []htcondor.AggregateRow {
	rows := make([]htcondor.AggregateRow, n)
	for i := range rows {
		rows[i] = htcondor.AggregateRow{Group: []string{fmt.Sprintf("owner%03d", i)}, Count: 10}
	}
	return rows
}

// An untruncated answer reports what it found and says nothing about
// limits -- the common case must not be cluttered with caveats.
func TestAggregateRenderUntruncated(t *testing.T) {
	out := renderScheddAggregate("JobStatus == 5", []string{"Owner"}, aggRows(3), false, -1)

	if strings.Contains(strings.ToUpper(out), "TRUNCATED") {
		t.Errorf("a complete answer must not claim truncation:\n%s", out)
	}
	if !strings.Contains(out, "30 job(s) in the live queue") {
		t.Errorf("total missing or wrong:\n%s", out)
	}
	if !strings.Contains(out, "constraint applied: JobStatus == 5") {
		t.Errorf("the effective constraint is not echoed:\n%s", out)
	}
}

// The reported bug: groups past the limit were dropped and the total
// undercounted, with nothing to say so. Both halves must now be visible.
func TestAggregateRenderTruncatedWithExactTotal(t *testing.T) {
	// 500 shown groups of 10 = 5,000 shown; 20,000 actually match.
	out := renderScheddAggregate("true", []string{"Owner"}, aggRows(aggregateGroupLimit), true, 20000)

	if !strings.Contains(out, "TRUNCATED") {
		t.Errorf("truncation is not announced:\n%s", out)
	}
	// The headline number must be the real one, not the sum of what fit.
	if !strings.Contains(out, "20000 job(s) match in total") {
		t.Errorf("the total is not the exact one:\n%s", out)
	}
	if !strings.Contains(out, "5000 are in the 500 group(s) shown") {
		t.Errorf("the shown subtotal is not distinguished from the total:\n%s", out)
	}
	// And the reader is told the omission is not random.
	if !strings.Contains(out, "alphabetically first") {
		t.Errorf("does not say which groups were kept:\n%s", out)
	}
}

// If the follow-up total query fails we still must not present the
// partial sum as if it were the answer.
func TestAggregateRenderTruncatedWithoutExactTotal(t *testing.T) {
	out := renderScheddAggregate("true", []string{"Owner"}, aggRows(aggregateGroupLimit), true, -1)

	if !strings.Contains(out, "TRUNCATED") {
		t.Errorf("truncation is not announced:\n%s", out)
	}
	if !strings.Contains(out, "lower bound") {
		t.Errorf("a partial total must be labelled a lower bound:\n%s", out)
	}
}

// A caller that gets zero needs to tell "no such jobs" from "not your
// jobs". Echoing the constraint actually applied is what makes that
// possible from the outside.
func TestAggregateRenderEchoesTheOwnerScopedConstraint(t *testing.T) {
	scoped := `(Owner == "alice") && (JobStatus == 5)`
	out := renderScheddAggregate(scoped, []string{"Owner"}, nil, false, -1)

	if !strings.Contains(out, scoped) {
		t.Errorf("the owner-scoped constraint is not visible to the caller:\n%s", out)
	}
	if !strings.Contains(out, "0 group(s)") {
		t.Errorf("an empty result is not reported as such:\n%s", out)
	}
}

// An empty constraint reaches the schedd as "true"; say that rather than
// leaving a blank where the constraint should be.
func TestAggregateRenderEmptyConstraintShowsTrue(t *testing.T) {
	out := renderScheddAggregate("", nil, aggRows(1), false, -1)
	if !strings.Contains(out, "constraint applied: true") {
		t.Errorf("empty constraint not rendered as true:\n%s", out)
	}
}

// The group cap must not be the listing default. 50 groups is not an
// answer to "count jobs by owner" on a busy access point.
func TestAggregateGroupLimitIsNotTheListingDefault(t *testing.T) {
	var listingDefault htcondor.QueryOptions
	if got := listingDefault.ApplyDefaults().Limit; aggregateGroupLimit == got {
		t.Errorf("the aggregate group cap (%d) is the listing default; "+
			"that is the value that silently dropped owners past the 50th", got)
	}
	if aggregateGroupLimit < 100 {
		t.Errorf("aggregateGroupLimit = %d, too small to answer a grouping question", aggregateGroupLimit)
	}
}
