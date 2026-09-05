package htcondor

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func mustExpr(t *testing.T, s string) *classad.Expr {
	t.Helper()
	e, err := classad.ParseExpr(s)
	if err != nil {
		t.Fatalf("ParseExpr(%q): %v", s, err)
	}
	return e
}

// The schedd evaluates an aggregate's constraint against an ad built
// from the PROJECTION, so any attribute the constraint names has to be
// in it. Leaving it out does not error -- the comparison is simply never
// true and the query returns nothing, which reads exactly like "no jobs
// match".
func TestAggregateProjectionCarriesConstraintAttributes(t *testing.T) {
	got := aggregateProjection([]string{"Owner"}, mustExpr(t, "JobStatus == 5"))

	if len(got) != 2 || got[0] != "Owner" {
		t.Fatalf("projection = %v, want the grouping first then the constraint's attributes", got)
	}
	if !containsFold(got, "JobStatus") {
		t.Errorf("projection %v omits JobStatus; the constraint would match nothing", got)
	}
}

// The grouping keeps its position and order: the returned rows are read
// back against it.
func TestAggregateProjectionKeepsGroupingOrder(t *testing.T) {
	got := aggregateProjection([]string{"Owner", "JobUniverse"}, mustExpr(t, "JobStatus == 5"))
	if len(got) < 2 || got[0] != "Owner" || got[1] != "JobUniverse" {
		t.Errorf("projection = %v, want the grouping first and in order", got)
	}
}

func TestAggregateProjectionDeduplicates(t *testing.T) {
	got := aggregateProjection([]string{"JobStatus"}, mustExpr(t, "JobStatus == 5"))
	if len(got) != 1 || got[0] != "JobStatus" {
		t.Errorf("projection = %v, want a single JobStatus", got)
	}
	// Case-insensitively, as ClassAd attribute names are.
	got = aggregateProjection([]string{"jobstatus"}, mustExpr(t, "JobStatus == 5"))
	if len(got) != 1 {
		t.Errorf("projection = %v, want the differing case treated as the same attribute", got)
	}
}

// A constant constraint names nothing, so the projection is just the
// grouping -- and an empty grouping with a constant constraint sends no
// projection at all, which is what the schedd wants for "count
// everything".
func TestAggregateProjectionWithNoReferences(t *testing.T) {
	if got := aggregateProjection([]string{"Owner"}, mustExpr(t, "true")); len(got) != 1 || got[0] != "Owner" {
		t.Errorf("projection = %v, want just the grouping", got)
	}
	if got := aggregateProjection(nil, mustExpr(t, "true")); len(got) != 0 {
		t.Errorf("projection = %v, want empty", got)
	}
}

// Scoped references are not job attributes a projection can carry.
func TestAggregateProjectionSkipsScopedReferences(t *testing.T) {
	got := aggregateProjection([]string{"Owner"}, mustExpr(t, `MY.JobStatus == 5`))
	for _, p := range got {
		if strings.Contains(p, ".") {
			t.Errorf("projection %v carries a scoped reference %q", got, p)
		}
	}
}

// Widening the projection makes the schedd group by the wider tuple, so
// the rows come back split. Folding restores the grouping asked for.
func TestFoldAggregateRows(t *testing.T) {
	// "count by Owner" constrained on JobStatus comes back per
	// (Owner, JobStatus); Group carries only Owner, so alice appears
	// twice.
	rows := []AggregateRow{
		{Group: []string{"alice"}, Count: 3},
		{Group: []string{"bob"}, Count: 5},
		{Group: []string{"alice"}, Count: 4},
	}
	got := foldAggregateRows(rows, []string{"Owner"})

	if len(got) != 2 {
		t.Fatalf("got %d group(s), want 2: %v", len(got), got)
	}
	if got[0].Group[0] != "alice" || got[0].Count != 7 {
		t.Errorf("first group = %v, want alice with 3+4=7", got[0])
	}
	if got[1].Group[0] != "bob" || got[1].Count != 5 {
		t.Errorf("second group = %v, want bob with 5", got[1])
	}
}

// With no grouping every row folds into one, which is what "count
// everything matching" means once the projection has been widened for
// the constraint.
func TestFoldAggregateRowsWithNoGrouping(t *testing.T) {
	got := foldAggregateRows([]AggregateRow{{Count: 3}, {Count: 4}, {Count: 5}}, nil)
	if len(got) != 1 || got[0].Count != 12 {
		t.Fatalf("got %v, want a single row of 12", got)
	}
}

// Two different groupings must not collide into one row through the
// join separator.
func TestFoldAggregateRowsDoesNotCollideGroups(t *testing.T) {
	rows := []AggregateRow{
		{Group: []string{"a", "b"}, Count: 1},
		{Group: []string{"a\x00b"}, Count: 1},
	}
	if got := foldAggregateRows(rows, []string{"x", "y"}); len(got) != 2 {
		t.Errorf("distinct groupings folded together: %v", got)
	}
}

func TestFoldAggregateRowsEmpty(t *testing.T) {
	if got := foldAggregateRows(nil, []string{"Owner"}); len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

func containsFold(hay []string, needle string) bool {
	for _, h := range hay {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}
