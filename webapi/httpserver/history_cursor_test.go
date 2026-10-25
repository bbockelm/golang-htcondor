package httpserver

import (
	"fmt"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections/vm"
)

// cursorValues are the values a history record's ClusterId or ProcId can
// carry around a cursor position n: the integers on either side of it,
// reals (including NaN), and the non-numbers. "" leaves the attribute off.
func cursorValues(n int) []string {
	return []string{
		"", "undefined", "error", "1/0", `"x"`, fmt.Sprintf(`"%d"`, n), "true", "false",
		"{1, 2}", "[a = 1]", `real("NaN")`, `real("INF")`, `-real("INF")`,
		fmt.Sprint(n - 1), fmt.Sprint(n), fmt.Sprint(n + 1), "0", "-1",
		fmt.Sprintf("%d.0", n), fmt.Sprintf("%d.5", n-1), fmt.Sprintf("%d.5", n),
		// Expression-valued.
		fmt.Sprintf("%d + 0", n), "Missing", "Missing + 1",
	}
}

// TestHistoryCursorPredicateEquivalent: the hoisted cursor evaluates to
// exactly the value the textbook keyset predicate does -- not only true
// where it is true, but undefined where it is undefined and an error
// where it is an error -- for every ClusterId and ProcId a record can
// carry. That makes the rewrite safe anywhere the predicate is used,
// including inside a caller's own expression.
func TestHistoryCursorPredicateEquivalent(t *testing.T) {
	const c, p = 1000, 3
	textbook := mustExpr(t, fmt.Sprintf("(ClusterId < %d || (ClusterId == %d && ProcId < %d))", c, c, p))
	hoisted := mustExpr(t, historyCursorPredicate(c, p))
	n := 0
	for _, cv := range cursorValues(c) {
		for _, pv := range cursorValues(p) {
			ad := recordWith(t, map[string]string{"ClusterId": cv, "ProcId": pv})
			want, got := textbook.Eval(ad), hoisted.Eval(ad)
			if !sameValue(want, got) {
				t.Errorf("ClusterId = %q, ProcId = %q: textbook %s (%v), hoisted %s (%v)",
					cv, pv, want, want.Type(), got, got.Type())
			}
			n++
		}
	}
	t.Logf("%d records agree", n)
}

// TestHistoryCursorPredicateIsProbed: the archive planner gets a ClusterId
// probe from the hoisted form and none from the textbook one, which is the
// reason for the rewrite.
func TestHistoryCursorPredicateIsProbed(t *testing.T) {
	if got, want := historyCursorPredicate(1000, 3), "ClusterId <= 1000 && (ClusterId < 1000 || ProcId < 3)"; got != want {
		t.Errorf("historyCursorPredicate = %q, want %q", got, want)
	}
	for _, c := range []struct {
		constraint string
		probed     bool
	}{
		{"(ClusterId < 1000 || (ClusterId == 1000 && ProcId < 3))", false},
		{historyCursorPredicate(1000, 3), true},
		{"(Owner == \"alice\") && (true && " + historyCursorPredicate(1000, 3) + ")", true},
	} {
		q, err := vm.Parse(c.constraint)
		if err != nil {
			t.Fatalf("vm.Parse(%q): %v", c.constraint, err)
		}
		found := false
		for _, pr := range q.Probes() {
			if strings.EqualFold(pr.Attr, "ClusterId") && pr.Op == "<=" {
				found = true
			}
		}
		if found != c.probed {
			t.Errorf("%q: ClusterId <= probe = %v, want %v", c.constraint, found, c.probed)
		}
	}
}

func mustExpr(t *testing.T, s string) *classad.Expr {
	t.Helper()
	e, err := classad.ParseExpr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return e
}

// recordWith is a record holding attrs; an empty value leaves the
// attribute off.
func recordWith(t *testing.T, attrs map[string]string) *classad.ClassAd {
	t.Helper()
	parts := []string{"Owner = \"alice\""}
	for k, v := range attrs {
		if v != "" {
			parts = append(parts, k+" = "+v)
		}
	}
	ad, err := classad.Parse("[" + strings.Join(parts, "; ") + "]")
	if err != nil {
		t.Fatalf("record %v: %v", parts, err)
	}
	return ad
}

// sameValue is whether two evaluation results are the same value of the
// same type.
func sameValue(a, b classad.Value) bool {
	return a.Type() == b.Type() && a.String() == b.String()
}
