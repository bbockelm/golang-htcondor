package multiap

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections/vm"
)

// definedAfterTextbook is the page predicate as it was first written:
// "T < t || (T == t && rest)".
func definedAfterTextbook(k histKey) string {
	return fmt.Sprintf("(%s isnt undefined && (%s < %d || (%s == %d && %s)))",
		attrEnteredHistory, attrEnteredHistory, k.T, attrEnteredHistory, k.T, tupleBefore(k))
}

// TestDefinedAfterEquivalent: the hoisted page predicate evaluates to
// exactly the value the textbook one does -- undefined and error included
// -- for every EnteredHistoryTime, ScheddName, ClusterId and ProcId a row
// can carry.
func TestDefinedAfterEquivalent(t *testing.T) {
	k := histKey{T: 1000, S: "ap2.example.org", C: 50, P: 3}
	textbook := mustExpr(t, definedAfterTextbook(k))
	hoisted := mustExpr(t, definedAfter(&k))
	odd := []string{"", "undefined", "error", `"x"`, "true", "{1}", `real("NaN")`}
	times := append([]string{"999", "1000", "1001", "999.5", "1000.0", "1000.5", `"1000"`}, odd...)
	schedds := append([]string{`"ap1.example.org"`, `"ap2.example.org"`, `"AP2.example.org"`, `"ap3.example.org"`}, odd...)
	clusters := append([]string{"49", "50", "51", "50.0"}, odd...)
	procs := append([]string{"2", "3", "4"}, odd...)
	n := 0
	for _, tv := range times {
		for _, sv := range schedds {
			for _, cv := range clusters {
				for _, pv := range procs {
					ad := rowWith(t, map[string]string{
						attrEnteredHistory: tv, AttrScheddName: sv, "ClusterId": cv, "ProcId": pv,
					})
					want, got := textbook.Eval(ad), hoisted.Eval(ad)
					if want.Type() != got.Type() || want.String() != got.String() {
						t.Fatalf("%s: textbook %s (%v), hoisted %s (%v)", ad, want, want.Type(), got, got.Type())
					}
					n++
				}
			}
		}
	}
	t.Logf("%d rows agree", n)
}

// TestDefinedAfterIsProbed: the archive planner gets a bound on
// EnteredHistoryTime from the hoisted predicate and none from the
// textbook one; definedAfterWithin adds the window's floor.
func TestDefinedAfterIsProbed(t *testing.T) {
	k := histKey{T: 1000, S: "ap2.example.org", C: 50, P: 3}
	probes := func(constraint string) []string {
		q, err := vm.Parse(constraint)
		if err != nil {
			t.Fatalf("vm.Parse(%q): %v", constraint, err)
		}
		var out []string
		for _, p := range q.Probes() {
			if strings.EqualFold(p.Attr, attrEnteredHistory) && p.Op != "present" {
				out = append(out, p.Op+fmt.Sprint(p.Vals))
			}
		}
		slices.Sort(out)
		return out
	}
	if got := probes(definedAfterTextbook(k)); len(got) != 0 {
		t.Errorf("textbook form probes %v; the test proves nothing", got)
	}
	if got, want := probes(definedAfter(&k)), []string{"<=[1000]"}; !slices.Equal(got, want) {
		t.Errorf("definedAfter probes %v, want %v", got, want)
	}
	if got, want := probes(definedAfterWithin(&k, 500, true)), []string{"<=[1000]", ">=[500]"}; !slices.Equal(got, want) {
		t.Errorf("definedAfterWithin probes %v, want %v", got, want)
	}
	if got, want := definedAfterWithin(&k, 500, false), definedAfter(&k); got != want {
		t.Errorf("definedAfterWithin without a floor = %q, want %q", got, want)
	}
}

// TestHistoryWindowFloorKeepsUnstampedRows: a QDate window on the hub's
// history adds the EnteredHistoryTime floor only to the read of rows that
// carry one. A row without it is still found, and a stamped row inside
// the window is dropped only if its stamp is impossibly early -- which is
// how the test sees that the floor was sent.
func TestHistoryWindowFloorKeepsUnstampedRows(t *testing.T) {
	hub := hubDB(t)
	hub.PutSource("ap1.example.org", StateFresh, 1)
	const q = 1757000000
	put := func(c int, qdate int64, entered string) {
		ad := fmt.Sprintf("ScheddName = \"ap1.example.org\"\nUser = \"alice@d\"\nOwner = \"alice\"\nClusterId = %d\nProcId = 0\nJobStatus = 4\nQDate = %d",
			c, qdate)
		if entered != "" {
			ad += "\nEnteredHistoryTime = " + entered
		}
		hub.AppendHistory(ad)
	}
	put(1, q, fmt.Sprint(q+100))
	put(2, q, fmt.Sprint(q+200))
	put(3, q, "")                    // no stamp
	put(4, q, fmt.Sprint(q-2*86400)) // stamped before it was submitted
	put(5, q-9*86400, fmt.Sprint(q-9*86400+10))
	s := newService(t, hub, newFakeRegistry("ap1.example.org"))

	window := fmt.Sprintf("QDate >= %d && QDate < %d", q, q+86400)
	for _, proj := range [][]string{nil, {"ClusterId"}} {
		for _, limit := range []int{1, 50} {
			var got []string
			token := ""
			for pages := 0; ; pages++ {
				if pages > 20 {
					t.Fatal("pagination did not terminate")
				}
				rows, res, err := s.ListHistory(context.Background(), ListRequest{
					User: "alice@d", Constraint: window, Limit: limit, PageToken: token, Projection: proj,
				})
				if err != nil {
					t.Fatalf("ListHistory: %v", err)
				}
				for _, r := range rows {
					got = append(got, fmt.Sprint(r.ID.Cluster))
				}
				if !res.HasMore {
					break
				}
				token = res.NextPageToken
			}
			if want := []string{"2", "1", "3"}; !slices.Equal(got, want) {
				t.Errorf("projection %v limit %d: clusters %v, want %v", proj, limit, got, want)
			}
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

func rowWith(t *testing.T, attrs map[string]string) *classad.ClassAd {
	t.Helper()
	var parts []string
	for k, v := range attrs {
		if v != "" {
			parts = append(parts, k+" = "+v)
		}
	}
	ad, err := classad.Parse("[" + strings.Join(parts, "; ") + "]")
	if err != nil {
		t.Fatalf("row %v: %v", parts, err)
	}
	return ad
}
