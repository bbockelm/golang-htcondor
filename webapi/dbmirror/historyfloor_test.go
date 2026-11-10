package dbmirror

import (
	"fmt"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections/vm"
)

func TestHistoryFloor(t *testing.T) {
	const s = 1757000000
	cases := []struct {
		constraint string
		want       int64 // 0: no floor
	}{
		// The calendar's drill-down and the shapes seen in production.
		{fmt.Sprintf("QDate >= %d && QDate < %d", s, s+86400), s - historyFloorSlack},
		{fmt.Sprintf("QDate < %d && QDate >= %d", s+86400, s), s - historyFloorSlack},
		{fmt.Sprintf("(Owner == \"alice\") && ((QDate < %d && QDate >= %d) && ClusterId <= 7 && (ClusterId < 7 || ProcId < 3))", s+86400, s), s - historyFloorSlack},
		// Mirror images, strict bounds, equality, MY., case.
		{fmt.Sprintf("%d <= QDate", s), s - historyFloorSlack},
		{fmt.Sprintf("%d < QDate", s), s - historyFloorSlack},
		{fmt.Sprintf("QDate > %d", s), s - historyFloorSlack},
		{fmt.Sprintf("QDate == %d", s), s - historyFloorSlack},
		{fmt.Sprintf("QDate is %d", s), s - historyFloorSlack},
		{fmt.Sprintf("MY.qdate >= %d", s), s - historyFloorSlack},
		{fmt.Sprintf("QDate >= %d.75", s), s - historyFloorSlack},
		{fmt.Sprintf("QDate >= %d + 100", s), s + 100 - historyFloorSlack},
		// The other job times, and the stamp itself, which needs no slack.
		{fmt.Sprintf("CompletionDate >= %d", s), s - historyFloorSlack},
		{fmt.Sprintf("EnteredCurrentStatus >= %d", s), s - historyFloorSlack},
		{fmt.Sprintf("EnteredHistoryTime >= %d", s), s},
		// && takes the tighter, || the looser and only when both bound.
		{fmt.Sprintf("QDate >= %d && EnteredHistoryTime >= %d", s, s), s},
		{fmt.Sprintf("EnteredCurrentStatus >= %d || CompletionDate >= %d", s, s+5), s - historyFloorSlack},
		{fmt.Sprintf("CompletionDate >= %d || EnteredHistoryTime >= %d", s, s), s - historyFloorSlack},
		{fmt.Sprintf("QDate >= %d || Owner == \"alice\"", s), 0},
		// Nothing to go on.
		{"true", 0},
		{fmt.Sprintf("QDate < %d", s), 0},
		{fmt.Sprintf("!(QDate < %d)", s), 0},
		{fmt.Sprintf("JobStartDate >= %d", s), 0},
		{fmt.Sprintf("TARGET.QDate >= %d", s), 0},
		{"QDate >= CurrentTime - 86400", 0},
		{"QDate >= RemoteWallClockTime", 0},
		{fmt.Sprintf("QDate >= \"%d\"", s), 0},
		{fmt.Sprintf("(QDate >= %d) ? true : false", s), 0},
		{"QDate >= real(\"NaN\")", 0},
		{"QDate >= 1000", 0}, // below the slack: no positive bound
		{"QDate >=", 0},      // unparseable
	}
	for _, c := range cases {
		got, ok := HistoryFloor(c.constraint)
		if c.want == 0 {
			if ok {
				t.Errorf("HistoryFloor(%q) = %d, want none", c.constraint, got)
			}
			continue
		}
		if !ok || got != c.want {
			t.Errorf("HistoryFloor(%q) = %d, %v; want %d", c.constraint, got, ok, c.want)
		}
	}
}

// The point of the floor is a conjunct the archive can probe. The planner
// gets nothing from the window as written.
func TestWithHistoryFloorIsProbed(t *testing.T) {
	const s = 1757000000
	window := fmt.Sprintf("QDate < %d && QDate >= %d", s+86400, s)
	if hasProbe(t, window, HistoryOrderAttr) {
		t.Fatalf("%q already probes %s; the test proves nothing", window, HistoryOrderAttr)
	}
	got := WithHistoryFloor(window)
	if want := fmt.Sprintf("(%s) && EnteredHistoryTime >= %d", window, s-historyFloorSlack); got != want {
		t.Errorf("WithHistoryFloor = %q, want %q", got, want)
	}
	if !hasProbe(t, got, HistoryOrderAttr) {
		t.Errorf("%q gives the planner no %s probe", got, HistoryOrderAttr)
	}
}

func TestWithHistoryFloorUnchanged(t *testing.T) {
	const s = 1757000000
	for _, c := range []string{
		"true",
		"Owner == \"alice\"",
		fmt.Sprintf("QDate < %d", s),
		// A top-level bound on the stamp already at least as tight.
		fmt.Sprintf("EnteredHistoryTime >= %d", s),
		fmt.Sprintf("(QDate >= %d) && EnteredHistoryTime >= %d", s, s-10),
		fmt.Sprintf("QDate >= %d && (%d <= EnteredHistoryTime)", s, s),
	} {
		if got := WithHistoryFloor(c); got != c {
			t.Errorf("WithHistoryFloor(%q) = %q, want it unchanged", c, got)
		}
	}
	// A looser one is tightened.
	c := fmt.Sprintf("QDate >= %d && EnteredHistoryTime >= %d", s, s-2*historyFloorSlack)
	if got := WithHistoryFloor(c); got == c {
		t.Errorf("WithHistoryFloor(%q) left a looser bound alone", c)
	}
}

// On every record the mirror archives -- EnteredHistoryTime set, and no
// earlier than the job's own times by more than the slack -- the floor
// changes nothing: each constraint matches exactly the records it matched
// before. The job times range over values a record can carry, including
// undefined, an error, a string, a real, NaN and absent.
func TestWithHistoryFloorAgreesOnArchivedRecords(t *testing.T) {
	const base = 1757000000
	stamps := []int64{base - 3*86400, base - 86400, base - 1, base, base + 1, base + 86400}
	// A job time relative to its record's stamp: at most the slack after
	// it (clock skew), anywhere before it.
	offsets := []string{"-200000", "-86401", "-1", "+0", "+1", "+86399", "+86400"}
	odd := []string{"", "undefined", "error", `"1757000000"`, `real("NaN")`, "true"}

	var jobTimes []func(stamp int64) string
	for _, o := range offsets {
		jobTimes = append(jobTimes,
			func(stamp int64) string { return fmt.Sprintf("%d%s", stamp, o) },
			func(stamp int64) string { return fmt.Sprintf("real(%d%s) + 0.5", stamp, o) })
	}
	for _, v := range odd {
		jobTimes = append(jobTimes, func(int64) string { return v })
	}

	constraints := []string{
		fmt.Sprintf("QDate >= %d && QDate < %d", base, base+86400),
		fmt.Sprintf("QDate > %d", base-1),
		fmt.Sprintf("QDate == %d", base),
		fmt.Sprintf("%d <= QDate", base+1),
		fmt.Sprintf("QDate >= %d.5", base),
		fmt.Sprintf("EnteredCurrentStatus >= %d || CompletionDate >= %d", base, base),
		fmt.Sprintf("(Owner == \"alice\") && (EnteredCurrentStatus >= %d || CompletionDate >= %d)", base, base+86400),
		fmt.Sprintf("CompletionDate >= %d || EnteredHistoryTime >= %d", base, base),
		fmt.Sprintf("QDate >= %d && ClusterId <= 7 && (ClusterId < 7 || ProcId < 3)", base),
	}

	n := 0
	for _, c := range constraints {
		rewritten := WithHistoryFloor(c)
		if rewritten == c {
			t.Fatalf("%q has no floor; the comparison proves nothing", c)
		}
		orig := mustParse(t, c)
		floored := mustParse(t, rewritten)
		for _, stamp := range stamps {
			for _, q := range jobTimes {
				for _, cd := range jobTimes {
					for _, ecs := range []string{fmt.Sprint(stamp), q(stamp)} {
						ad := archivedRecord(t, stamp, q(stamp), cd(stamp), ecs)
						want, got := isTrue(orig.Eval(ad)), isTrue(floored.Eval(ad))
						if want != got {
							t.Fatalf("%s\n  original %q matched %v\n  floored  %q matched %v", ad, c, want, rewritten, got)
						}
						n++
					}
				}
			}
		}
	}
	t.Logf("%d evaluations agree", n)
}

// And it does change the answer for a record whose QDate is more than the
// slack after its stamp: that is the cost, and the test pins it down so the
// slack is not silently shrunk.
func TestWithHistoryFloorDropsAnImpossibleRecord(t *testing.T) {
	const base = 1757000000
	c := fmt.Sprintf("QDate >= %d", base)
	ad := archivedRecord(t, base-historyFloorSlack-1, fmt.Sprint(base), "0", fmt.Sprint(base-historyFloorSlack-1))
	if !isTrue(mustParse(t, c).Eval(ad)) {
		t.Fatal("the record should match the window")
	}
	if isTrue(mustParse(t, WithHistoryFloor(c)).Eval(ad)) {
		t.Error("a record stamped more than the slack before its QDate still matched")
	}
	ad = archivedRecord(t, base-historyFloorSlack, fmt.Sprint(base), "0", fmt.Sprint(base-historyFloorSlack))
	if !isTrue(mustParse(t, WithHistoryFloor(c)).Eval(ad)) {
		t.Error("a record stamped exactly the slack before its QDate was dropped")
	}
}

// archivedRecord is a history record as the mirror stores it: the stamp
// always set, the job times as given ("" leaves one off).
func archivedRecord(t *testing.T, stamp int64, qdate, completion, entered string) *classad.ClassAd {
	t.Helper()
	parts := []string{"Owner = \"alice\"", "ClusterId = 7", "ProcId = 1", fmt.Sprintf("%s = %d", HistoryOrderAttr, stamp)}
	for _, kv := range [][2]string{{"QDate", qdate}, {"CompletionDate", completion}, {"EnteredCurrentStatus", entered}} {
		if kv[1] != "" {
			parts = append(parts, kv[0]+" = "+kv[1])
		}
	}
	ad, err := classad.Parse("[" + strings.Join(parts, "; ") + "]")
	if err != nil {
		t.Fatalf("record %v: %v", parts, err)
	}
	return ad
}

func mustParse(t *testing.T, s string) *classad.Expr {
	t.Helper()
	e, err := classad.ParseExpr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return e
}

func isTrue(v classad.Value) bool {
	b, err := v.BoolValue()
	return err == nil && b
}

// hasProbe reports whether the archive planner gets a probe on attr from
// constraint.
func hasProbe(t *testing.T, constraint, attr string) bool {
	t.Helper()
	q, err := vm.Parse(constraint)
	if err != nil {
		t.Fatalf("vm.Parse(%q): %v", constraint, err)
	}
	for _, p := range q.Probes() {
		if strings.EqualFold(p.Attr, attr) {
			return true
		}
	}
	return false
}
