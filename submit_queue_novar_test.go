package htcondor

import (
	"strings"
	"testing"
)

// TestQueueWithoutLoopVariable covers `queue [N] in (...)` and
// `queue [N] from ...` written without a loop variable, which HTCondor allows
// and which this parser used to drop on the floor: the item list was ignored
// and the statement degraded to a plain `queue [N]`, so the submission got the
// wrong number of jobs and none of the items.
//
// The expected values were taken from HTCondor's own parser (SubmitHash) for
// the same submit files.
func TestQueueWithoutLoopVariable(t *testing.T) {
	cases := []struct {
		name  string
		queue string
		args  []string
	}{
		// One job per item, the item bound to the default variable Item.
		{"in without count", "queue in (a, b)", []string{`"a"`, `"b"`}},
		// N jobs per item, item-major: every step of an item before the next.
		{"in with count", "queue 2 in (a, b)", []string{`"a"`, `"a"`, `"b"`, `"b"`}},
		{"in with count of one", "queue 1 in (a, b)", []string{`"a"`, `"b"`}},
		{"single item", "queue in (only)", []string{`"only"`}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sf, err := ParseSubmitFile(strings.NewReader(
				"executable = /bin/sleep\narguments = $(item)\n" + c.queue + "\n"))
			if err != nil {
				t.Fatalf("parse %q: %v", c.queue, err)
			}
			res, err := sf.Submit(1)
			if err != nil {
				t.Fatalf("submit: %v", err)
			}
			if len(res.ProcAds) != len(c.args) {
				t.Fatalf("%q produced %d procs, want %d", c.queue, len(res.ProcAds), len(c.args))
			}
			for i, want := range c.args {
				expr, ok := res.ProcAds[i].Lookup("Args")
				if !ok {
					t.Errorf("proc %d has no Args", i)
					continue
				}
				if got := expr.String(); got != want {
					t.Errorf("proc %d: $(item) expanded to %s, want %s", i, got, want)
				}
			}
		})
	}
}

// TestItemIsNotTheItemIndex pins that $(Item) is the item's VALUE, not its
// position. It used to be set to the index, so `queue in (a, b)` gave
// arguments 0 and 1 instead of a and b.
func TestItemIsNotTheItemIndex(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(
		"executable = /bin/sleep\narguments = $(item)-$(itemindex)\nqueue in (x, y)\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	want := []string{`"x-0"`, `"y-1"`}
	if len(res.ProcAds) != len(want) {
		t.Fatalf("got %d procs, want %d", len(res.ProcAds), len(want))
	}
	for i, w := range want {
		expr, ok := res.ProcAds[i].Lookup("Args")
		if !ok {
			t.Fatalf("proc %d has no Args", i)
		}
		if got := expr.String(); got != w {
			t.Errorf("proc %d: Args = %s, want %s", i, got, w)
		}
	}
}

// TestNamedLoopVariableLeavesItemUnset covers the other half: when the queue
// statement names its own variable, HTCondor does not also bind Item, so
// $(Item) expands to nothing. This parser bound it to the item index, so a
// submit file mentioning $(Item) alongside a named variable silently got a
// number.
func TestNamedLoopVariableLeavesItemUnset(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(
		"executable = /bin/sleep\narguments = [$(item)]\nqueue 2 x in (a, b)\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if len(res.ProcAds) != 4 {
		t.Fatalf("got %d procs, want 4", len(res.ProcAds))
	}
	for i, ad := range res.ProcAds {
		expr, ok := ad.Lookup("Args")
		if !ok {
			t.Fatalf("proc %d has no Args", i)
		}
		if got := expr.String(); got != `"[]"` {
			t.Errorf("proc %d: Args = %s, want \"[]\" -- $(Item) must be unset when the statement names its own variable", i, got)
		}
	}
}
