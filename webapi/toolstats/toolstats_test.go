package toolstats

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestRecordCountsCallsAndDuration(t *testing.T) {
	s := New()
	s.Record("query_jobs", "bbockelm", "claude-code/2.1", OutcomeOK, 300*time.Millisecond)
	s.Record("query_jobs", "bbockelm", "claude-code/2.1", OutcomeOK, 700*time.Millisecond)

	snap := s.Snapshot()
	e, ok := snap[Key{"query_jobs", "bbockelm", "claude-code/2.1", OutcomeOK}]
	if !ok {
		t.Fatalf("series missing: %+v", snap)
	}
	if e.Calls != 2 {
		t.Errorf("Calls = %d, want 2", e.Calls)
	}
	if e.DurationSum < 0.999 || e.DurationSum > 1.001 {
		t.Errorf("DurationSum = %v, want ~1.0", e.DurationSum)
	}
}

// TestRecordPlacesEachCallInExactlyOneBucket: the buckets are stored
// NON-cumulative and made cumulative at render time. Double-counting
// here would inflate every quantile downstream, and is invisible unless
// the boundaries are checked individually.
func TestRecordPlacesEachCallInExactlyOneBucket(t *testing.T) {
	for _, tc := range []struct {
		name string
		d    time.Duration
		want int // index into DurationBuckets, -1 for "beyond the last"
	}{
		{"below the first boundary", 1 * time.Millisecond, 0},
		{"exactly on a boundary", 100 * time.Millisecond, 2},
		{"just over a boundary", 101 * time.Millisecond, 3},
		{"beyond the last boundary", 10 * time.Minute, -1},
		{"zero", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := New()
			s.Record("t", "u", "c", OutcomeOK, tc.d)
			e := s.Snapshot()[Key{"t", "u", "c", OutcomeOK}]

			var total uint64
			for i, n := range e.Buckets {
				total += n
				if tc.want >= 0 && i == tc.want && n != 1 {
					t.Errorf("bucket %d (<=%v) = %d, want 1", i, DurationBuckets[i], n)
				}
				if (tc.want < 0 || i != tc.want) && n != 0 {
					t.Errorf("bucket %d (<=%v) = %d, want 0", i, DurationBuckets[i], n)
				}
			}
			if tc.want < 0 && total != 0 {
				t.Errorf("a call past the last boundary landed in a bucket")
			}
			// Whatever the buckets say, the call is always counted --
			// that is what makes Calls the histogram's _count.
			if e.Calls != 1 {
				t.Errorf("Calls = %d, want 1", e.Calls)
			}
		})
	}
}

func TestRecordFillsInMissingIdentity(t *testing.T) {
	s := New()
	s.Record("get_job", "", "", OutcomeOK, time.Second)
	if _, ok := s.Snapshot()[Key{"get_job", UnknownUser, UnknownClient, OutcomeOK}]; !ok {
		t.Errorf("an unidentified call was not recorded as unknown: %+v", s.Snapshot())
	}
}

// A tools/call whose params did not parse never named a tool. Counting
// it would put protocol errors in the same table as tool results.
func TestRecordIgnoresACallWithNoTool(t *testing.T) {
	s := New()
	s.Record("", "u", "c", OutcomeError, time.Second)
	if n := len(s.Snapshot()); n != 0 {
		t.Errorf("recorded %d series for a call that named no tool", n)
	}
}

// A clock that steps backwards mid-call yields a negative duration. It
// must not reach the histogram sum, which every later reader derives
// an average from.
func TestRecordClampsANegativeDuration(t *testing.T) {
	s := New()
	s.Record("t", "u", "c", OutcomeOK, -5*time.Second)
	e := s.Snapshot()[Key{"t", "u", "c", OutcomeOK}]
	if e.DurationSum != 0 {
		t.Errorf("DurationSum = %v, want 0", e.DurationSum)
	}
	if e.Calls != 1 {
		t.Errorf("the call itself was dropped: Calls = %d", e.Calls)
	}
}

// TestLabelSpaceKeepsTheBusiestWhenItMustCollapse pins the safety
// valve. Under the ceiling nothing is touched; over it, the series an
// operator most wants to see keep their names.
func TestLabelSpaceKeepsTheBusiestWhenItMustCollapse(t *testing.T) {
	totals := map[string]uint64{"alice": 100, "bob": 50, "carol": 10, "dave": 1}

	all := labelSpace(totals, 10)
	for name := range totals {
		if all[name] != name {
			t.Errorf("under the ceiling, %q was collapsed to %q", name, all[name])
		}
	}

	two := labelSpace(totals, 2)
	if two["alice"] != "alice" || two["bob"] != "bob" {
		t.Errorf("the busiest values lost their identity: %+v", two)
	}
	if two["carol"] != OtherLabel || two["dave"] != OtherLabel {
		t.Errorf("the quiet values were not collapsed: %+v", two)
	}
}

// Equal volumes must break ties by name: a scrape that reshuffled its
// label values between ticks would show every affected series as
// ending and a new one starting.
func TestLabelSpaceIsDeterministicOnTies(t *testing.T) {
	totals := map[string]uint64{"a": 5, "b": 5, "c": 5, "d": 5}
	first := labelSpace(totals, 2)
	for i := 0; i < 50; i++ {
		if got := labelSpace(totals, 2); fmt.Sprint(got) != fmt.Sprint(first) {
			t.Fatalf("label space is not deterministic: %+v vs %+v", got, first)
		}
	}
	if first["a"] != "a" || first["b"] != "b" {
		t.Errorf("ties did not break by name: %+v", first)
	}
}

func TestSetMaxLabelValuesRefusesToDisableTheBound(t *testing.T) {
	s := New()
	for _, n := range []int{0, -1} {
		s.SetMaxLabelValues(n)
		if s.maxLabelValues != DefaultMaxLabelValues {
			t.Errorf("SetMaxLabelValues(%d) left the ceiling at %d; an unbounded label "+
				"space must not be reachable by configuration", n, s.maxLabelValues)
		}
	}
}

// TestCollectSumsCollapsedSeriesRatherThanEmittingThemTwice is the
// bug this guards: two users collapsed to "other" produce the same
// label set, and prometheus treats a duplicate label set as a
// collection error that drops the WHOLE scrape -- not just the
// offending metric.
func TestCollectSumsCollapsedSeriesRatherThanEmittingThemTwice(t *testing.T) {
	s := New()
	s.SetMaxLabelValues(1)
	s.Record("query_jobs", "alice", "cc", OutcomeOK, time.Second) // busiest, keeps its name
	s.Record("query_jobs", "alice", "cc", OutcomeOK, time.Second)
	s.Record("query_jobs", "bob", "cc", OutcomeOK, time.Second)   // collapses
	s.Record("query_jobs", "carol", "cc", OutcomeOK, time.Second) // collapses

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(s))
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v (a duplicate label set drops the entire scrape)", err)
	}

	got := map[string]float64{}
	for _, f := range families {
		if f.GetName() != "htcondor_api_mcp_tool_calls_total" {
			continue
		}
		for _, m := range f.Metric {
			got[labelValue(m, "user")] += m.GetCounter().GetValue()
		}
	}
	if got["alice"] != 2 {
		t.Errorf("alice = %v, want 2", got["alice"])
	}
	if got[OtherLabel] != 2 {
		t.Errorf("%s = %v, want 2 (bob and carol summed)", OtherLabel, got[OtherLabel])
	}
}

// The distinct-user gauge is counted over the VERBATIM names, so it
// stays right exactly where the label has stopped being able to say so.
func TestUserGaugeCountsRealUsersEvenWhenTheLabelCollapsed(t *testing.T) {
	s := New()
	s.SetMaxLabelValues(1)
	for _, u := range []string{"alice", "bob", "carol"} {
		s.Record("query_jobs", u, "cc", OutcomeOK, time.Second)
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(s))
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "htcondor_api_mcp_tool_users" {
			continue
		}
		if v := f.Metric[0].GetGauge().GetValue(); v != 3 {
			t.Errorf("tool_users = %v, want 3", v)
		}
		return
	}
	t.Errorf("no htcondor_api_mcp_tool_users metric was produced")
}

// An "unknown" user is not a user. Counting it would report a tool
// nobody has authenticated against as having one user.
func TestUserGaugeDoesNotCountTheUnknownUser(t *testing.T) {
	s := New()
	s.Record("get_job", "", "cc", OutcomeOK, time.Second)
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(s))
	families, _ := reg.Gather()
	for _, f := range families {
		if f.GetName() != "htcondor_api_mcp_tool_users" {
			continue
		}
		if v := f.Metric[0].GetGauge().GetValue(); v != 0 {
			t.Errorf("tool_users = %v, want 0", v)
		}
	}
}

// The histogram must be cumulative and its count must cover calls that
// fell past the last boundary -- otherwise prometheus rejects it.
func TestCollectHistogramIsCumulativeAndCountsEveryCall(t *testing.T) {
	s := New()
	s.Record("watch_jobs", "u", "cc", OutcomeOK, 10*time.Millisecond)
	s.Record("watch_jobs", "u", "cc", OutcomeOK, 2*time.Second)
	s.Record("watch_jobs", "u", "cc", OutcomeOK, 20*time.Minute) // past the last bucket

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(s))
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "htcondor_api_mcp_tool_duration_seconds" {
			continue
		}
		h := f.Metric[0].GetHistogram()
		if h.GetSampleCount() != 3 {
			t.Errorf("sample count = %d, want 3 (the long call must still be counted)",
				h.GetSampleCount())
		}
		var prev uint64
		for _, b := range h.Bucket {
			if b.GetCumulativeCount() < prev {
				t.Errorf("buckets are not cumulative: %d after %d", b.GetCumulativeCount(), prev)
			}
			prev = b.GetCumulativeCount()
		}
		if prev != 2 {
			t.Errorf("last bucket = %d, want 2; the 20-minute call must be in none of them", prev)
		}
		return
	}
	t.Errorf("no duration histogram was produced")
}

// The duration histogram deliberately carries no user label: fourteen
// series per user per tool is the blowup this split exists to avoid.
func TestDurationHistogramCarriesNoUserLabel(t *testing.T) {
	s := New()
	s.Record("t", "alice", "cc", OutcomeOK, time.Second)
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(s))
	families, _ := reg.Gather()
	for _, f := range families {
		if f.GetName() != "htcondor_api_mcp_tool_duration_seconds" {
			continue
		}
		for _, l := range f.Metric[0].Label {
			if l.GetName() == "user" {
				t.Errorf("the duration histogram grew a user label")
			}
		}
	}
}

func TestLoadResizesBucketsWhenTheBoundariesChanged(t *testing.T) {
	s := New()
	s.Load(map[Key]Entry{
		{"t", "u", "c", OutcomeOK}: {Calls: 7, Buckets: []uint64{1, 2}}, // a shorter, older array
	})
	e := s.Snapshot()[Key{"t", "u", "c", OutcomeOK}]
	if len(e.Buckets) != len(DurationBuckets) {
		t.Errorf("buckets = %d, want %d", len(e.Buckets), len(DurationBuckets))
	}
	if e.Calls != 7 {
		t.Errorf("resizing the buckets lost the call count: %d", e.Calls)
	}
	if e.Buckets[0] != 1 || e.Buckets[1] != 2 {
		t.Errorf("resizing moved the existing counts: %v", e.Buckets)
	}
}

// A snapshot handed out must not alias the live state, or a flush in
// progress would read counts that changed underneath it.
func TestSnapshotDoesNotAliasLiveState(t *testing.T) {
	s := New()
	s.Record("t", "u", "c", OutcomeOK, time.Second)
	snap := s.Snapshot()
	s.Record("t", "u", "c", OutcomeOK, time.Second)
	if got := snap[Key{"t", "u", "c", OutcomeOK}].Calls; got != 1 {
		t.Errorf("the snapshot changed under the caller: Calls = %d, want 1", got)
	}
}

func TestOutcomeConstantsAreTheDocumentedStrings(t *testing.T) {
	// These are a wire contract: the mcpserver package spells them
	// independently so it need not import this one, and the SQLite
	// rows outlive any rename.
	for got, want := range map[string]string{
		OutcomeOK: "ok", OutcomeError: "error", OutcomeRefused: "refused",
	} {
		if got != want {
			t.Errorf("outcome constant = %q, want %q", got, want)
		}
	}
}

func labelValue(m *dto.Metric, name string) string {
	for _, l := range m.Label {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

// The help text is what an operator reads at 3am. Keep the promises
// the comments make -- particularly that the counter survives restart,
// which is surprising enough to be worth saying on the metric itself.
func TestHelpTextSaysTheCounterSurvivesRestart(t *testing.T) {
	reg := prometheus.NewRegistry()
	s := New()
	s.Record("t", "u", "c", OutcomeOK, time.Second)
	reg.MustRegister(NewCollector(s))
	families, _ := reg.Gather()
	for _, f := range families {
		if f.GetName() == "htcondor_api_mcp_tool_calls_total" {
			if !strings.Contains(strings.ToLower(f.GetHelp()), "startup") {
				t.Errorf("the counter's help does not mention that it resumes: %q", f.GetHelp())
			}
			return
		}
	}
	t.Errorf("the calls counter was not produced at all")
}

// TestHallucinatedToolNamesCannotMintUnboundedLabels: the tool label
// looks like it comes from a fixed catalogue, but an unknown-tool call
// is recorded under whatever name the caller sent. Ordering by volume
// is what keeps the real tools from being the ones collapsed.
func TestHallucinatedToolNamesCannotMintUnboundedLabels(t *testing.T) {
	s := New()
	s.SetMaxLabelValues(2)
	for i := 0; i < 10; i++ {
		s.Record("query_jobs", "u", "c", OutcomeOK, time.Second)
	}
	for i := 0; i < 5; i++ {
		s.Record("get_job", "u", "c", OutcomeOK, time.Second)
	}
	for i := 0; i < 100; i++ {
		s.Record(fmt.Sprintf("invented_tool_%d", i), "u", "c", OutcomeUnknownTool, time.Millisecond)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(s))
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	tools := map[string]bool{}
	for _, f := range families {
		if f.GetName() != "htcondor_api_mcp_tool_calls_total" {
			continue
		}
		for _, m := range f.Metric {
			tools[labelValue(m, "tool")] = true
		}
	}
	if !tools["query_jobs"] || !tools["get_job"] {
		t.Errorf("a real tool was collapsed while invented ones were kept: %v", tools)
	}
	if len(tools) > 3 { // the two real ones plus "other"
		t.Errorf("102 distinct tool names produced %d labels: %v", len(tools), tools)
	}
}

func TestUnknownToolIsItsOwnOutcome(t *testing.T) {
	if OutcomeUnknownTool != "unknown_tool" {
		t.Errorf("OutcomeUnknownTool = %q", OutcomeUnknownTool)
	}
	if OutcomeUnknownTool == OutcomeError {
		t.Errorf("an unknown tool and a failed tool must not share an outcome")
	}
}
