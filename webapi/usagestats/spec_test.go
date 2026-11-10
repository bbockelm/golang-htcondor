package usagestats

import (
	"strings"
	"testing"
	"time"
)

// Two kinds must not collide anywhere that would make one overwrite
// the other: same table, same metric names, same tab.
func TestSpecsAreDistinctWhereItMatters(t *testing.T) {
	seen := map[string]map[string]string{
		"kind": {}, "table": {}, "subsystem+noun": {},
	}
	for _, spec := range Specs() {
		for field, value := range map[string]string{
			"kind":           spec.Kind,
			"table":          spec.Table,
			"subsystem+noun": spec.Subsystem + "_" + spec.Noun,
		} {
			if other, dup := seen[field][value]; dup {
				t.Errorf("%s %q is shared by %q and %q", field, value, other, spec.Kind)
			}
			seen[field][value] = spec.Kind
		}
		if spec.DefaultOutcome == "" || !spec.knownOutcome(spec.DefaultOutcome) {
			t.Errorf("%s: DefaultOutcome %q is not in its own vocabulary",
				spec.Kind, spec.DefaultOutcome)
		}
		if len(spec.Outcomes) == 0 || spec.Outcomes[0] != OutcomeOK {
			t.Errorf("%s: outcomes %v should lead with the success case", spec.Kind, spec.Outcomes)
		}
	}
}

// The MCP metric names are a wire contract: a dashboard or an alert
// that references one breaks silently if it is renamed, and the
// generalization that introduced the spec is exactly the change that
// could have done it.
func TestMCPMetricNamesAreUnchanged(t *testing.T) {
	spec := MCPSpec()
	for _, want := range []string{
		"htcondor_api_mcp_tool_calls_total",
		"htcondor_api_mcp_tool_duration_seconds",
		"htcondor_api_mcp_tool_last_call_timestamp_seconds",
		"htcondor_api_mcp_tool_users",
	} {
		got := "htcondor_api_" + spec.Subsystem + "_" + spec.Noun + "_" +
			strings.TrimPrefix(want, "htcondor_api_"+spec.Subsystem+"_"+spec.Noun+"_")
		if got != want {
			t.Errorf("metric name = %q, want %q", got, want)
		}
	}
	// The table and its key column are a contract with migration 0015.
	if spec.Table != "mcp_tool_stats" || spec.NameColumn != "tool" {
		t.Errorf("MCP spec writes to %s(%s); migration 0015 created mcp_tool_stats(tool)",
			spec.Table, spec.NameColumn)
	}
}

func TestRESTSpecMatchesItsMigration(t *testing.T) {
	spec := RESTSpec()
	if spec.Table != "rest_endpoint_stats" || spec.NameColumn != "endpoint" {
		t.Errorf("REST spec writes to %s(%s); migration 0029 created rest_endpoint_stats(endpoint)",
			spec.Table, spec.NameColumn)
	}
}

func TestSpecForKind(t *testing.T) {
	if spec, ok := SpecForKind("rest"); !ok || spec.Kind != "rest" {
		t.Errorf(`SpecForKind("rest") = %+v, %v`, spec, ok)
	}
	if _, ok := SpecForKind("nonsense"); ok {
		t.Error("SpecForKind accepted a kind nobody defines")
	}
}

// An outcome outside the vocabulary must not widen it. Outcome is a
// Prometheus label whose value set is supposed to be closed, and a
// store that accepted anything would widen it in the durable table as
// well as in the scrape.
func TestAnUnknownOutcomeFoldsIntoTheDefault(t *testing.T) {
	s := New(RESTSpec())
	// MCP's vocabulary used against the REST store: the kind of
	// mistake a shared package makes possible.
	s.Record("GET /api/v1/jobs", "alice", "curl", OutcomeUnknownTool, time.Millisecond)
	s.Record("GET /api/v1/jobs", "alice", "curl", "", time.Millisecond)

	for k, e := range s.Snapshot() {
		if k.Outcome != RESTSpec().DefaultOutcome {
			t.Errorf("outcome %q was recorded against the REST store (%d calls); "+
				"want it folded into %q", k.Outcome, e.Calls, RESTSpec().DefaultOutcome)
		}
	}
	if n := len(s.Snapshot()); n != 1 {
		t.Errorf("series = %d, want both calls folded onto one", n)
	}
}

// A summary row carries every outcome its spec defines, zero
// included: a column that vanished on a quiet day would read as the
// feature being gone rather than as nothing having happened.
func TestEveryOutcomeHasAColumn(t *testing.T) {
	for _, spec := range Specs() {
		s := New(spec)
		s.Record("something", "alice", "curl", OutcomeOK, time.Millisecond)
		summary := Summarize(spec, s.Snapshot(), Filter{})
		if summary.Kind != spec.Kind || summary.Noun != spec.Noun {
			t.Errorf("summary = %q/%q, want %q/%q",
				summary.Kind, summary.Noun, spec.Kind, spec.Noun)
		}
		for _, outcome := range spec.Outcomes {
			if _, ok := summary.Totals.Outcomes[outcome]; !ok {
				t.Errorf("%s: totals carry no %q column", spec.Kind, outcome)
			}
			for _, row := range summary.ByName {
				if _, ok := row.Outcomes[outcome]; !ok {
					t.Errorf("%s: row %q carries no %q column", spec.Kind, row.Name, outcome)
				}
			}
		}
	}
}

// A row persisted under an outcome the spec no longer lists still
// counts toward the total; it just has no column. Dropping it from
// Calls would make the figures disagree with the table.
func TestARetiredOutcomeStillCountsTowardTheTotal(t *testing.T) {
	spec := RESTSpec()
	snap := map[Key]Entry{
		{Name: "GET /x", User: "alice", Client: "curl", Outcome: OutcomeOK}:      {Calls: 3},
		{Name: "GET /x", User: "alice", Client: "curl", Outcome: "retired_2024"}: {Calls: 2},
	}
	summary := Summarize(spec, snap, Filter{})
	if summary.Totals.Calls != 5 {
		t.Errorf("calls = %d, want 5", summary.Totals.Calls)
	}
	if _, ok := summary.Totals.Outcomes["retired_2024"]; ok {
		t.Error("a retired outcome was given a column the vocabulary does not admit")
	}
}

// The MCP outcome strings are a wire contract with the mcpserver
// package, which spells them out rather than importing this one (see
// its ToolStatsRecorder comment). Its side is pinned by a test of its
// own; this is the other side.
//
// It matters more than it used to. Record now folds an outcome
// outside the spec into the default, so a rename here would no longer
// show up as a strange label on the page -- every refused call would
// quietly become an error.
func TestMCPOutcomeStringsArePinned(t *testing.T) {
	spec := MCPSpec()
	want := []string{"ok", "error", "refused", "unknown_tool"}
	if len(spec.Outcomes) != len(want) {
		t.Fatalf("outcomes = %v, want %v", spec.Outcomes, want)
	}
	for i, w := range want {
		if spec.Outcomes[i] != w {
			t.Errorf("outcome %d = %q, want %q; mcpserver sends the literal",
				i, spec.Outcomes[i], w)
		}
	}
}

// The REST outcome strings are a contract with the admin page, which
// renders a column per outcome, and with any dashboard built on the
// label.
func TestRESTOutcomeStringsArePinned(t *testing.T) {
	want := []string{"ok", "denied", "not_found", "rate_limited", "client_error", "error"}
	got := RESTSpec().Outcomes
	if len(got) != len(want) {
		t.Fatalf("outcomes = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("outcome %d = %q, want %q", i, got[i], w)
		}
	}
}
