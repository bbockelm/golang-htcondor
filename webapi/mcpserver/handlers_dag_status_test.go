package mcpserver

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// dagStatusText renders dag_status's report for a job ad, so the
// hold-versus-spooling decision can be tested without a schedd.
func dagStatusText(t *testing.T, attrs map[string]interface{}) string {
	t.Helper()
	ad := classad.New()
	for k, v := range attrs {
		if err := ad.Set(k, v); err != nil {
			t.Fatalf("setting %s: %v", k, err)
		}
	}
	return renderDagStatus(7, OwnerScope{Owner: "alice"}, ad)
}

// TestDagStatusSeparatesSpoolingFromStuck is the distinction that decides
// whether a caller waits or acts.
//
// Both states are JobStatus 5. A workflow spooling its input will start on
// its own; one held for any other reason never will. Reporting them the
// same way told an agent to keep waiting on a workflow that had already
// failed -- which is exactly what happened to the integration test, at a
// cost of five minutes per run.
func TestDagStatusSeparatesSpoolingFromStuck(t *testing.T) {
	spooling := dagStatusText(t, map[string]interface{}{
		"JobStatus": 5, "HoldReasonCode": 16, "HoldReason": "Spooling input data files",
	})
	if strings.Contains(spooling, "STUCK") {
		t.Errorf("a job spooling its input was reported as stuck:\n%s", spooling)
	}
	if !strings.Contains(spooling, "clears on its own") {
		t.Errorf("a spooling hold should say it resolves itself:\n%s", spooling)
	}

	stuck := dagStatusText(t, map[string]interface{}{
		"JobStatus": 5, "HoldReasonCode": 13, "HoldReason": "Transfer input files failure",
	})
	if !strings.Contains(stuck, "STUCK") {
		t.Errorf("a job held for a reason that will not clear was not flagged:\n%s", stuck)
	}
	if !strings.Contains(stuck, "Transfer input files failure") {
		t.Errorf("the hold reason is what the caller acts on, and it is missing:\n%s", stuck)
	}
	if strings.Contains(stuck, "clears on its own") {
		t.Errorf("a terminal hold was described as self-resolving:\n%s", stuck)
	}
}

// TestDagStatusHeldWithNoCodeIsStuck: an ad with no HoldReasonCode is not
// evidence of a spooling hold. Treating the missing value as "probably
// spooling" is the fail-open version of this check.
func TestDagStatusHeldWithNoCodeIsStuck(t *testing.T) {
	got := dagStatusText(t, map[string]interface{}{"JobStatus": 5})
	if !strings.Contains(got, "STUCK") {
		t.Errorf("a hold with no code should be treated as terminal, not assumed benign:\n%s", got)
	}
}

// TestDagStatusRunningWithoutProgressIsNotAlarming: DAGMan publishes its
// node counts only once it has parsed the DAG, so a just-started workflow
// legitimately has none. That must not read as a failure.
func TestDagStatusRunningWithoutProgressIsNotAlarming(t *testing.T) {
	got := dagStatusText(t, map[string]interface{}{"JobStatus": 2})
	if strings.Contains(got, "STUCK") {
		t.Errorf("a running workflow with no counts yet was reported as stuck:\n%s", got)
	}
	if !strings.Contains(got, "has not published progress yet") {
		t.Errorf("the normal just-started case lost its explanation:\n%s", got)
	}
}
