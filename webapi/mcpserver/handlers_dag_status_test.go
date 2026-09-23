package mcpserver

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// dagAd builds a job ad from attribute values, so the decisions below
// can be exercised without a schedd.
func dagAd(t *testing.T, attrs map[string]interface{}) *classad.ClassAd {
	t.Helper()
	ad := classad.New()
	for k, v := range attrs {
		if err := ad.Set(k, v); err != nil {
			t.Fatalf("setting %s: %v", k, err)
		}
	}
	return ad
}

// dagStatusText renders the workflow section get_job appends for a
// DAGMan job ad.
func dagStatusText(t *testing.T, attrs map[string]interface{}) string {
	t.Helper()
	return renderDagSection(7, dagAd(t, attrs))
}

// TestDagSectionSeparatesSpoolingFromStuck is the distinction that
// decides whether a caller waits or acts.
//
// Both states are JobStatus 5. A workflow spooling its input will start on
// its own; one held for any other reason never will. Reporting them the
// same way told an agent to keep waiting on a workflow that had already
// failed -- which is exactly what happened to the integration test, at a
// cost of five minutes per run.
func TestDagSectionSeparatesSpoolingFromStuck(t *testing.T) {
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

// TestDagSectionHeldWithNoCodeIsStuck: an ad with no HoldReasonCode is
// not evidence of a spooling hold. Treating the missing value as
// "probably spooling" is the fail-open version of this check.
func TestDagSectionHeldWithNoCodeIsStuck(t *testing.T) {
	got := dagStatusText(t, map[string]interface{}{"JobStatus": 5})
	if !strings.Contains(got, "STUCK") {
		t.Errorf("a hold with no code should be treated as terminal, not assumed benign:\n%s", got)
	}
}

// TestDagSectionRunningWithoutProgressIsNotAlarming: DAGMan publishes its
// node counts only once it has parsed the DAG, so a just-started workflow
// legitimately has none. That must not read as a failure.
func TestDagSectionRunningWithoutProgressIsNotAlarming(t *testing.T) {
	got := dagStatusText(t, map[string]interface{}{"JobStatus": 2})
	if strings.Contains(got, "STUCK") {
		t.Errorf("a running workflow with no counts yet was reported as stuck:\n%s", got)
	}
	if !strings.Contains(got, "has not published progress yet") {
		t.Errorf("the normal just-started case lost its explanation:\n%s", got)
	}
}

// TestDagSectionPointsAtTheNodeJobs. The node jobs used to be behind an
// include_nodes flag, which meant a caller that did not know to pass it
// was never told the link existed. Naming the constraint costs one line
// and works for the finished nodes too, which no flag could reach: they
// have left the queue.
func TestDagSectionPointsAtTheNodeJobs(t *testing.T) {
	got := dagStatusText(t, map[string]interface{}{"JobStatus": 2, "DAG_NodesTotal": 3})
	for _, want := range []string{
		`query_jobs(constraint="DAGManJobId == 7")`,
		"query_job_archive",
		"DAGNodeName",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the section never mentions %q:\n%s", want, got)
		}
	}
}

// TestDagSectionIsOnlyForDagManJobs. The detection is what decides
// whether an ordinary job's answer grows a workflow report that means
// nothing for it.
//
// Two tests, because neither covers the whole life of a workflow:
// DAG_NodesTotal only appears once DAGMan has published, and Cmd is
// there from submission -- which is the window in which a workflow is
// spooling or stuck, and most needs explaining.
func TestDagSectionIsOnlyForDagManJobs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs map[string]interface{}
		want  bool
	}{
		{"published counts", map[string]interface{}{"DAG_NodesTotal": 3, "Cmd": "/bin/sh"}, true},
		{"dagman path", map[string]interface{}{"Cmd": "/usr/bin/condor_dagman"}, true},
		{"relocated dagman", map[string]interface{}{"Cmd": "/opt/condor/bin/condor_dagman"}, true},
		{"bare name", map[string]interface{}{"Cmd": "condor_dagman"}, true},
		{"vanilla job", map[string]interface{}{"Cmd": "/bin/sleep", "JobStatus": 2}, false},
		// A name that merely ends in the same letters is not the binary.
		{"lookalike", map[string]interface{}{"Cmd": "/usr/bin/not_condor_dagman"}, false},
		{"no Cmd at all", map[string]interface{}{"JobStatus": 1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDagManJob(dagAd(t, tc.attrs)); got != tc.want {
				t.Errorf("isDagManJob(%v) = %v, want %v", tc.attrs, got, tc.want)
			}
		})
	}
}

// TestDagSectionNamesTheDagFile. Everything a caller has to go looking
// for in the spool is named after the DAG -- DAGMan's own log and the
// rescue DAG -- and nothing in the job ad records the name except the
// arguments. Printing "<dag>.dagman.out" hands the caller a riddle in
// place of a file name.
func TestDagSectionNamesTheDagFile(t *testing.T) {
	failed := renderDagSection(7, dagAd(t, map[string]interface{}{
		"JobStatus": 2, "DAG_NodesTotal": 3, "DAG_NodesFailed": 1,
		"Arguments": "-f -l . -Lockfile diamond.dag.lock -Dag diamond.dag -MaxIdle 5",
	}))
	if !strings.Contains(failed, "diamond.dag.rescue001") {
		t.Errorf("the rescue DAG is not named after the workflow:\n%s", failed)
	}
	if strings.Contains(failed, "<dag>") {
		t.Errorf("the placeholder survived even though the name was recoverable:\n%s", failed)
	}
	if !strings.Contains(failed, "DAG file: diamond.dag") {
		t.Errorf("the section does not say which DAG it is:\n%s", failed)
	}

	done := renderDagSection(7, dagAd(t, map[string]interface{}{
		"JobStatus": 4, "DAG_NodesTotal": 3, "DAG_NodesDone": 3,
		"Args": "-f -l . -Dag pipeline.dag",
	}))
	if !strings.Contains(done, "pipeline.dagman.out") {
		t.Errorf("DAGMan's log is not named, and Args was not read:\n%s", done)
	}

	// No arguments at all: the placeholder is the fallback, not a crash
	// and not a wrong name.
	none := renderDagSection(7, dagAd(t, map[string]interface{}{
		"JobStatus": 2, "DAG_NodesTotal": 3, "DAG_NodesFailed": 1,
	}))
	if !strings.Contains(none, "<dag>.dag.rescue001") {
		t.Errorf("an unrecoverable name did not fall back to the placeholder:\n%s", none)
	}
}

// TestDagFileFromAdParsesRealArguments. The hand-written argument
// strings above are only as good as this project's idea of what it
// generates, so the extraction is also run against the argument string
// the generator actually produces, round-tripped through the submit
// parser the way the schedd would see it.
func TestDagFileFromAdParsesRealArguments(t *testing.T) {
	ad := dagmanManagerJobAd(t, "diamond.dag")
	if got := dagFileFromAd(ad); got != "diamond.dag" {
		args, _ := ad.EvaluateAttrString("Arguments")
		if args == "" {
			args, _ = ad.EvaluateAttrString("Args")
		}
		t.Errorf("dagFileFromAd = %q, want diamond.dag (Arguments = %q)", got, args)
	}
}

// TestSplitV2ArgsGroupsQuotedRuns: a single-quoted run is one argument,
// which is how a -CsdVersion string with spaces in it survives. Splitting
// on whitespace alone would make the token after -Dag right by accident
// and everything after it wrong.
func TestSplitV2ArgsGroupsQuotedRuns(t *testing.T) {
	got := splitV2Args(`-Dag wf.dag -CsdVersion '$CondorVersion: 25.4.0 BuildID: test $' -MaxIdle 5`)
	want := []string{"-Dag", "wf.dag", "-CsdVersion", "$CondorVersion: 25.4.0 BuildID: test $", "-MaxIdle", "5"}
	if len(got) != len(want) {
		t.Fatalf("splitV2Args = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("token %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestGetJobAppendsTheDagSectionOnlyForWorkflows exercises the decision
// as get_job makes it: what a caller's answer gains, and what an
// ordinary job's answer must not gain.
//
// The negative half is the one worth having. A workflow report on a
// /bin/sleep job is not merely noise -- "DAGMan has not published
// progress yet" is a sentence that reads as a problem, on a job that has
// none.
func TestGetJobAppendsTheDagSectionOnlyForWorkflows(t *testing.T) {
	manager := map[string]interface{}{
		"JobStatus": 2, "DAG_NodesTotal": 3, "DAG_NodesDone": 1, "DAG_Status": 0,
		"Cmd": "/usr/bin/condor_dagman", "Arguments": "-f -l . -Dag diamond.dag",
	}
	structured := map[string]interface{}{"job_id": "7.0"}
	got := appendDagSection("Job 7.0:\n{}", structured, 7, dagAd(t, manager))
	if !strings.Contains(got, "--- DAGMan workflow ---") {
		t.Fatalf("a manager job's answer has no workflow section:\n%s", got)
	}
	if !strings.HasPrefix(got, "Job 7.0:\n{}") {
		t.Errorf("the section replaced the job ad rather than following it:\n%s", got)
	}
	if !strings.Contains(got, "nodes: 3 total, 1 done") {
		t.Errorf("the node counts are missing:\n%s", got)
	}
	dag, ok := structured["dag"].(map[string]interface{})
	if !ok {
		t.Fatalf("structured content carries no dag object: %v", structured)
	}
	for attr, want := range map[string]interface{}{
		"dag_nodestotal": int64(3), "dag_nodesdone": int64(1),
		"dag_status": int64(0), "job_status": int64(2), "dag_file": "diamond.dag",
	} {
		if dag[attr] != want {
			t.Errorf("dag[%q] = %v (%T), want %v", attr, dag[attr], dag[attr], want)
		}
	}

	vanilla := map[string]interface{}{"JobStatus": 2, "Cmd": "/bin/sleep", "ClusterId": 7}
	plain := map[string]interface{}{"job_id": "7.0"}
	if got := appendDagSection("Job 7.0:\n{}", plain, 7, dagAd(t, vanilla)); got != "Job 7.0:\n{}" {
		t.Errorf("an ordinary job's answer grew a workflow section:\n%s", got)
	}
	if _, ok := plain["dag"]; ok {
		t.Errorf("an ordinary job's structured content carries a dag object: %v", plain)
	}
}
