package dagman

import (
	"strings"
	"testing"
)

// findingAbout returns the first finding whose message mentions all the
// given substrings, so a test can name what it is looking for rather than
// depending on finding order.
func findingAbout(r *Report, want ...string) *Finding {
	for i := range r.Findings {
		ok := true
		for _, w := range want {
			if !strings.Contains(r.Findings[i].Message, w) {
				ok = false
				break
			}
		}
		if ok {
			return &r.Findings[i]
		}
	}
	return nil
}

func TestAnalyzeCleanSelfContainedWorkflow(t *testing.T) {
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag: `
SUBMIT-DESCRIPTION work {
    executable = /bin/echo
    transfer_executable = false
    arguments = "hello"
}
JOB A work
JOB B work
PARENT A CHILD B
`,
	})
	if r.Fatal() {
		t.Fatalf("a self-contained workflow was refused: %v", r.Errors())
	}
	if len(r.Findings) != 0 {
		t.Errorf("unexpected findings: %+v", r.Findings)
	}
	// The DAG itself must be in the spool allow-set or the schedd drops
	// it and DAGMan starts with nothing to run.
	if len(r.Required) != 1 || r.Required[0] != "wf.dag" {
		t.Errorf("Required = %v, want [wf.dag]", r.Required)
	}
}

func TestAnalyzeMissingSubmitFileIsReported(t *testing.T) {
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag:     "JOB A analysis.sub\n",
		Files:   map[string]string{"analyze.sub": "executable = /bin/true\nqueue\n"},
	})
	if f := findingAbout(r, "analysis.sub", "not among the supplied files"); f == nil {
		t.Errorf("the missing submit file was not reported: %+v", r.Findings)
	}
	// The supplied-but-unused half is the one that names the typo. Without
	// it the caller is told a file is missing but not that they sent a
	// near-miss, and a spooled file nothing references is silently dropped.
	if f := findingAbout(r, "analyze.sub", "nothing in the DAG references it"); f == nil {
		t.Errorf("the unreferenced supplied file was not reported: %+v", r.Findings)
	}
}

func TestAnalyzeStagesNodeInputsWithTheDag(t *testing.T) {
	// A node job runs with Iwd set to the DAG's spool directory, so its
	// own inputs have to be in the DAG's spool. Forgetting this produces a
	// workflow that submits cleanly and fails on its first node.
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag: `
SUBMIT-DESCRIPTION work {
    executable = run.sh
    transfer_input_files = data.csv, https://example.org/big.tar
    input = stdin.txt
}
JOB A work
`,
		Files: map[string]string{
			"run.sh":    "#!/bin/sh\n",
			"data.csv":  "1,2\n",
			"stdin.txt": "",
		},
	})
	if r.Fatal() {
		t.Fatalf("refused: %v", r.Errors())
	}
	if len(r.Findings) != 0 {
		t.Fatalf("unexpected findings: %+v", r.Findings)
	}
	got := strings.Join(r.Required, ",")
	for _, want := range []string{"wf.dag", "run.sh", "data.csv", "stdin.txt"} {
		if !strings.Contains(got, want) {
			t.Errorf("Required = %v, missing %s", r.Required, want)
		}
	}
	// A URL is fetched by the execute node; staging it would pull the
	// bytes through the access point for nothing.
	if strings.Contains(got, "example.org") {
		t.Errorf("a URL was treated as a file to stage: %v", r.Required)
	}
}

func TestAnalyzeAbsoluteExecutableIsNotStaged(t *testing.T) {
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag: `
JOB A {
    executable = /bin/sh
    transfer_executable = false
}
`,
	})
	if len(r.Findings) != 0 {
		t.Errorf("/bin/sh was treated as something to stage: %+v", r.Findings)
	}
}

func TestAnalyzeSpliceIsFatalButSubdagIsNot(t *testing.T) {
	// This is the distinction the whole package is built around. SPLICE is
	// read when DAGMan parses the DAG; SUBDAG EXTERNAL is read when the
	// node becomes ready, which is what lets an earlier node generate it.
	splice := Analyze(Input{DagName: "wf.dag", Dag: "SPLICE S pieces.dag\n"})
	if !splice.Fatal() {
		t.Errorf("a missing SPLICE file should be fatal: %+v", splice.Findings)
	}

	subdag := Analyze(Input{DagName: "wf.dag", Dag: "SUBDAG EXTERNAL S stage2.dag\n"})
	if subdag.Fatal() {
		t.Fatalf("a missing SUBDAG file must NOT be fatal -- generating it during the run is the "+
			"documented idiom: %v", subdag.Errors())
	}
	if len(subdag.Deferred) != 1 || subdag.Deferred[0] != "stage2.dag" {
		t.Errorf("Deferred = %v, want [stage2.dag]", subdag.Deferred)
	}
	f := findingAbout(subdag, "stage2.dag")
	if f == nil {
		t.Fatalf("the deferred sub-DAG was not mentioned at all: %+v", subdag.Findings)
	}
	if f.Severity != Advisory {
		t.Errorf("an unattributable SUBDAG file is severity %v, want Advisory: %s", f.Severity, f.Message)
	}
	// Naming it as arriving later must satisfy the reference, because the
	// name is what has to be decided at submit time; the bytes are not.
	declared := Analyze(Input{DagName: "wf.dag", Dag: "SUBDAG EXTERNAL S stage2.dag\n",
		Declared: []string{"stage2.dag"}})
	if len(declared.Deferred) != 0 || len(declared.Findings) != 0 {
		t.Errorf("a declared file should satisfy the reference: %+v %+v", declared.Deferred, declared.Findings)
	}
}

func TestAnalyzeSubdagProducerOrdering(t *testing.T) {
	// When a node declares the sub-DAG in transfer_output_files we can
	// name the producer, and then the useful question is whether anything
	// orders it before the SUBDAG node. Unordered, the sub-DAG can become
	// ready before the file exists.
	dag := `
SUBMIT-DESCRIPTION gen {
    executable = /bin/sh
    transfer_executable = false
    transfer_output_files = stage2.dag
}
JOB G gen
SUBDAG EXTERNAL S stage2.dag
%s
`
	unordered := Analyze(Input{DagName: "wf.dag", Dag: strings.Replace(dag, "%s", "", 1)})
	f := findingAbout(unordered, "stage2.dag", "not an ancestor")
	if f == nil {
		t.Fatalf("an unordered producer was not reported: %+v", unordered.Findings)
	}
	if f.Severity != Warning {
		t.Errorf("severity = %v, want Warning", f.Severity)
	}

	ordered := Analyze(Input{DagName: "wf.dag", Dag: strings.Replace(dag, "%s", "PARENT G CHILD S", 1)})
	if f := findingAbout(ordered, "not an ancestor"); f != nil {
		t.Errorf("a correctly ordered producer was still reported: %s", f.Message)
	}
}

func TestAnalyzeGraphErrorsAreFatal(t *testing.T) {
	cycle := Analyze(Input{DagName: "wf.dag", Dag: `
JOB A a.sub
JOB B b.sub
PARENT A CHILD B
PARENT B CHILD A
`, Files: map[string]string{"a.sub": "queue\n", "b.sub": "queue\n"}})
	if !cycle.Fatal() {
		t.Errorf("a cycle should be fatal: %+v", cycle.Findings)
	}
	if findingAbout(cycle, "cycle") == nil {
		t.Errorf("the cycle was not named: %+v", cycle.Findings)
	}

	dangling := Analyze(Input{DagName: "wf.dag", Dag: "JOB A a.sub\nPARENT A CHILD Nope\n",
		Files: map[string]string{"a.sub": "queue\n"}})
	if !dangling.Fatal() {
		t.Errorf("a CHILD naming an undeclared node should be fatal: %+v", dangling.Findings)
	}
}

func TestAnalyzeBasenameCollisionIsFatal(t *testing.T) {
	// The spool directory is flat: both paths become "data.txt" and one
	// silently overwrites the other, with no diagnostic from DAGMan or the
	// schedd.
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag: `
JOB A {
    executable = /bin/true
    transfer_executable = false
    transfer_input_files = runA/data.txt
}
JOB B {
    executable = /bin/true
    transfer_executable = false
    transfer_input_files = runB/data.txt
}
`,
	})
	if !r.Fatal() {
		t.Fatalf("a basename collision should be fatal: %+v", r.Findings)
	}
	if findingAbout(r, "data.txt", "overwrite") == nil {
		t.Errorf("the collision was not explained: %+v", r.Findings)
	}
}

func TestAnalyzeDirIsRefused(t *testing.T) {
	r := Analyze(Input{DagName: "wf.dag", Dag: "JOB A a.sub DIR subdir\n",
		Files: map[string]string{"a.sub": "queue\n"}})
	if !r.Fatal() {
		t.Errorf("DIR cannot be honored in a flat spool and should be refused: %+v", r.Findings)
	}
}

func TestAnalyzeIncludeIsFatalAndScriptIsNot(t *testing.T) {
	// INCLUDE is read when DAGMan parses the DAG, so the workflow cannot
	// start without it. A missing PRE script only fails that node, and
	// there are arrangements where it is already on the access point.
	inc := Analyze(Input{DagName: "wf.dag", Dag: "INCLUDE common.inc\n"})
	if !inc.Fatal() {
		t.Errorf("a missing INCLUDE should be fatal: %+v", inc.Findings)
	}

	script := Analyze(Input{DagName: "wf.dag", Dag: "JOB A a.sub\nSCRIPT PRE A pre.sh\n",
		Files: map[string]string{"a.sub": "queue\n"}})
	if script.Fatal() {
		t.Errorf("a missing PRE script should not be fatal: %v", script.Errors())
	}
	if findingAbout(script, "pre.sh") == nil {
		t.Errorf("the missing PRE script was not reported at all: %+v", script.Findings)
	}
}

func TestAnalyzeRequiredIncludesDeclaredButNotMissingFiles(t *testing.T) {
	// Required is the spool allow-set. A name the caller promised belongs
	// in it -- that is the whole reason to declare it up front. A file
	// that is merely referenced and will never arrive must NOT be in it:
	// naming a file that does not exist makes the spool transfer fail
	// outright, which is worse than the run-time error already warned about.
	r := Analyze(Input{
		DagName:  "wf.dag",
		Dag:      "JOB A a.sub\n",
		Files:    map[string]string{"a.sub": "executable = /bin/true\ntransfer_input_files = later.dat\nqueue\n"},
		Declared: []string{"later.dat"},
	})
	got := strings.Join(r.Required, ",")
	if !strings.Contains(got, "later.dat") {
		t.Errorf("a declared file is missing from the allow-set: %v", r.Required)
	}

	missing := Analyze(Input{
		DagName: "wf.dag",
		Dag:     "JOB A a.sub\n",
		Files:   map[string]string{"a.sub": "executable = /bin/true\ntransfer_input_files = never.dat\nqueue\n"},
	})
	if strings.Contains(strings.Join(missing.Required, ","), "never.dat") {
		t.Errorf("a file that will never arrive was put in the allow-set: %v", missing.Required)
	}
}

func TestAnalyzeMacroValuesAreNotGuessed(t *testing.T) {
	// VARS can give each node a different value, so a macro reference is
	// unresolvable here. Guessing would either demand a file nothing uses
	// or approve a workflow that is missing one.
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag: `
JOB A {
    executable = /bin/true
    transfer_executable = false
    transfer_input_files = $(infile)
}
VARS A infile="a.dat"
`,
	})
	if len(r.Findings) != 0 {
		t.Errorf("a macro-valued input produced findings: %+v", r.Findings)
	}
}
