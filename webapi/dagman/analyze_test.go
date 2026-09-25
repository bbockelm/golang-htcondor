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

func TestAnalyzeMissingSubmitFileIsDeferredNotDemanded(t *testing.T) {
	// A submit file written to disk is not read until the node is
	// submitted, so a DAG may legitimately name one that an earlier node
	// will write. It is deferred exactly like a sub-DAG description.
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag:     "JOB A analysis.sub\n",
		Files:   map[string]string{"analyze.sub": "executable = /bin/true\nqueue\n"},
	})
	f := findingAbout(r, "analysis.sub")
	if f == nil {
		t.Fatalf("the unsupplied submit file was not mentioned at all: %+v", r.Findings)
	}
	if f.Severity != Advisory {
		t.Errorf("an unattributable submit file is severity %v, want Advisory: %s", f.Severity, f.Message)
	}
	if !strings.Contains(f.Message, "generated during the run is expected") {
		t.Errorf("the note does not say a generated submit file is supported: %s", f.Message)
	}
	if len(r.Deferred) != 1 || r.Deferred[0] != "analysis.sub" {
		t.Errorf("Deferred = %v, want [analysis.sub]", r.Deferred)
	}
	// The supplied-but-unused half still names the near-miss, but softly:
	// with a description generated at run time this analysis cannot see
	// every reference, so it must not call the file a misspelling.
	u := findingAbout(r, "analyze.sub", "references it")
	if u == nil {
		t.Fatalf("the unreferenced supplied file was not reported: %+v", r.Findings)
	}
	if u.Severity != Advisory {
		t.Errorf("unreferenced-file severity = %v, want Advisory", u.Severity)
	}
	if strings.Contains(u.Message, "usually a misspelling") {
		t.Errorf("the analyzer claimed a misspelling it cannot see: %s", u.Message)
	}
	if !strings.Contains(u.Message, "generated at run time") {
		t.Errorf("the note does not say why it cannot tell: %s", u.Message)
	}
}

func TestAnalyzeUnreferencedFileIsBluntWhenNothingIsHidden(t *testing.T) {
	// The softened wording is for when the analyzer is blind. When every
	// referrer IS visible, the near-miss diagnosis is earned.
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag: `
JOB A {
    executable = /bin/true
    transfer_executable = false
}
`,
		Files: map[string]string{"stray.dat": "x\n"},
	})
	f := findingAbout(r, "stray.dat", "references it")
	if f == nil {
		t.Fatalf("the unreferenced supplied file was not reported: %+v", r.Findings)
	}
	if !strings.Contains(f.Message, "usually a misspelling") {
		t.Errorf("a fully visible DAG should still name the near-miss: %s", f.Message)
	}
}

func TestAnalyzeDeferredSubmitFileOrdering(t *testing.T) {
	// The reviewer's input: a node generates another node's submit file.
	// With the edge in place there is nothing to report; without it, the
	// sub-DAG ordering warning applies to submit files too.
	dag := `
SUBMIT-DESCRIPTION gen {
    executable = /bin/sh
    transfer_executable = false
    transfer_output_files = a.sub
}
JOB G gen
JOB A a.sub
%s
`
	ordered := Analyze(Input{DagName: "wf.dag", Dag: strings.Replace(dag, "%s", "PARENT G CHILD A", 1)})
	for _, f := range ordered.Findings {
		if f.Severity > Advisory {
			t.Errorf("a generated submit file with an edge produced %v: %s", f.Severity, f.Message)
		}
	}
	if len(ordered.Deferred) != 1 || ordered.Deferred[0] != "a.sub" {
		t.Errorf("Deferred = %v, want [a.sub]", ordered.Deferred)
	}

	unordered := Analyze(Input{DagName: "wf.dag", Dag: strings.Replace(dag, "%s", "", 1)})
	f := findingAbout(unordered, "a.sub", "not an ancestor")
	if f == nil {
		t.Fatalf("an unordered submit-file producer was not reported: %+v", unordered.Findings)
	}
	if f.Severity != Warning {
		t.Errorf("severity = %v, want Warning", f.Severity)
	}
}

func TestAnalyzeDeclaredSubmitDescriptionIsFlagged(t *testing.T) {
	// A description that arrives later is satisfied as a name, but its own
	// inputs cannot be checked -- and they have to be declared too.
	r := Analyze(Input{DagName: "wf.dag", Dag: "JOB A a.sub\n", Declared: []string{"a.sub"}})
	f := findingAbout(r, "a.sub", "cannot be checked here")
	if f == nil {
		t.Fatalf("a declared-only submit description was not flagged: %+v", r.Findings)
	}
	if f.Severity != Advisory {
		t.Errorf("severity = %v, want Advisory", f.Severity)
	}
	if len(r.Deferred) != 0 {
		t.Errorf("a declared file is not deferred: %v", r.Deferred)
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
    transfer_input_files = sibling.dat
}
`,
		Files: map[string]string{"sibling.dat": "x\n"},
	})
	if len(r.Findings) != 0 {
		t.Errorf("/bin/sh was treated as something to stage: %+v", r.Findings)
	}
	// The control: the analyzer IS looking at this body, so the relative
	// sibling next to the absolute executable must be in the allow-set.
	// Without this a no-op analyzer passes the assertion above.
	if !contains(r.Required, "sibling.dat") {
		t.Errorf("Required = %v, want it to contain sibling.dat", r.Required)
	}
	// And an absolute path is not silently in the allow-set either.
	if contains(r.Required, "/bin/sh") {
		t.Errorf("an absolute executable was put in the allow-set: %v", r.Required)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
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
	// $(RETRY) is one of DAGMan's own macros: its value is the node's
	// retry count at the moment it is submitted, which nothing here can
	// know. Guessing would either demand a file nothing uses or approve a
	// workflow that is missing one. (A macro that IS knowable -- a VARS
	// value, $(JOB) -- is expanded instead; see
	// TestAnalyzeExpandsVarsInFileNames.)
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag: `
JOB A {
    executable = /bin/true
    transfer_executable = false
    transfer_input_files = input.$(RETRY), sidecar.dat
}
VARS A infile="a.dat"
`,
		Files: map[string]string{"sidecar.dat": "x\n"},
	})
	if len(r.Findings) != 0 {
		t.Errorf("a macro-valued input produced findings: %+v", r.Findings)
	}
	// The control: the analyzer read this body, and the literal sibling in
	// it is staged. Without this a no-op analyzer satisfies the assertion
	// above by doing nothing at all.
	if !contains(r.Required, "sidecar.dat") {
		t.Errorf("Required = %v, want it to contain sidecar.dat", r.Required)
	}
	// And the macro itself is neither demanded nor invented as a file.
	if findingAbout(r, "$(") != nil {
		t.Errorf("the macro reference was demanded as a file: %+v", r.Findings)
	}
}

func TestAnalyzeBareNameCollidesWithSubdirectoryPath(t *testing.T) {
	// The spool is flat, so a supplied "data.txt" and a node's
	// "runB/data.txt" land on the same name. The old check only compared
	// paths that contained a slash, so this pair went unnoticed -- the
	// more likely shape of the two, since the caller supplies bare names.
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag: `
JOB A {
    executable = /bin/true
    transfer_executable = false
    transfer_input_files = runB/data.txt
}
`,
		Files: map[string]string{"data.txt": "1\n"},
	})
	if !r.Fatal() {
		t.Fatalf("a bare name colliding with a subdirectory path should be fatal: %+v", r.Findings)
	}
	if findingAbout(r, "data.txt", "runB/data.txt", "overwrite") == nil {
		t.Errorf("the collision was not explained: %+v", r.Findings)
	}
}

func TestAnalyzeCollisionNeedsTwoDistinctPaths(t *testing.T) {
	// The same path named twice is not a collision. Feeding in the
	// supplied files and the node bodies makes that easy to get wrong.
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag: `
JOB A {
    executable = /bin/true
    transfer_executable = false
    transfer_input_files = data.txt
}
JOB B {
    executable = /bin/true
    transfer_executable = false
    transfer_input_files = data.txt
}
`,
		Files: map[string]string{"data.txt": "1\n"},
	})
	if f := findingAbout(r, "overwrite"); f != nil {
		t.Errorf("one path used twice was reported as a collision: %s", f.Message)
	}
}

func TestAnalyzeSuppliedIncludeIsParsed(t *testing.T) {
	// INCLUDE is textual inclusion at parse time. When the file is in
	// hand the nodes it declares are part of the graph, so an edge naming
	// one is not "not declared".
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag:     "INCLUDE more.dag\nPARENT A CHILD B\n",
		Files: map[string]string{
			"more.dag": "JOB A a.sub\nJOB B b.sub\n",
			"a.sub":    "executable = /bin/true\nqueue\n",
			"b.sub":    "executable = /bin/true\nqueue\n",
		},
	})
	if r.Fatal() {
		t.Fatalf("a supplied INCLUDE was still refused: %v", r.Errors())
	}
	if f := findingAbout(r, "not declared"); f != nil {
		t.Errorf("a node declared in the INCLUDE was not seen: %s", f.Message)
	}
	if f := findingAbout(r, "more.dag", "references it"); f != nil {
		t.Errorf("the INCLUDE file was called unreferenced: %s", f.Message)
	}
}

func TestParseIncludeMergesTheIncludedGraph(t *testing.T) {
	d := parseText("INCLUDE more.dag\nPARENT A CHILD B\n", &resolver{
		lookup: func(name string) (string, bool) {
			if name == "more.dag" {
				return "JOB A a.sub\nJOB B b.sub\n", true
			}
			return "", false
		},
	})
	if len(d.Nodes) != 2 {
		t.Fatalf("nodes = %+v, want 2 from the included file", d.Nodes)
	}
	if len(d.Edges) != 1 {
		t.Fatalf("edges = %+v, want 1", d.Edges)
	}
	if d.Incomplete {
		t.Error("a supplied INCLUDE must not leave the graph incomplete")
	}
	if d.Nodes[0].Source != "more.dag" {
		t.Errorf("node source = %q, want more.dag so its line number means something", d.Nodes[0].Source)
	}
}

func TestAnalyzeUnsuppliedIncludeSuppressesUndeclaredNodes(t *testing.T) {
	// A missing INCLUDE is fatal, but the node set in hand is admittedly
	// partial: calling the edge's nodes undeclared is this package's
	// ignorance, not the DAG's mistake.
	r := Analyze(Input{DagName: "wf.dag", Dag: "INCLUDE more.dag\nPARENT A CHILD B\n"})
	if !r.Fatal() {
		t.Fatalf("a missing INCLUDE should be fatal: %+v", r.Findings)
	}
	if f := findingAbout(r, "not declared"); f != nil {
		t.Errorf("an incomplete graph claimed a node is undeclared: %s", f.Message)
	}
}

func TestAnalyzeIncludeCycleTerminates(t *testing.T) {
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag:     "INCLUDE a.dag\n",
		Files:   map[string]string{"a.dag": "INCLUDE b.dag\nJOB A a.sub\n", "b.dag": "INCLUDE a.dag\n"},
	})
	if findingAbout(r, "already being parsed") == nil {
		t.Errorf("an include cycle was not reported: %+v", r.Findings)
	}
}

func TestAnalyzeSuppliedSpliceIsParsed(t *testing.T) {
	// A splice is inlined at parse time, so its nodes' files are the
	// parent DAG's problem: they have to be in the spool now.
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag:     "SPLICE SP pieces.dag\n",
		Files:   map[string]string{"pieces.dag": "JOB X x.sub\n"},
	})
	if findingAbout(r, "x.sub") == nil {
		t.Fatalf("a spliced node's submit file was not noticed: %+v", r.Findings)
	}

	withFile := Analyze(Input{
		DagName: "wf.dag",
		Dag:     "SPLICE SP pieces.dag\n",
		Files:   map[string]string{"pieces.dag": "JOB X x.sub\n", "x.sub": "executable = /bin/true\nqueue\n"},
	})
	if !contains(withFile.Required, "x.sub") {
		t.Errorf("Required = %v, want it to contain the spliced node's submit file", withFile.Required)
	}
	if f := findingAbout(withFile, "x.sub", "references it"); f != nil {
		t.Errorf("a spliced node's submit file was called unreferenced: %s", f.Message)
	}
}

func TestParseSplicePrefixesNodeNames(t *testing.T) {
	d := parseText("SPLICE SP pieces.dag\n", &resolver{
		lookup: func(name string) (string, bool) {
			if name == "pieces.dag" {
				return "JOB X x.sub\nJOB Y y.sub\nPARENT X CHILD Y\n", true
			}
			return "", false
		},
	})
	if _, ok := d.NodeByName("SP+X"); !ok {
		t.Fatalf("spliced nodes were not scoped: %+v", d.Nodes)
	}
	if len(d.Edges) != 1 || d.Edges[0].Parent != "SP+X" || d.Edges[0].Child != "SP+Y" {
		t.Errorf("spliced edges were not scoped: %+v", d.Edges)
	}
}

func TestAnalyzeEmptyDagIsFatal(t *testing.T) {
	r := Analyze(Input{DagName: "wf.dag", Dag: "# nothing but a comment\n"})
	if !r.Fatal() {
		t.Fatalf("a DAG with no nodes should be fatal: %+v", r.Findings)
	}
	if findingAbout(r, "declares no nodes") == nil {
		t.Errorf("the empty DAG was not explained: %+v", r.Findings)
	}
}

func TestAnalyzeOneLineDagIsFatalAndSaysWhy(t *testing.T) {
	// The failure mode this message exists for: a caller that writes the
	// whole workflow as one string with literal backslash-n in it. DAG
	// syntax is line-oriented, so nothing is declared at all.
	r := Analyze(Input{DagName: "wf.dag", Dag: `\nJOB A a.sub\nJOB B b.sub\n`})
	if !r.Fatal() {
		t.Fatalf("a one-line DAG declares no nodes and should be fatal: %+v", r.Findings)
	}
	f := findingAbout(r, "declares no nodes")
	if f == nil {
		t.Fatalf("the empty DAG was not explained: %+v", r.Findings)
	}
	if !strings.Contains(f.Message, `use real newlines, not \n`) {
		t.Errorf("the message does not name the likely cause: %s", f.Message)
	}
}

func TestAnalyzeEmptyDagNameIsFatalAndStaysOutOfRequired(t *testing.T) {
	r := Analyze(Input{Dag: "JOB A a.sub\n", Files: map[string]string{"a.sub": "queue\n"}})
	if !r.Fatal() {
		t.Fatalf("a workflow with no DAG file name should be fatal: %+v", r.Findings)
	}
	for _, name := range r.Required {
		if name == "" {
			t.Fatalf("an empty name reached the spool allow-set: %q", r.Required)
		}
	}
}

func TestAnalyzeAllNodesResolves(t *testing.T) {
	// ALL_NODES is a stand-in for every node, not a node that is missing.
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag:     "JOB A a.sub\nSCRIPT PRE ALL_NODES pre.sh\nVARS all_nodes k=\"v\"\n",
		Files:   map[string]string{"a.sub": "queue\n", "pre.sh": "#!/bin/sh\n"},
	})
	if f := findingAbout(r, "not declared"); f != nil {
		t.Errorf("ALL_NODES was treated as an undeclared node: %s", f.Message)
	}
}

func TestAnalyzeVarsNamesTheNodeAsWritten(t *testing.T) {
	r := Analyze(Input{DagName: "wf.dag", Dag: "JOB A a.sub\nVARS MissinG k=\"v\"\n",
		Files: map[string]string{"a.sub": "queue\n"}})
	f := findingAbout(r, "VARS names node")
	if f == nil {
		t.Fatalf("an undeclared VARS node was not reported: %+v", r.Findings)
	}
	if !strings.Contains(f.Message, "MissinG") {
		t.Errorf("the message lost the author's spelling: %s", f.Message)
	}
}

func TestAnalyzeDuplicateAndReservedNodeNamesAreFatal(t *testing.T) {
	dup := Analyze(Input{DagName: "wf.dag", Dag: "JOB A a.sub\nJOB a b.sub\n",
		Files: map[string]string{"a.sub": "queue\n", "b.sub": "queue\n"}})
	if findingAbout(dup, "declared twice") == nil {
		t.Errorf("a duplicate node name was not reported: %+v", dup.Findings)
	}
	if !dup.Fatal() {
		t.Errorf("a duplicate node name should be fatal")
	}

	reserved := Analyze(Input{DagName: "wf.dag", Dag: "JOB CHILD a.sub\n",
		Files: map[string]string{"a.sub": "queue\n"}})
	if !reserved.Fatal() || findingAbout(reserved, "reserved word") == nil {
		t.Errorf("a reserved node name should be fatal: %+v", reserved.Findings)
	}

	plus := Analyze(Input{DagName: "wf.dag", Dag: "JOB A+B a.sub\n",
		Files: map[string]string{"a.sub": "queue\n"}})
	if !plus.Fatal() || findingAbout(plus, "'+'") == nil {
		t.Errorf("a node name containing '+' should be fatal: %+v", plus.Findings)
	}
}

func TestAnalyzeSubdagProducerInASuppliedSubmitFile(t *testing.T) {
	// The producer's description lives in a file the caller supplied, not
	// in an inline block. Resolving a body three different ways in three
	// different functions is how this came out as "no node declares it".
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag:     "JOB G g.sub\nSUBDAG EXTERNAL S stage2.dag\n",
		Files: map[string]string{
			"g.sub": "executable = /bin/sh\ntransfer_executable = false\ntransfer_output_files = stage2.dag\nqueue\n",
		},
	})
	if findingAbout(r, "stage2.dag", "not an ancestor") == nil {
		t.Fatalf("a producer written in a supplied submit file was not seen: %+v", r.Findings)
	}
	if f := findingAbout(r, "No node declares it"); f != nil {
		t.Errorf("the producer was missed and reported as unattributable: %s", f.Message)
	}
}

func TestAnalyzeInitialdirIsRefused(t *testing.T) {
	r := Analyze(Input{DagName: "wf.dag", Dag: `
JOB A {
    executable = /bin/true
    transfer_executable = false
    initialdir = work
}
`})
	if !r.Fatal() {
		t.Fatalf("initialdir cannot be honored in a flat spool: %+v", r.Findings)
	}
	if findingAbout(r, "initialdir", "flattens") == nil {
		t.Errorf("the initialdir refusal was not explained: %+v", r.Findings)
	}
}

func TestAnalyzeShouldTransferFilesNoNeedsNothingStaged(t *testing.T) {
	r := Analyze(Input{DagName: "wf.dag", Dag: `
JOB A {
    executable = /bin/true
    transfer_executable = false
    should_transfer_files = NO
    transfer_input_files = on_the_share.dat
}
`})
	if f := findingAbout(r, "on_the_share.dat"); f != nil {
		t.Errorf("a node that transfers nothing was still asked to stage a file: %s", f.Message)
	}
}

func TestAnalyzeDirectoryTransferIsWarned(t *testing.T) {
	r := Analyze(Input{DagName: "wf.dag", Dag: `
JOB A {
    executable = /bin/true
    transfer_executable = false
    transfer_input_files = inputs/
}
`})
	f := findingAbout(r, "inputs/", "directory")
	if f == nil {
		t.Fatalf("a directory transfer was not reported: %+v", r.Findings)
	}
	if f.Severity != Warning {
		t.Errorf("severity = %v, want Warning", f.Severity)
	}
}

func TestAnalyzeUrlQueryCommaIsNotAFileSeparator(t *testing.T) {
	r := Analyze(Input{DagName: "wf.dag", Dag: `
JOB A {
    executable = /bin/true
    transfer_executable = false
    transfer_input_files = data.csv, https://example.org/get?keys=1,2
}
`, Files: map[string]string{"data.csv": "1\n"}})
	if f := findingAbout(r, `2 is not among`); f != nil {
		t.Errorf("a URL query string was split into a bogus file: %s", f.Message)
	}
	if len(r.Findings) != 0 {
		t.Errorf("unexpected findings: %+v", r.Findings)
	}
}

func TestAnalyzeRescueDagAndOutputsAreNotUnreferenced(t *testing.T) {
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag: `
JOB A {
    executable = /bin/true
    transfer_executable = false
}
NODE_STATUS_FILE status.txt
`,
		Files: map[string]string{"wf.dag.rescue001": "JOB A a.sub\n", "status.txt": ""},
	})
	if f := findingAbout(r, "rescue001", "references it"); f != nil {
		t.Errorf("a rescue DAG was called unreferenced: %s", f.Message)
	}
	if f := findingAbout(r, "status.txt", "references it"); f != nil {
		t.Errorf("a declared DAG output was called unreferenced: %s", f.Message)
	}
}

func TestAnalyzeDotIncludeHeaderIsDemanded(t *testing.T) {
	r := Analyze(Input{DagName: "wf.dag", Dag: `
JOB A {
    executable = /bin/true
    transfer_executable = false
}
DOT wf.dot UPDATE INCLUDE header.dot
`})
	if findingAbout(r, "header.dot", "not among the supplied files") == nil {
		t.Errorf("the DOT INCLUDE header was not demanded: %+v", r.Findings)
	}
	if f := findingAbout(r, "wf.dot", "not among"); f != nil {
		t.Errorf("the dot output file was demanded as an input: %s", f.Message)
	}
}

func TestReachableIsNotTrueForANodeWithNoEdges(t *testing.T) {
	d := Parse("JOB A a.sub\n")
	if reachable(d, "A", "A") {
		t.Error("a node with no edges must not be reachable from itself")
	}
	cyc := Parse("JOB A a.sub\nPARENT A CHILD A\n")
	if !reachable(cyc, "A", "A") {
		t.Error("a real self-edge is a path")
	}
}

func TestAnalyzeDescriptorThatIsBothADescriptionAndAFile(t *testing.T) {
	// A name can be a SUBMIT-DESCRIPTION and a supplied file at once.
	// Resolving it as the former does not make the latter unused, and
	// calling the caller's file unreferenced would tell them to delete
	// the thing the workflow may actually run.
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag: `
SUBMIT-DESCRIPTION work {
    executable = /bin/echo
    transfer_executable = false
}
JOB A work
`,
		Files: map[string]string{"work": "executable = /bin/echo\nqueue\n"},
	})
	if f := findingAbout(r, "work", "references it"); f != nil {
		t.Errorf("a file that shares a description's name was called unreferenced: %s", f.Message)
	}
}

func TestAnalyzeDeferredIsDeduplicated(t *testing.T) {
	// Two nodes can read the same generated file. Listing it twice makes
	// the caller think there are two things to produce.
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag:     "SUBDAG EXTERNAL S1 stage2.dag\nSUBDAG EXTERNAL S2 stage2.dag\n",
	})
	if len(r.Deferred) != 1 || r.Deferred[0] != "stage2.dag" {
		t.Errorf("Deferred = %v, want [stage2.dag] once", r.Deferred)
	}
}

// TestAnalyzeReportsEnvGetAndCarriesEnvSet. ENV GET is the one DAG
// command this path cannot honour: it copies variables out of the
// SUBMITTING process's environment, which for a remote submission is
// this server's container, not the access point. Dropping it silently
// gives DAGMan a manager job missing exactly the variables the workflow
// was written to depend on.
func TestAnalyzeReportsEnvGetAndCarriesEnvSet(t *testing.T) {
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag: `
ENV GET PATH BEARER_TOKEN_FILE
ENV SET FOO=bar;BAZ=qux
SET_JOB_ATTR TestNumber = 17
JOB A { executable = /bin/true
transfer_executable = false
}
`,
	})
	f := findingAbout(r, "ENV GET", "cannot be honoured")
	if f == nil {
		t.Fatalf("ENV GET was accepted silently: %+v", r.Findings)
	}
	if f.Severity != Warning {
		t.Errorf("ENV GET finding severity = %v, want Warning", f.Severity)
	}
	if !strings.Contains(f.Message, "PATH BEARER_TOKEN_FILE") {
		t.Errorf("the finding does not name the variables: %s", f.Message)
	}
	if !strings.Contains(f.Message, "ENV SET") {
		t.Errorf("the finding does not say what to do instead: %s", f.Message)
	}

	// ENV SET and SET_JOB_ATTR are honoured, so neither produces a
	// finding -- and both reach the report, so the handler does not have
	// to parse the DAG a second time.
	if f := findingAbout(r, "ENV SET FOO"); f != nil {
		t.Errorf("ENV SET produced a finding: %s", f.Message)
	}
	if f := findingAbout(r, "SET_JOB_ATTR TestNumber"); f != nil {
		t.Errorf("SET_JOB_ATTR produced a finding: %s", f.Message)
	}
	if got := r.EnvSet; len(got) != 2 || got["FOO"] != "bar" || got["BAZ"] != "qux" {
		t.Errorf("Report.EnvSet = %+v, want FOO=bar BAZ=qux", got)
	}
	if len(r.JobAttrs) != 1 || r.JobAttrs[0].Name != "TestNumber" || r.JobAttrs[0].Value != "17" {
		t.Errorf("Report.JobAttrs = %+v, want TestNumber = 17", r.JobAttrs)
	}
}

// TestAnalyzeRefusesReservedJobAttrs. The manager job's submit file is
// not the DAG's to rewrite: OtherJobRemoveRequirements is what makes
// removing the workflow remove its node jobs, and IsDaemonCore is what
// gets DAGMan a command socket the schedd agrees it has. Both failures
// are invisible at submit time.
func TestAnalyzeRefusesReservedJobAttrs(t *testing.T) {
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag: `
SET_JOB_ATTR OtherJobRemoveRequirements = "False"
SET_JOB_ATTR isdaemoncore = False
SET_JOB_ATTR JobBatchName = "mine"
JOB A { executable = /bin/true
transfer_executable = false
}
`,
	})
	for _, name := range []string{"OtherJobRemoveRequirements", "isdaemoncore"} {
		f := findingAbout(r, "SET_JOB_ATTR "+name, "is ignored")
		if f == nil {
			t.Fatalf("%s was accepted: %+v", name, r.Findings)
		}
		if f.Severity != Warning {
			t.Errorf("%s finding severity = %v, want Warning", name, f.Severity)
		}
	}
	// JobBatchName is a user's to set: condor_submit_dag exposes it as
	// -batch-name, so a DAG setting it is supported.
	if len(r.JobAttrs) != 1 || r.JobAttrs[0].Name != "JobBatchName" {
		t.Errorf("JobAttrs = %+v, want only JobBatchName to survive", r.JobAttrs)
	}
}

// fanOutGatherDag is the commonest workflow shape there is: one submit
// description, one node per sample through a VARS macro, and a gather
// node that reads the files those produced by their literal names.
//
// It is a test fixture rather than a literal because the point of the
// test below is one line of it -- the PARENT edges -- being removed.
func fanOutGatherDag(edges bool) string {
	dag := `
SUBMIT-DESCRIPTION work {
    executable = /bin/sh
    transfer_executable = false
    arguments = "-c 'echo $(sample) > result_$(sample).txt'"
    transfer_output_files = result_$(sample).txt
}
JOB analyze_1 work
JOB analyze_2 work
JOB analyze_3 work
VARS analyze_1 sample="1"
VARS analyze_2 sample="2"
VARS analyze_3 sample="3"
JOB COMBINE {
    executable = /bin/sh
    transfer_executable = false
    arguments = "-c 'cat result_*.txt > combined.txt'"
    transfer_input_files = result_1.txt, result_2.txt, result_3.txt
    transfer_output_files = combined.txt
}
`
	if edges {
		dag += "PARENT analyze_1 analyze_2 analyze_3 CHILD COMBINE\n"
	}
	return dag
}

// TestAnalyzeFanOutGatherIsClean: the producer's transfer_output_files is
// `result_$(sample).txt` and the consumer names `result_1.txt`. Comparing
// those unexpanded made every such workflow -- the most ordinary one
// there is -- come back with three warnings that the files it produces
// are missing, which teaches a caller to ignore the notes entirely.
func TestAnalyzeFanOutGatherIsClean(t *testing.T) {
	r := Analyze(Input{DagName: "wf.dag", Dag: fanOutGatherDag(true)})
	if r.Fatal() {
		t.Fatalf("a fan-out/gather workflow was refused: %v", r.Errors())
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Message, "result_") {
			t.Errorf("a file an ancestor produces was reported: %s", f.Message)
		}
	}
	// The files are still accounted for: they are expected to appear
	// while the workflow runs.
	if !contains(r.Deferred, "result_1.txt") {
		t.Errorf("Deferred = %v, want the produced files in it", r.Deferred)
	}
}

// TestAnalyzeFanOutGatherWithoutEdgesIsWarned is the other half, and the
// one that proves the check above is not simply silence: with the
// PARENT line gone nothing orders the gather after the producers, so the
// gather can become ready before the files exist.
func TestAnalyzeFanOutGatherWithoutEdgesIsWarned(t *testing.T) {
	r := Analyze(Input{DagName: "wf.dag", Dag: fanOutGatherDag(false)})
	f := findingAbout(r, "result_1.txt", "not an ancestor")
	if f == nil {
		t.Fatalf("an unordered producer/consumer pair was not reported: %+v", r.Findings)
	}
	if !strings.Contains(f.Message, "analyze_1") || !strings.Contains(f.Message, "PARENT analyze_1 CHILD COMBINE") {
		t.Errorf("the warning does not name the producer or the fix: %s", f.Message)
	}
	if f.Severity != Warning {
		t.Errorf("severity = %v, want warning", f.Severity)
	}
}

// TestAnalyzeExpandsVarsInFileNames: a node input named through a VARS
// macro resolves to a file the caller DID supply, so it is neither
// demanded nor called unreferenced.
func TestAnalyzeExpandsVarsInFileNames(t *testing.T) {
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag: `
JOB A {
    executable = /bin/true
    transfer_executable = false
    transfer_input_files = data_$(sample).txt
}
VARS A sample="1"
`,
		Files: map[string]string{"data_1.txt": "x\n"},
	})
	if len(r.Findings) != 0 {
		t.Errorf("a supplied file named through VARS produced findings: %+v", r.Findings)
	}
	if !contains(r.Required, "data_1.txt") {
		t.Errorf("Required = %v, want data_1.txt in the spool allow-set", r.Required)
	}
}

// TestAnalyzeExpandsTheJobMacro: $(JOB) is the node's own name, which
// DAGMan supplies to every node job it submits.
func TestAnalyzeExpandsTheJobMacro(t *testing.T) {
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag: `
JOB setup {
    executable = /bin/true
    transfer_executable = false
    transfer_output_files = $(JOB).out
}
JOB use {
    executable = /bin/true
    transfer_executable = false
    transfer_input_files = setup.out
}
PARENT setup CHILD use
`,
	})
	if len(r.Findings) != 0 {
		t.Errorf("$(JOB) was not expanded to the node name: %+v", r.Findings)
	}
}

// TestAnalyzeUnresolvedMacroStillSoftensTheUnreferencedNote: a macro this
// package cannot resolve leaves the analysis unable to see every
// reference, and a "you misspelled this" verdict from a reader that
// admits it cannot read the workflow is a guess dressed as a diagnosis.
func TestAnalyzeUnresolvedMacroStillSoftensTheUnreferencedNote(t *testing.T) {
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag: `
JOB A {
    executable = /bin/true
    transfer_executable = false
    transfer_input_files = input.$(RETRY)
}
`,
		Files: map[string]string{"orphan.dat": "x\n"},
	})
	if findingAbout(r, "input.$(RETRY)") != nil {
		t.Errorf("an unresolvable macro was demanded as a file: %+v", r.Findings)
	}
	f := findingAbout(r, "orphan.dat")
	if f == nil {
		t.Fatalf("a supplied file nothing references was not mentioned: %+v", r.Findings)
	}
	if !strings.Contains(f.Message, "VARS macros cannot be checked") {
		t.Errorf("the note is stated as a diagnosis rather than a blind spot: %s", f.Message)
	}
	// And the softening is not permanent: with nothing unresolvable in
	// the workflow the same orphan is named as the probable misspelling
	// it is.
	sure := Analyze(Input{
		DagName: "wf.dag",
		Dag:     "JOB A {\n    executable = /bin/true\n    transfer_executable = false\n}\n",
		Files:   map[string]string{"orphan.dat": "x\n"},
	})
	if findingAbout(sure, "orphan.dat", "usually a misspelling") == nil {
		t.Errorf("without a blind spot the orphan should be named outright: %+v", sure.Findings)
	}
}

// TestAnalyzeCycleUsesTheAuthorsSpelling: the graph is walked folded,
// because DAGMan matches node names case-insensitively -- but a message
// built from the folded form tells an author about nodes "a -> b -> c"
// they never wrote.
func TestAnalyzeCycleUsesTheAuthorsSpelling(t *testing.T) {
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag: "JOB A a.sub\nJOB B a.sub\nJOB C a.sub\n" +
			"PARENT A CHILD B\nPARENT B CHILD C\nPARENT C CHILD A\n",
		Files: map[string]string{"a.sub": "queue\n"},
	})
	f := findingAbout(r, "cycle")
	if f == nil {
		t.Fatalf("the cycle was not reported: %+v", r.Findings)
	}
	if !strings.Contains(f.Message, "A -> B -> C -> A") {
		t.Errorf("the cycle is not spelled as the DAG spells its nodes: %s", f.Message)
	}
}

// TestAnalyzeReportsADanglingLineContinuation is the one place an author
// ever learns that DAGMan is silently dropping their last line.
//
// DagParser::getnextline accumulates the continuation, reaches EOF,
// returns false, and throws the partial logical line away: no warning, no
// parse error, and condor_dag_checker reports nothing either. The
// workflow runs, missing whatever that line said.
func TestAnalyzeReportsADanglingLineContinuation(t *testing.T) {
	r := Analyze(Input{
		DagName: "wf.dag",
		Dag:     "JOB A a.sub\nJOB B b.sub\nPARENT A CHILD \\\n",
	})
	f := findingAbout(r, "line continuation", "discards")
	if f == nil {
		t.Fatalf("a DAG whose last line DAGMan throws away was reported as clean: %+v", r.Findings)
	}
	if f.Severity != Warning {
		t.Errorf("severity = %v, want warning: the line is lost and nothing else says so", f.Severity)
	}
	if f.Line != 3 {
		t.Errorf("finding is on line %d, want 3", f.Line)
	}
	if !strings.Contains(f.Message, `PARENT A CHILD \`) {
		t.Errorf("the finding does not quote the line that is lost: %q", f.Message)
	}

	// Blank lines and comments after it do not end the continuation --
	// DagParser::getnextline tests skip_line FIRST -- so the line is
	// still the last real one and still lost.
	r = Analyze(Input{DagName: "wf.dag", Dag: "JOB A a.sub\nRETRY A 3 \\\n\n# done\n"})
	if findingAbout(r, "line continuation", "discards") == nil {
		t.Errorf("a blank line and a comment hid the dangling continuation: %+v", r.Findings)
	}

	// A continuation that is actually continued is not reported, nor is
	// a backslash anywhere but at the end of the last real line.
	for _, dag := range []string{
		"JOB A a.sub\nJOB B b.sub\nPARENT A CHILD \\\n  B\n",
		`JOB A a.sub` + "\n" + `VARS A path="c:\\tmp"` + "\n",
	} {
		r := Analyze(Input{DagName: "wf.dag", Dag: dag})
		if f := findingAbout(r, "line continuation", "discards"); f != nil {
			t.Errorf("a well-formed DAG was reported as losing a line (%q):\n%s", f.Message, dag)
		}
	}
}
