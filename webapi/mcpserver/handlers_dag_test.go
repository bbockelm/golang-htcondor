package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/dagman"
	"github.com/bbockelm/golang-htcondor/webapi/submitpolicy"
)

// submitDagArgs is the minimum a call needs, so a test can vary one thing.
func submitDagArgs(dag string) map[string]interface{} {
	return map[string]interface{}{"dag": dag, "dry_run": true}
}

// dryRun runs submit_dag without a schedd. dry_run is what makes that
// possible, and it is also the tool's own pre-submit check, so the cheap
// tests and the feature exercise the same path.
func dryRun(t *testing.T, s *Server, args map[string]interface{}) (string, map[string]interface{}, error) {
	t.Helper()
	res, err := s.toolSubmitDag(context.Background(), args)
	if err != nil {
		return "", nil, err
	}
	m, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("result is %T, not a map", res)
	}
	structured, _ := m["structuredContent"].(map[string]interface{})
	var text strings.Builder
	for _, c := range m["content"].([]map[string]interface{}) {
		text.WriteString(c["text"].(string))
	}
	return text.String(), structured, nil
}

func TestSubmitDagRefusesAWorkflowThatCannotStart(t *testing.T) {
	s := &Server{}
	// A real submission refuses: nothing should reach the queue.
	_, err := s.toolSubmitDag(context.Background(),
		map[string]interface{}{"dag": "JOB A a.sub\nPARENT A CHILD Ghost\n"})
	if err == nil {
		t.Fatal("a PARENT/CHILD naming an undeclared node was accepted")
	}
	if !strings.Contains(err.Error(), "Ghost") {
		t.Errorf("the refusal does not name the problem: %v", err)
	}
}

// TestSubmitDagDryRunReportsFatalFindingsInsteadOfRefusing: a dry run is
// the caller asking what is wrong with a workflow. Answering with one
// error hides the other four, and hides the notes entirely -- so the
// check that exists to save a round trip cost several.
func TestSubmitDagDryRunReportsFatalFindingsInsteadOfRefusing(t *testing.T) {
	s := &Server{}
	text, structured, err := dryRun(t, s, submitDagArgs("JOB A a.sub\nPARENT A CHILD Ghost\n"))
	if err != nil {
		t.Fatalf("a dry run should report a broken workflow, not refuse it: %v", err)
	}
	if fatal, _ := structured["fatal"].(bool); !fatal {
		t.Errorf("the dry run did not mark the workflow unstartable: %v", structured)
	}
	errs, _ := structured["errors"].([]string)
	if len(errs) == 0 || !strings.Contains(strings.Join(errs, " "), "Ghost") {
		t.Errorf("the fatal findings are missing from the result: %v", structured["errors"])
	}
	if !strings.Contains(text, "CANNOT be submitted") || !strings.Contains(text, "Ghost") {
		t.Errorf("the dry run's text does not say the workflow cannot start:\n%s", text)
	}
	// And it still shows everything else it would have shown.
	if !strings.Contains(text, "would be submitted as") {
		t.Errorf("a broken workflow's dry run dropped the manager job:\n%s", text)
	}
}

func TestSubmitDagComputesTheSpoolAllowSet(t *testing.T) {
	// The caller never writes transfer_input_files. It is derived from the
	// DAG, because a name missing from the job ad's TransferInput is
	// skipped at spool time rather than rejected -- so a hand-written list
	// fails invisibly.
	s := &Server{}
	_, structured, err := dryRun(t, s, map[string]interface{}{
		"dry_run": true,
		"dag":     "JOB A a.sub\nSCRIPT POST A tidy.sh\n",
		"files": map[string]interface{}{
			"a.sub":   "executable = work.sh\ntransfer_input_files = in.dat\nqueue\n",
			"tidy.sh": "#!/bin/sh\n",
			"work.sh": "#!/bin/sh\n",
			"in.dat":  "x\n",
		},
	})
	if err != nil {
		t.Fatalf("submit_dag: %v", err)
	}
	files, _ := structured["input_files"].([]string)
	for _, want := range []string{"workflow.dag", "a.sub", "tidy.sh", "work.sh", "in.dat"} {
		found := false
		for _, f := range files {
			if f == want {
				found = true
			}
		}
		if !found {
			t.Errorf("input_files = %v, missing %s", files, want)
		}
	}
}

func TestSubmitDagRejectsPathsInFileNames(t *testing.T) {
	// The spool directory is flat, so a name with a directory in it would
	// arrive somewhere the DAG does not look. Refusing here beats a
	// workflow that submits and then cannot find its own files.
	s := &Server{}
	for _, tc := range []struct {
		name string
		args map[string]interface{}
	}{
		{"dag_name", map[string]interface{}{"dag": "JOB A a.sub\n", "dag_name": "sub/wf.dag", "dry_run": true}},
		{"files key", map[string]interface{}{"dag": "JOB A a.sub\n", "dry_run": true,
			"files": map[string]interface{}{"sub/a.sub": "queue\n"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := dryRun(t, s, tc.args); err == nil {
				t.Error("a path was accepted where only a bare name works")
			}
		})
	}
}

// TestSubmitDagHasNoAdditionalInputFiles pins the removal of an argument
// that could not work.
//
// It promised a second chance that does not exist: SpoolJobFilesFromFS
// stats every name in TransferInput and fails on the first one missing,
// so declaring a file and not sending it failed the whole submission --
// and the spool is one-shot, so completing it releases the hold and the
// upload tools then refuse. Offering it left callers a documented path
// whose every outcome was a broken workflow.
func TestSubmitDagHasNoAdditionalInputFiles(t *testing.T) {
	var submitDag Tool
	for _, tool := range dagTools() {
		if tool.Name == "submit_dag" {
			submitDag = tool
		}
	}
	props, _ := submitDag.InputSchema["properties"].(map[string]interface{})
	if _, ok := props["additional_input_files"]; ok {
		t.Error("additional_input_files is still offered; no value of it produces a workflow that runs")
	}
	if strings.Contains(submitDag.Description, "additional_input_files") ||
		strings.Contains(submitDag.Description, "create_input_upload_url") {
		t.Errorf("the description still points at an upload-afterwards path:\n%s", submitDag.Description)
	}
	// And it says what to do instead.
	if !strings.Contains(submitDag.Description, "transfer_input_files") {
		t.Errorf("the description does not name the path bulk data must take:\n%s", submitDag.Description)
	}
}

// TestSubmitDagDescriptionReachesTheModelAsLines: the example is the
// tool's whole teaching of the shape it wants, and it only teaches it if
// it arrives as lines. Written with "\n" escapes inside a quoted Go
// string, JSON encoding doubles them and the model is served one line of
// literal backslash-n -- which is what this asserts against, on the
// encoded bytes a client receives rather than on the Go constant.
func TestSubmitDagDescriptionReachesTheModelAsLines(t *testing.T) {
	raw, err := json.Marshal(dagTools())
	if err != nil {
		t.Fatalf("marshalling the catalogue: %v", err)
	}
	var decoded []map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decoding the catalogue: %v", err)
	}
	for _, tool := range decoded {
		if tool["name"] != "submit_dag" {
			continue
		}
		desc, _ := tool["description"].(string)
		if strings.Contains(desc, `\n`) || strings.Contains(desc, `\"`) {
			t.Errorf("the description carries literal escape sequences rather than line breaks:\n%s", desc)
		}
		if !strings.Contains(desc, "\n  SUBMIT-DESCRIPTION work {\n") {
			t.Errorf("the example is not laid out as lines:\n%s", desc)
		}
		if !strings.Contains(desc, `arguments = "-c 'echo hi > out_$(sample).txt'"`) {
			t.Errorf("the example's quoting did not survive encoding:\n%s", desc)
		}
		// The example is a fan-out/gather, which is the shape nearly every
		// real workflow has: one description per stage, VARS per node, and
		// a gather node reading what they produced. An example without it
		// teaches the one shape that needs no thought.
		for _, want := range []string{"\n  VARS A sample=\"1\"\n", "transfer_output_files = out_$(sample).txt",
			"transfer_input_files = out_1.txt, out_2.txt", "PARENT A B CHILD GATHER"} {
			if !strings.Contains(desc, want) {
				t.Errorf("the example does not show %q:\n%s", want, desc)
			}
		}
		// And it says how the files actually move between stages, and
		// which of them arrive runnable.
		for _, want := range []string{
			"Node outputs land in the workflow's directory.",
			"declare it in the producer's transfer_output_files",
			"Files named in a SCRIPT line or as a node's executable are staged executable",
		} {
			if !strings.Contains(desc, want) {
				t.Errorf("the description never says %q:\n%s", want, desc)
			}
		}
		return
	}
	t.Fatal("submit_dag is not in the catalogue")
}

// TestAnnotationsAgreeWithReadOnlyClassification. The two lists are read
// by different consumers -- annotations by the client and the broker,
// readOnlyMCPTools by this server's own OAuth scope gate -- and nothing
// compared them. get_job_stdout and its siblings were declared readOnly
// to clients and classified write-only by the gate, so a read-scoped
// token was shown tools it was then refused.
func TestAnnotationsAgreeWithReadOnlyClassification(t *testing.T) {
	s := &Server{}
	res, _ := s.handleListTools(context.Background(), nil).(map[string]interface{})
	tools, _ := res["tools"].([]Tool)
	if len(tools) == 0 {
		t.Fatal("the catalogue is empty; this test would assert nothing")
	}
	for _, tool := range tools {
		ann := annotationsFor(tool.Name)
		if ann == nil {
			t.Errorf("%s is served with no annotation policy", tool.Name)
			continue
		}
		if ann.ReadOnlyHint != IsReadOnlyTool(tool.Name) {
			t.Errorf("%s: readOnlyHint=%v but IsReadOnlyTool=%v -- a client is told one thing and the "+
				"scope gate enforces the other", tool.Name, ann.ReadOnlyHint, IsReadOnlyTool(tool.Name))
		}
	}
	// The other direction: a tool the gate calls read-only that the
	// annotations never mention is the same drift, seen from the side the
	// catalogue cannot show.
	for name := range readOnlyMCPTools {
		ann := annotationsFor(name)
		if ann == nil {
			t.Errorf("%s is in the read-only allowlist with no annotation policy", name)
			continue
		}
		if !ann.ReadOnlyHint {
			t.Errorf("%s is read-only to the scope gate but not to clients", name)
		}
	}
}

func TestSubmitDagDryRunSubmitsNothingAndShowsTheJob(t *testing.T) {
	// With no schedd configured, a dry run that tried to submit would
	// panic or error. Getting a submit file back is therefore proof it
	// stopped before the schedd.
	s := &Server{}
	text, structured, err := dryRun(t, s, submitDagArgs("JOB A {\n  executable = /bin/true\n}\n"))
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !strings.Contains(text, "nothing was submitted") {
		t.Errorf("the dry run does not say it submitted nothing:\n%s", text)
	}
	sub, _ := structured["submit_file"].(string)
	if !strings.Contains(sub, "universe    = scheduler") || !strings.Contains(sub, "transfer_executable = false") {
		t.Errorf("the dry run did not show the DAGMan job it would submit:\n%s", sub)
	}
}

// TestSubmitDagDryRunShowsTheSitePolicy: a dry run that showed a submit
// file the site would then rewrite is showing the wrong job. The point
// of the mode is to see what would be submitted.
func TestSubmitDagDryRunShowsTheSitePolicy(t *testing.T) {
	s := &Server{submitPolicy: submitpolicy.Policy{Overrides: `+ProjectName = "site"`}}
	_, structured, err := dryRun(t, s, submitDagArgs("JOB A {\n  executable = /bin/true\n}\n"))
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	sub, _ := structured["submit_file"].(string)
	if !strings.Contains(sub, "ProjectName") {
		t.Errorf("the dry run showed a manager job the site policy had not touched:\n%s", sub)
	}
}

func TestSubmitDagAppliesSitePolicyToNodeSubmitFiles(t *testing.T) {
	// DAGMan submits node jobs itself, on the access point, long after
	// this call returns -- so this is the only chance site policy has to
	// reach them. Without it an operator's mandatory directive would cover
	// the one job that does no work and none of the ones that do.
	s := &Server{submitPolicy: submitpolicy.Policy{Overrides: "+ProjectName = \"site\""}}
	got := s.policyForStagedFile("a.sub", "executable = /bin/true\nqueue\n")
	if !strings.Contains(got, "ProjectName") {
		t.Errorf("site policy did not reach the node submit description:\n%s", got)
	}

	// A script is not a submit file. Splicing submit-file text into it
	// would corrupt it, so the narrow extension test is deliberate.
	script := "#!/bin/sh\necho hi\n"
	if out := s.policyForStagedFile("tidy.sh", script); out != script {
		t.Errorf("site policy was spliced into a shell script:\n%s", out)
	}
}

// TestSubmitDagAppliesSitePolicyToInlineDescriptions is the same rule for
// the shape the tool actually recommends.
//
// Every inline block bypassed site policy, because policyForStagedFile
// only ever sees a separate .sub file -- so following the tool's own
// advice was the way to escape the operator's mandatory directives.
func TestSubmitDagAppliesSitePolicyToInlineDescriptions(t *testing.T) {
	s := &Server{submitPolicy: submitpolicy.Policy{Overrides: `+ProjectName = "site"`}}
	dag := `SUBMIT-DESCRIPTION work {
  executable = /bin/sh
}
JOB A work
JOB B @=body
  executable = /bin/sh
@body
SCRIPT PRE A setup.sh
FINAL cleanup {
  executable = /bin/true
}
`
	staged := s.policyForInlineDescriptions(dag)
	if n := strings.Count(staged, "ProjectName"); n != 3 {
		t.Errorf("site policy reached %d of the 3 inline descriptions:\n%s", n, staged)
	}
	// It has to land INSIDE each block: outside one it is a DAG command
	// DAGMan does not recognise, not a submit directive.
	for _, block := range []string{"work {", "@=body", "cleanup {"} {
		i := strings.Index(staged, block)
		if i < 0 {
			t.Fatalf("the block opened by %q is gone:\n%s", block, staged)
		}
		rest := staged[i:]
		policy := strings.Index(rest, "ProjectName")
		closes := strings.Index(rest, "\n}")
		if at := strings.Index(rest, "\n@body"); closes < 0 || (at >= 0 && at < closes) {
			closes = at
		}
		if policy < 0 || (closes >= 0 && policy > closes) {
			t.Errorf("the policy did not land inside the block opened by %q:\n%s", block, staged)
		}
	}
	// And the DAG still describes the same workflow.
	before, after := dagman.Parse(dag), dagman.Parse(staged)
	if len(after.Nodes) != len(before.Nodes) || len(after.Errors) != 0 || len(after.Fatals) != 0 {
		t.Errorf("the rewritten DAG no longer parses to the same graph: %d nodes, errors %v %v\n%s",
			len(after.Nodes), after.Errors, after.Fatals, staged)
	}
	for i := range before.Nodes {
		if before.Nodes[i].Name != after.Nodes[i].Name {
			t.Errorf("node %d changed name: %s -> %s", i, before.Nodes[i].Name, after.Nodes[i].Name)
		}
	}
	// A DAG with no policy configured comes through byte for byte.
	plain := &Server{}
	if out := plain.policyForInlineDescriptions(dag); out != dag {
		t.Error("an unconfigured policy still rewrote the DAG")
	}
}

func TestSubmitDagAcceptsAGeneratedSubdag(t *testing.T) {
	// A SUBDAG whose .dag file an earlier node produces is the documented
	// idiom, and the file is absent at submit time by design. Refusing it
	// would make the tool useless for the workflows most worth running.
	s := &Server{}
	text, structured, err := dryRun(t, s, submitDagArgs(
		"JOB gen gen.sub\nSUBDAG EXTERNAL S stage2.dag\nPARENT gen CHILD S\n"))
	if err != nil {
		t.Fatalf("a generated sub-DAG was refused: %v", err)
	}
	deferred, _ := structured["deferred"].([]string)
	found := false
	for _, d := range deferred {
		if d == "stage2.dag" {
			found = true
		}
	}
	if !found {
		t.Errorf("deferred = %v, want it to include stage2.dag", deferred)
	}
	if !strings.Contains(text, "stage2.dag") {
		t.Errorf("the response never mentions the file the run must produce:\n%s", text)
	}
}

func TestSubmitDagRequiresADag(t *testing.T) {
	s := &Server{}
	if _, _, err := dryRun(t, s, map[string]interface{}{"dry_run": true}); err == nil {
		t.Error("submit_dag accepted a call with no dag")
	}
}

func TestSubmitDagRejectsNonStringFileContents(t *testing.T) {
	// A model that sends a number or an object for a file's contents gets
	// a clear error rather than a workflow staged with "map[]" in it.
	s := &Server{}
	_, _, err := dryRun(t, s, map[string]interface{}{
		"dag": "JOB A a.sub\n", "dry_run": true,
		"files": map[string]interface{}{"a.sub": 42},
	})
	if err == nil {
		t.Fatal("a non-string file body was accepted")
	}
	if !strings.Contains(err.Error(), "a.sub") {
		t.Errorf("the error does not name the offending file: %v", err)
	}
}

// TestSubmitDagRefusesAnOversizedWorkflow. Everything in this call
// travelled through a context window and is spooled in one transfer, so
// a workflow carrying its data inline is a workflow submitted the wrong
// way. The refusal has to name the right way, or it reads as a quota to
// work around.
func TestSubmitDagRefusesAnOversizedWorkflow(t *testing.T) {
	s := &Server{}
	_, _, err := dryRun(t, s, map[string]interface{}{
		"dag":     "JOB A a.sub\n",
		"dry_run": true,
		"files": map[string]interface{}{
			"a.sub":  "executable = /bin/true\ntransfer_executable = false\nqueue\n",
			"in.dat": strings.Repeat("x", maxDagSubmissionBytes),
		},
	})
	if err == nil {
		t.Fatal("a megabyte of inline data was accepted")
	}
	if !strings.Contains(err.Error(), "transfer_input_files") {
		t.Errorf("the refusal does not say where bulk data belongs: %v", err)
	}
}

// TestSubmitDagLintsNodeSubmitDescriptions: the node jobs are the ones
// that do the work, and nothing looked at them. submit_job refuses
// `executable = /bin/true` with no transfer_executable; the same
// description inside a DAG reached the queue and held every node, hours
// later, with nothing tying the hold back to this call.
func TestSubmitDagLintsNodeSubmitDescriptions(t *testing.T) {
	s := &Server{}
	text, structured, err := dryRun(t, s, map[string]interface{}{
		"dry_run": true,
		"dag":     "JOB A {\n  executable = /bin/true\n}\nJOB B b.sub\n",
		"files":   map[string]interface{}{"b.sub": "executable = /usr/bin/python3\nqueue\n"},
	})
	if err != nil {
		t.Fatalf("the lint refused the workflow instead of warning: %v", err)
	}
	notes, _ := structured["notes"].([]string)
	joined := strings.Join(notes, "\n")
	for _, want := range []string{"node A", "b.sub", "transfer_executable"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the notes do not mention %q:\n%s", want, joined)
		}
	}
	if !strings.Contains(text, "transfer_executable") {
		t.Errorf("the caller-visible text does not carry the warning:\n%s", text)
	}
}

// TestSubmitDagLintDoesNotWarnAboutVarsMacros: $(NodeName) supplied by a
// VARS line is the standard DAG idiom, and the undefined-macro check
// knows nothing about VARS. Warning on the most ordinary workflow there
// is teaches a caller to ignore the notes, which costs the warnings that
// matter.
func TestSubmitDagLintDoesNotWarnAboutVarsMacros(t *testing.T) {
	s := &Server{}
	_, structured, err := dryRun(t, s, map[string]interface{}{
		"dry_run": true,
		"dag": "SUBMIT-DESCRIPTION step {\n  executable = /bin/sh\n  transfer_executable = false\n" +
			"  arguments = \"-c 'echo $(NodeName)'\"\n  output = $(NodeName).out\n}\n" +
			"JOB A step\nVARS A NodeName=\"A\"\n",
	})
	if err != nil {
		t.Fatalf("submit_dag: %v", err)
	}
	notes, _ := structured["notes"].([]string)
	for _, n := range notes {
		if strings.Contains(n, "NodeName") {
			t.Errorf("a VARS-supplied macro was reported as undefined: %s", n)
		}
	}
	// The check still works for a macro nothing defines.
	_, structured, err = dryRun(t, s, map[string]interface{}{
		"dry_run": true,
		"dag": "JOB A {\n  executable = /bin/sh\n  transfer_executable = false\n" +
			"  arguments = \"-c 'echo $(hostname)'\"\n}\n",
	})
	if err != nil {
		t.Fatalf("submit_dag: %v", err)
	}
	notes, _ = structured["notes"].([]string)
	if !strings.Contains(strings.Join(notes, "\n"), "hostname") {
		t.Errorf("the undefined-macro check stopped firing entirely: %v", notes)
	}
}

// TestSubmitDagWarnsAboutNodeOAuthServices: DAGMan submits node jobs
// later, so the schedd's credential transform cannot be observed at
// submit time the way toolSubmitJob observes it. The only warning
// possible is the one the description itself gives away.
func TestSubmitDagWarnsAboutNodeOAuthServices(t *testing.T) {
	s := &Server{}
	_, structured, err := dryRun(t, s, map[string]interface{}{
		"dry_run": true,
		"dag":     "JOB A {\n  executable = /bin/sh\n  transfer_executable = false\n  use_oauth_services = scitokens\n}\n",
	})
	if err != nil {
		t.Fatalf("submit_dag: %v", err)
	}
	notes, _ := structured["notes"].([]string)
	if len(notes) == 0 || !strings.Contains(notes[0], "OAuth") {
		t.Errorf("a node needing credentials produced no leading note: %v", notes)
	}
}

// TestStagedModeFollowsTheParseNotTheExtension. A PRE script spooled
// 0644 fails with EACCES the first time DAGMan runs it, reported as a
// node failure with no cause. The extension rule covered setup.sh and
// missed setup, which is the same file and the same failure.
func TestStagedModeFollowsTheParseNotTheExtension(t *testing.T) {
	files := map[string]string{
		"setup":   "#!/bin/sh\n",
		"run":     "#!/bin/sh\n",
		"a.sub":   "executable = run\nqueue\n",
		"data.in": "x\n",
	}
	exec := executableStagedNames(dagman.Parse("JOB A a.sub\nSCRIPT PRE A setup\n"), files)
	if mode := stagedMode("setup", exec); mode != 0o755 {
		t.Errorf("a PRE script with no extension was staged %o; DAGMan cannot run it", mode)
	}
	if mode := stagedMode("run", exec); mode != 0o755 {
		t.Errorf("a node's own executable was staged %o", mode)
	}
	if mode := stagedMode("data.in", exec); mode != 0o644 {
		t.Errorf("an input file was made executable (%o)", mode)
	}
	// The extension rule stays as a fallback for a file the parse cannot
	// attribute -- a script named only in a node's arguments, say.
	if mode := stagedMode("helper.sh", map[string]bool{}); mode != 0o755 {
		t.Errorf("the extension fallback is gone: helper.sh staged %o", mode)
	}
}

// TestDagFollowUpAdviceNamesToolsThatExist. watch_jobs has no job_id
// parameter, so "watch_jobs on cluster N" was an instruction a model
// could not carry out; what it did instead was poll in a loop.
func TestDagFollowUpAdviceNamesToolsThatExist(t *testing.T) {
	report := &dagman.Report{Required: []string{"workflow.dag"}}
	res := dagSubmitResult(42, "workflow.dag", report, nil, dagman.Instrumentation{
		DotFile: "workflow.dot", StatusFile: "workflow.status"})
	text := res["content"].([]map[string]interface{})[0]["text"].(string)

	want := `To wait for the whole workflow, register watch_jobs(constraint="ClusterId == 42", event="done") ` +
		`and collect it with check_watches -- do not call get_job in a loop. ` +
		`Use get_job(job_id="42.0") for a one-off "how far along is it".`
	if !strings.Contains(text, want) {
		t.Errorf("the follow-up advice is not the one that works:\n%s", text)
	}
	if !strings.Contains(text, `get_job_output(job_id="42.0")`) {
		t.Errorf("the result never says where the node outputs end up:\n%s", text)
	}
}

// TestSubmitDagResultHandsOverTheNodeConstraint: the workflow's node
// jobs are not in the manager's cluster -- DAGMan submits each as its own
// -- so a caller holding the returned cluster id has nothing that matches
// them. The link is DAGManJobId, and handing the constraint over
// ready-made is the difference between querying the nodes and querying
// the manager job again and concluding the workflow has no jobs.
func TestSubmitDagResultHandsOverTheNodeConstraint(t *testing.T) {
	res := dagSubmitResult(42, "workflow.dag", &dagman.Report{Required: []string{"workflow.dag"}}, nil,
		dagman.Instrumentation{DotFile: "workflow.dot", StatusFile: "workflow.status"})
	structured, _ := res["structuredContent"].(map[string]interface{})
	got, _ := structured["node_constraint"].(string)
	if got != "DAGManJobId == 42" {
		t.Errorf("node_constraint = %q, want %q", got, "DAGManJobId == 42")
	}
	// Well-formed in the sense that matters: it is a constraint the query
	// tools accept -- it parses, and it evaluates true against a node job
	// of this workflow and false against anything else.
	ad, err := classad.Parse(fmt.Sprintf("[ constraint = %s ]", got))
	if err != nil {
		t.Fatalf("node_constraint is not a valid ClassAd expression: %v", err)
	}
	for _, tc := range []struct {
		dagManJobID int
		want        bool
	}{{42, true}, {43, false}} {
		ad.InsertAttr("DAGManJobId", int64(tc.dagManJobID))
		if v, ok := ad.EvaluateAttrBool("constraint"); !ok || v != tc.want {
			t.Errorf("%s against DAGManJobId == %d evaluated %v,%v; want %v",
				got, tc.dagManJobID, v, ok, tc.want)
		}
	}
	text := res["content"].([]map[string]interface{})[0]["text"].(string)
	want := `Node jobs carry DAGManJobId == 42 and DAGNodeName. ` +
		`List them with query_jobs(constraint="DAGManJobId == 42"); ` +
		`finished ones with query_job_archive on the same constraint.`
	if !strings.Contains(text, want) {
		t.Errorf("the result never says how to find the node jobs:\n%s", text)
	}
}

// TestDagSectionTellsAFinishedWorkflowWhereItsOutputIs: the node jobs'
// sandboxes are gone by then and their output came back to the manager
// job's spool, which is the one place a caller does not think to look.
func TestDagSectionTellsAFinishedWorkflowWhereItsOutputIs(t *testing.T) {
	done := dagStatusText(t, map[string]interface{}{"JobStatus": 4, "DAG_NodesTotal": 3, "DAG_NodesDone": 3})
	if !strings.Contains(done, `get_job_output(job_id="7.0")`) {
		t.Errorf("a completed workflow does not say how to collect its output:\n%s", done)
	}
	running := dagStatusText(t, map[string]interface{}{"JobStatus": 2, "DAG_NodesTotal": 3})
	if strings.Contains(running, "get_job_output") {
		t.Errorf("a running workflow was told to collect output that is not there yet:\n%s", running)
	}
}

// TestDagSectionPointsAtTheRescueDag: a failed workflow is resumable, and
// the rescue DAG is how. Without saying so, the only visible option is
// to build the remaining graph by hand.
func TestDagSectionPointsAtTheRescueDag(t *testing.T) {
	got := dagStatusText(t, map[string]interface{}{
		"JobStatus": 2, "DAG_NodesTotal": 3, "DAG_NodesFailed": 1,
	})
	if !strings.Contains(got, "rescue001") || !strings.Contains(got, "get_job_output") {
		t.Errorf("a failed workflow is not told how to resume:\n%s", got)
	}
}

// TestSpoolFailureAlwaysNamesTheCluster. The manager job exists either
// way; whether it is still in the queue decides what the caller must do
// next. A removal that reports zero jobs removed is not a success, and
// reporting it as one leaves a held job nothing in the answer accounts
// for.
func TestSpoolFailureAlwaysNamesTheCluster(t *testing.T) {
	cause := errors.New("no such file")
	removed := spoolFailureMessage(99, true, cause)
	if !strings.Contains(removed, "99.0") || !strings.Contains(removed, "was removed") {
		t.Errorf("a cleaned-up failure does not say so: %s", removed)
	}
	if !strings.Contains(removed, "no such file") {
		t.Errorf("the cause is missing: %s", removed)
	}
	stranded := spoolFailureMessage(99, false, cause)
	if !strings.Contains(stranded, "99.0") || !strings.Contains(stranded, "could NOT be removed") {
		t.Errorf("a stranded job is not reported: %s", stranded)
	}
	if !strings.Contains(stranded, "remove_job") {
		t.Errorf("the caller is not told how to clean up: %s", stranded)
	}
}

// TestDagmanLayoutPrecedence: an operator's explicit path wins, the
// schedd's own BIN answers when there is none, and the package default
// is the last resort. Discovery must never turn an empty BIN into
// "/condor_dagman".
func TestDagmanLayoutPrecedence(t *testing.T) {
	layout := func(bin string, noPort bool) func(context.Context) (string, bool) {
		return func(context.Context) (string, bool) { return bin, noPort }
	}
	for _, tc := range []struct {
		name       string
		configured string
		bin        string
		wantExe    string
	}{
		{"configured wins", "/opt/condor/sbin/condor_dagman", "/usr/bin", "/opt/condor/sbin/condor_dagman"},
		{"discovered", "", "/opt/condor/bin", "/opt/condor/bin/condor_dagman"},
		{"unknown falls back", "", "", dagman.DefaultDagmanPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{dagmanPath: tc.configured, dagmanLayoutFn: layout(tc.bin, false)}
			_, structured, err := dryRun(t, s, submitDagArgs("JOB A {\n  executable = /bin/true\n}\n"))
			if err != nil {
				t.Fatalf("dry run: %v", err)
			}
			sub, _ := structured["submit_file"].(string)
			if !strings.Contains(sub, "executable  = "+tc.wantExe+"\n") {
				t.Errorf("want condor_dagman at %s:\n%s", tc.wantExe, sub)
			}
		})
	}

	// DAGMAN_DISABLE_PORT is the other half: asking for a command port an
	// access point refuses to give makes DAGMan fail to start.
	s := &Server{dagmanLayoutFn: layout("", true)}
	_, structured, err := dryRun(t, s, submitDagArgs("JOB A {\n  executable = /bin/true\n}\n"))
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	sub, _ := structured["submit_file"].(string)
	if strings.Contains(sub, "IsDaemonCore") {
		t.Errorf("a site with DAGMAN_DISABLE_PORT still asked for a command port:\n%s", sub)
	}

	// Discovery runs once per server, whatever it is asked.
	calls := 0
	counted := &Server{dagmanLayoutFn: func(context.Context) (string, bool) {
		calls++
		return "/usr/bin", false
	}}
	for i := 0; i < 3; i++ {
		counted.dagmanLayout(context.Background())
	}
	if calls != 1 {
		t.Errorf("the schedd was asked %d times; it should be asked once", calls)
	}
}

// TestSubmitDagPassesTheDagsOwnConfig: a DAG that names a CONFIG file
// expects DAGMan to read it, and a remote DAGMan learns about it only
// through _CONDOR_DAGMAN_CONFIG_FILE.
func TestSubmitDagPassesTheDagsOwnConfig(t *testing.T) {
	s := &Server{}
	_, structured, err := dryRun(t, s, map[string]interface{}{
		"dry_run": true,
		"dag":     "CONFIG dagman.config\nJOB A a.sub\n",
		"files": map[string]interface{}{
			"dagman.config": "DAGMAN_MAX_JOBS_IDLE = 5\n",
			"a.sub":         "executable = /bin/true\ntransfer_executable = false\nqueue\n",
		},
	})
	if err != nil {
		t.Fatalf("submit_dag: %v", err)
	}
	sub, _ := structured["submit_file"].(string)
	if !strings.Contains(sub, "_CONDOR_DAGMAN_CONFIG_FILE=dagman.config") {
		t.Errorf("the DAG's CONFIG file never reached DAGMan:\n%s", sub)
	}
	// Two of them is a workflow that disagrees with itself; DAGMan is a
	// better judge of that than a guess here would be.
	if got := soleConfigFile(dagman.Parse("CONFIG a\nCONFIG b\n")); got != "" {
		t.Errorf("two CONFIG files produced a choice between them: %q", got)
	}
}

// TestSubmitDagOmitsCsdVersion: -CsdVersion describes the condor_submit
// that wrote the file, and this server is not one. Sending this binary's
// version claimed something about the access point that is not true.
func TestSubmitDagOmitsCsdVersion(t *testing.T) {
	s := &Server{}
	_, structured, err := dryRun(t, s, submitDagArgs("JOB A {\n  executable = /bin/true\n}\n"))
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if sub, _ := structured["submit_file"].(string); strings.Contains(sub, "-CsdVersion") {
		t.Errorf("the manager job still claims a submit version:\n%s", sub)
	}
}

// dagmanManagerJobAd is the job ad the schedd would receive for a
// workflow this server submits: the generated submit file, run through
// the same parser and submit path the real submission takes.
//
// Hand-writing the Arguments string would test this package's idea of
// what it generates rather than what it generates, and the two have
// differed before -- argument quoting is applied by the submit library,
// not by the generator.
func dagmanManagerJobAd(t *testing.T, dagName string) *classad.ClassAd {
	t.Helper()
	text, err := dagman.SubmitFile(dagman.SubmitOptions{
		DagName:    dagName,
		InputFiles: []string{dagName},
		MaxIdle:    5,
	})
	if err != nil {
		t.Fatalf("SubmitFile: %v", err)
	}
	sf, err := htcondor.ParseSubmitFile(strings.NewReader(text))
	if err != nil {
		t.Fatalf("the generated submit file does not parse: %v\n%s", err, text)
	}
	res, err := sf.Submit(42)
	if err != nil {
		t.Fatalf("Submit: %v\n%s", err, text)
	}
	if len(res.ProcAds) != 1 {
		t.Fatalf("got %d procs, want 1", len(res.ProcAds))
	}
	return res.ProcAds[0]
}
