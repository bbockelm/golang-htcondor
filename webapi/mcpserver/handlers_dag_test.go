package mcpserver

import (
	"context"
	"strings"
	"testing"

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
	_, _, err := dryRun(t, s, submitDagArgs("JOB A a.sub\nPARENT A CHILD Ghost\n"))
	if err == nil {
		t.Fatal("a PARENT/CHILD naming an undeclared node was accepted")
	}
	if !strings.Contains(err.Error(), "Ghost") {
		t.Errorf("the refusal does not name the problem: %v", err)
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
		{"additional_input_files", map[string]interface{}{"dag": "JOB A a.sub\n", "dry_run": true,
			"additional_input_files": []interface{}{"sub/later.dat"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := dryRun(t, s, tc.args); err == nil {
				t.Error("a path was accepted where only a bare name works")
			}
		})
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
	if len(deferred) != 1 || deferred[0] != "stage2.dag" {
		t.Errorf("deferred = %v, want [stage2.dag]", deferred)
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
