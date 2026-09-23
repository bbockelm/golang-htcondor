package dagman

import (
	"strings"
	"testing"
)

func TestSubmitFileShape(t *testing.T) {
	got, err := SubmitFile(SubmitOptions{
		DagName:       "wf.dag",
		CondorVersion: "$CondorVersion: 25.4.0 BuildID: test $",
		InputFiles:    []string{"wf.dag", "a.sub"},
		BatchName:     "my workflow",
		MaxIdle:       10,
	})
	if err != nil {
		t.Fatalf("SubmitFile: %v", err)
	}

	for _, want := range []string{
		// DAGMan is a scheduler-universe job: it runs on the access point,
		// not on an execute node.
		"universe    = scheduler",
		// Load-bearing. The schedd rewrites a spooled job's file paths to
		// basenames but skips the executable when this is false, which is
		// what lets condor_dagman keep its absolute path while the
		// workflow collapses into the spool directory.
		"transfer_executable = false",
		// Without this the spooling path is not taken and Iwd is never
		// rewritten to the spool directory, so DAGMan starts somewhere the
		// workflow is not.
		"should_transfer_files = YES",
		// Removing the DAGMan job has to remove the node jobs too.
		"DAGManJobId =?= $(cluster)",
		"-Dag wf.dag",
		"-Lockfile wf.dag.lock",
		"-MaxIdle 10",
		"transfer_input_files = a.sub,wf.dag",
		"queue",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("submit file is missing %q:\n%s", want, got)
		}
	}

	// The version string contains spaces, so it has to survive argument
	// quoting intact or DAGMan reads a truncated version and refuses to
	// start.
	if !strings.Contains(got, "'$CondorVersion: 25.4.0 BuildID: test $'") {
		t.Errorf("the -CsdVersion argument was not quoted as one argument:\n%s", got)
	}
	if !strings.Contains(got, `My.JobBatchName = "my workflow"`) {
		t.Errorf("batch name not set:\n%s", got)
	}
}

func TestSubmitFileRequiresAVersion(t *testing.T) {
	// DAGMan treats a -CsdVersion it cannot parse as fatal, so a job
	// submitted without one exits immediately and the caller is left with
	// a cluster id and no workflow.
	if _, err := SubmitFile(SubmitOptions{DagName: "wf.dag"}); err == nil {
		t.Error("SubmitFile accepted an empty CondorVersion")
	}
}

func TestSubmitFileRejectsAPathDagName(t *testing.T) {
	// The spool directory is flat. A name with a directory in it would be
	// rewritten to its basename by the schedd, and the -Dag argument would
	// then point somewhere that does not exist.
	_, err := SubmitFile(SubmitOptions{DagName: "sub/wf.dag", CondorVersion: "v"})
	if err == nil {
		t.Fatal("SubmitFile accepted a DagName with a directory")
	}
	if !strings.Contains(err.Error(), "flat") {
		t.Errorf("error does not explain why: %v", err)
	}
}

func TestSubmitFileOmitsUnsetThrottles(t *testing.T) {
	got, err := SubmitFile(SubmitOptions{DagName: "wf.dag", CondorVersion: "v"})
	if err != nil {
		t.Fatalf("SubmitFile: %v", err)
	}
	for _, unwanted := range []string{"-MaxIdle", "-MaxJobs", "-MaxPre", "-MaxPost", "JobBatchName"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("unset option %q was emitted anyway:\n%s", unwanted, got)
		}
	}
}
