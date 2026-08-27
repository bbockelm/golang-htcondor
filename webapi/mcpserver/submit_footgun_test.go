package mcpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// The two submit-file mistakes reported from a live demo, each of which
// previously cost a full submit → hold → query → stdout → stderr
// diagnostic cycle to identify. Both are caught before the schedd is
// contacted, so they are testable without one — and that is the point:
// the caller learns at submit time instead of from a hold reason.

func footgunServer(t *testing.T) *Server {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return &Server{
		// Unreachable on purpose: reaching the schedd at all would mean
		// the check did not fire.
		schedd:    htcondor.NewSchedd("test_schedd", "127.0.0.1:1"),
		logger:    logger,
		delegated: false,
	}
}

// TestSubmitRejectsSystemExecutableWithoutTransferFlag: a bare
// /bin/bash with transfer_executable left at its default sends HTCondor
// looking for a copy in an empty spool dir, and the job holds with
// "No such file or directory" — which names neither the executable nor
// the setting responsible.
func TestSubmitRejectsSystemExecutableWithoutTransferFlag(t *testing.T) {
	s := footgunServer(t)

	_, err := s.toolSubmitJob(context.Background(), map[string]interface{}{
		"submit_file": "executable = /bin/bash\narguments = -c \"echo hi\"\nqueue\n",
	})
	if err == nil {
		t.Fatal("expected the submit to be rejected before it reached the schedd")
	}
	msg := err.Error()
	// The message has to carry the fix, not just the diagnosis: this is
	// read by an LLM composing the next attempt.
	for _, want := range []string{"transfer_executable", "/bin/bash"} {
		if !strings.Contains(msg, want) {
			t.Errorf("rejection does not mention %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "connect") || strings.Contains(msg, "submission failed") {
		t.Errorf("the submit reached the schedd instead of being rejected: %s", msg)
	}
}

// TestSubmitWarnsAboutMacroExpansionInArguments: $(...) in a submit file
// is HTCondor macro expansion, not shell substitution. `$(hostname)` is
// expanded away before bash ever sees it, the job runs, and the command
// is quietly wrong — there is no error at submit time to notice.
func TestSubmitWarnsAboutMacroExpansionInArguments(t *testing.T) {
	warnings := warnUndefinedMacros(
		"executable = /bin/bash\ntransfer_executable = False\n" +
			"arguments = \"-c 'echo $(hostname)'\"\nqueue\n")
	if len(warnings) == 0 {
		t.Fatal("no warning for $(hostname) in arguments")
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{"$(hostname)", "arguments", "script"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warning does not mention %q: %s", want, joined)
		}
	}
}

// TestSubmitJobDescriptionKeepsBothRules guards the tool description
// itself. The checks above fire at submit time, but the description is
// what an LLM reads while composing the call — it is the difference
// between never making the mistake and being told about it afterwards.
// Description text is easy to trim in good faith, so the two rules are
// pinned here.
func TestSubmitJobDescriptionKeepsBothRules(t *testing.T) {
	s := footgunServer(t)
	listed, ok := s.handleListTools(context.Background(), nil).(map[string]interface{})
	if !ok {
		t.Fatal("tools/list did not return an object")
	}
	tools, ok := listed["tools"].([]Tool)
	if !ok {
		t.Fatalf("tools/list has no tool slice: %#v", listed)
	}
	var desc string
	for _, tool := range tools {
		if tool.Name == "submit_job" {
			desc = tool.Description
		}
	}
	if desc == "" {
		t.Fatal("submit_job has no description")
	}
	for _, want := range []string{"$(", "transfer_executable", "script"} {
		if !strings.Contains(desc, want) {
			t.Errorf("submit_job description no longer mentions %q:\n%s", want, desc)
		}
	}
}
