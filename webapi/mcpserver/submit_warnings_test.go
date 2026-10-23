package mcpserver

import (
	"context"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// TestToolSubmitJobRejectsSystemExecutable checks the rejection happens
// before the schedd is contacted. The server's schedd points at a port
// nothing listens on, so a submit attempt would surface as a connection
// error rather than the lint message.
func TestToolSubmitJobRejectsSystemExecutable(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	s := &Server{
		schedd: htcondor.NewSchedd("test_schedd", "127.0.0.1:1"),
		logger: logger,
	}
	_, err = s.toolSubmitJob(context.Background(), map[string]interface{}{
		"submit_file": "executable = /bin/bash\narguments = -c \"echo hi\"\nqueue 1\n",
	})
	if err == nil {
		t.Fatal("expected submit_job to reject the submit file")
	}
	if !strings.Contains(err.Error(), "transfer_executable = False") {
		t.Fatalf("expected the lint message, got: %v", err)
	}
}

// TestFormatSubmitWarnings checks the response text the caller actually
// reads: nothing when the submit file is clean, and each diagnostic on
// its own bullet with the remove-and-resubmit hint when it is not.
func TestFormatSubmitWarnings(t *testing.T) {
	if got := formatSubmitWarnings(nil); got != "" {
		t.Errorf("a clean submit file should add nothing to the response, got %q", got)
	}
	got := formatSubmitWarnings([]string{"first problem", "second problem"})
	for _, want := range []string{"WARNINGS about this submit file:", "- first problem\n", "- second problem\n", "remove_job"} {
		if !strings.Contains(got, want) {
			t.Errorf("warning block %q does not contain %q", got, want)
		}
	}
	if !strings.HasSuffix(got, "\n\n") {
		t.Errorf("warning block should end with a blank line, got %q", got)
	}
}
