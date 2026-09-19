package httpserver

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/interactive"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestInteractiveTerminalSubmitFileSetsJobBatchName is a regression test
// for "the interactive page always says No active terminal sessions even
// when the user just submitted one".
//
// The list handler ([httpserver/handlers_interactive.go]) filters on the
// JobBatchName ad attribute having a known prefix. The submit-file the
// terminal-create handler emits used to spell the key as
// `job_batch_name`, but our submit parser at [submit.go]'s
// setExtendedJobExprs only recognizes the bare `batch_name` form (the
// same spelling condor_submit accepts). The misspelled key was a no-op
// — the schedd stored the job without JobBatchName, the prefix filter
// matched zero rows, and every list returned "No active terminal
// sessions" no matter how many were actually queued.
//
// The test asserts the round trip explicitly: build the submit file
// with the production helper, parse it through the same parser the
// schedd-submit path uses, and check the resulting ad has
// JobBatchName populated with the expected prefix. Running this is
// cheaper than spinning up a schedd and gives us precise feedback if
// the parser key contract ever changes.
func TestInteractiveTerminalSubmitFileSetsJobBatchName(t *testing.T) {
	const (
		instanceID = "deadbeefdeadbeef"
		batchName  = interactiveTerminalBatchPrefix + instanceID
	)
	src := buildInteractiveTerminalSubmitFile(interactive.SubmitArgs{
		InstanceID: instanceID,
		BatchName:  batchName,
		Cpus:       1,
		MemoryMB:   1024,
		DiskMB:     1024,
	})

	sf, err := htcondor.ParseSubmitFile(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseSubmitFile: %v\nsubmit file:\n%s", err, src)
	}
	result, err := sf.Submit(1000)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if len(result.ProcAds) != 1 {
		t.Fatalf("expected 1 proc ad, got %d", len(result.ProcAds))
	}

	got, ok := result.ProcAds[0].EvaluateAttrString("JobBatchName")
	if !ok {
		t.Fatalf("JobBatchName attribute not set on submitted ad — the list handler's prefix filter would skip every job. Submit file:\n%s",
			src)
	}
	if got != batchName {
		t.Errorf("JobBatchName = %q, want %q", got, batchName)
	}

	// Also verify the prefix predicate the list handler uses agrees,
	// since the whole point of setting JobBatchName is to make this
	// check pass.
	if !strings.HasPrefix(got, interactiveTerminalBatchPrefix) {
		t.Errorf("JobBatchName %q does not start with prefix %q", got, interactiveTerminalBatchPrefix)
	}
}

// TestInteractiveTerminalRequestValidatesSubmitLines: user submit_lines
// are validated the same way as the MCP session path -- session-defining
// commands rejected, benign additions accepted.
func TestInteractiveTerminalRequestValidatesSubmitLines(t *testing.T) {
	base := func(lines string) *InteractiveCreateTerminalRequest {
		r := &InteractiveCreateTerminalRequest{Cpus: 1, MemoryMB: 1024, DiskMB: 1024, SubmitLines: lines}
		return r
	}
	if err := base("executable = /bin/sh").validate(); err == nil {
		t.Error("expected submit_lines to reject an executable override")
	}
	if err := base("queue 5").validate(); err == nil {
		t.Error("expected submit_lines to reject a queue statement")
	}
	if err := base("+ProjectName = \"P\"").validate(); err != nil {
		t.Errorf("benign submit_lines rejected: %v", err)
	}
}

// TestInteractiveTerminalSubmitFileIncludesCallerLines: a validated caller
// line reaches the generated submit file.
func TestInteractiveTerminalSubmitFileIncludesCallerLines(t *testing.T) {
	src := buildInteractiveTerminalSubmitFile(interactive.SubmitArgs{
		InstanceID:        "deadbeefdeadbeef",
		BatchName:         interactiveTerminalBatchPrefix + "deadbeefdeadbeef",
		Cpus:              1,
		MemoryMB:          1024,
		DiskMB:            1024,
		CallerSubmitLines: "+ProjectName = \"MyProj\"",
	})
	if !strings.Contains(src, `+ProjectName = "MyProj"`) {
		t.Errorf("caller submit line missing from submit file:\n%s", src)
	}
}
