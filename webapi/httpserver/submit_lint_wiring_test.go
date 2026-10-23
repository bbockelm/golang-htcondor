package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/submitlint"
)

// postSubmit posts a submit file to /api/v1/jobs as alice and returns the
// recorder, so a test can read both the status and the body.
func postSubmit(t *testing.T, f *twoOwnerFixture, submitFile string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(JobSubmitRequest{SubmitFile: submitFile})
	if err != nil {
		t.Fatalf("marshalling the request: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/jobs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	f.bearer(t, "alice")(req)
	rec := httptest.NewRecorder()
	f.s.ServeHTTP(rec, req)
	return rec
}

// TestRESTSubmitDoesNotRefuseWhatMCPRefuses: submit_job rejects a
// system-path executable with the default transfer_executable, because
// the agent it serves cannot put that file in the job's spool. A REST
// caller may be on the submitting host, and this endpoint has accepted
// that submit file since it existed -- several of this repo's own
// integration tests submit `executable = /bin/sleep` exactly this way --
// so here the same finding is advice, not a refusal.
//
// The fixture's schedd accepts no submissions, so this reaches it and
// fails there. Any 400 would mean the diagnostic had become a rejection.
func TestRESTSubmitDoesNotRefuseWhatMCPRefuses(t *testing.T) {
	f := twoOwnerScheddServer(t)
	rec := postSubmit(t, f,
		"executable = /bin/sleep\narguments = 60\n"+
			"output = run.out\nerror = run.err\nlog = run.log\nqueue 1\n")

	if rec.Code == http.StatusBadRequest {
		t.Fatalf("a submit file this endpoint has always accepted must not become a 400: %s",
			rec.Body.String())
	}
}

// TestAdvisoryCarriesTheFatalDiagnostic: downgrading the refusal must not
// mean dropping what it said. The caller still has to be told that their
// job is heading for a file-transfer hold.
func TestAdvisoryCarriesTheFatalDiagnostic(t *testing.T) {
	insp := submitlint.Inspect(
		"executable = /bin/sleep\noutput = run.out\nerror = run.err\nlog = run.log\nqueue 1\n")
	if insp.Fatal == nil {
		t.Fatal("expected a fatal diagnostic for a system-path executable")
	}
	advisory := insp.Advisory()
	if len(advisory) == 0 || !strings.Contains(advisory[0], "transfer_executable") {
		t.Fatalf("the fatal diagnostic should lead the advice, got %v", advisory)
	}
	if len(advisory) != len(insp.Warnings)+1 {
		t.Errorf("advice should be the warnings plus the fatal one, got %v", advisory)
	}
}

// TestAdvisoryIsJustTheWarningsWhenNothingIsFatal guards the other half:
// no empty leading entry, no duplication.
func TestAdvisoryIsJustTheWarningsWhenNothingIsFatal(t *testing.T) {
	insp := submitlint.Inspect("executable = run.sh\nqueue 1\n")
	if insp.Fatal != nil {
		t.Fatalf("unexpected fatal: %v", insp.Fatal)
	}
	if got := len(insp.Advisory()); got != len(insp.Warnings) {
		t.Errorf("advice should be exactly the warnings, got %d for %d warnings",
			got, len(insp.Warnings))
	}
}

// TestSubmitResponseCarriesWarnings pins the wire field the submission
// page reads to decide whether to tell the user their output is being
// thrown away. Renaming it would leave the warnings computed, logged and
// invisible.
func TestSubmitResponseCarriesWarnings(t *testing.T) {
	encoded, err := json.Marshal(JobSubmitResponse{
		ClusterID: 7,
		JobIDs:    []string{"7.0"},
		Warnings:  []string{"output is /dev/null"},
	})
	if err != nil {
		t.Fatalf("marshalling the response: %v", err)
	}
	if !strings.Contains(string(encoded), `"warnings":["output is /dev/null"]`) {
		t.Errorf("warnings are not on the wire as expected: %s", encoded)
	}
	// Absent warnings must not appear at all; the page distinguishes
	// "nothing wrong" from "an empty list of things wrong".
	clean, err := json.Marshal(JobSubmitResponse{ClusterID: 7, JobIDs: []string{"7.0"}})
	if err != nil {
		t.Fatalf("marshalling the clean response: %v", err)
	}
	if strings.Contains(string(clean), "warnings") {
		t.Errorf("a clean submit should carry no warnings key: %s", clean)
	}
}
