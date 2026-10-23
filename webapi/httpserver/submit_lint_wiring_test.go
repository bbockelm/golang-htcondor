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

// TestRESTSubmitRejectsFatalSubmitFiles: the submit-file checks ran on the
// MCP path only, so a submit file MCP refuses outright went through the
// REST path -- the one the web UI and its assistant post to -- and became
// a job that holds on file transfer with a message about errno 2.
//
// The fixture's schedd accepts no submissions, so a submit file that got
// past the lint fails with a transport error instead. That is what makes
// this test meaningful: it can only pass if the rejection happened before
// the schedd was reached.
func TestRESTSubmitRejectsFatalSubmitFiles(t *testing.T) {
	f := twoOwnerScheddServer(t)
	rec := postSubmit(t, f,
		"executable = /bin/bash\narguments = -c \"echo hi\"\n"+
			"output = run.out\nerror = run.err\nlog = run.log\nqueue 1\n")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a submit file with no working outcome, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "transfer_executable") {
		t.Errorf("the rejection should say what to fix, got: %s", rec.Body.String())
	}
}

// TestRESTSubmitDoesNotRejectWarnings: a submit file that merely discards
// its output is a job someone may well have meant to submit, so it is
// advice, not a refusal. This one has to get past the lint and fail at the
// schedd -- any 400 here would mean warnings had become rejections.
func TestRESTSubmitDoesNotRejectWarnings(t *testing.T) {
	f := twoOwnerScheddServer(t)
	rec := postSubmit(t, f,
		"executable = /bin/bash\ntransfer_executable = false\narguments = -c \"echo hi\"\nqueue 1\n")

	if rec.Code == http.StatusBadRequest {
		t.Fatalf("a submit file with only warnings must not be refused, got 400: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "transfer_executable") {
		t.Errorf("this submit file has nothing fatal wrong with it: %s", rec.Body.String())
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
