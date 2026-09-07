package httpserver

import (
	"net/http"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

func TestJobActionRefusalMapsTheScheddsReason(t *testing.T) {
	tests := []struct {
		name    string
		results *htcondor.JobActionResults
		want    int
	}{
		{"already held", &htcondor.JobActionResults{AlreadyDone: 1}, http.StatusConflict},
		{"wrong state for the action", &htcondor.JobActionResults{BadStatus: 1}, http.StatusConflict},
		{"no such job", &htcondor.JobActionResults{NotFound: 1}, http.StatusNotFound},
		{"not allowed", &htcondor.JobActionResults{PermissionDenied: 1}, http.StatusForbidden},
		{"schedd limit", &htcondor.JobActionResults{LimitExceeded: 1}, http.StatusTooManyRequests},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, msg, ok := jobActionRefusal(tt.results, "hold")
			if !ok {
				t.Fatalf("expected the reason to be recognised, got ok=false")
			}
			if code != tt.want {
				t.Errorf("status = %d, want %d", code, tt.want)
			}
			if msg == "" {
				t.Error("expected a message explaining the refusal")
			}
		})
	}
}

func TestJobActionRefusalLeavesUnexplainedFailuresAlone(t *testing.T) {
	// An unexplained failure is a server fault until shown otherwise:
	// dressing one up as a 4xx would tell the caller their request was
	// bad when the schedd may well be broken.
	for _, tt := range []struct {
		name    string
		results *htcondor.JobActionResults
	}{
		{"no results at all", nil},
		{"results that explain nothing", &htcondor.JobActionResults{}},
		{"only a generic error", &htcondor.JobActionResults{Error: 1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, ok := jobActionRefusal(tt.results, "hold"); ok {
				t.Error("expected the 500 to stand")
			}
		})
	}
}

func TestJobActionRefusalIgnoresPartialSuccess(t *testing.T) {
	// A bulk action that moved some jobs and refused others is not a
	// refusal: the caller gets the per-outcome totals in a 200 body, and
	// turning it into a 4xx would hide the part that worked.
	r := &htcondor.JobActionResults{Success: 2, AlreadyDone: 1}
	if _, _, ok := jobActionRefusal(r, "hold"); ok {
		t.Error("a partly successful action must not be reported as a refusal")
	}
}
