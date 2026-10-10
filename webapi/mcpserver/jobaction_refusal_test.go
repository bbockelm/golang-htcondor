package mcpserver

import (
	"context"
	"errors"
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// refusingAction answers a job action the way the schedd does when it acts on
// nothing: the per-job counts, and the refusal that carries them.
func refusingAction(results *htcondor.JobActionResults) func(context.Context, string, string) (*htcondor.JobActionResults, error) {
	return func(context.Context, string, string) (*htcondor.JobActionResults, error) {
		return results, &htcondor.JobActionRefusedError{Results: results}
	}
}

// Every single-job tool acts by constraint, and a constraint matching nothing
// comes back with every count zero. The tool used to report that as
// "job hold failed: action failed: result=0".
func TestSingleJobActionReportsTheScheddsReason(t *testing.T) {
	for _, tc := range []struct {
		name    string
		results *htcondor.JobActionResults
		want    string
	}{
		{"no such job", &htcondor.JobActionResults{}, "not in the queue"},
		{"already held", &htcondor.JobActionResults{AlreadyDone: 1}, "already in that state"},
		{"not allowed", &htcondor.JobActionResults{PermissionDenied: 1}, "permission denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := (&Server{}).performJobAction(htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.domain"), map[string]interface{}{"job_id": "12.0"},
				refusingAction(tc.results), "Held via MCP", "hold")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want an error saying %q", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), "result=0") {
				t.Errorf("the schedd's reason was replaced by its wire code: %v", err)
			}
		})
	}
}

func TestSingleJobActionStillFailsOnTransportErrors(t *testing.T) {
	_, err := (&Server{}).performJobAction(htcondor.WithAuthenticatedUser(context.Background(), "alice@uid.domain"), map[string]interface{}{"job_id": "12.0"},
		func(context.Context, string, string) (*htcondor.JobActionResults, error) {
			return nil, errors.New("connection refused")
		}, "Held via MCP", "hold")
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("got %v, want the connection failure", err)
	}
}
