package httpserver

import "testing"

// A job sits in JobStatus 5 with HoldReasonCode 16 between submit and the
// end of input spooling. Counting it as "held" on the dashboard makes a
// routine submit look like a failure, and disagrees with the jobs page,
// which labels the same job "Uploading Inputs".
func TestDashboardStatusName(t *testing.T) {
	tests := []struct {
		name           string
		status         int64
		holdReasonCode int64
		want           string
	}{
		{"spooling input is its own bucket", 5, holdReasonCodeSpoolingInput, "uploading"},
		{"a real hold is still held", 5, 3, "held"},
		{"a hold with no reason is still held", 5, 0, "held"},
		// The override is keyed on both fields: an idle job that happens
		// to carry a stale HoldReasonCode must not be re-bucketed.
		{"idle with a stale hold code stays idle", 1, holdReasonCodeSpoolingInput, "idle"},
		{"running", 2, 0, "running"},
		{"removed", 3, 0, "removed"},
		{"completed", 4, 0, "completed"},
		{"transferring output", 6, 0, "transferring_output"},
		{"suspended", 7, 0, "suspended"},
		{"unknown status keeps the numeric form", 42, 0, "status_42"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dashboardStatusName(tt.status, tt.holdReasonCode); got != tt.want {
				t.Errorf("dashboardStatusName(%d, %d) = %q, want %q",
					tt.status, tt.holdReasonCode, got, tt.want)
			}
		})
	}
}
