package htcondor

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestRemoteSubmitKeepsSpooledJobsInQueue pins the interaction between the
// parser's LeaveJobInQueue default and a spooling submission.
//
// condor_submit writes false for a LOCAL submission -- the job leaves the
// queue when it finishes -- and a ten-day expression for one that spools,
// because the submitter has to be able to fetch the output after the job is
// done. This parser cannot tell which it is: the ad is built before anything
// decides to spool. So the parser writes the local default, the remote path
// replaces it, and only a leave_in_queue the SUBMITTER wrote outranks both.
//
// The ordering matters more than it looks. The remote path used to replace
// the attribute only when it was ABSENT, which held until the parser started
// writing the default -- and then a spooled job left the queue the moment it
// completed, taking its sandbox with it before it could be downloaded.
// TestReceiveJobSandboxIntegration catches that end to end, against a real
// schedd; this is the same thing in one function.
func TestRemoteSubmitKeepsSpooledJobsInQueue(t *testing.T) {
	build := func(src string) *classad.ClassAd {
		t.Helper()
		sf, err := ParseSubmitFile(strings.NewReader(src))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
		if err != nil {
			t.Fatalf("MakeJobAd: %v", err)
		}
		return ad
	}

	// What the parser leaves for a local submission.
	local := build("executable = /bin/true\nqueue\n")
	if got, _ := local.Lookup("LeaveJobInQueue"); got == nil || got.String() != "false" {
		t.Fatalf("parser default LeaveJobInQueue = %v, want false", got)
	}

	// A spooling submission replaces it, defaulted or not.
	spooled := build("executable = /bin/true\ntransfer_input_files = a.txt\nqueue\n")
	configureRemoteJobAd(spooled, false)
	expr, ok := spooled.Lookup("LeaveJobInQueue")
	if !ok || expr == nil {
		t.Fatal("LeaveJobInQueue is missing from a spooled job's ad")
	}
	if text := expr.String(); !strings.Contains(text, "CompletionDate") {
		t.Errorf("spooled LeaveJobInQueue = %s, want the expression that keeps it for output retrieval", text)
	}

	// The submitter's own value is not replaced.
	own := build("executable = /bin/true\ntransfer_input_files = a.txt\nleave_in_queue = JobStatus == 4\nqueue\n")
	configureRemoteJobAd(own, true)
	expr, ok = own.Lookup("LeaveJobInQueue")
	if !ok || expr == nil {
		t.Fatal("LeaveJobInQueue is missing")
	}
	if text := expr.String(); strings.Contains(text, "CompletionDate") {
		t.Errorf("LeaveJobInQueue = %s, want the submitter's own expression", text)
	}
}
