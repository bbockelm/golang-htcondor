package htcondor

import (
	"strings"
	"testing"
)

// TestPolicyExpressionsAreExpressions pins the fix for a job that is removed
// when it should have been requeued.
//
// The job policy expressions have to reach the job ad as ClassAd
// EXPRESSIONS. HTCondor's evaluator (condor_utils/user_job_policy.cpp,
// AnalyzePolicy ~415-427) evaluates each one and requires a number back;
// a string -- even a string whose text reads "ExitCode == 0" -- is not a
// number, so the expression counts as unsatisfied and evaluation falls
// through to the default action. For on_exit_remove that default is REMOVE,
// so a DAGMan manager job that should have been requeued after an abnormal
// exit disappeared from the queue instead, taking a part-finished workflow
// with it.
//
// This library stored all five as strings, which is why the assertions below
// are about the TYPE in the ad and not just its text.
func TestPolicyExpressionsAreExpressions(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(
		"universe = vanilla\n" +
			"executable = /bin/true\n" +
			"on_exit_remove = (ExitCode =!= UNDEFINED && ExitCode == 0)\n" +
			"on_exit_hold = ExitCode =!= 0\n" +
			"periodic_remove = JobStatus == 5\n" +
			"periodic_hold = JobStatus == 1\n" +
			"periodic_release = JobStatus == 5\n" +
			"queue\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	// The evaluator needs these two to resolve.
	_ = ad.Set("ExitCode", int64(0))
	_ = ad.Set("JobStatus", int64(5))

	for _, attr := range []string{"OnExitRemove", "OnExitHold", "PeriodicRemove", "PeriodicHold", "PeriodicRelease"} {
		expr, ok := ad.Lookup(attr)
		if !ok {
			t.Errorf("%s is missing from the job ad", attr)
			continue
		}
		if text := expr.String(); strings.HasPrefix(text, `"`) {
			t.Errorf("%s = %s: stored as a string literal, which the policy evaluator "+
				"does not treat as a boolean", attr, text)
		}
		if _, isString := ad.EvaluateAttrString(attr); isString {
			t.Errorf("%s evaluates to a string; the policy evaluator requires a number", attr)
		}
		if _, isBool := ad.EvaluateAttrBool(attr); !isBool {
			t.Errorf("%s does not evaluate to a boolean against a job ad with ExitCode and JobStatus set", attr)
		}
	}
}

// TestPolicyExpressionRejectsUnparseableText makes sure a malformed policy
// expression is reported rather than quietly stored as a string, which is
// the failure mode this replaced.
func TestPolicyExpressionRejectsUnparseableText(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(
		"universe = vanilla\nexecutable = /bin/true\nperiodic_remove = JobStatus ==\nqueue\n"))
	if err != nil {
		// Rejecting at parse time is just as good.
		return
	}
	if _, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil); err == nil {
		t.Error("MakeJobAd accepted a periodic_remove that is not a ClassAd expression")
	}
}
