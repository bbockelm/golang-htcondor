package htcondor

import (
	"strings"
	"testing"
)

// TestMaxIdleReachesTheJobAd pins that a submit file asking to be throttled
// says so in the job ad.
//
// max_idle and materialize_max_idle set JobMaterializeMaxIdle in HTCondor's
// own parser (the prunable_keywords table in condor_utils/submit_utils.cpp).
// This library dropped both, so a submission that asked the schedd to keep at
// most N procs idle was submitted with nothing recording that, and ran
// unthrottled.
func TestMaxIdleReachesTheJobAd(t *testing.T) {
	for _, keyword := range []string{"max_idle", "materialize_max_idle"} {
		t.Run(keyword, func(t *testing.T) {
			sf, err := ParseSubmitFile(strings.NewReader(
				"executable = /bin/sleep\n" + keyword + " = 5\nqueue 10\n"))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
			if err != nil {
				t.Fatalf("MakeJobAd: %v", err)
			}
			got, ok := ad.EvaluateAttrInt("JobMaterializeMaxIdle")
			if !ok {
				t.Fatalf("%s = 5 did not set JobMaterializeMaxIdle", keyword)
			}
			if got != 5 {
				t.Errorf("JobMaterializeMaxIdle = %d, want 5", got)
			}
		})
	}
}

// TestMaxIdleIsAnExpression checks the value keeps its type. HTCondor stores
// this keyword as an expression (f_as_expr), not an integer, so a value that
// refers to other attributes has to survive rather than be flattened or
// dropped by an integer parse.
func TestMaxIdleIsAnExpression(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(
		"executable = /bin/sleep\nmax_idle = 2 * 3\nqueue 10\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	expr, ok := ad.Lookup("JobMaterializeMaxIdle")
	if !ok {
		t.Fatal("JobMaterializeMaxIdle is missing from the job ad")
	}
	if text := expr.String(); strings.HasPrefix(text, `"`) {
		t.Errorf("JobMaterializeMaxIdle = %s: stored as a string literal", text)
	}
	if got, ok := ad.EvaluateAttrInt("JobMaterializeMaxIdle"); !ok || got != 6 {
		t.Errorf("JobMaterializeMaxIdle evaluated to (%d, %v), want (6, true)", got, ok)
	}
}

// TestMaxMaterializeIsNotAJobAttribute records the keyword that looks like it
// belongs here and does not. max_materialize never reaches the job ad in
// HTCondor either: want_factory_submit reads it and condor_submit passes it to
// SetJobFactory as the materialize limit. Setting it here would be a
// divergence, not a fix.
func TestMaxMaterializeIsNotAJobAttribute(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(
		"executable = /bin/sleep\nmax_materialize = 2\nqueue 10\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	for _, attr := range []string{"JobMaterializeLimit", "JobMaterializeMaxIdle"} {
		if _, ok := ad.Lookup(attr); ok {
			t.Errorf("max_materialize set %s; HTCondor's parser sets no job attribute for it", attr)
		}
	}
}
