package htcondor

import (
	"strings"
	"testing"
)

// TestStringIsBooleanParam pins HTCondor's string_is_boolean_param, which is
// how condor_submit reads every boolean submit command.
//
// It is NOT a fixed vocabulary of words. A value beginning with "true", "1",
// "false" or "0" and then nothing but whitespace is that literal; anything
// else is a ClassAd EXPRESSION evaluated to a boolean. Reading it as a word
// list made `nice_user = 2` a normal job and accepted `nice_user = yes`,
// which condor_submit refuses.
func TestStringIsBooleanParam(t *testing.T) {
	for _, tc := range []struct {
		in    string
		value bool
		ok    bool
	}{
		// The literal path, which is a PREFIX plus trailing whitespace.
		{"true", true, true},
		{"TRUE", true, true},
		{"True", true, true},
		{"true ", true, true},
		{"1", true, true},
		{"false", false, true},
		{"0", false, true},

		// Everything else is an expression.
		{"2", true, true},
		{"-1", true, true},
		{"1.5", true, true},
		{"0.0", false, true},
		{"1 + 1", true, true},
		{"true || false", true, true},
		{" 1", true, true}, // the leading space defeats the literal path
		{"10", true, true}, // "1" then "0" is not the literal, but 10 is a number
		{"1==1", true, true},

		// Not a boolean at all, which condor_submit refuses the
		// submission over.
		{"01", false, false}, // "0" then "1"; and 01 is not an expression
		{"yes", false, false},
		{"no", false, false},
		{"t", false, false},
		{"f", false, false},
		{"truex", false, false},
		{"x", false, false},
		{`"true"`, false, false},
		{"undefined", false, false},
		{"{1}", false, false},
	} {
		value, ok := stringIsBooleanParam(tc.in)
		if ok != tc.ok || (ok && value != tc.value) {
			t.Errorf("stringIsBooleanParam(%q) = %v, %v; want %v, %v", tc.in, value, ok, tc.value, tc.ok)
		}
	}
}

// TestBooleanSubmitCommandRefusesANonBoolean covers the submission being
// refused, which is the half the differential fuzzer cannot see: it compares
// ads, and when condor_submit writes none there is nothing to compare.
func TestBooleanSubmitCommandRefusesANonBoolean(t *testing.T) {
	for _, line := range []string{
		// Only the commands a VANILLA job reaches. vm_vnc and
		// suspend_job_at_exec are read by SetVMParams and SetTDP, which
		// this job never gets to, so condor_submit does not refuse them
		// here either.
		"nice_user = yes",
		"hold = t",
		"stream_output = no",
		"skip_filechecks = undefined",
	} {
		src := "executable = /bin/true\n" + line + "\nqueue\n"
		sf, err := ParseSubmitFile(strings.NewReader(src))
		if err != nil {
			t.Fatalf("%s: parse: %v", line, err)
		}
		if _, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil); err == nil {
			t.Errorf("%s: accepted, want it refused as not a boolean", line)
		}
	}

	// "warn" is the one non-boolean skip_filechecks takes.
	sf, err := ParseSubmitFile(strings.NewReader("executable = /bin/true\nskip_filechecks = warn\nqueue\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("skip_filechecks = warn: %v", err)
	}
	if _, ok := ad.Lookup("SkipFileChecks"); ok {
		t.Error("SkipFileChecks is on the ad; condor_submit writes no attribute for it")
	}
}

// TestBooleanSubmitCommandValue covers the value half, which the fuzzer does
// see.
func TestBooleanSubmitCommandValue(t *testing.T) {
	for _, tc := range []struct {
		value string
		nice  bool
	}{
		{"true", true}, {"1", true}, {"2", true}, {"1.5", true},
		{"1 + 1", true}, {"true || false", true}, {"10", true},
		{"false", false}, {"0", false}, {"0.0", false},
	} {
		ad := adFor(t, "executable = /bin/true\nnice_user = "+tc.value+"\nqueue\n")
		_, held := ad["AcctGroup"]
		if held != tc.nice {
			t.Errorf("nice_user = %s: AcctGroup present = %v, want %v", tc.value, held, tc.nice)
		}
	}
}

// TestHoldAtSubmitCarriesItsReason covers the reason beside the status.
//
// SetJobStatus writes HoldReasonCode 15 (SubmittedOnHold) and the text with
// it, so condor_q can say why the job is held and condor_release has a code
// to match on. Go set the status alone.
func TestHoldAtSubmitCarriesItsReason(t *testing.T) {
	ad := adFor(t, "executable = /bin/true\nhold = true\nqueue\n")
	if got := ad["JobStatus"]; got != "5" {
		t.Errorf("JobStatus = %s, want 5", got)
	}
	if got := ad["HoldReasonCode"]; got != "15" {
		t.Errorf("HoldReasonCode = %s, want 15", got)
	}
	if got := ad["HoldReason"]; got != `"submitted on hold at user's request"` {
		t.Errorf("HoldReason = %s", got)
	}

	// Not held: no reason either.
	ad = adFor(t, "executable = /bin/true\nhold = false\nqueue\n")
	for _, attr := range []string{"HoldReasonCode", "HoldReason"} {
		if got, ok := ad[attr]; ok {
			t.Errorf("%s = %s on a job that is not held", attr, got)
		}
	}
}
