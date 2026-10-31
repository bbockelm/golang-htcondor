package htcondor

import (
	"strings"
	"testing"
)

// TestEnvironmentReachesTheAdUnquoted pins a failure with no symptom at
// submit time: the job runs, and its environment is populated with
// variables whose names begin with a double quote.
//
// HTCondor reads the ad's `Environment` with Env::MergeFromV2Raw
// (condor_utils/env.cpp), which does NOT strip the surrounding quotes that
// mark the V2 form in a submit file. Storing the submit-file text verbatim
// therefore yields a first variable called `"CONDOR_CONFIG` and a last one
// whose value ends in a quote -- so nothing the caller asked for is set,
// and nothing reports it.
func TestEnvironmentReachesTheAdUnquoted(t *testing.T) {
	ad := mustJobAd(t, `executable = /bin/true
environment = "CONDOR_CONFIG=/tmp/cfg PATH=/usr/bin _CONDOR_MAX_DAGMAN_LOG=0"
queue
`)
	got, ok := ad.EvaluateAttrString("Environment")
	if !ok {
		t.Fatal("Environment was not set at all")
	}
	if strings.Contains(got, `"`) {
		t.Errorf("Environment = %q still carries submit-file quoting; "+
			"HTCondor would read the first variable's name as %q", got, `"CONDOR_CONFIG`)
	}
	if got != "CONDOR_CONFIG=/tmp/cfg PATH=/usr/bin _CONDOR_MAX_DAGMAN_LOG=0" {
		t.Errorf("Environment = %q", got)
	}
}

// TestEnvironmentV2EscapedQuoteIsCollapsed: `""` inside the quoted form
// stands for one literal quote.
func TestEnvironmentV2EscapedQuoteIsCollapsed(t *testing.T) {
	ad := mustJobAd(t, `executable = /bin/true
environment = "GREETING=say""hi"""
queue
`)
	got, _ := ad.EvaluateAttrString("Environment")
	if got != `GREETING=say"hi"` {
		t.Errorf("Environment = %q, want %q", got, `GREETING=say"hi"`)
	}
}

// TestLegacyEnvironmentIsConvertedToV2: the unquoted form is V1, and
// condor_submit CONVERTS it rather than storing the text. `A=1;B=2` becomes
// `Environment = "A=1 B=2"` -- V2 raw, where the separator is a space.
//
// This test used to assert the opposite, that a V1 value belongs under `Env`.
// The danger it was guarding against is real -- V1 text left under the V2
// attribute name is read as one variable whose value contains the rest -- but
// the answer is to convert, which is what SetEnvironment does. `Env` is
// written only for the `env` keyword with a V1 value, and then with an
// EnvDelim beside it; see TestEnvironmentIsReEncoded.
func TestLegacyEnvironmentIsConvertedToV2(t *testing.T) {
	ad := mustJobAd(t, `executable = /bin/true
environment = A=1;B=2
queue
`)
	if _, ok := ad.EvaluateAttrString("Env"); ok {
		t.Error("the `environment` keyword wrote Env; condor_submit writes Environment for it")
	}
	got, ok := ad.EvaluateAttrString("Environment")
	if !ok {
		t.Fatal("Environment is missing")
	}
	if got != "A=1 B=2" {
		t.Errorf("Environment = %q, want %q", got, "A=1 B=2")
	}
}
