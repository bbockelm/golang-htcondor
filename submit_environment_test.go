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

// TestLegacyEnvironmentGoesToEnv: the unquoted form is V1, which HTCondor
// reads from `Env` with an auto-detected delimiter. Left in `Environment`
// it is parsed as space-delimited V2, and `A=1;B=2` becomes the single
// variable A with the value "1;B=2".
func TestLegacyEnvironmentGoesToEnv(t *testing.T) {
	ad := mustJobAd(t, `executable = /bin/true
environment = A=1;B=2
queue
`)
	if _, ok := ad.EvaluateAttrString("Environment"); ok {
		t.Error("a V1 environment was stored as Environment, where it is parsed as space-delimited V2")
	}
	got, ok := ad.EvaluateAttrString("Env")
	if !ok {
		t.Fatal("a V1 environment was not stored as Env")
	}
	if got != "A=1;B=2" {
		t.Errorf("Env = %q", got)
	}
}
