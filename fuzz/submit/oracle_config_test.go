//go:build libcondor_utils

package fuzzsubmit

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// TestOracleInitializesConfig checks the shim's own environment rather than
// either parser: the submit code reaches param(), so the shim has to call
// config() before it builds a SubmitHash, the way condor_submit does.
//
// Without that step those lookups answer from an uninitialized config, which
// both suppresses attributes the tool would set -- making real divergences
// invisible -- and leaves make_job_ad dereferencing the result, which ends the
// test process rather than reporting a finding.
//
// These files are the shortest ones that reach param() on the container path;
// none of them is a divergence, and they pass here whatever either parser
// does with them.
func TestOracleInitializesConfig(t *testing.T) {
	requireOracle(t)

	for _, src := range []string{
		"container_image = docker://busybox\nqueue\n",
		"universe = container\ncontainer_image = docker://busybox\nqueue\n",
		"universe = container\ncontainer_image = busybox\nexecutable = /bin/sleep\nqueue\n",
		"universe = docker\ndocker_image = busybox\nqueue\n",
	} {
		res := oracle.MakeAds(src, oracle.ModeAds, MaxProcs)
		if res.Panic {
			t.Errorf("oracle threw on %q: %s", src, res.Err)
		}
		if !res.OK && res.Err == "" {
			t.Errorf("oracle failed with no message on %q", src)
		}
	}
}
