//go:build libcondor_utils

package fuzzsubmit

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// TestOracleHandlesContainerImage pins the fix for an oracle crash, not a
// parser divergence.
//
// container_image sends the submit code through param(), and the shim used to
// leave HTCondor's global config uninitialized, so these two lines segfaulted
// inside make_job_ad and took the whole test process down. Real condor_submit
// parses them fine because it calls config() first.
//
// A crash here is unrecoverable -- it kills the fuzzer rather than reporting a
// finding -- so it is worth a test of its own.
func TestOracleHandlesContainerImage(t *testing.T) {
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
