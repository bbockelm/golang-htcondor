//go:build libcondor_utils

package fuzzsubmit

import "testing"

// TestJobLeaseFloorAcrossProcs compares JobLeaseDuration proc by proc, which
// the sweep cannot be relied on to do: whether the generator writes a small
// job_lease_duration with more than one proc depends on the oracle's keyword
// table, so the case reproduces against one condor build and not another.
//
// What it pins is C++ applying its own 20-second floor to ONE PROC.
// already_warned_job_lease_too_small is a flag for not repeating a warning,
// and it gates the value correction as well (submit_utils.cpp: declared
// ~667, tested 3598, set 3603, never reset), so "JobLeaseDuration less than
// 20 seconds is not allowed, using 20 instead" is printed once and applied
// once -- and every proc after the first keeps a lease the code has just
// said is not allowed.
//
// Go applies the floor to every proc. Both halves are asserted, so a change
// on either side is a failure rather than a quiet drift: C++ corrects proc 0
// and leaves the rest, Go corrects all of them.
func TestJobLeaseFloorAcrossProcs(t *testing.T) {
	requireOracle(t)

	for _, tc := range []struct {
		src        string
		cppProc0   string
		cppLater   string
		goEveryOne string
	}{
		{
			src:        "executable = /bin/true\njob_lease_duration = 1\nqueue 3\n",
			cppProc0:   "20",
			cppLater:   "1",
			goEveryOne: "20",
		},
		{
			src:        "executable = /bin/true\njob_lease_duration = 19\nqueue 3\n",
			cppProc0:   "20",
			cppLater:   "19",
			goEveryOne: "20",
		},
		{
			// At or above the floor nothing is corrected, so both sides
			// agree on every proc -- the control for the two above.
			src:        "executable = /bin/true\njob_lease_duration = 25\nqueue 3\n",
			cppProc0:   "25",
			cppLater:   "25",
			goEveryOne: "25",
		},
	} {
		t.Run(tc.src, func(t *testing.T) {
			cppAds, goAds := bothSides(t, tc.src)
			keys := cppAds.Keys()
			if len(keys) != 3 {
				t.Fatalf("want 3 procs, got %d", len(keys))
			}
			for i, key := range keys {
				want := tc.cppLater
				if i == 0 {
					want = tc.cppProc0
				}
				cppVal, _ := lookupFold(cppAds.ByKey[key], "JobLeaseDuration")
				if !sameValue(cppVal, want) {
					t.Errorf("cpp %s JobLeaseDuration = %s, want %s", key, cppVal, want)
				}
				goVal, _ := lookupFold(goAds.ByKey[key], "JobLeaseDuration")
				if !sameValue(goVal, tc.goEveryOne) {
					t.Errorf("go %s JobLeaseDuration = %s, want %s", key, goVal, tc.goEveryOne)
				}
			}
		})
	}
}
