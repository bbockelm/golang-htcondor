package fuzzsubmit

import "testing"

// TestDivergenceEntriesLoad is how a broken divergences/ layout gets
// reported. loadDivergences cannot refuse to build, and an unreadable entry
// would otherwise show up as a flood of fresh divergences with no hint of
// why, so the load error is kept and failed on here.
//
// It needs no oracle, and is deliberately not behind the libcondor_utils tag:
// the entries are data, a typo in one is an ordinary mistake, and the build
// that catches it should be the one everybody runs.
func TestDivergenceEntriesLoad(t *testing.T) {
	if divergenceLoadErr != nil {
		t.Fatalf("divergences/ did not load: %v", divergenceLoadErr)
	}
	if len(knownDivergent) == 0 || len(hostDerived) == 0 {
		t.Fatalf("divergences/ loaded empty: %d seed entries, %d host entries",
			len(knownDivergent), len(hostDerived))
	}
}
