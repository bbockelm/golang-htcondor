//go:build libcondor_utils

package fuzzsubmit

import "testing"

// TestDivergenceEntriesLoad is how a broken divergences/ layout gets
// reported. loadDivergences cannot refuse to build, and an unreadable entry
// would otherwise show up as a flood of fresh divergences with no hint of
// why, so the load error is kept and failed on here.
func TestDivergenceEntriesLoad(t *testing.T) {
	if divergenceLoadErr != nil {
		t.Fatalf("divergences/ did not load: %v", divergenceLoadErr)
	}
	if len(knownDivergent) == 0 || len(hostDerived) == 0 {
		t.Fatalf("divergences/ loaded empty: %d seed entries, %d host entries",
			len(knownDivergent), len(hostDerived))
	}
}
