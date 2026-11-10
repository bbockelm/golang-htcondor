package fuzzconfig

import (
	"fmt"
	"maps"
	"os"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/config/oracle"
)

// TestMain settles which upstream changes the linked oracle carries before
// any test consults the recorded divergences.
//
// It has to happen first: a seed recorded against a change this HTCondor does
// not have would be expected to diverge when the two sides actually agree,
// and a class scoped to that change would excuse a divergence this HTCondor
// should never produce.
//
// It also checks afterwards that the probe is still the one in force. Tests
// swap the trait set to exercise both sides of a change, and one that leaves
// it swapped moves the ground under everything that runs later -- the fuzz
// seed corpus most of all, which Go runs after every Test and which would
// then weigh its findings against the wrong HTCondor. The symptom is a seed
// reported as a new divergence although it is recorded, so the check names
// the cause instead.
func TestMain(m *testing.M) {
	var probed map[string]bool
	if oracle.Available {
		oracleHas = probeOracleTraits()
		probed = maps.Clone(oracleHas)
		fmt.Fprintf(os.Stderr, "config oracle traits:%s\n", describeTraits(oracleHas))
	}

	code := m.Run()

	// Unconditionally: with no oracle linked both are empty, and a test that
	// leaves an override behind is caught in that build too.
	if !maps.Equal(oracleHas, probed) {
		fmt.Fprintf(os.Stderr,
			"a test left the oracle traits overridden, so every test after it and the fuzz seed corpus faced the wrong HTCondor.\nin force at the end:%s\nprobed:%s\n",
			describeTraits(oracleHas), describeTraits(probed))
		code = 1
	}
	os.Exit(code)
}
