package fuzzconfig

import (
	"fmt"
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
func TestMain(m *testing.M) {
	if oracle.Available {
		oracleHas = probeOracleTraits()
		fmt.Fprintf(os.Stderr, "config oracle traits:%s\n", describeTraits(oracleHas))
	}
	os.Exit(m.Run())
}
