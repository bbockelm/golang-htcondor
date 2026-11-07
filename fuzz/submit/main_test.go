package fuzzsubmit

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// TestMain settles which recorded divergences apply to the oracle this binary
// is linked against, before any test consults them.
//
// It has to happen here rather than in each test: record() reads the entry
// maps directly, and an entry about an upstream change the linked HTCondor
// does not have would otherwise excuse a divergence that HTCondor should never
// produce -- which is the one failure this whole mechanism exists to prevent.
//
// A probe that cannot run is fatal. The alternative is comparing against an
// oracle whose behavior we have not established, where every entry is a guess.
func TestMain(m *testing.M) {
	if oracle.Available {
		facts, err := gatherOracleFacts()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot probe the oracle, so no recorded divergence can be trusted: %v\n", err)
			os.Exit(1)
		}
		have := probeOracleTraits(facts)
		fmt.Fprintf(os.Stderr, "oracle %s\ntraits:%s\n", oracle.Version(), describeTraits(have))
		if dropped := activateDivergences(have); len(dropped) > 0 {
			fmt.Fprintf(os.Stderr, "entries not applicable to this oracle: %s\n", strings.Join(dropped, " "))
		}
	}
	os.Exit(m.Run())
}
