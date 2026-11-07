//go:build libcondor_utils

package fuzzsubmit

import (
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// TestVersionTableAgreesWithTheOracle is the only check that ties
// SubmitBehaviorFor's release table to a real parser.
//
// Everywhere else the two are kept apart on purpose: the harness decides what
// the oracle does by PROBING it, because a version number cannot be trusted
// to say whether a backported change is present. The table has to answer the
// same question from the number alone, since that is all a caller holding a
// schedd's CondorVersion has. Here they meet: for the oracle actually linked
// in, the answer from the probes and the answer from the table must match.
//
// A mismatch is one of two things, and the message says both because they are
// fixed in different places: the table is wrong about which release carries a
// change, or this oracle was built from a branch whose version number does
// not describe its contents -- a feature branch cut before the change went
// in, rather than a release or main.
func TestVersionTableAgreesWithTheOracle(t *testing.T) {
	requireOracle(t)

	facts, err := gatherOracleFacts()
	if err != nil {
		t.Fatalf("probing the oracle: %v", err)
	}
	version := oracle.Version()
	fromTable := htcondor.SubmitBehaviorFor(version)
	fromProbes := goBehaviorFor(probeOracleTraits(facts))

	if fromTable != fromProbes {
		t.Errorf("for oracle %s\n  SubmitBehaviorFor says %+v\n  probing it says      %+v\n"+
			"either submitBehaviorReleases names the wrong release for a change, "+
			"or this oracle is built from a branch whose version does not describe what it carries",
			version, fromTable, fromProbes)
	}
}
