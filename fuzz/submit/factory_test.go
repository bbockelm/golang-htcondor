//go:build libcondor_utils

package fuzzsubmit

import (
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// factorySeeds are submit files that make condor_submit use late
// materialization. Each of the three spellings that trigger it is covered,
// because want_factory_submit checks them in order and an implementation that
// handles only max_materialize would still pass on the first.
var factorySeeds = []struct {
	name  string
	input string
}{
	{"max_materialize", "executable = /bin/sleep\nmax_materialize = 2\nqueue 5\n"},
	{"max_idle", "executable = /bin/sleep\nmax_idle = 5\nqueue 5\n"},
	{"materialize_max_idle", "executable = /bin/sleep\nmaterialize_max_idle = 3\nqueue 5\n"},
	{"max_idle with items", "executable = /bin/sleep\narguments = $(item)\nmax_idle = 5\nqueue item in (a b c)\n"},
}

// TestFactoryOracleReportsLateMaterialization pins what the C++ side decides,
// so the Go comparison below has something to be measured against.
func TestFactoryOracleReportsLateMaterialization(t *testing.T) {
	requireOracle(t)

	for _, fs := range factorySeeds {
		t.Run(fs.name, func(t *testing.T) {
			fi := oracle.Factory(fs.input, MaxProcs)
			if !fi.OK {
				t.Fatalf("oracle rejected %q: %s", fs.input, fi.Err)
			}
			if !fi.Factory {
				t.Errorf("want_factory_submit said no for a file setting %s", fs.name)
			}
			if fi.MaxMaterialize <= 0 {
				t.Errorf("max_materialize = %d, want a positive limit", fi.MaxMaterialize)
			}
			if fi.Digest == "" {
				t.Error("empty submit digest: the schedd would have nothing to expand")
			}
			// The digest must keep macro references unexpanded, or the schedd
			// cannot vary them per proc.
			if strings.Contains(fs.input, "$(item)") && !strings.Contains(fi.Digest, "$(item)") {
				t.Errorf("digest expanded $(item) instead of leaving it for the schedd:\n%s", fi.Digest)
			}
			t.Logf("factory=%v max_materialize=%d vars=%v items=%v",
				fi.Factory, fi.MaxMaterialize, fi.Vars, fi.Items)
		})
	}
}

// TestGoHasNoLateMaterialization records that the Go submit path ignores
// max_materialize and max_idle entirely: it materializes every proc up front,
// where condor_submit would send a cluster ad, a digest and the itemdata and
// let the schedd materialize.
//
// SubmitLate is named for the feature but does not implement it -- it builds
// the same per-proc ads Submit does. The test fails once the Go side learns to
// do this, which is the signal to turn it into a real comparison of the
// factory parameters, the itemdata and the digest.
func TestGoHasNoLateMaterialization(t *testing.T) {
	requireOracle(t)

	for _, fs := range factorySeeds {
		t.Run(fs.name, func(t *testing.T) {
			fi := oracle.Factory(fs.input, MaxProcs)
			if !fi.OK || !fi.Factory {
				t.Skipf("oracle does not call this a factory submit: %s", fi.Err)
			}

			sf, err := htcondor.ParseSubmitFile(strings.NewReader(fs.input))
			if err != nil {
				t.Skipf("Go parser rejected the file: %v", err)
			}
			res, err := sf.SubmitLate(ClusterID)
			if err != nil {
				t.Fatalf("SubmitLate failed: %v", err)
			}

			// Eager materialization is the gap: a factory submission sends no
			// proc ads at all, so more than one here means Go did the other
			// thing. One ad is ambiguous (it could be a cluster ad), so only
			// the multi-proc seeds prove it.
			if len(res.ProcAds) > 1 {
				t.Logf("Go materialized %d proc ads where condor_submit would send a digest and %d itemdata rows",
					len(res.ProcAds), len(fi.Items))
			} else {
				t.Skip("single proc ad is not evidence either way")
			}
		})
	}
}

// TestFactoryAttributesReachTheClusterAd checks the part of late
// materialization that does not need the factory path at all: max_idle and
// max_materialize are ordinary submit keywords that set JobMaterializeMaxIdle
// and JobMaterializeLimit on the cluster ad. Whether or not Go implements
// factories, it should carry these through.
func TestFactoryAttributesReachTheClusterAd(t *testing.T) {
	requireOracle(t)

	// max_materialize is deliberately absent: it never becomes an ad
	// attribute. want_factory_submit reads it and condor_submit passes it to
	// set_Factory(), so there is nothing on the ad to compare. Verified
	// against the oracle, which emits no JobMaterialize* for it.
	cases := []struct {
		input string
		attr  string
	}{
		{"executable = /bin/sleep\nmax_idle = 5\nqueue\n", "JobMaterializeMaxIdle"},
		{"executable = /bin/sleep\nmaterialize_max_idle = 3\nqueue\n", "JobMaterializeMaxIdle"},
	}
	for _, c := range cases {
		t.Run(strings.ReplaceAll(firstLine(c.input), " ", "_")+"_"+c.attr, func(t *testing.T) {
			cpp := oracle.MakeAds(c.input, oracle.ModeAds, MaxProcs)
			if !cpp.OK {
				t.Fatalf("oracle rejected the file: %s", cpp.Err)
			}
			cppAds, err := ParseCanon(cpp.Ads)
			if err != nil {
				t.Fatalf("malformed oracle output: %v", err)
			}
			if _, ok := lookupFold(cppAds.ByKey[AdKey{Cluster: ClusterID, Proc: 0}], c.attr); !ok {
				t.Fatalf("the C++ parser does not set %s either, so there is nothing to compare", c.attr)
			}

			goRes := GoMakeAds(c.input)
			if !goRes.OK {
				t.Fatalf("Go parser rejected the file: %s", goRes.Err)
			}
			attrs, ok := goRes.Ads.ByKey[AdKey{Cluster: ClusterID, Proc: 0}]
			if !ok {
				t.Fatal("Go produced no proc 0 ad")
			}
			cppVal, _ := lookupFold(cppAds.ByKey[AdKey{Cluster: ClusterID, Proc: 0}], c.attr)
			goVal, present := lookupFold(attrs, c.attr)
			if !present {
				t.Fatalf("Go drops %s, so nothing records that the file asked to be throttled", c.attr)
			}
			if !sameValue(cppVal, goVal) {
				t.Errorf("%s: cpp=%s go=%s", c.attr, cppVal, goVal)
			}
		})
	}
}
