//go:build libcondor_utils

package fuzzsubmit

import (
	"strconv"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// gpuRequestAttrs are every attribute the GPU request keywords write.
var gpuRequestAttrs = []string{
	"RequestGPUs", "RequireGPUs",
	"GPUsMinCapability", "GPUsMaxCapability",
	"GPUsMinMemory", "GPUsMinRuntime",
	"CUDAVersion",
}

// TestGPURequestKeywordsMatchOracle compares the GPU request family
// attribute by attribute, which the sweep cannot do for two of them.
//
// GPUsMinCapability and GPUsMaxCapability stay in knownDivergentGenerated
// over the int-versus-real printing of a whole-number real, so the sweep
// skips them entirely -- which would leave the two keywords free to write
// the wrong NUMBER, or to write nothing, unnoticed. Here they are compared
// directly, and a case the ClassAd type difference hides is still required
// to hold the same number.
//
// It also pins the shape of the derived RequireGPUs, which is the point of
// the family: the clauses are joined with a left-associative `&&` in a
// fixed order, so a reordering is a different expression tree even though
// it is the same value.
func TestGPURequestKeywordsMatchOracle(t *testing.T) {
	requireOracle(t)

	for _, src := range []string{
		// The keywords are read only once the file has asked for a GPU.
		"executable = /bin/sleep\ngpus_minimum_capability = 8.0\ngpus_minimum_memory = 4G\nrequire_gpus = Capability > 5\nqueue\n",
		"executable = /bin/sleep\nrequest_gpus = undefined\ngpus_minimum_capability = 8.0\nqueue\n",
		// One clause at a time.
		"executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_capability = 8.0\nqueue\n",
		"executable = /bin/sleep\nrequest_gpus = 1\ngpus_maximum_capability = 9.0\nqueue\n",
		"executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_memory = 4G\nqueue\n",
		"executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_runtime = 12.1\nqueue\n",
		// All four, where the order and the grouping are visible.
		"executable = /bin/sleep\nrequest_gpus = 1\ngpus_minimum_capability = 8.0\ngpus_maximum_capability = 9.0\ngpus_minimum_memory = 4G\ngpus_minimum_runtime = 12.1\nqueue\n",
		// A submitter's own require_gpus, with and without a property it
		// already constrains.
		"executable = /bin/sleep\nrequest_gpus = 1\nrequire_gpus = DriverVersion > 11\ngpus_minimum_capability = 8.0\ngpus_maximum_capability = 9.0\nqueue\n",
		"executable = /bin/sleep\nrequest_gpus = 1\nrequire_gpus = Capability > 5\ngpus_minimum_capability = 8.0\ngpus_minimum_memory = 4G\nqueue\n",
		"executable = /bin/sleep\nrequest_gpus = 1\nrequire_gpus = GlobalMemoryMb > 100 || DriverVersion > 11\ngpus_minimum_capability = 8.0\nqueue\n",
		// The attribute-name spelling of each keyword, and the attributes
		// supplied directly, which the derivation still reads.
		"executable = /bin/sleep\nrequest_gpus = 1\nGPUsMinCapability = 8.0\nGPUsMaxCapability = 9.0\nqueue\n",
		"executable = /bin/sleep\nrequest_gpus = 1\n+GPUsMinCapability = 8.0\n+GPUsMinMemory = 100\nqueue\n",
		// cuda_version, whose encoding is not gpus_minimum_runtime's.
		"executable = /bin/sleep\nrequest_gpus = 1\ncuda_version = 12.1\ngpus_minimum_runtime = 12.1\nqueue\n",
		// No GPU request at all: every attribute must be absent on both
		// sides rather than present and empty.
		"executable = /bin/sleep\nqueue\n",
	} {
		t.Run(strings.ReplaceAll(firstGPULine(src), " ", "_"), func(t *testing.T) {
			cpp := oracle.MakeAds(src, oracle.ModeAds, MaxProcs)
			if !cpp.OK {
				t.Fatalf("oracle rejected the file: %s", cpp.Err)
			}
			cppAds, err := ParseCanon(cpp.Ads)
			if err != nil {
				t.Fatalf("malformed oracle output: %v", err)
			}
			goRes := GoMakeAds(src)
			if !goRes.OK {
				t.Fatalf("Go parser rejected the file: %s", goRes.Err)
			}

			for _, key := range cppAds.Keys() {
				goAttrs, ok := goRes.Ads.ByKey[key]
				if !ok {
					t.Fatalf("Go produced no ad %s", key)
				}
				for _, attr := range gpuRequestAttrs {
					cppVal, cppHas := lookupFold(cppAds.ByKey[key], attr)
					goVal, goHas := lookupFold(goAttrs, attr)
					switch {
					case cppHas != goHas:
						t.Errorf("%s %s: cpp present=%v (%s), go present=%v (%s)", key, attr, cppHas, cppVal, goHas, goVal)
					case !cppHas:
					case sameValue(cppVal, goVal):
					case sameNumber(cppVal, goVal):
						// The whole-number real recorded in
						// knownDivergentGenerated. The VALUE still has
						// to match; when the unparser stops dropping
						// the fractional part, sameValue will catch
						// these and the two entries can go.
						if attr != "GPUsMinCapability" && attr != "GPUsMaxCapability" {
							t.Errorf("%s %s: same number, different ClassAd type, which is only expected of the capability pair: cpp=%s go=%s", key, attr, cppVal, goVal)
						}
					default:
						t.Errorf("%s %s: cpp=%s go=%s", key, attr, cppVal, goVal)
					}
				}
			}
		})
	}
}

// sameNumber reports whether two rendered values are the same number
// however each side typed it, which is what is left to assert once the
// ClassAd type difference is set aside.
func sameNumber(a, b string) bool {
	fa, erra := strconv.ParseFloat(strings.TrimSpace(a), 64)
	fb, errb := strconv.ParseFloat(strings.TrimSpace(b), 64)
	return erra == nil && errb == nil && fa == fb
}

// firstGPULine names a case after the line that makes it interesting.
func firstGPULine(src string) string {
	for _, line := range strings.Split(src, "\n") {
		l := strings.ToLower(line)
		if strings.Contains(l, "gpu") || strings.Contains(l, "cuda") {
			return line
		}
	}
	return firstLine(src)
}
