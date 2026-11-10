//go:build libcondor_utils

package fuzzsubmit

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// TestOnEvictMemoryTransformMatchesOracle compares TransformOnEvict
// attribute by attribute, which the main sweep cannot.
//
// TransformOnEvict has two writers in condor_submit: the retry_request_*
// family, which names the resource it built a transform for, and
// `on_evict_checks`, which names transforms the submitter wrote. Only the
// first is implemented here, so the attribute stays in
// knownDivergentGenerated and the sweep never compares it -- which would
// leave the retry family free to write the wrong thing. These files use no
// on_evict_checks, so the oracle's value is the retry family's alone and
// can be asserted directly.
func TestOnEvictMemoryTransformMatchesOracle(t *testing.T) {
	requireOracle(t)

	for _, src := range []string{
		"executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory = 2048\nqueue\n",
		"executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory = 128, 256, 512\nqueue\n",
		"executable = /bin/sleep\nrequest_memory = 100, 400\nqueue\n",
		"executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory_max = 4096\nretry_request_memory_increase = 128\nqueue\n",
		"executable = /bin/sleep\nrequest_memory = 100\nretry_request_memory_increase = 128\nqueue\n",
		"executable = /bin/sleep\nretry_request_memory = 128, 256\nqueue 2\n",
		// No retry at all: neither side names a transform, so the
		// attribute must be absent rather than present and empty.
		"executable = /bin/sleep\nrequest_memory = 100\nqueue\n",
	} {
		t.Run(strings.ReplaceAll(firstRetryLine(src), " ", "_"), func(t *testing.T) {
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
				cppVal, cppHas := lookupFold(cppAds.ByKey[key], "TransformOnEvict")
				goAttrs, ok := goRes.Ads.ByKey[key]
				if !ok {
					t.Fatalf("Go produced no ad %s", key)
				}
				goVal, goHas := lookupFold(goAttrs, "TransformOnEvict")
				switch {
				case cppHas != goHas:
					t.Errorf("%s TransformOnEvict: cpp present=%v (%s), go present=%v (%s)", key, cppHas, cppVal, goHas, goVal)
				case cppHas && !sameValue(cppVal, goVal):
					t.Errorf("%s TransformOnEvict: cpp=%s go=%s", key, cppVal, goVal)
				}
			}
		})
	}
}

// firstRetryLine names a case after the line that makes it interesting.
func firstRetryLine(src string) string {
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(line, "request_memory") || strings.HasPrefix(line, "retry_request_memory") {
			return line
		}
	}
	return firstLine(src)
}
