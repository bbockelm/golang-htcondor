//go:build libcondor_utils

package fuzzsubmit

import (
	"fmt"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// stdFileAttrs are the six attributes SetStdin/SetStdout/SetStderr write
// besides the file names themselves.
var stdFileAttrs = []string{
	"TransferIn", "TransferOut", "TransferErr",
	"StreamIn", "StreamOut", "StreamErr",
}

// TestStdFileTransferMatchesOracle compares the std-file transfer and stream
// attributes file by file, which the sweep cannot do for them.
//
// All six are in knownDivergentGenerated over one case -- `transfer_<x> =
// true` with no file named -- where C++ writes a different answer for proc 0
// than for every proc after it. Skipping them in the sweep would also leave
// the stream a job's stdout actually takes uncompared, so the comparison
// happens here instead, over files that do name their files, where the two
// sides agree on every proc.
//
// The divergent case is asserted too, in the only two ways that hold: Go's
// answer is the same for every proc, and it is C++'s answer for proc 0.
func TestStdFileTransferMatchesOracle(t *testing.T) {
	requireOracle(t)

	agree := []string{
		"executable = /bin/true\noutput = o.txt\nerror = e.txt\ninput = i.txt\nqueue 3\n",
		"executable = /bin/true\noutput = o.txt\ntransfer_output = true\nqueue 3\n",
		"executable = /bin/true\noutput = o.txt\ntransfer_output = false\nqueue 3\n",
		"executable = /bin/true\noutput = o.txt\nstream_output = true\nqueue 3\n",
		"executable = /bin/true\nerror = e.txt\nstream_error = true\ntransfer_error = true\nqueue 3\n",
		"executable = /bin/true\ninput = i.txt\nstream_input = true\nqueue 3\n",
		"executable = /bin/true\noutput = /dev/null\nqueue 3\n",
		"executable = /bin/true\nqueue 3\n",
	}
	for _, src := range agree {
		t.Run(fmt.Sprintf("%q", src), func(t *testing.T) {
			cppAds, goAds := bothSides(t, src)
			for _, key := range cppAds.Keys() {
				goAttrs, ok := goAds.ByKey[key]
				if !ok {
					t.Fatalf("Go produced no ad %s", key)
				}
				for _, attr := range stdFileAttrs {
					cppVal, cppHas := lookupFold(cppAds.ByKey[key], attr)
					goVal, goHas := lookupFold(goAttrs, attr)
					switch {
					case cppHas != goHas:
						t.Errorf("%s %s: cpp present=%v (%s), go present=%v (%s)", key, attr, cppHas, cppVal, goHas, goVal)
					case cppHas && !sameValue(cppVal, goVal):
						t.Errorf("%s %s: cpp=%s go=%s", key, attr, cppVal, goVal)
					}
				}
			}
		})
	}

	// The recorded divergence: `transfer_<x> = true` with no file named.
	// SetStdout consults the std file only when the ad does not already
	// carry one (`if (value || ! job->Lookup(ATTR_JOB_OUTPUT))`), and an
	// empty file name is what clears transfer_it. By proc 1 the cluster ad
	// carries Out, so the check is skipped and the keyword stands -- the
	// same submit file produces TransferOut = false for proc 0 and true
	// for every proc after it.
	for _, src := range []string{
		"executable = /bin/true\ntransfer_input = true\nqueue 3\n",
		"executable = /bin/true\ntransfer_output = true\nqueue 3\n",
		"executable = /bin/true\ntransfer_error = true\nqueue 3\n",
	} {
		t.Run("stale state "+fmt.Sprintf("%q", src), func(t *testing.T) {
			cppAds, goAds := bothSides(t, src)
			keys := cppAds.Keys()
			if len(keys) < 2 {
				t.Fatalf("want at least two procs, got %d", len(keys))
			}
			for _, attr := range stdFileAttrs {
				first, firstHas := lookupFold(goAds.ByKey[keys[0]], attr)
				for _, key := range keys[1:] {
					v, has := lookupFold(goAds.ByKey[key], attr)
					if has != firstHas || v != first {
						t.Errorf("%s %s: Go answers %q for proc %d and %q for proc 0; one submit file, one answer",
							key, attr, v, key.Proc, first)
					}
				}
				cppVal, cppHas := lookupFold(cppAds.ByKey[keys[0]], attr)
				switch {
				case cppHas != firstHas:
					t.Errorf("proc 0 %s: cpp present=%v (%s), go present=%v (%s)", attr, cppHas, cppVal, firstHas, first)
				case cppHas && !sameValue(cppVal, first):
					t.Errorf("proc 0 %s: cpp=%s go=%s", attr, cppVal, first)
				}
			}
		})
	}
}

// bothSides runs one submit file through both parsers.
func bothSides(t *testing.T, src string) (Ads, Ads) {
	t.Helper()
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
	return cppAds, goRes.Ads
}
