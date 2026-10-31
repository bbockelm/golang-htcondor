//go:build libcondor_utils

package fuzzsubmit

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// transferAttrs is the family this file pins: everything SubmitHash's
// SetTransferFiles, SetStdin/SetStdout/SetStderr and the transfer part of
// SetRequirements decide between them.
//
// ShouldTransferFiles is deliberately absent. Its DEFAULT still differs
// (condor_submit uses IF_NEEDED, this package YES) and that difference is
// recorded in knownDivergent rather than fixed here, so asserting the
// attribute would fail on every file that does not set it. Everything
// else about should_transfer_files -- which spellings are legal, what
// they canonicalize to, and what they do to WhenToTransferOutput -- is
// asserted through the attributes below.
var transferAttrs = []string{
	"WhenToTransferOutput",
	"WantFTOnCheckpoint",
	"WantTransferPluginMethods",
	"TransferInput",
	"TransferOutput",
	"TransferIn",
	"TransferOut",
	"TransferErr",
	"StreamIn",
	"StreamOut",
	"StreamErr",
	"OutputDestination",
}

// transferFiles are submit files chosen to reach each decision in that
// family. The generated sweep does not reliably produce them -- a
// `should_transfer_files = NO` file that condor_submit still accepts is a
// narrow target, and whether a given 600-file corpus contains one is an
// accident of the generator -- so a green sweep says nothing about these.
// They are written out here instead, and compared attribute by attribute
// against the oracle rather than through the sweep's known-divergence
// filter.
var transferFiles = []string{
	// should/when as one decision.
	"executable = /bin/sleep\nshould_transfer_files = NO\nqueue\n",
	"executable = /bin/sleep\nshould_transfer_files = NEVER\nqueue\n",
	"executable = /bin/sleep\nshould_transfer_files = FALSE\nqueue\n",
	"executable = /bin/sleep\nshould_transfer_files = always\nwhen_to_transfer_output = ONEXIT\nqueue\n",
	"executable = /bin/sleep\nshould_transfer_files = AUTO\nqueue\n",
	"executable = /bin/sleep\nShouldTransferFiles = TRUE\nqueue\n",
	"executable = /bin/sleep\nwhen_to_transfer_output = ON_EXIT_OR_EVICT\nqueue\n",
	"executable = /bin/sleep\nWhenToTransferOutput = ALWAYS\nqueue\n",
	"executable = /bin/sleep\nwhen_to_transfer_output = ON_SUCCESS\nqueue\n",
	"executable = /bin/sleep\nqueue\n",

	// checkpoint_exit_code turns on transfer-on-checkpoint.
	"executable = /bin/sleep\ncheckpoint_exit_code = 85\nqueue\n",
	"executable = /bin/sleep\ncheckpoint_exit_code = 0\nqueue\n",

	// The file lists, including the attribute-name spelling.
	"executable = /bin/sleep\ntransfer_input_files = a.txt, b.txt\nqueue\n",
	"executable = /bin/sleep\nTransferInputFiles = a.txt, b.txt\nqueue\n",
	"executable = /bin/sleep\ntransfer_output_files = o.txt\nqueue\n",
	"executable = /bin/sleep\nTransferOutputFiles = o.txt, p.txt\nqueue\n",
	"executable = /bin/sleep\ntransfer_input_files = my file.txt, other.txt\nqueue\n",
	"executable = /bin/sleep\ntransfer_input_files = \"\"\nqueue\n",
	"executable = /bin/sleep\ntransfer_output_files = \"\"\nqueue\n",

	// Plugin methods: needed, supplied, and both.
	"executable = /bin/sleep\ntransfer_input_files = osdf:///a/b, https://x/y, plain.txt\nqueue\n",
	"executable = /bin/sleep\ntransfer_input_files = osdf:///a/b\ntransfer_plugins = osdf,pelican=/usr/bin/p\nqueue\n",
	"executable = /bin/sleep\ntransfer_input_files = osdf:///a/b, davs://d/e\ntransfer_plugins = OSDF=/usr/bin/p\nqueue\n",
	"executable = /bin/sleep\ntransfer_input_files = chtc+https://x/y\nqueue\n",
	"executable = /bin/sleep\ntransfer_input_files = OSDF://a/b, osdf://c/d\nqueue\n",
	"executable = /bin/sleep\noutput_destination = file:///tmp/out\nqueue\n",
	"executable = /bin/sleep\noutput_destination = \"file:///tmp/out\"\nqueue\n",
	"executable = /bin/sleep\noutput_destination = notaurl\nqueue\n",
	"executable = /bin/sleep\ntransfer_output_remaps = \"o=osdf:///x ; e = https://y\"\nqueue\n",
	"executable = /bin/sleep\n+TransferInput = \"http://x/y\"\nqueue\n",
	// The gates: a universe that never transfers, and a Requirements
	// that already names the attribute condor_submit would have added.
	"universe = grid\ngrid_resource = batch slurm\nexecutable = /bin/sleep\ntransfer_input_files = osdf:///a/b\nqueue\n",
	"universe = local\nexecutable = /bin/sleep\ntransfer_input_files = osdf:///a/b\nqueue\n",
	"executable = /bin/sleep\nrequirements = TARGET.HasFileTransfer\ntransfer_input_files = osdf:///a/b\nqueue\n",
	"executable = /bin/sleep\nrequirements = MY.HasFileTransfer\ntransfer_input_files = osdf:///a/b\nqueue\n",
	"executable = /bin/sleep\nrequirements = TARGET.HasJobTransferPlugins\ntransfer_input_files = osdf:///a/b\nqueue\n",
	"executable = /bin/sleep\nrequirements = TARGET.HasFileTransferPluginMethods isnt undefined\ntransfer_input_files = osdf:///a/b\nqueue\n",

	// The standard streams: stream vs transfer, and the null file.
	"executable = /bin/sleep\ninput = in.txt\noutput = out.txt\nerror = err.txt\nstream_input = true\nstream_output = true\nstream_error = true\nqueue\n",
	"executable = /bin/sleep\noutput = out.txt\nstream_output = false\nqueue\n",
	"executable = /bin/sleep\ninput = in.txt\ntransfer_input = false\nqueue\n",
	"executable = /bin/sleep\noutput = out.txt\ntransfer_output = false\nstream_output = true\nqueue\n",
	"executable = /bin/sleep\ninput = /dev/null\nstream_input = true\nqueue\n",
	"executable = /bin/sleep\nstream_output = true\nqueue\n",
}

// TestTransferAttributesMatchOracle compares the file-transfer family
// attribute by attribute against SubmitHash.
//
// The sweep in generated_test.go cannot stand in for this. It filters
// every attribute still listed in knownDivergentGenerated, and the files
// it generates are whatever the keyword table and the corpus bytes happen
// to produce -- so an attribute can go quiet there because the generator
// stopped writing a keyword rather than because the Go parser got it
// right. These files reach each case on purpose.
func TestTransferAttributesMatchOracle(t *testing.T) {
	requireOracle(t)

	for _, src := range transferFiles {
		t.Run(strings.ReplaceAll(transferCaseName(src), " ", "_"), func(t *testing.T) {
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
				for _, attr := range transferAttrs {
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
}

// TestTransferContradictionsAreRejected pins the four combinations of
// should_transfer_files and when_to_transfer_output that condor_submit
// refuses outright, plus the two unusable values.
//
// Acceptance is not asserted by the sweep -- check() skips any file one
// side rejected -- so without this a Go parser that quietly accepted
// "should_transfer_files = MAYBE" and wrote it into the job ad would look
// exactly as green as one that rejected it.
func TestTransferContradictionsAreRejected(t *testing.T) {
	requireOracle(t)

	for _, src := range []string{
		"executable = /bin/sleep\nshould_transfer_files = MAYBE\nqueue\n",
		"executable = /bin/sleep\nwhen_to_transfer_output = SOMETIME\nqueue\n",
		"executable = /bin/sleep\nshould_transfer_files = \"YES\"\nqueue\n",
		"executable = /bin/sleep\nshould_transfer_files = NO\nwhen_to_transfer_output = ON_EXIT\nqueue\n",
		"executable = /bin/sleep\nshould_transfer_files = IF_NEEDED\nwhen_to_transfer_output = ON_EXIT_OR_EVICT\nqueue\n",
		"executable = /bin/sleep\nshould_transfer_files = NO\ntransfer_input_files = a.txt\nqueue\n",
		"executable = /bin/sleep\nshould_transfer_files = NO\ntransfer_output_files = \"\"\nqueue\n",
	} {
		t.Run(strings.ReplaceAll(transferCaseName(src), " ", "_"), func(t *testing.T) {
			if cpp := oracle.MakeAds(src, oracle.ModeAds, MaxProcs); cpp.OK {
				t.Fatalf("the oracle accepted this file, so it is the wrong case for this test")
			}
			if goRes := GoMakeAds(src); goRes.OK {
				t.Errorf("Go accepted a file condor_submit rejects")
			}
		})
	}
}

// transferCaseName names a case after the line that makes it interesting:
// the last line before the queue statement, which is the setting under
// test in every file above.
func transferCaseName(src string) string {
	lines := strings.Split(strings.TrimSpace(src), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if !strings.HasPrefix(strings.ToLower(lines[i]), "queue") {
			return lines[i]
		}
	}
	return firstLine(src)
}
