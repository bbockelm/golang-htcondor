//go:build libcondor_utils

package fuzzsubmit

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// SubmitHash::submit_param ends with
//
//	if( * pval_expanded == '\0' ) { free( pval_expanded ); return NULL; }
//
// so a submit command that expands to nothing is indistinguishable from
// one the file never wrote. Every submit command goes through it, which
// makes this a rule about the whole language rather than about any one
// keyword, and the keyword table's own "an empty value sets nothing" case
// in simple_keywords_test.go only reaches the keywords that table drives.
//
// The files below are the places where an empty value is not merely
// ignored but changes which branch runs: the executable, where it decides
// between resolving a path and taking SetExecutable's ignore_it path, and
// the alternate-name pairs, where it decides whether the alternate is
// consulted at all.
var emptyValueFiles = []string{
	// A docker or container job needs no executable. An empty one and an
	// absent one are the same thing, and neither is resolved -- resolving
	// "" would put the submitting directory in Cmd.
	"executable =\ndocker_image = busybox\nqueue\n",
	"executable =\ncontainer_image = busybox\nqueue\n",
	"universe = docker\nexecutable =\ndocker_image = busybox\nqueue\n",
	"docker_image = busybox\nqueue\n",
	"container_image = busybox\nqueue\n",
	"universe = docker\ndocker_image = busybox\nqueue\n",
	// An empty primary suppresses its alternate rather than deferring to
	// it: lookup_macro picks the name on presence, before expanding, and
	// the empty result is judged afterwards.
	"executable = /bin/true\noutput =\nstdout = so.txt\nqueue\n",
	"executable = /bin/true\nerror =\nstderr = se.txt\nqueue\n",
	"executable = /bin/true\ninput =\nstdin = si.txt\nqueue\n",
	"executable = /bin/true\nmax_idle =\nmaterialize_max_idle = 9\nqueue\n",
	// An empty value on keywords that otherwise write an attribute.
	"executable = /bin/true\ntransfer_executable =\nqueue\n",
	"executable = /bin/true\nrequest_memory =\nqueue\n",
	"executable = /bin/true\narguments =\nqueue\n",
	"executable = /bin/true\nuniverse =\nqueue\n",
	"executable = /bin/true\ninitialdir =\nqueue\n",
	"executable = /bin/true\ntransfer_input_files =\nqueue\n",
}

func TestEmptyValuesMatchOracle(t *testing.T) {
	requireOracle(t)
	for _, src := range emptyValueFiles {
		t.Run(strings.ReplaceAll(strings.TrimSpace(src), "\n", "; "), func(t *testing.T) {
			fresh, _, skip := check(t, src)
			if skip {
				t.Fatalf("not comparable; one side rejected:\n%s", src)
			}
			for _, d := range fresh {
				t.Errorf("%s\n--- submit file ---\n%s", d, src)
			}
		})
	}
}

// Where an executable IS required, an empty one is as fatal as none:
// SetExecutable gets the same NULL either way. Both sides must refuse,
// which check cannot assert -- it skips any file one side rejects.
func TestEmptyExecutableIsRejectedByBoth(t *testing.T) {
	requireOracle(t)
	for _, src := range []string{
		"executable =\nqueue\n",
		"queue\n",
		"universe = vanilla\nexecutable =\nqueue\n",
	} {
		t.Run(strings.ReplaceAll(strings.TrimSpace(src), "\n", "; "), func(t *testing.T) {
			if cpp := oracle.MakeAds(src, oracle.ModeAds, MaxProcs); cpp.OK {
				t.Errorf("the oracle accepted the file; this test no longer tests what it says")
			}
			if goRes := GoMakeAds(src); goRes.OK {
				t.Errorf("the Go parser accepted a file the oracle refuses")
			}
		})
	}
}
