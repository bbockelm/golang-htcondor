package htcondor

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// submitProcAd parses src and returns its single proc ad. Unlike
// submitInDir it hands back the ad rather than its string attributes,
// which is what reading a boolean takes.
func submitProcAd(t *testing.T, src string) *classad.ClassAd {
	t.Helper()
	t.Chdir(t.TempDir())
	sf, err := ParseSubmitFile(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseSubmitFile(%q): %v", src, err)
	}
	sub, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("Submit(%q): %v", src, err)
	}
	if len(sub.ProcAds) != 1 {
		t.Fatalf("got %d proc ads, want 1", len(sub.ProcAds))
	}
	return sub.ProcAds[0]
}

// An assignment that expands to nothing is the same as no assignment at
// all, because SubmitHash::submit_param ends with
//
//	if( * pval_expanded == '\0' ) { free( pval_expanded ); return NULL; }
//
// and every submit command in condor_submit is read through it. The
// expectations below were measured against HTCondor's own SubmitHash
// through the differential oracle in fuzz/submit.
//
//	executable =, docker_image = busybox   -> Cmd = "", TransferExecutable = false
//	executable =, container_image = ...    -> same
//	universe = docker, executable =        -> same
//	docker_image = busybox, no executable  -> same
//	executable =, nothing else             -> rejected, as with no executable

// A docker or container job needs no executable: the image carries the
// command. SetExecutable sends those down its ignore_it path, which
// leaves Cmd empty and turns the transfer off.
//
// The empty value must not be resolved. full_path("") is the submitting
// directory, so resolving it would put the submitter's working directory
// in Cmd -- a value that depends on where they were standing, names no
// file on the execute node, and differs between two submissions of the
// same file.
func TestEmptyExecutableOnAContainerJob(t *testing.T) {
	for _, src := range []string{
		"executable =\ndocker_image = busybox\nqueue\n",
		"executable =\ncontainer_image = busybox\nqueue\n",
		"universe = docker\nexecutable =\ndocker_image = busybox\nqueue\n",
		// No executable keyword at all is the same thing, and is what
		// an ordinary docker submit file looks like.
		"docker_image = busybox\nqueue\n",
		"container_image = busybox\nqueue\n",
		"universe = docker\ndocker_image = busybox\nqueue\n",
	} {
		t.Run(strings.ReplaceAll(strings.TrimSpace(src), "\n", "; "), func(t *testing.T) {
			ad := submitProcAd(t, src)
			if cmd, ok := ad.EvaluateAttrString("Cmd"); !ok || cmd != "" {
				t.Errorf("Cmd = %q (present=%v), want an empty string", cmd, ok)
			}
			if xfer, ok := ad.EvaluateAttrBool("TransferExecutable"); !ok || xfer {
				t.Errorf("TransferExecutable = %v (present=%v), want false", xfer, ok)
			}
		})
	}
}

// Outside those two, an empty executable is as fatal as no executable --
// the same error, because submit_param hands SetExecutable the same NULL.
func TestEmptyExecutableIsRejectedWhereAnExecutableIsRequired(t *testing.T) {
	for _, src := range []string{
		"executable =\nqueue\n",
		"queue\n",
		"universe = vanilla\nexecutable =\nqueue\n",
	} {
		t.Run(strings.ReplaceAll(strings.TrimSpace(src), "\n", "; "), func(t *testing.T) {
			sf, err := ParseSubmitFile(strings.NewReader(src))
			if err != nil {
				t.Fatalf("ParseSubmitFile: %v", err)
			}
			if _, err := sf.Submit(1); err == nil {
				t.Error("the file was accepted; want an error about the missing executable")
			}
		})
	}
}

// An empty primary still suppresses its alternate, because the two tests
// submit_param makes are at different points: lookup_macro picks the name
// on PRESENCE, before expanding anything, and the empty result is judged
// afterwards on whichever name was picked. So `output =` keeps `stdout`
// from being consulted, and checkStdFile canonicalizes the unnamed stream
// to /dev/null rather than to so.txt.
func TestEmptyPrimarySuppressesItsAlternate(t *testing.T) {
	_, ad := submitInDir(t, "executable = a.sh\noutput =\nstdout = so.txt\nqueue\n")
	wantAttr(t, ad, "Out", "/dev/null")
}
