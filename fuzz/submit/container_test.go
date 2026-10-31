//go:build libcondor_utils

package fuzzsubmit

import (
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/fuzz/submit/oracle"
)

// containerAttrs is the family this file pins: everything
// SubmitHash::SetExecutable, SetContainerSpecial and
// process_container_input_files decide about a container or docker job's
// image, plus the input transfer list the image lands on.
//
// The port attributes a container service gets are named after the
// service, so they cannot be listed here; the files below reach them and
// the whole-ad comparison in TestContainerAdsMatchOracle covers them.
var containerAttrs = []string{
	"ContainerImage",
	"ContainerImageFullPath",
	"ContainerImageSource",
	"ContainerServiceNames",
	"DockerImage",
	"WantContainer",
	"WantDocker",
	"WantDockerImage",
	"WantSIF",
	"WantSandboxImage",
	"TransferInput",
	"CommonInputCatalogs",
}

// containerFiles reach each branch of process_container_input_files and
// each universe gate around the image keywords.
//
// They are written out rather than left to the generated sweep for two
// reasons. The sweep's container files are whatever the keyword table
// and the corpus bytes happen to produce, so a branch can go uncovered
// without anything saying so; and the image keywords only mean anything
// in a universe the generator picked for other reasons.
var containerFiles = []string{
	// Transferred: the image is rewritten to its basename, the
	// submit-side path moves to ContainerImageFullPath, and the path
	// goes on the input list.
	"universe = container\ncontainer_image = /stash/img/foo.sif\nexecutable = /bin/sleep\nqueue\n",
	"container_image = /stash/img/foo.sif\nexecutable = /bin/sleep\nqueue\n",
	"universe = local\ncontainer_image = /stash/img/foo.sif\nexecutable = /bin/sleep\nqueue\n",
	// The attribute's own name is a second spelling of the keyword.
	"universe = container\nContainerImage = /stash/img/foo.sif\nexecutable = /bin/sleep\nqueue\n",
	// A sandbox directory written with a trailing separator: one
	// separator comes off so the basename is the directory's name.
	"universe = container\ncontainer_image = /stash/img/sandbox/\nexecutable = /bin/sleep\nqueue\n",
	// A URL that is not a repository is still fetched by the file
	// transfer, and its scheme becomes the source.
	"universe = container\ncontainer_image = osdf:///x/y/foo.sif\nexecutable = /bin/sleep\nqueue\n",
	// The image goes on the END of the list the submit file named.
	"universe = container\ncontainer_image = /stash/img/foo.sif\ntransfer_input_files = a.txt, b.txt\nexecutable = /bin/sleep\nqueue\n",
	// Quotes are part of the value that reaches
	// process_container_input_files, which is why the basename keeps
	// one and the want-flag is still read from the unquoted image.
	"universe = container\ncontainer_image = \"  /stash/img/foo.sif  \"\nexecutable = /bin/sleep\nqueue\n",

	// Not transferred: each of the three ways the decision tree returns
	// early, and the source each records.
	"universe = container\ncontainer_image = /stash/img/foo.sif\ntransfer_container = false\nexecutable = /bin/sleep\nqueue\n",
	"universe = container\ncontainer_image = /stash/img/foo.sif\nTransferContainer = false\nexecutable = /bin/sleep\nqueue\n",
	"universe = container\ncontainer_image = /cvmfs/x/foo.sif\nexecutable = /bin/sleep\nqueue\n",
	"universe = container\ncontainer_image = docker://busybox\nexecutable = /bin/sleep\nqueue\n",
	"universe = container\ncontainer_image = oras://reg/img:tag\nexecutable = /bin/sleep\nqueue\n",
	// A custom attribute cannot turn the transfer off: condor_submit
	// applies those after this decision.
	"universe = container\ncontainer_image = /stash/img/foo.sif\n+TransferContainer = false\nexecutable = /bin/sleep\nqueue\n",

	// The source is the part before the FIRST colon, which a path
	// containing one reaches as readily as a URL does.
	"universe = container\ncontainer_image = /stash/a:b/foo.sif\nexecutable = /bin/sleep\nqueue\n",

	// A common image is named as an input CATALOG instead of being
	// copied per job, and the catalog is keyed by a hash of the path --
	// the image's full path when it is a path, the URL itself when it
	// is a URL.
	"universe = container\ncontainer_image = /stash/img/foo.sif\ncontainer_is_common = true\nexecutable = /bin/sleep\nqueue\n",
	"universe = container\ncontainer_image = rel/foo.sif\ncontainer_is_common = true\nexecutable = /bin/sleep\nqueue\n",
	"universe = container\ncontainer_image = osdf:///x/foo.sif\ncontainer_is_common = true\nexecutable = /bin/sleep\nqueue\n",
	"universe = container\ncontainer_image = docker://busybox\ncontainer_is_common = true\nexecutable = /bin/sleep\nqueue\n",

	// docker_image: on its own, alongside the container universe, and
	// as the docker universe.
	"universe = container\ndocker_image = busybox\nexecutable = /bin/sleep\nqueue\n",
	"docker_image = busybox\nexecutable = /bin/sleep\nqueue\n",
	"universe = docker\ndocker_image = busybox\nexecutable = /bin/sleep\nqueue\n",
	"universe = docker\nDockerImage = busybox\nexecutable = /bin/sleep\nqueue\n",

	// The universes that read neither keyword. An image here reaches
	// condor_submit's ad not at all.
	"universe = scheduler\ndocker_image = busybox\nexecutable = /bin/sleep\nqueue\n",
	"universe = scheduler\ncontainer_image = /stash/img/foo.sif\nexecutable = /bin/sleep\nqueue\n",
	"universe = grid\ngrid_resource = batch slurm\ndocker_image = busybox\nexecutable = /bin/sleep\nqueue\n",
	"universe = grid\ngrid_resource = batch slurm\ncontainer_image = /stash/img/foo.sif\nexecutable = /bin/sleep\nqueue\n",
	"universe = scheduler\ncontainer_service_names = web\nweb_container_port = 80\nexecutable = /bin/sleep\nqueue\n",

	// container_service_names: stored verbatim rather than
	// canonicalized, with a port attribute per service.
	"universe = container\ncontainer_image = /stash/img/foo.sif\ncontainer_service_names = web, db\nweb_container_port = 80\ndb_container_port = 90\nexecutable = /bin/sleep\nqueue\n",
	"universe = docker\ndocker_image = busybox\ncontainer_service_names = web\nweb_container_port = 80\nexecutable = /bin/sleep\nqueue\n",
	"universe = container\ncontainer_image = /stash/img/foo.sif\nContainerServiceNames = web\nweb_container_port = 0\nexecutable = /bin/sleep\nqueue\n",
	// Whitespace separates service names as readily as a comma does.
	"universe = container\ncontainer_image = /stash/img/foo.sif\ncontainer_service_names = web web2\nweb_container_port = 80\nweb2_container_port = 81\nexecutable = /bin/sleep\nqueue\n",
}

// TestContainerAdsMatchOracle compares the family attribute by
// attribute, and works out part of the list from the ads themselves:
// two of the attributes at stake are named after something the submit
// file chose, a container service's port landing in
// `<service>_ContainerPort` and a common image's catalog in
// `_x_catalog_container_<hash>`, so a fixed list would miss both
// whichever side wrote them.
//
// It does not go through the sweep's known-divergence filter. An
// attribute still listed in knownDivergentGenerated would be waved
// through there, and none of these files should need that.
func TestContainerAdsMatchOracle(t *testing.T) {
	requireOracle(t)

	for _, src := range containerFiles {
		t.Run(strings.ReplaceAll(containerCaseName(src), " ", "_"), func(t *testing.T) {
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
				for _, attr := range containerAdAttrs(cppAds.ByKey[key], goAttrs) {
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

// containerAdAttrs is containerAttrs plus every attribute either side
// wrote whose name belongs to this family but is not fixed: the
// per-service port attributes and the common-input catalogs.
func containerAdAttrs(cppAttrs, goAttrs map[string]string) []string {
	attrs := append([]string(nil), containerAttrs...)
	seen := map[string]bool{}
	for _, a := range attrs {
		seen[strings.ToLower(a)] = true
	}
	for _, side := range []map[string]string{cppAttrs, goAttrs} {
		for _, name := range namesFold(side) {
			lower := strings.ToLower(name)
			if seen[lower] {
				continue
			}
			if strings.HasSuffix(lower, "_containerport") || strings.HasPrefix(lower, "_x_catalog_") {
				seen[lower] = true
				attrs = append(attrs, name)
			}
		}
	}
	return attrs
}

// TestContainerRefusalsMatchOracle pins the submit files condor_submit
// refuses outright. Acceptance is not asserted by the generated sweep --
// check() skips any file one side rejected -- so without this a Go
// parser that quietly accepted a container service with no port, or an
// image scheme HTCondor cannot run, would look exactly as green as one
// that rejected it. The job would then be matched and fail on the
// execute node instead.
func TestContainerRefusalsMatchOracle(t *testing.T) {
	requireOracle(t)

	for _, src := range []string{
		// A service nothing can reach.
		"universe = container\ncontainer_image = /stash/img/foo.sif\ncontainer_service_names = web\nexecutable = /bin/sleep\nqueue\n",
		"universe = container\ncontainer_image = /stash/img/foo.sif\ncontainer_service_names = web\nweb_container_port = 70000\nexecutable = /bin/sleep\nqueue\n",
		"universe = container\ncontainer_image = /stash/img/foo.sif\ncontainer_service_names = web, db\nweb_container_port = 80\nexecutable = /bin/sleep\nqueue\n",
		// Image schemes with no runtime or plugin behind them.
		"universe = container\ncontainer_image = instance://foo\nexecutable = /bin/sleep\nqueue\n",
		"universe = container\ncontainer_image = library://foo/bar\nexecutable = /bin/sleep\nqueue\n",
		"universe = container\ncontainer_image = shub://foo\nexecutable = /bin/sleep\nqueue\n",
		// A container job with no image at all, including the case
		// where a later assignment emptied the keyword.
		"universe = container\nexecutable = /bin/sleep\nqueue\n",
		"universe = container\ncontainer_image = /stash/img/foo.sif\ncontainer_image =\nexecutable = /bin/sleep\nqueue\n",
		// The docker universe needs its image and refuses the other one.
		"universe = docker\nexecutable = /bin/sleep\nqueue\n",
		// A custom attribute is not an image: condor_submit applies
		// those after it has already refused the file.
		"universe = docker\n+DockerImage = \"busybox\"\nexecutable = /bin/sleep\nqueue\n",
		"universe = docker\ndocker_image = busybox\ncontainer_image = /stash/img/foo.sif\nexecutable = /bin/sleep\nqueue\n",
		// Two images naming two different runtimes.
		"universe = container\ndocker_image = busybox\ncontainer_image = /stash/img/foo.sif\nexecutable = /bin/sleep\nqueue\n",
	} {
		t.Run(strings.ReplaceAll(containerCaseName(src), " ", "_"), func(t *testing.T) {
			if cpp := oracle.MakeAds(src, oracle.ModeAds, MaxProcs); cpp.OK {
				t.Fatalf("the oracle accepted this file, so it is the wrong case for this test")
			}
			if goRes := GoMakeAds(src); goRes.OK {
				t.Errorf("Go accepted a file condor_submit rejects")
			}
		})
	}
}

// containerCaseName names a case after the keyword line that makes it
// interesting: the image or the universe, whichever the file leads with.
func containerCaseName(src string) string {
	lines := strings.Split(strings.TrimSpace(src), "\n")
	var name []string
	for _, line := range lines {
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "universe"),
			strings.Contains(lower, "image"),
			strings.Contains(lower, "container"),
			strings.Contains(lower, "port"):
			name = append(name, strings.TrimSpace(line))
		}
	}
	if len(name) == 0 {
		return firstLine(src)
	}
	return strings.Join(name, "|")
}
