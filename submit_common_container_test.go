package htcondor

import (
	"strings"
	"testing"
)

// commonContainerAd parses src under b and returns the proc ad's
// CommonInputCatalogs and TransferInput, which are the two attributes a
// common image moves between: a common one names a catalog and is not
// transferred, an ordinary one is an input file.
func commonContainerAd(t *testing.T, src string, b SubmitBehavior, knobs SubmitParamMap) (catalogs, input string) {
	t.Helper()
	t.Chdir(t.TempDir())
	sf, err := ParseSubmitFileWithOptions(strings.NewReader(src),
		SubmitParseOptions{Behavior: b, Params: knobs})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	catalogs, _ = ad.EvaluateAttrString("CommonInputCatalogs")
	input, _ = ad.EvaluateAttrString("TransferInput")
	return catalogs, input
}

const commonImage = "container_image = /x/foo.sif\nexecutable = /bin/true\nqueue\n"

// Under CommonContainerVanillaOnly a container image is common only for a
// vanilla job. A common image names a cache on an execute node, so asking
// for one in a universe that is never matched to a startd produced a job
// that named a catalog nothing would ever supply AND left the image out
// of its input list, so it arrived with no image at all.
func TestCommonContainerIsVanillaOnly(t *testing.T) {
	on := SubmitBehavior{CommonContainerVanillaOnly: true}

	for _, tc := range []struct {
		name       string
		universe   string
		wantCommon bool
		// wantTransferred is whether the image ends up in TransferInput.
		// It is not simply the opposite of wantCommon: outside vanilla
		// and local there is no container job at all, so the image
		// keyword writes nothing and there is nothing to transfer.
		wantTransferred bool
	}{
		{"vanilla", "universe = vanilla\n", true, false},
		// container and docker universes are vanilla jobs carrying a
		// want-flag, so they keep it.
		{"container", "universe = container\n", true, false},
		// No universe line at all is vanilla.
		{"unstated", "", true, false},
		{"local", "universe = local\n", false, true},
		{"scheduler", "universe = scheduler\n", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.universe + "container_is_common = true\n" + commonImage
			catalogs, input := commonContainerAd(t, src, on, nil)
			if gotCommon := catalogs != ""; gotCommon != tc.wantCommon {
				t.Errorf("CommonInputCatalogs = %q, so common=%v; want common=%v", catalogs, gotCommon, tc.wantCommon)
			}
			if got := strings.Contains(input, "foo.sif"); got != tc.wantTransferred {
				t.Errorf("TransferInput = %q, so the image is transferred=%v; want %v", input, got, tc.wantTransferred)
			}
		})
	}
}

// The pool's two knobs are read inside the same gate, so neither can make
// a non-vanilla job's image common on the job's behalf.
func TestCommonContainerKnobsAreInsideTheVanillaGate(t *testing.T) {
	on := SubmitBehavior{CommonContainerVanillaOnly: true}

	for _, knobs := range []SubmitParamMap{
		{"CONTAINER_IMAGES_COMMON_BY_DEFAULT": "true"},
		{"CONTAINER_REGEX_COMMON_BY_DEFAULT": ".*[.]sif"},
	} {
		if catalogs, _ := commonContainerAd(t, "universe = vanilla\n"+commonImage, on, knobs); catalogs == "" {
			t.Errorf("%v: no CommonInputCatalogs for a vanilla job; the knob is not being read at all", knobs)
		}
		if catalogs, _ := commonContainerAd(t, "universe = local\n"+commonImage, on, knobs); catalogs != "" {
			t.Errorf("%v: CommonInputCatalogs = %q for a local job", knobs, catalogs)
		}
	}
}

// Without the behavior the request is honoured in any universe, which is
// what condor_submit did before HTCONDOR-4003 and what an access point
// running an older release still does.
func TestCommonContainerIsHonouredInAnyUniverseByDefault(t *testing.T) {
	src := "universe = local\ncontainer_is_common = true\n" + commonImage
	if catalogs, _ := commonContainerAd(t, src, SubmitBehavior{}, nil); catalogs == "" {
		t.Error("no CommonInputCatalogs; the old behavior is no longer reachable")
	}
}
