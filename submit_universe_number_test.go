package htcondor

import (
	"strings"
	"testing"
)

// A universe is named by a NUMBER as well as by a word, and the number is
// tried first: CondorUniverseNumberEx runs atoi before the name lookup, so
// the digits need only be a prefix. Reading only names made every numeric
// universe come out as the vanilla default -- a scheduler- or
// parallel-universe job silently handed to a startd.
//
// Every expectation here was measured against HTCondor's own SubmitHash
// through the oracle in fuzz/submit.
func TestNumericUniverseIsRead(t *testing.T) {
	for _, tc := range []struct {
		univ string
		want int
	}{
		{"5", UniverseVanilla},
		{"7", UniverseScheduler},
		{"8", UniverseMPI},
		{"9", UniverseGrid},
		{"11", UniverseParallel},
		{"12", UniverseLocal},
		// atoi's rules: leading space, a sign, leading zeros, and any
		// trailing junk at all.
		{" 7", UniverseScheduler},
		{"+7", UniverseScheduler},
		{"007", UniverseScheduler},
		{"7.9", UniverseScheduler},
		{"7junk", UniverseScheduler},
		{"7A0000000000000000000000", UniverseScheduler},
	} {
		t.Run(tc.univ, func(t *testing.T) {
			ad := submitProcAd(t, "universe = "+tc.univ+"\nmachine_count = 2\ngrid_resource = batch slurm\nexecutable = /bin/true\nqueue\n")
			got, ok := ad.EvaluateAttrInt("JobUniverse")
			if !ok {
				t.Fatal("the job ad has no JobUniverse")
			}
			if int(got) != tc.want {
				t.Errorf("universe = %s gave JobUniverse %d, want %d", tc.univ, got, tc.want)
			}
		})
	}
}

// mpi is a universe of its own, number 8, not another spelling of
// parallel: SetParallelParams gives the two different attributes.
func TestMPIIsItsOwnUniverse(t *testing.T) {
	ad := submitProcAd(t, "universe = mpi\nmachine_count = 2\nexecutable = /bin/true\nqueue\n")
	got, _ := ad.EvaluateAttrInt("JobUniverse")
	if int(got) != UniverseMPI {
		t.Errorf("JobUniverse = %d, want %d", got, UniverseMPI)
	}
	// The parallel sandbox attributes are parallel's alone.
	if _, ok := ad.Lookup("WantIOProxy"); ok {
		t.Error("an MPI job got WantIOProxy, which belongs to the parallel universe")
	}
}

// condor_submit refuses a universe it does not know and one it can no
// longer run. Falling back to vanilla ran a typo as a real job and gave
// `universe = standard` a JobUniverse no shadow has been able to run for
// years.
func TestUnknownAndUnsupportedUniversesAreRefused(t *testing.T) {
	for _, univ := range []string{
		"vanillaX", "unknown", "globus", // no such name
		"0", "14", "99", "-1", // no such number
		"standard", "1", // gone
	} {
		t.Run(univ, func(t *testing.T) {
			// The parse is where it is caught: a file naming a universe
			// nothing can run does not become valid later.
			sf, err := ParseSubmitFile(strings.NewReader("universe = " + univ + "\nexecutable = /bin/true\nqueue\n"))
			if err != nil {
				return
			}
			if _, err := sf.Submit(1); err == nil {
				t.Errorf("universe = %s was accepted; condor_submit refuses it", univ)
			}
		})
	}
}

// A file with no universe command is vanilla, and is not refused.
func TestAbsentUniverseIsVanilla(t *testing.T) {
	ad := submitProcAd(t, "executable = /bin/true\nqueue\n")
	got, _ := ad.EvaluateAttrInt("JobUniverse")
	if int(got) != UniverseVanilla {
		t.Errorf("JobUniverse = %d, want %d", got, UniverseVanilla)
	}
}
