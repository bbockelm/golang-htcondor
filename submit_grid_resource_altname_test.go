package htcondor

import (
	"strings"
	"testing"
)

// TestGridResourceIsReadThroughItsAttributeName covers the two places that
// looked grid_resource up by its KEYWORD alone.
//
// condor_submit reads it as submit_param(SUBMIT_KEY_GridResource,
// ATTR_GRID_RESOURCE), so `GridResource = ec2 ...` names the same thing --
// and a submit file that uses the attribute spelling is one HTCondor
// accepts. Both decisions that depend on the grid type were made as though
// the job had named no grid resource at all:
//
//   - the executable of an ec2/gce/azure job is the name of the job rather
//     than a file, so it is kept as written and not transferred. Go resolved
//     it against the submitting directory, putting a path from the
//     submitting machine into Cmd, EC2TagName and CloudLabelName, and left
//     TransferExecutable unset.
//   - a grid job bound for a batch system through the blahp takes none of
//     the JOB_DEFAULT_REQUEST* defaults. Go wrote all three.
func TestGridResourceIsReadThroughItsAttributeName(t *testing.T) {
	const ec2 = "universe = grid\n%s = ec2 x\nexecutable = myjob\n" +
		"ec2_access_key_id = k\nec2_secret_access_key = s\nec2_ami_id = ami-1\nqueue\n"

	for _, spelling := range []string{"grid_resource", "GridResource", "gridresource"} {
		ad := adFor(t, strings.Replace(ec2, "%s", spelling, 1))
		if got := ad["Cmd"]; got != `"myjob"` {
			t.Errorf("%s: Cmd = %s, want the name as written", spelling, got)
		}
		if got := ad["TransferExecutable"]; got != "false" {
			t.Errorf("%s: TransferExecutable = %s, want false", spelling, got)
		}
	}

	// A blahp batch job takes no resource defaults.
	for _, spelling := range []string{"grid_resource", "GridResource"} {
		ad := adFor(t, "universe = grid\n"+spelling+" = batch slurm\nexecutable = myjob\nqueue\n")
		for _, attr := range []string{"RequestCpus", "RequestMemory", "RequestDisk"} {
			if got, ok := ad[attr]; ok {
				t.Errorf("%s: %s = %s, want it absent for a blahp batch job", spelling, attr, got)
			}
		}
	}
}
