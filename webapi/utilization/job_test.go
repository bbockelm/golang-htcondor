package utilization

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func parseAd(t *testing.T, text string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.ParseOld(text)
	if err != nil {
		t.Fatalf("parsing %q: %v", text, err)
	}
	return ad
}

// MemoryUsage is recorded as an expression over ResidentSetSize, and a
// request can be an expression over other attributes. Both have to be
// evaluated, and one that cannot be evaluated drops out rather than
// becoming zero.
func TestFromAdEvaluatesExpressions(t *testing.T) {
	ad := parseAd(t, `ClusterId = 7
ProcId = 1
Owner = "alice"
JobStatus = 4
ExitCode = 0
RequestCpus = 4
RequestMemory = 512 * RequestCpus
RequestDisk = SomethingNotProjected * 2
ResidentSetSize = 2097152
MemoryUsage = ((ResidentSetSize + 1023) / 1024)
RemoteWallClockTime = 3600.0`)
	j := FromAd(ad, "")
	if j.RequestMemory == nil || *j.RequestMemory != 2048 {
		t.Errorf("RequestMemory = %v, want 2048 (512 * RequestCpus)", j.RequestMemory)
	}
	if j.MemoryUsage == nil || *j.MemoryUsage != 2048 {
		t.Errorf("MemoryUsage = %v, want 2048 MiB from ResidentSetSize", j.MemoryUsage)
	}
	if j.RequestDisk != nil {
		t.Errorf("RequestDisk = %v, want nil: it does not evaluate to a number", *j.RequestDisk)
	}
	if j.Wall != 3600 || j.Cluster != 7 || j.Proc != 1 || !j.succeeded() {
		t.Errorf("job = %+v", j)
	}
}

// CPU time is divided by wall clock, so the two must cover the same runs.
// RemoteWallClockTime sums every run; RemoteUserCpu restarts at each run.
func TestFromAdCPUCoversTheSameRunsAsWall(t *testing.T) {
	for _, tc := range []struct {
		name string
		ad   string
		want *float64
	}{
		{
			// Two runs, 3600 s of wall between them. The cumulative pair
			// says 7200 s of CPU: two cores. The last run alone (600 s)
			// would claim a sixth of one.
			name: "cumulative pair spans every run",
			ad: `JobStatus = 4
NumJobStarts = 2
RemoteWallClockTime = 3600
CumulativeRemoteUserCpu = 7000
CumulativeRemoteSysCpu = 200
RemoteUserCpu = 600
RemoteSysCpu = 0`,
			want: f(2),
		},
		{
			name: "per-run pair is the whole story for one run",
			ad: `JobStatus = 4
NumJobStarts = 1
RemoteWallClockTime = 1000
RemoteUserCpu = 1500
RemoteSysCpu = 500`,
			want: f(2),
		},
		{
			// Without the cumulative pair, a restarted job's CPU covers
			// only its last run. Not measured, rather than wrong.
			name: "per-run pair after a restart is not comparable",
			ad: `JobStatus = 4
NumJobStarts = 3
RemoteWallClockTime = 3600
RemoteUserCpu = 600
RemoteSysCpu = 0`,
			want: nil,
		},
		{
			name: "under a minute is not measured",
			ad: `JobStatus = 4
RemoteWallClockTime = 59
CumulativeRemoteUserCpu = 59`,
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := FromAd(parseAd(t, tc.ad), "")
			got := j.coresUsed()
			switch {
			case tc.want == nil && got != nil:
				t.Errorf("cores = %v, want unmeasured", *got)
			case tc.want != nil && (got == nil || *got != *tc.want):
				t.Errorf("cores = %v, want %v", got, *tc.want)
			}
		})
	}
}

func TestFromAdHolds(t *testing.T) {
	for _, tc := range []struct {
		name               string
		ad                 string
		memory, disk, over bool
	}{
		{
			name:   "removed while held for memory",
			ad:     "JobStatus = 3\nHoldReasonCode = 34\nHoldReasonSubCode = 102",
			memory: true, over: true,
		},
		{
			// A release moves the hold reason to LastHoldReason*.
			name:   "held for memory, released, completed",
			ad:     "JobStatus = 4\nLastHoldReasonCode = 34\nLastHoldReasonSubCode = 102\nNumHoldsByReason = [ JobOutOfResources = 1 ]",
			memory: true, over: true,
		},
		{
			name:   "machine policy hold for memory",
			ad:     "JobStatus = 3\nHoldReasonCode = 21\nHoldReasonSubCode = 102",
			memory: true, over: true,
		},
		{
			name: "held for disk",
			ad:   "JobStatus = 4\nLastHoldReasonCode = 34\nLastHoldReasonSubCode = 104\nNumHoldsByReason = [ JobOutOfResources = 1 ]",
			disk: true,
		},
		{
			// The most recent hold was something else; the count is all
			// that is left, and it means memory.
			name:   "count without a subcode",
			ad:     "JobStatus = 4\nLastHoldReasonCode = 1\nNumHoldsByReason = [ UserRequest = 1; JobOutOfResources = 2 ]",
			memory: true, over: true,
		},
		{
			// retry_request_memory evicts rather than holds.
			name: "evicted for memory by a retry policy",
			ad:   "JobStatus = 4\nVacateReasonCode = 34\nVacateReasonSubCode = 102",
			over: true,
		},
		{
			name: "held by the user",
			ad:   "JobStatus = 3\nHoldReasonCode = 1\nNumHoldsByReason = [ UserRequest = 1 ]",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := FromAd(parseAd(t, tc.ad), "")
			if j.HeldForMemory != tc.memory || j.HeldForDisk != tc.disk || j.ExceededMemory != tc.over {
				t.Errorf("memory=%v disk=%v exceeded=%v, want %v %v %v",
					j.HeldForMemory, j.HeldForDisk, j.ExceededMemory, tc.memory, tc.disk, tc.over)
			}
		})
	}
}

// GPUsAverageUsage sums over the job's GPUs; utilization is per GPU
// requested.
func TestGPUUtilizationIsPerRequestedGPU(t *testing.T) {
	j := FromAd(parseAd(t, "JobStatus = 4\nRequestGPUs = 2\nGPUsAverageUsage = 1.5\nRemoteWallClockTime = 600"), "")
	if u := j.GPUUtilization(); u == nil || *u != 0.75 {
		t.Errorf("utilization = %v, want 0.75", u)
	}
}

func TestReservesNothing(t *testing.T) {
	for _, tc := range []struct {
		j    Job
		want bool
	}{
		{Job{Universe: 7, Cmd: "/usr/bin/condor_dagman"}, true},
		{Job{Universe: 5, Cmd: "/usr/bin/condor_dagman"}, true},
		{Job{Universe: 12, Cmd: "run.sh"}, true},
		{Job{Universe: 5, Cmd: "run.sh"}, false},
	} {
		if got := tc.j.reservesNothing(); got != tc.want {
			t.Errorf("%+v: reservesNothing = %v", tc.j, got)
		}
	}
}
