package utilization

import (
	"fmt"
	"math"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// Sizing a workflow whose RequestMemory is a formula over its own usage
// -- the shape CHTC recommends, `max({2048, 1.5 * MemoryUsage})`.
//
// A job that outgrows the start is held, the formula regrows its request
// against the usage just measured, and the job runs again. That is a
// retry by a different mechanism, and it leaves the same shape of record
// a retry ladder does: RemoteWallClockTime sums both runs and
// CommittedTime holds only the run that finished, because a run that
// ends in a hold commits nothing.
//
// Read without that, such a job is charged its whole wall clock at the
// grown request AND a second full run at it -- four runs' worth of
// reservation for a job that ran twice. The advice that follows is to
// abandon the formula for one flat request, which is the same bad advice
// the retry ladder used to get.

const (
	adaptiveStart = 2048.0 // where the formula starts
	fitPeak       = 1500.0 // under the start: one run, no regrow
	growPeak      = 2600.0 // over it: held, regrown to 1.5 x 2600
	grownRequest  = 1.5 * growPeak
)

// adaptiveShape is how one job of the workflow ran.
type adaptiveShape struct {
	wall      float64 // every run summed, as RemoteWallClockTime is
	committed float64 // the run that finished, as CommittedTime is
	peak      float64
	holds     int // NumHoldsByReason, 0 means the attribute is absent
	// truth is what the job really reserved, MiB-hours.
	truth float64
}

var (
	// adaptiveFit never reached the start: one run, one request.
	adaptiveFit = adaptiveShape{wall: 3600, committed: 3600, peak: fitPeak,
		truth: adaptiveStart * 1}
	// adaptiveRegrown hit its ceiling five minutes in, was held, and the
	// hour that counted ran at the grown request. The five minutes are
	// thrown away, but they were reserved at the START -- charging them
	// at the grown request is the overstatement this guards.
	adaptiveRegrown = adaptiveShape{wall: 3900, committed: 3600, peak: growPeak, holds: 1,
		truth: adaptiveStart*(300.0/3600) + grownRequest*1}
)

// adaptiveAd renders one job. Its RequestMemory is the formula itself,
// so the starting value and the value in force are both derived the way
// they are from a real record, not asserted into the fixture.
func adaptiveAd(i int, s adaptiveShape) *classad.ClassAd {
	var extra string
	if s.holds > 0 {
		extra += fmt.Sprintf("HoldReasonCode = %d\nHoldReasonSubCode = %d\n",
			holdOutOfResources, subcodeMemory)
		extra += fmt.Sprintf("NumHoldsByReason = [ JobOutOfResources = %d ]\n", s.holds)
	}
	starts := 1
	if s.wall > s.committed {
		starts = 2
	}
	text := fmt.Sprintf(`ClusterId = 200
ProcId = %d
Owner = "alice"
JobBatchName = "formula"
Cmd = "/home/alice/run.sh"
JobUniverse = 5
JobStatus = 4
ExitCode = 0
QDate = 1760000000
JobStartDate = 1760000100
CompletionDate = %d
EnteredCurrentStatus = %d
RequestMemory = %s
RequestCpus = 1
RequestDisk = 1048576
ResidentSetSize = %.0f
ResidentSetSize_RAW = %.0f
MemoryUsage = ((ResidentSetSize + 1023) / 1024)
DiskUsage = 204800
RemoteWallClockTime = %g
CommittedTime = %g
CumulativeRemoteUserCpu = %g
CumulativeRemoteSysCpu = 0.0
NumJobStarts = %d
%s`, i, 1760000000+int(s.wall), 1760000000+int(s.wall), chtcFormula,
		s.peak*1024, s.peak*1024, s.wall, s.committed, s.wall*0.8, starts, extra)
	ad, err := classad.ParseOld(text)
	if err != nil {
		panic(err)
	}
	return ad
}

// adaptiveWorkflow builds n jobs, every `share`th of them regrown, and
// returns the plan and what the workflow truly reserved.
func adaptiveWorkflow(t *testing.T, share int, regrown adaptiveShape) (*memoryPlan, float64) {
	t.Helper()
	const n = 200
	var reader JobReader
	var truth float64
	jobs := make([]Job, 0, n)
	for i := range n {
		s := adaptiveFit
		if share > 0 && i%share == 0 {
			s = regrown
		}
		truth += s.truth
		jobs = append(jobs, reader.FromAd(adaptiveAd(i, s), ""))
	}
	samples := make([]memoryJob, 0, n)
	for i := range jobs {
		if mj, ok := memorySample(&jobs[i]); ok {
			samples = append(samples, mj)
		}
	}
	if len(samples) != n {
		t.Fatalf("memorySample dropped %d of %d jobs", n-len(samples), n)
	}
	plan := planMemory(samples)
	if plan == nil {
		t.Fatal("planMemory returned nil")
	}
	return plan, truth
}

// TestAdaptiveCostIsExactWhenTheRecordCanSplitIt is the heart of it: one
// regrow and no checkpoints, so CommittedTime is the run that finished
// and the wall clock divides between the two requests exactly.
func TestAdaptiveCostIsExactWhenTheRecordCanSplitIt(t *testing.T) {
	plan, truth := adaptiveWorkflow(t, 3, adaptiveRegrown)
	if plan.currentFloor != plan.currentCost {
		t.Errorf("floor %.0f and cost %.0f differ; every regrown job here is splittable",
			plan.currentFloor, plan.currentCost)
	}
	if rel := math.Abs(plan.currentCost-truth) / truth; rel > 0.001 {
		t.Errorf("reserved %.0f MiB-hours, truth %.0f (%.2f%% out)", plan.currentCost, truth, 100*rel)
	}
}

// TestAdaptiveIsNotFlattenedWhenItIsWorking is the regression this
// exists for: a workflow whose formula is doing its job must not be told
// to drop it for one flat request, whatever share of its jobs regrow.
//
// One flat request that fits the largest job reserves that much for
// every job, and these mostly peak well under it. Charging the regrow
// twice made the formula look like the expensive one and produced a
// saving of some seventy GiB-hours for abandoning the cheaper mechanism.
//
// The recommendation may still be a BETTER rerun than the one in force
// -- the formula regrows to 1.5x the peak it measured, where sizing from
// the peak directly is tighter -- and that is a different thing from
// flattening.
//
// At a one-in-two regrow rate the flat request and the formula come out
// within half a percent of each other, and which one the sizing picks
// turns on a tiebreak rather than on the arithmetic this pins. That case
// is left out deliberately.
func TestAdaptiveIsNotFlattenedWhenItIsWorking(t *testing.T) {
	for _, share := range []int{5, 3} {
		t.Run(fmt.Sprintf("one-in-%d-regrows", share), func(t *testing.T) {
			plan, _ := adaptiveWorkflow(t, share, adaptiveRegrown)
			if plan.retry <= 0 {
				t.Errorf("recommended a flat %.0f MiB and no rerun at all; the formula already reruns these jobs",
					plan.recommended)
			}
			if plan.recommended >= plan.single {
				t.Errorf("recommended %.0f MiB, the request that fits every job -- that is the flattening",
					plan.recommended)
			}
			if plan.recommendedCost >= plan.currentCost {
				t.Errorf("recommended %.0f MiB at %.0f MiB-hours against the %.0f the formula reserves: it costs MORE",
					plan.recommended, plan.recommendedCost, plan.currentCost)
			}
		})
	}
}

// TestAdaptiveIsFlattenedWhenItIsWasteful is the other side: a job that
// burns a long run before it is held wastes more than a larger request
// would, and the advice must still say so. Without this the fix above
// could be "never recommend anything", which is not the same as right.
func TestAdaptiveIsFlattenedWhenItIsWasteful(t *testing.T) {
	// Two hours thrown away before the hold, one hour that counted.
	wasteful := adaptiveShape{wall: 10800, committed: 3600, peak: growPeak, holds: 1,
		truth: adaptiveStart*2 + grownRequest*1}
	plan, truth := adaptiveWorkflow(t, 2, wasteful)
	if plan.recommendedCost >= truth {
		t.Errorf("recommended %.0f MiB at %.0f MiB-hours, no better than the %.0f the formula reserves",
			plan.recommended, plan.recommendedCost, truth)
	}
}

// TestAdaptiveRegrowIsCountedOnce: a job held twice spent its
// uncommitted time at two different requests, so the cost cannot be
// split and must be reported as a range that CONTAINS the truth.
func TestAdaptiveRegrowCountedTwiceBrackets(t *testing.T) {
	twice := adaptiveShape{wall: 11400, committed: 3600, peak: growPeak, holds: 2,
		// 2048 for an hour, then something between 2048 and 3900 for
		// another hour, then 3900 for the hour that counted.
		truth: adaptiveStart*1 + 3072*1 + grownRequest*1}
	plan, truth := adaptiveWorkflow(t, 3, twice)
	if !(plan.currentFloor <= truth && truth <= plan.currentCost) {
		t.Errorf("truth %.0f outside the reported range [%.0f, %.0f]",
			truth, plan.currentFloor, plan.currentCost)
	}
	if plan.currentFloor == plan.currentCost {
		t.Error("reported an exact figure for a cost the record cannot split")
	}
}

// TestRestartThatIsNotAboutMemoryKeepsItsWallClock: a job preempted and
// rerun at the SAME request lost that time to the pool, not to its
// memory. A larger request would not have saved it -- it would have been
// preempted just the same -- so pricing a candidate request against it
// must charge both runs, not one.
//
// This is the limit on reading reruns out of NumJobStarts, which counts
// every restart whatever caused it.
func TestRestartThatIsNotAboutMemoryKeepsItsWallClock(t *testing.T) {
	preempted := adaptiveShape{wall: 7200, committed: 3600, peak: fitPeak,
		truth: adaptiveStart * 2}
	var reader JobReader
	j := reader.FromAd(adaptiveAd(1, preempted), "")
	mj, ok := memorySample(&j)
	if !ok {
		t.Fatal("memorySample dropped the job")
	}
	if mj.reruns != 0 {
		t.Errorf("counted %d memory reruns; the job was restarted, but not for its memory", mj.reruns)
	}
	const request = 4096.0
	cost, _ := expectedCost([]memoryJob{mj}, request, 0)
	if want := request * 2; math.Abs(cost-want) > 0.001 {
		t.Errorf("a %.0f MiB request over the job costs %.0f MiB-hours, want %.0f: it runs twice either way",
			request, cost, want)
	}
	// The cost of the request in force is unchanged either way, because
	// both runs held the same request. Checked so the test cannot be
	// read as saying the split would have been harmless.
	plan, truth := adaptiveWorkflow(t, 2, preempted)
	if rel := math.Abs(plan.currentCost-truth) / truth; rel > 0.001 {
		t.Errorf("reserved %.0f MiB-hours, truth %.0f (%.2f%% out)", plan.currentCost, truth, 100*rel)
	}
}

// TestAdaptiveHoldCountIsRead: NumHoldsByReason is where a second hold
// shows at all -- the codes describe only the most recent one.
func TestAdaptiveHoldCountIsRead(t *testing.T) {
	var reader JobReader
	for _, holds := range []int{0, 1, 3} {
		s := adaptiveShape{wall: 3900, committed: 3600, peak: growPeak, holds: holds}
		j := reader.FromAd(adaptiveAd(1, s), "")
		if int(j.MemoryHolds) != holds {
			t.Errorf("holds = %d, want %d", j.MemoryHolds, holds)
		}
		if j.HeldForMemory != (holds > 0) {
			t.Errorf("held = %v for %d holds", j.HeldForMemory, holds)
		}
	}
}

// TestFormulaStartIsLoweredWhenItIsTooHigh: a formula that starts at 2
// GB for jobs that mostly peak near 800 MiB wastes more than a gigabyte
// on four jobs in five. Starting it lower and letting the formula catch
// the tail -- which it already catches -- is the whole saving.
//
// What blocked that advice was the cap on how often a recommendation may
// send a job back for a second run. The cap is there so nobody is handed
// a retry they did not ask for; a workflow whose formula already reruns
// one job in five has asked for it, and holding it to one in ten leaves
// only a flat request that costs MORE than what it runs today.
func TestFormulaStartIsLoweredWhenItIsTooHigh(t *testing.T) {
	var reader JobReader
	const n = 200
	cheap := adaptiveShape{wall: 3600, committed: 3600, peak: 800, truth: adaptiveStart}
	samples := make([]memoryJob, 0, n)
	for i := range n {
		s := cheap
		if i%5 == 0 {
			s = adaptiveRegrown
		}
		j := reader.FromAd(adaptiveAd(i, s), "")
		if mj, ok := memorySample(&j); ok {
			samples = append(samples, mj)
		}
	}
	plan := planMemory(samples)
	if plan == nil {
		t.Fatal("planMemory returned nil")
	}
	if plan.recommendedCost >= plan.currentCost {
		t.Errorf("recommended %.0f MiB at %.0f MiB-hours against the %.0f it reserves today: the advice costs MORE than doing nothing",
			plan.recommended, plan.recommendedCost, plan.currentCost)
	}
	if plan.recommended >= plan.typical {
		t.Errorf("recommended %.0f MiB, no lower than the %.0f the formula starts at", plan.recommended, plan.typical)
	}
	// The cap must come from what the workflow already does, not the
	// constant: one job in five regrows, so one in five is allowed.
	if got, want := plan.maxRetryFraction(), 0.20; math.Abs(got-want) > 0.001 {
		t.Errorf("retry cap %.2f, want the %.2f the formula already runs at", got, want)
	}
}
