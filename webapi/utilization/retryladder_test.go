package utilization

import (
	"fmt"
	"math"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// Sizing a workflow that already uses retry_request_memory.
//
// retry_request_memory installs an ON-EVICT job transform that REWRITES
// RequestMemory, so the record of a job that climbed carries only the
// rung it ended on. Read naively, such a workflow looks like one where
// every job asked for the large request and comfortably fitted it, and
// the advice that follows is to flatten the ladder -- which reserves
// more memory, not less.
//
// The rungs themselves are not recoverable from a climber's own record:
// submit builds RetryRequestMemory from the RETRIES, so the original
// request is in no attribute at all. It is recovered from the workflow,
// because the jobs that never climbed still hold it.

const (
	ladderBase  = 1024.0 // request_memory
	ladderRetry = 4096.0 // the rung a climber ends on
	ladderMid   = 2048.0 // an intermediate rung, in the list form
)

// ladderShape is how one job of the workflow ran.
type ladderShape struct {
	request   float64
	starts    int
	wall      float64 // every run summed, as RemoteWallClockTime is
	committed float64 // the run that finished, as CommittedTime is
	peak      float64
	index     int  // RetryRequestMemoryIndex; 0 means the attribute is absent
	list      bool // the record carries a RetryRequestMemory list
	ckpts     int
	// lost marks a job the ladder did not save: it outgrew the top rung
	// and was removed for it, rather than finishing at a larger request.
	lost bool
	// truth is what the job really reserved, MiB-hours.
	truth float64
}

var (
	// fitted never outgrew request_memory: one run at the first rung.
	fitted = ladderShape{request: ladderBase, starts: 1, wall: 3600, committed: 3600,
		peak: 700, truth: ladderBase * 1}
	// climbedOnce is the documented two-rung case, written
	// `retry_request_memory = 4 GB`. A single retry value leaves NO
	// RetryRequestMemory and no index -- the transform body is a plain
	// SET -- so only TransformOnEvict says there is a ladder at all.
	climbedOnce = ladderShape{request: ladderRetry, starts: 2, wall: 7200, committed: 4200,
		peak: 3400, truth: ladderBase*(3000.0/3600) + ladderRetry*(4200.0/3600)}
	// roomy never climbed either, but uses a fraction of the first rung.
	// A workflow of these has a cheaper ladder available to it, where one
	// of `fitted` is already sized about right and the only advice the
	// sizing can give is the ladder it already runs.
	roomy = ladderShape{request: ladderBase, starts: 1, wall: 3600, committed: 3600,
		peak: 200, truth: ladderBase * 1}
	// climbedTwice is the list form, `retry_request_memory = 2 GB, 4 GB`.
	// CommittedTime covers only the run that finished, so the two runs
	// before it sat at two different rungs and the wall clock cannot be
	// split from this record.
	climbedTwice = ladderShape{request: ladderRetry, starts: 3, wall: 10200, committed: 4200,
		peak: 3400, index: 2, list: true,
		truth: ladderBase*(3000.0/3600) + ladderMid*(3000.0/3600) + ladderRetry*(4200.0/3600)}
	// checkpointed climbed once, but committed work from before the
	// eviction too. HTCondor only ever ADDS to CommittedTime -- it is
	// never reset after submit -- so for a checkpointing job it spans the
	// rungs and cannot divide them.
	checkpointed = ladderShape{request: ladderRetry, starts: 2, wall: 7200, committed: 7200,
		peak: 3400, ckpts: 3,
		truth: ladderBase*(3000.0/3600) + ladderRetry*(4200.0/3600)}
)

// ladderAd renders one job. ladder says the workflow was submitted with a
// retry ladder at all; a control workflow sets it false.
func ladderAd(i int, s ladderShape, ladder bool) *classad.ClassAd {
	var extra string
	if ladder {
		extra += "TransformOnEvict = \"RequestMemory\"\n"
	}
	if s.list {
		extra += fmt.Sprintf("RetryRequestMemory = { %g,%g }\n", ladderMid, ladderRetry)
	}
	if s.index > 0 {
		extra += fmt.Sprintf("RetryRequestMemoryIndex = %d\n", s.index)
	}
	if s.ckpts > 0 {
		extra += fmt.Sprintf("NumCkpts = %d\n", s.ckpts)
	}
	status := 4
	if s.lost {
		status = 3
		extra += fmt.Sprintf("VacateReasonCode = %d\nVacateReasonSubCode = %d\n",
			holdOutOfResources, subcodeMemory)
	}
	text := fmt.Sprintf(`ClusterId = 100
ProcId = %d
Owner = "alice"
JobBatchName = "ladder"
Cmd = "/home/alice/run.sh"
JobUniverse = 5
JobStatus = %d
ExitCode = 0
QDate = 1760000000
JobStartDate = 1760000100
CompletionDate = %d
EnteredCurrentStatus = %d
RequestMemory = %g
RequestCpus = 1
RequestDisk = 1048576
MemoryUsage = %g
DiskUsage = 204800
RemoteWallClockTime = %g
CommittedTime = %g
CumulativeRemoteUserCpu = %g
CumulativeRemoteSysCpu = 0.0
NumJobStarts = %d
%s`, i, status, 1760000000+int(s.wall), 1760000000+int(s.wall),
		s.request, s.peak+float64(i%200), s.wall, s.committed, s.wall*0.8, s.starts, extra)
	ad, err := classad.ParseOld(text)
	if err != nil {
		panic(err)
	}
	return ad
}

// ladderWorkflow builds n jobs, every `share`th of them a climber, and
// returns the plan and what the workflow truly reserved.
func ladderWorkflow(t *testing.T, share int, climber ladderShape, ladder bool) (*memoryPlan, float64, int) {
	t.Helper()
	const n = 200
	var reader JobReader
	var truth float64
	climbers := 0
	jobs := make([]Job, 0, n)
	for i := range n {
		s := fitted
		if share > 0 && i%share == 0 {
			s = climber
			climbers++
		}
		truth += s.truth
		jobs = append(jobs, reader.FromAd(ladderAd(i, s, ladder), ""))
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
	return plan, truth, climbers
}

// TestLadderIsKeptNotFlattened is the regression this exists for: a
// workflow that already retries must not be told to drop the retry,
// whatever share of its jobs use it.
func TestLadderIsKeptNotFlattened(t *testing.T) {
	for _, share := range []int{10, 3, 2} {
		t.Run(fmt.Sprintf("one-in-%d-climbs", share), func(t *testing.T) {
			plan, _, climbers := ladderWorkflow(t, share, climbedOnce, true)
			if plan.retry <= 0 {
				t.Errorf("recommended a flat %.0f MiB and no retry; the workflow already retries at %.0f",
					plan.recommended, ladderRetry)
			}
			if plan.recommended != ladderBase {
				t.Errorf("recommended request %.0f MiB, want the first rung %.0f", plan.recommended, ladderBase)
			}
			if plan.typical != ladderBase {
				t.Errorf("typical request %.0f MiB, want the first rung %.0f -- the rung a climber ENDS on is not what anyone asked for",
					plan.typical, ladderBase)
			}
			if plan.climbed != climbers {
				t.Errorf("counted %d climbers, want %d", plan.climbed, climbers)
			}
		})
	}
}

// TestLadderCostIsExactWhenTheRecordCanSplitIt: one climb, no
// checkpoints, so CommittedTime is the run that finished and the wall
// clock divides between the two rungs exactly.
func TestLadderCostIsExactWhenTheRecordCanSplitIt(t *testing.T) {
	plan, truth, _ := ladderWorkflow(t, 3, climbedOnce, true)
	if plan.currentFloor != plan.currentCost {
		t.Errorf("floor %.0f and cost %.0f differ; every climber here is splittable",
			plan.currentFloor, plan.currentCost)
	}
	if rel := math.Abs(plan.currentCost-truth) / truth; rel > 0.001 {
		t.Errorf("reserved %.0f MiB-hours, truth %.0f (%.2f%% out)", plan.currentCost, truth, 100*rel)
	}
}

// TestLadderCostBracketsTheTruthWhenItCannot: a checkpointing job and a
// job that climbed twice both leave CommittedTime unable to divide the
// rungs. The cost must then be reported as a range that CONTAINS the
// truth, not as a figure that happens to be above it.
func TestLadderCostBracketsTheTruthWhenItCannot(t *testing.T) {
	for _, tc := range []struct {
		name    string
		climber ladderShape
	}{
		{"checkpointing", checkpointed},
		{"climbed-twice", climbedTwice},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, truth, _ := ladderWorkflow(t, 3, tc.climber, true)
			if plan.currentFloor >= plan.currentCost {
				t.Fatalf("floor %.0f is not below cost %.0f; this climber is not splittable and the two must differ",
					plan.currentFloor, plan.currentCost)
			}
			if plan.currentFloor > truth || truth > plan.currentCost {
				t.Errorf("truth %.0f is outside [%.0f, %.0f]", truth, plan.currentFloor, plan.currentCost)
			}
		})
	}
}

// TestCheckpointingJobIsNotSplit pins the reason: CommittedTime is not
// reset on eviction, so a checkpointing job's committed hours span the
// rungs and must not be read as the last run's.
func TestCheckpointingJobIsNotSplit(t *testing.T) {
	var reader JobReader
	plain := reader.FromAd(ladderAd(0, climbedOnce, true), "")
	ckpt := reader.FromAd(ladderAd(0, checkpointed, true), "")
	if !ckpt.Checkpointed {
		t.Fatal("NumCkpts did not reach the Job; is it in Projection()?")
	}
	base := reader.FromAd(ladderAd(1, fitted, true), "")
	for _, tc := range []struct {
		name string
		job  *Job
		want bool
	}{
		{"no checkpoints", &plain, true},
		{"checkpointed", &ckpt, false},
	} {
		// The climber's first rung comes from the workflow, so the
		// non-climber has to be in the slice settleLadder sees.
		fit, ok1 := memorySample(&base)
		mj, ok2 := memorySample(tc.job)
		if !ok1 || !ok2 {
			t.Fatalf("%s: no sample", tc.name)
		}
		settled := []memoryJob{fit, mj}
		settleLadder(settled)
		if got := settled[1].splittable(); got != tc.want {
			t.Errorf("%s: splittable = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestClimberIsInTheRequestSummary: a job that climbed carries no first
// rung of its own, and must not fall out of the chart that describes what
// the workflow requested.
func TestClimberIsInTheRequestSummary(t *testing.T) {
	const n, share = 200, 3
	var reader JobReader
	jobs := make([]Job, 0, n)
	for i := range n {
		s := fitted
		if i%share == 0 {
			s = climbedOnce
		}
		jobs = append(jobs, reader.FromAd(ladderAd(i, s, true), ""))
	}
	resp := Analyze(jobs, Options{Days: 30})
	if len(resp.Workflows) != 1 {
		t.Fatalf("want 1 workflow, got %d", len(resp.Workflows))
	}
	req := resp.Workflows[0].Memory.Request
	if req == nil {
		t.Fatal("no request summary")
	}
	if req.Typical != ladderBase || req.Max != ladderBase {
		t.Errorf("request summary typical %.0f / max %.0f, want the first rung %.0f on both: "+
			"the rung a climber ENDS on is not a request anyone made",
			req.Typical, req.Max, ladderBase)
	}

	// The unit that decides it, where a climber's absence IS observable.
	climber := reader.FromAd(ladderAd(0, climbedOnce, true), "")
	climber.RetryClimbs = 1 // the list spelling, which says so per job
	if got, ok := startForSummary(&climber, 0); !ok || got != ladderRetry {
		t.Errorf("with no first rung recovered: (%v, %v), want (%v, true) -- "+
			"a job must not drop out of the summary", got, ok, ladderRetry)
	}
	got, ok := startForSummary(&climber, ladderBase)
	if !ok || got != ladderBase {
		t.Errorf("startForSummary = (%v, %v), want (%v, true)", got, ok, ladderBase)
	}
}

// TestNoLadderIsUnchanged guards the ordinary path: a workflow with no
// retry transform must be read exactly as before, with no climbers
// inferred and no gap between the two cost bounds.
func TestNoLadderIsUnchanged(t *testing.T) {
	plan, _, _ := ladderWorkflow(t, 0, fitted, false)
	if plan.climbed != 0 || plan.ladderJobs != 0 {
		t.Errorf("inferred %d climbers and %d ladder jobs in a workflow with no ladder", plan.climbed, plan.ladderJobs)
	}
	if plan.currentFloor != plan.currentCost {
		t.Errorf("floor %.0f and cost %.0f differ with nothing to be uncertain about",
			plan.currentFloor, plan.currentCost)
	}
	if plan.maxRetryFraction() != maxRetryFraction {
		t.Errorf("retry cap %.3f, want the constant %.3f for a workflow that does not already retry",
			plan.maxRetryFraction(), maxRetryFraction)
	}
}

// TestSingleRungLadderIsFoundWithoutAnIndex: the documented two-rung
// spelling sets no RetryRequestMemoryIndex, so the climbers are found by
// their request standing above the workflow's first rung.
func TestSingleRungLadderIsFoundWithoutAnIndex(t *testing.T) {
	var reader JobReader
	j := reader.FromAd(ladderAd(0, climbedOnce, true), "")
	if j.RetryClimbs != 0 {
		t.Fatal("fixture carries an index; this case is about the spelling that has none")
	}
	if !j.MemoryRetry {
		t.Fatal("TransformOnEvict did not mark the job as using a memory retry ladder")
	}
	if j.climbedLadder() {
		t.Fatal("climbedLadder() cannot know from this record alone; the workflow decides")
	}
	plan, _, _ := ladderWorkflow(t, 3, climbedOnce, true)
	if plan.baseRung != ladderBase {
		t.Errorf("recovered first rung %.0f, want %.0f", plan.baseRung, ladderBase)
	}
	if plan.climbed == 0 {
		t.Error("no climber found: a job requesting more than the first rung in a ladder workflow climbed it")
	}
}

// TestLadderIsFlaggedOnTheRequestSummary: the page needs a structured
// signal, not only the advice prose. Without it a request marker reads
// "requested 1 GB" and never mentions the rung the ladder retries at.
func TestLadderIsFlaggedOnTheRequestSummary(t *testing.T) {
	var reader JobReader
	jobs := make([]Job, 0, 200)
	for i := range 200 {
		s := fitted
		if i%3 == 0 {
			s = climbedOnce
		}
		jobs = append(jobs, reader.FromAd(ladderAd(i, s, true), ""))
	}
	req := Analyze(jobs, Options{Days: 30}).Workflows[0].Memory.Request
	if req == nil {
		t.Fatal("no request summary")
	}
	if !req.Retry {
		t.Error("Retry not set on a workflow where two jobs in three carry a ladder")
	}
	if req.RetryMiB != ladderRetry {
		t.Errorf("RetryMiB = %.0f, want the largest rung reached, %.0f", req.RetryMiB, ladderRetry)
	}
	if req.Typical != ladderBase {
		t.Errorf("Typical = %.0f, want the first rung %.0f", req.Typical, ladderBase)
	}
}

// TestNoLadderLeavesTheFlagOff keeps the flag off the ordinary path, so
// a page can treat it as "this workflow retries" rather than as noise.
func TestNoLadderLeavesTheFlagOff(t *testing.T) {
	var reader JobReader
	jobs := make([]Job, 0, 200)
	for i := range 200 {
		jobs = append(jobs, reader.FromAd(ladderAd(i, fitted, false), ""))
	}
	req := Analyze(jobs, Options{Days: 30}).Workflows[0].Memory.Request
	if req == nil {
		t.Fatal("no request summary")
	}
	if req.Retry || req.RetryMiB != 0 {
		t.Errorf("Retry = %v / RetryMiB = %.0f on a workflow with no ladder", req.Retry, req.RetryMiB)
	}
}

// TestRetryAdviceSaysWhyItCannotBeApplied: a retry is set up at submit
// time, so it is not an edit to a queued job. The page has to be able to
// say that instead of listing a title under "not applied".
//
// The jobs that never climb use a fifth of the first rung, so there is a
// cheaper ladder to recommend. A workflow whose ladder is already sized
// right gets no advice at all to not apply (see
// TestLadderAlreadySizedGetsNoAdvice).
func TestRetryAdviceSaysWhyItCannotBeApplied(t *testing.T) {
	var reader JobReader
	jobs := make([]Job, 0, 200)
	for i := range 200 {
		s := roomy
		if i%3 == 0 {
			s = climbedOnce
		}
		jobs = append(jobs, reader.FromAd(ladderAd(i, s, true), ""))
	}
	w := Analyze(jobs, Options{Days: 30}).Workflows[0]
	a := adviceByResource(w, ResourceMemory)
	if a == nil {
		t.Fatal("no memory advice")
	}
	if a.ID != "memory-retry" {
		t.Fatalf("advice id = %q, want memory-retry", a.ID)
	}
	if a.Applies {
		t.Error("a retry recommendation was offered as an edit to queued jobs")
	}
	if a.WhyNotApplied == "" {
		t.Error("no reason given for advice the page cannot apply")
	}
}

// TestAppliedAdviceCarriesNoReason: the field is for advice that cannot
// be applied, so an ordinary recommendation must leave it empty.
func TestAppliedAdviceCarriesNoReason(t *testing.T) {
	jobs := append(jobsAt(30, 1, 700, 4096), jobsAt(30, 100, 800, 4096)...)
	w := onlyWorkflow(t, jobs)
	a := adviceByResource(w, ResourceMemory)
	if a == nil || !a.Applies {
		t.Skipf("fixture produced no applicable memory advice (%+v)", a)
	}
	if a.WhyNotApplied != "" {
		t.Errorf("applicable advice carries a reason it was not applied: %q", a.WhyNotApplied)
	}
}

// TestLadderAlreadySizedGetsNoAdvice: when the sizing's best answer is
// the ladder the workflow already runs, there is nothing to say.
//
// It used to be said anyway, as a warning: "Request 1 GB of memory and
// retry at 4 GB" to someone whose submit file already says exactly that,
// because a peak above the request reads as urgent everywhere else. Here
// the jobs that peaked above it were rerun and finished.
func TestLadderAlreadySizedGetsNoAdvice(t *testing.T) {
	var reader JobReader
	jobs := make([]Job, 0, 200)
	for i := range 200 {
		s := fitted
		if i%3 == 0 {
			s = climbedOnce
		}
		jobs = append(jobs, reader.FromAd(ladderAd(i, s, true), ""))
	}
	w := Analyze(jobs, Options{Days: 30}).Workflows[0]
	a := adviceByResource(w, ResourceMemory)
	if a == nil {
		t.Fatal("no memory advice")
	}
	if a.Severity != SeverityInfo {
		t.Errorf("severity %q for a ladder that is already sized right: %q / %q",
			a.Severity, a.Title, a.Detail)
	}
	if len(a.Submit) > 0 {
		t.Errorf("submit lines %q; the workflow already has that configuration", a.Submit)
	}
	if a.Saves != nil {
		t.Errorf("claimed %v saved by changing nothing", a.Saves)
	}
	// The curve marks what they run, not a point the advice declined to
	// push: a page reading "fits" beside a different mark contradicts
	// itself. The point keeps its retry, because these jobs needed one.
	var marked *MemoryCurvePoint
	for i := range w.MemoryCurve {
		if w.MemoryCurve[i].IsRecommended {
			marked = &w.MemoryCurve[i]
		}
	}
	if marked == nil || marked.RequestMiB != ladderBase {
		t.Fatalf("marked point = %+v, want the first rung %.0f", marked, ladderBase)
	}
	if marked.RetryMiB == nil {
		t.Error("the marked point dropped its retry, on a workflow where a third of the jobs needed one")
	}
}

// TestLadderThatRanOutStillWarns: the quiet case above is for a ladder
// that CAUGHT the jobs which outgrew their request. One that ran out of
// rungs did not -- those jobs were removed, and everything they had done
// went with them.
//
// Raising the ceiling reserves more memory, not less, so this advice can
// never pay for itself in reserved hours. It has to be given anyway.
func TestLadderThatRanOutStillWarns(t *testing.T) {
	ranOut := ladderShape{request: ladderRetry, starts: 2, wall: 7200, committed: 0,
		peak: 5000, lost: true, truth: ladderBase*1 + ladderRetry*1}
	var reader JobReader
	jobs := make([]Job, 0, 200)
	for i := range 200 {
		s := fitted
		if i%4 == 0 {
			s = ranOut
		}
		jobs = append(jobs, reader.FromAd(ladderAd(i, s, true), ""))
	}
	w := Analyze(jobs, Options{Days: 30}).Workflows[0]
	a := adviceByResource(w, ResourceMemory)
	if a == nil {
		t.Fatal("no memory advice")
	}
	if a.Severity != SeverityWarn {
		t.Errorf("severity %q with a quarter of the jobs removed for outgrowing the top rung: %q / %q",
			a.Severity, a.Title, a.Detail)
	}
	if len(a.Submit) == 0 {
		t.Error("no submit lines; the ladder needs a larger ceiling and the page has to name it")
	}
}
