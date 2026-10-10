package utilization

import (
	"math"
	"slices"
	"testing"
)

func f(x float64) *float64 { return &x }

// completed is a finished, successful job of the "sim" workflow.
func completed(cluster int64, peakMiB, requestMiB, wallSeconds float64) Job {
	code := int64(0)
	return Job{
		Cluster: cluster, Owner: "alice", Cmd: "/home/alice/sim", Universe: 5,
		QDate: 1000 + cluster, Status: statusCompleted, ExitCode: &code,
		RequestMemory: f(requestMiB), RequestCpus: f(1), MemoryUsage: f(peakMiB),
		Wall: wallSeconds,
	}
}

// jobsAt is n one-hour jobs with the same peak and request.
func jobsAt(n int, startCluster int64, peak, request float64) []Job {
	out := make([]Job, 0, n)
	for i := range n {
		out = append(out, completed(startCluster+int64(i), peak, request, 3600))
	}
	return out
}

func onlyWorkflow(t *testing.T, jobs []Job) Workflow {
	t.Helper()
	resp := Analyze(jobs, Options{Days: 7})
	if len(resp.Workflows) != 1 {
		t.Fatalf("got %d workflows, want 1", len(resp.Workflows))
	}
	return resp.Workflows[0]
}

func adviceByResource(w Workflow, resource string) *Advice {
	for i := range w.Advice {
		if w.Advice[i].Resource == resource {
			return &w.Advice[i]
		}
	}
	return nil
}

func recommendedPoint(t *testing.T, w Workflow) MemoryCurvePoint {
	t.Helper()
	var found []MemoryCurvePoint
	for _, p := range w.MemoryCurve {
		if p.IsRecommended {
			found = append(found, p)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one recommended point, got %d in %+v", len(found), w.MemoryCurve)
	}
	return found[0]
}

func TestNiceMiB(t *testing.T) {
	for _, tc := range []struct{ in, want float64 }{
		{0, 128},
		{1, 128},
		{128, 128},
		{129, 256},
		{990, 1024},
		{1024, 1024},
		{1025, 1280},
		{1126.4, 1280},
		{4095, 4096},
		{4097, 4608},
		{6758.4, 7168},
		{16384, 16384},
		{16385, 17408},
	} {
		if got := niceMiB(tc.in); got != tc.want {
			t.Errorf("niceMiB(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// Every job peaks within a few MiB of the others: one request with a
// little headroom fits all of them, and a retry would buy nothing.
//
// 30 jobs peaking at 900..929 MiB, an hour each, all requesting 4 GiB.
// The largest, 929 MiB, plus 10% is 1021.9, which rounds up to 1 GiB;
// every percentile does too. 1 GiB for 30 hours is 30,720 MiB-h against
// the 122,880 the 4 GiB requests reserved: 90 GiB-h saved.
func TestMemoryTightDistributionIsOneRequest(t *testing.T) {
	var jobs []Job
	for i := range 30 {
		jobs = append(jobs, completed(int64(i+1), 900+float64(i), 4096, 3600))
	}
	w := onlyWorkflow(t, jobs)

	p := recommendedPoint(t, w)
	if p.RequestMiB != 1024 || p.RetryMiB != nil || p.ReservedMiBHours != 30720 {
		t.Errorf("recommended point = %+v, want 1024 MiB, no retry, 30720 MiB-h", p)
	}
	a := adviceByResource(w, ResourceMemory)
	if a == nil || a.ID != "memory-lower" || a.Severity != SeveritySuggest {
		t.Fatalf("memory advice = %+v, want memory-lower/suggest", a)
	}
	if !slices.Equal(a.Submit, []string{"request_memory = 1 GB"}) {
		t.Errorf("submit = %q", a.Submit)
	}
	if a.Saves == nil || a.Saves.Unit != UnitGiBHours || a.Saves.Amount != 90 {
		t.Errorf("saves = %+v, want 90 GiB-h", a.Saves)
	}
	// The current request is on the curve and marked, so the page can
	// show where the jobs stand.
	var current []float64
	for _, p := range w.MemoryCurve {
		if p.IsCurrent {
			current = append(current, p.RequestMiB)
		}
	}
	if !slices.Equal(current, []float64{4096}) {
		t.Errorf("current points = %v, want [4096]", current)
	}
}

// The case retries exist for: almost every job is small, a few are not.
//
// 100 jobs, an hour each, all requesting 8 GiB: 95 peak at 800 MiB, 2 at
// 1500 MiB, 3 at 6 GiB. Fitting everything takes nice(6144*1.1) = 7 GiB.
// Every percentile through p95 is 800 MiB, so 800*1.1 rounds up to 896
// MiB; five jobs exceed that and rerun at 7 GiB.
//
// Expected reservation at 896 with the stopped attempt charged its FULL
// hour: 100*896 + 5*7168 = 125,440 MiB-h. One 7 GiB request would reserve
// 716,800; the 8 GiB the jobs asked for reserved 819,200. The retry saves
// far more than 15% over the single request, and (819200-125440)/1024 =
// 677.5 GiB-h over what they did.
func TestMemoryLongTailRecommendsRetry(t *testing.T) {
	var jobs []Job
	jobs = append(jobs, jobsAt(95, 1, 800, 8192)...)
	jobs = append(jobs, jobsAt(2, 200, 1500, 8192)...)
	jobs = append(jobs, jobsAt(3, 300, 6144, 8192)...)
	w := onlyWorkflow(t, jobs)

	p := recommendedPoint(t, w)
	if p.RequestMiB != 896 || p.RetryMiB == nil || *p.RetryMiB != 7168 {
		t.Fatalf("recommended point = %+v, want 896 MiB retrying at 7168", p)
	}
	if p.ReservedMiBHours != 125440 {
		t.Errorf("reserved = %v MiB-h, want 125440 (each stopped attempt charged its full wall)", p.ReservedMiBHours)
	}
	if p.RetryFraction != 0.05 {
		t.Errorf("retry fraction = %v, want 0.05", p.RetryFraction)
	}

	a := adviceByResource(w, ResourceMemory)
	if a == nil || a.ID != "memory-retry" || a.Severity != SeveritySuggest {
		t.Fatalf("memory advice = %+v, want memory-retry/suggest", a)
	}
	if !slices.Equal(a.Submit, []string{"request_memory = 896 MB", "retry_request_memory = 7 GB"}) {
		t.Errorf("submit = %q", a.Submit)
	}
	if a.Saves == nil || a.Saves.Amount != 677.5 {
		t.Errorf("saves = %+v, want 677.5 GiB-h", a.Saves)
	}
	if a.Title != "Request 896 MB of memory and retry at 7 GB" {
		t.Errorf("title = %q", a.Title)
	}

	// The single request is on the curve with no retry.
	var single *MemoryCurvePoint
	for i := range w.MemoryCurve {
		if w.MemoryCurve[i].RequestMiB == 7168 {
			single = &w.MemoryCurve[i]
		}
	}
	if single == nil || single.RetryMiB != nil || single.ReservedMiBHours != 716800 {
		t.Errorf("single-request point = %+v, want 7168 MiB, no retry, 716800 MiB-h", single)
	}
	// Sorted by request.
	if !slices.IsSortedFunc(w.MemoryCurve, func(a, b MemoryCurvePoint) int {
		return int(a.RequestMiB - b.RequestMiB)
	}) {
		t.Errorf("curve is not sorted by request: %+v", w.MemoryCurve)
	}
}

// phi = 1: the reservation of a job that reruns is its request for its
// whole wall plus the retry for its whole wall again. Pinned directly so
// that "the failed attempt ran half as long" cannot creep back in.
func TestExpectedCostChargesTheFullFailedAttempt(t *testing.T) {
	jobs := []memoryJob{
		{peak: 500, wallHours: 2},
		{peak: 3000, wallHours: 4},
	}
	cost, frac := expectedCost(jobs, 1024, 4096)
	// 1024*2 + 1024*4 + 4096*4 = 2048 + 4096 + 16384.
	if cost != 22528 {
		t.Errorf("cost = %v, want 22528", cost)
	}
	if frac != 0.5 {
		t.Errorf("retry fraction = %v, want 0.5", frac)
	}
}

// A retry that saves under 15% over one request that fits everything is
// not worth the reruns.
//
// 20 jobs, an hour each: 18 at 900 MiB, 2 at 1100. One request of 1280
// reserves 25,600 MiB-h; 1024 with a retry at 1280 reserves 20*1024 +
// 2*1280 = 23,040, a 10% saving.
func TestMemorySmallRetrySavingIsNotRecommended(t *testing.T) {
	var jobs []Job
	jobs = append(jobs, jobsAt(18, 1, 900, 1280)...)
	jobs = append(jobs, jobsAt(2, 100, 1100, 1280)...)
	w := onlyWorkflow(t, jobs)

	p := recommendedPoint(t, w)
	if p.RequestMiB != 1280 || p.RetryMiB != nil {
		t.Errorf("recommended = %+v, want 1280 MiB alone", p)
	}
	var at1024 *MemoryCurvePoint
	for i := range w.MemoryCurve {
		if w.MemoryCurve[i].RequestMiB == 1024 {
			at1024 = &w.MemoryCurve[i]
		}
	}
	if at1024 == nil || at1024.ReservedMiBHours != 23040 || at1024.RetryMiB == nil || *at1024.RetryMiB != 1280 {
		t.Errorf("1024 point = %+v, want 23040 MiB-h retrying at 1280", at1024)
	}
	if a := adviceByResource(w, ResourceMemory); a == nil || a.ID != "memory-ok" {
		t.Errorf("advice = %+v, want memory-ok (the jobs already ask for 1280)", a)
	}
}

// A retry that more than one job in ten would take is not recommended
// however much it saves.
func TestMemoryRetryFractionIsCapped(t *testing.T) {
	var jobs []Job
	jobs = append(jobs, jobsAt(80, 1, 500, 8192)...)
	jobs = append(jobs, jobsAt(20, 100, 6000, 8192)...)
	w := onlyWorkflow(t, jobs)
	p := recommendedPoint(t, w)
	if p.RetryFraction > maxRetryFraction {
		t.Errorf("recommended %+v reruns more than %v of jobs", p, maxRetryFraction)
	}
}

// A job held for exceeding its memory is known to need MORE than it
// asked for, even though its own peak was cut off. Leaving it out sizes
// the next submission from the jobs that happened to fit.
//
// 25 jobs at 900 MiB requesting 1 GiB fit: the plan is 1 GiB and the
// advice says so. Add one job removed after being held for memory at
// that same 1 GiB: its peak counts as 1024, nice(1024*1.1) = 1280, and
// 1024 with a retry at 1280 now reserves 26*1024 + 1280 = 27,904 MiB-h
// against 33,280 for 1280 alone -- a retry, flagged as a warning.
func TestMemoryHeldJobRaisesTheRecommendation(t *testing.T) {
	base := jobsAt(25, 1, 900, 1024)
	w := onlyWorkflow(t, base)
	if a := adviceByResource(w, ResourceMemory); a == nil || a.ID != "memory-ok" {
		t.Fatalf("without the held job: advice = %+v, want memory-ok", a)
	}
	if p := recommendedPoint(t, w); p.RequestMiB != 1024 || p.RetryMiB != nil {
		t.Fatalf("without the held job: recommended = %+v", p)
	}

	held := Job{
		Cluster: 99, Owner: "alice", Cmd: "/home/alice/sim", Universe: 5, QDate: 2000,
		Status: statusRemoved, RequestMemory: f(1024), RequestCpus: f(1), Wall: 3600,
		HeldForMemory: true, ExceededMemory: true,
	}
	w = onlyWorkflow(t, append(base, held))

	if w.Holds.Memory != 1 {
		t.Errorf("holds.memory = %d, want 1", w.Holds.Memory)
	}
	p := recommendedPoint(t, w)
	if p.RequestMiB != 1024 || p.RetryMiB == nil || *p.RetryMiB != 1280 || p.ReservedMiBHours != 27904 {
		t.Errorf("recommended = %+v, want 1024 retrying at 1280, 27904 MiB-h", p)
	}
	a := adviceByResource(w, ResourceMemory)
	if a == nil || a.ID != "memory-retry" || a.Severity != SeverityWarn {
		t.Fatalf("advice = %+v, want memory-retry/warn", a)
	}
	if !slices.Contains(a.Submit, "retry_request_memory = 1280 MB") {
		t.Errorf("submit = %q", a.Submit)
	}
	if w.Memory.PeakMiB == nil || w.Memory.PeakMiB.Max != 1024 {
		t.Errorf("peak distribution = %+v, want the held job counted at its request", w.Memory.PeakMiB)
	}
	var outcomes []string
	for _, s := range w.Samples {
		outcomes = append(outcomes, s.Outcome)
	}
	if !slices.Contains(outcomes, OutcomeMemoryExceeded) {
		t.Errorf("sample outcomes = %v, want one memory_exceeded", outcomes)
	}
}

// A removed job that was NOT stopped for memory stopped early for some
// other reason, and its peak is an understatement. It stays out.
func TestMemoryRemovedJobDoesNotSizeMemory(t *testing.T) {
	base := jobsAt(25, 1, 900, 1024)
	removed := completed(99, 5000, 1024, 3600)
	removed.Status = statusRemoved
	removed.ExitCode = nil
	w := onlyWorkflow(t, append(base, removed))
	if w.Memory.PeakMiB.N != 25 || w.Memory.PeakMiB.Max != 900 {
		t.Errorf("peaks = %+v, want the 25 completed jobs only", w.Memory.PeakMiB)
	}
}

// Only finished jobs are analysed at all. A running job's MemoryUsage is
// where it is now, not where it will peak -- memory often climbs at the
// end -- so it must never reach the sizing.
func TestRunningJobsNeverReachTheAnalysis(t *testing.T) {
	jobs := jobsAt(25, 1, 900, 1024)
	for i := range 5 {
		running := completed(int64(500+i), 6000, 1024, 3600)
		running.Status = 2
		running.ExitCode = nil
		jobs = append(jobs, running)
	}
	idle := completed(600, 7000, 1024, 0)
	idle.Status = 1
	held := completed(601, 7000, 1024, 3600)
	held.Status = 5
	held.HeldForMemory, held.ExceededMemory = true, true
	jobs = append(jobs, idle, held)

	resp := Analyze(jobs, Options{Days: 7})
	if resp.JobsConsidered != 25 {
		t.Errorf("jobs_considered = %d, want 25", resp.JobsConsidered)
	}
	w := resp.Workflows[0]
	if w.Memory.PeakMiB.Max != 900 || w.Holds.Memory != 0 {
		t.Errorf("peaks = %+v holds = %+v; unfinished jobs leaked in", w.Memory.PeakMiB, w.Holds)
	}
}

// Under twenty finished jobs, a 95th percentile is one job: no memory
// advice and no curve.
func TestMemoryNeedsTwentyJobs(t *testing.T) {
	w := onlyWorkflow(t, jobsAt(19, 1, 900, 8192))
	if len(w.MemoryCurve) != 0 {
		t.Errorf("curve = %+v, want empty", w.MemoryCurve)
	}
	if w.MemoryCurve == nil {
		t.Error("curve is nil; it must marshal as []")
	}
	if a := adviceByResource(w, ResourceMemory); a != nil {
		t.Errorf("memory advice with 19 jobs: %+v", a)
	}
	if w.Memory.PeakMiB == nil || w.Memory.PeakMiB.N != 19 {
		t.Errorf("the distribution is still reported: %+v", w.Memory.PeakMiB)
	}

	w = onlyWorkflow(t, jobsAt(20, 1, 900, 8192))
	if len(w.MemoryCurve) == 0 || adviceByResource(w, ResourceMemory) == nil {
		t.Error("20 jobs should be enough for memory advice")
	}
}

// Jobs that outgrew what most jobs ask for are a warning even when no
// job was held -- they were lucky, or the pool is lenient.
func TestMemoryPeakAboveRequestWarns(t *testing.T) {
	var jobs []Job
	jobs = append(jobs, jobsAt(24, 1, 900, 1024)...)
	jobs = append(jobs, completed(100, 1500, 1024, 3600))
	w := onlyWorkflow(t, jobs)
	a := adviceByResource(w, ResourceMemory)
	if a == nil || a.Severity != SeverityWarn {
		t.Fatalf("advice = %+v, want a warning", a)
	}
	if a.ID != "memory-raise" && a.ID != "memory-retry" {
		t.Errorf("id = %q", a.ID)
	}
	if math.IsNaN(recommendedPoint(t, w).ReservedMiBHours) {
		t.Error("NaN cost")
	}
}
