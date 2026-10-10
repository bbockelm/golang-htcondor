package utilization

import (
	"fmt"
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
// 20 jobs, an hour each, asking for 4 GiB: 18 peak at 900 MiB, 2 at 1100.
// One request of 1280 reserves 25,600 MiB-h; 1024 with a retry at 1280
// reserves 20*1024 + 2*1280 = 23,040, only a 10% saving -- so the advice
// is 1280 alone, saving (81,920 - 25,600)/1024 = 55 GiB-h over the 4 GiB
// requests.
func TestMemorySmallRetrySavingIsNotRecommended(t *testing.T) {
	var jobs []Job
	jobs = append(jobs, jobsAt(18, 1, 900, 4096)...)
	jobs = append(jobs, jobsAt(2, 100, 1100, 4096)...)
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
	a := adviceByResource(w, ResourceMemory)
	if a == nil || a.ID != "memory-lower" || !slices.Equal(a.Submit, []string{"request_memory = 1280 MB"}) {
		t.Fatalf("advice = %+v, want memory-lower to 1280 MB alone", a)
	}
	if a.Saves == nil || a.Saves.Amount != 55 {
		t.Errorf("saves = %+v, want 55 GiB-h", a.Saves)
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

// The grid is every round request between the bounds while that is few
// enough to plot, and an even-ratio sample of them otherwise.
func TestRequestGrid(t *testing.T) {
	// 896 and 1024, then 256 MiB steps to 4 GiB (12), then 512 MiB steps
	// to 7 GiB (6).
	g := requestGrid(800, 7168)
	if len(g) != 20 || g[0] != 896 || g[1] != 1024 || g[2] != 1280 || g[len(g)-1] != 7168 {
		t.Errorf("grid(800, 7168) = %v", g)
	}
	wide := requestGrid(100, 64*1024)
	if len(wide) > maxCurvePoints || len(wide) < 20 || wide[0] != 128 || wide[len(wide)-1] != 64*1024 {
		t.Errorf("grid(100, 64 GiB) has %d points: %v", len(wide), wide)
	}
	for _, grid := range [][]float64{g, wide, requestGrid(5000, 1000)} {
		if !slices.IsSorted(grid) || len(slices.Compact(slices.Clone(grid))) != len(grid) {
			t.Errorf("grid not ascending and distinct: %v", grid)
		}
		for _, r := range grid {
			if niceMiB(r) != r {
				t.Errorf("grid value %v is not a round request", r)
			}
		}
	}
	// Even ratios: no step on the sampled grid is more than a few times
	// the size of the others in relative terms.
	for i := 1; i < len(wide); i++ {
		if ratio := wide[i] / wide[i-1]; ratio > 2.01 {
			t.Errorf("step %v -> %v is too coarse", wide[i-1], wide[i])
		}
	}
}

// The long-tail curve is dense: every round request from just above the
// 5th-percentile peak (896) to the one that fits everything (7 GiB) --
// twenty -- and on to the current 8 GiB (7.5 and 8). Two points off the recommendation,
// hand-checked: 1024 reruns the same five jobs, 102,400 + 5*7168 =
// 138,240 MiB-h; 1536 fits the two 1500 MiB jobs, 153,600 + 3*7168 =
// 175,104.
func TestMemoryCurveIsDense(t *testing.T) {
	var jobs []Job
	jobs = append(jobs, jobsAt(95, 1, 800, 8192)...)
	jobs = append(jobs, jobsAt(2, 200, 1500, 8192)...)
	jobs = append(jobs, jobsAt(3, 300, 6144, 8192)...)
	w := onlyWorkflow(t, jobs)
	if len(w.MemoryCurve) != 22 {
		t.Errorf("curve has %d points, want 22", len(w.MemoryCurve))
	}
	at := map[float64]MemoryCurvePoint{}
	for _, p := range w.MemoryCurve {
		at[p.RequestMiB] = p
	}
	if p := at[1024]; p.ReservedMiBHours != 138240 || p.RetryFraction != 0.05 {
		t.Errorf("1024 point = %+v", p)
	}
	if p := at[1536]; p.ReservedMiBHours != 175104 || p.RetryFraction != 0.03 {
		t.Errorf("1536 point = %+v", p)
	}
	// Above the request that fits everything, cost is just request times
	// wall: 8192 * 100.
	if p := at[8192]; !p.IsCurrent || p.RetryMiB != nil || p.ReservedMiBHours != 819200 {
		t.Errorf("current point = %+v", p)
	}
}

// The dense grid finds requests the old percentile-plus-10% candidates
// stepped over. 95 jobs peak at exactly 1000 MiB and 5 at 3000, an hour
// each, all asking for 4 GiB. Fitting everything takes nice(3300) = 3328.
// 1024 covers the 95 and reruns 5 at 3328: 102,400 + 16,640 = 119,040
// MiB-h, against 332,800 for 3328 alone. (1000 * 1.1 rounds up to 1280,
// which would reserve 144,640.) Saved against the 409,600 the jobs
// reserved: 283.75 GiB-h.
func TestMemoryDenseGridFindsTheCheaperRequest(t *testing.T) {
	var jobs []Job
	jobs = append(jobs, jobsAt(95, 1, 1000, 4096)...)
	jobs = append(jobs, jobsAt(5, 200, 3000, 4096)...)
	w := onlyWorkflow(t, jobs)
	p := recommendedPoint(t, w)
	if p.RequestMiB != 1024 || p.RetryMiB == nil || *p.RetryMiB != 3328 || p.ReservedMiBHours != 119040 {
		t.Errorf("recommended = %+v, want 1024 retrying at 3328, 119040 MiB-h", p)
	}
	a := adviceByResource(w, ResourceMemory)
	if a == nil || a.ID != "memory-retry" || !slices.Equal(a.Submit, []string{"request_memory = 1 GB", "retry_request_memory = 3328 MB"}) {
		t.Fatalf("advice = %+v", a)
	}
	if a.Saves == nil || a.Saves.Amount != 283.8 {
		t.Errorf("saves = %+v, want 283.8 GiB-h", a.Saves)
	}
}

// When the advice is to keep the current request, the curve marks the
// current request -- not a cheaper point the advice declined to push --
// with no retry beside it.
func TestMemoryOKMarksTheCurrentRequest(t *testing.T) {
	// 25 jobs peaking at 1000 MiB asking for 1 GiB: the grid offers
	// nothing cheaper by enough to bother, so the advice is "fits".
	w := onlyWorkflow(t, jobsAt(25, 1, 1000, 1024))
	a := adviceByResource(w, ResourceMemory)
	if a == nil || a.ID != "memory-ok" {
		t.Fatalf("advice = %+v, want memory-ok", a)
	}
	p := recommendedPoint(t, w)
	if p.RequestMiB != 1024 || !p.IsCurrent || p.RetryMiB != nil {
		t.Errorf("recommended = %+v, want the current 1024 with no retry", p)
	}
}

// assertCurveMatchesAdvice is the invariant the page relies on: the
// point marked recommended is the request (and retry) the memory advice
// tells the user to submit, or the current request when the advice is to
// keep it.
func assertCurveMatchesAdvice(t *testing.T, name string, w Workflow) {
	t.Helper()
	a := adviceByResource(w, ResourceMemory)
	if len(w.MemoryCurve) == 0 {
		if a != nil {
			t.Errorf("%s: memory advice %q with no curve", name, a.ID)
		}
		return
	}
	var rec []MemoryCurvePoint
	for _, p := range w.MemoryCurve {
		if p.IsRecommended {
			rec = append(rec, p)
		}
	}
	if len(rec) != 1 {
		t.Errorf("%s: %d recommended points", name, len(rec))
		return
	}
	p := rec[0]
	if a == nil {
		t.Errorf("%s: a curve but no memory advice", name)
		return
	}
	if a.ID == "memory-ok" {
		if !p.IsCurrent || p.RetryMiB != nil || len(a.Submit) != 0 {
			t.Errorf("%s: memory-ok but recommended point %+v, submit %q", name, p, a.Submit)
		}
		return
	}
	want := []string{"request_memory = " + submitSize(p.RequestMiB)}
	if p.RetryMiB != nil {
		want = append(want, "retry_request_memory = "+submitSize(*p.RetryMiB))
	}
	if !slices.Equal(a.Submit, want) {
		t.Errorf("%s: advice %s submits %q, recommended point says %q", name, a.ID, a.Submit, want)
	}
}

func TestMemoryCurveMatchesAdvice(t *testing.T) {
	fixtures := map[string][]Job{
		"tight":  jobsAt(30, 1, 920, 4096),
		"ok":     jobsAt(25, 1, 1000, 1024),
		"fits":   jobsAt(25, 1, 900, 1024),
		"small":  append(jobsAt(18, 1, 900, 1280), jobsAt(2, 100, 1100, 1280)...),
		"dense":  append(jobsAt(95, 1, 1000, 4096), jobsAt(5, 200, 3000, 4096)...),
		"capped": append(jobsAt(80, 1, 500, 8192), jobsAt(20, 100, 6000, 8192)...),
		"under":  append(jobsAt(24, 1, 900, 1024), completed(100, 1500, 1024, 3600)),
		"longtail": append(append(jobsAt(95, 1, 800, 8192), jobsAt(2, 200, 1500, 8192)...),
			jobsAt(3, 300, 6144, 8192)...),
	}
	held := Job{Cluster: 99, Owner: "alice", Cmd: "/home/alice/sim", Universe: 5, QDate: 2000,
		Status: statusRemoved, RequestMemory: f(1024), Wall: 3600, HeldForMemory: true, ExceededMemory: true}
	fixtures["held"] = append(jobsAt(25, 1, 900, 1024), held)

	// And a spread of shapes from a fixed pseudo-random sequence: peaks
	// from a few hundred MiB to tens of GiB, ragged walls and requests.
	seed := uint64(1)
	next := func() float64 {
		seed = seed*6364136223846793005 + 1442695040888963407
		return float64(seed>>11) / float64(1<<53)
	}
	for k := range 200 {
		base := 200 + next()*20000
		tail := 1 + next()*6
		request := niceMiB(base * (0.8 + next()*2))
		var jobs []Job
		for i := range 20 + int(next()*200) {
			peak := base * (0.7 + next()*0.4)
			if next() < 0.06 {
				peak *= tail
			}
			jobs = append(jobs, completed(int64(i+1), math.Round(peak), request, 60+next()*20000))
		}
		fixtures[fmt.Sprintf("random-%d", k)] = jobs
	}

	for name, jobs := range fixtures {
		for _, w := range Analyze(jobs, Options{}).Workflows {
			assertCurveMatchesAdvice(t, name, w)
		}
	}
}

// A job evicted for memory by a retry policy and then removed was never
// held, but it still outgrew its request; the advice warns all the same.
func TestMemoryEvictedJobWarns(t *testing.T) {
	evicted := Job{Cluster: 99, Owner: "alice", Cmd: "/home/alice/sim", Universe: 5, QDate: 2000,
		Status: statusRemoved, RequestMemory: f(1024), Wall: 3600, ExceededMemory: true}
	w := onlyWorkflow(t, append(jobsAt(25, 1, 900, 1024), evicted))
	if w.Holds.Memory != 0 {
		t.Fatalf("holds = %+v", w.Holds)
	}
	a := adviceByResource(w, ResourceMemory)
	if a == nil || a.ID != "memory-retry" || a.Severity != SeverityWarn {
		t.Errorf("advice = %+v, want memory-retry/warn", a)
	}
	assertCurveMatchesAdvice(t, "evicted", w)
}
