package utilization

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
)

// Advice.
//
// Every piece of advice is a change to the next submit file, written in
// the user's terms: their jobs, their numbers, submit lines they can
// paste. None of it mentions how the numbers were obtained -- a person
// deciding what to request does not need to know where history is kept.

// minAdviceJobs is the fewest measured jobs CPU, disk or GPU advice rests
// on. Memory has its own, higher bar (minMemoryJobs), because its advice
// includes a retry rate that needs a tail to estimate.
const minAdviceJobs = 10

// CPU thresholds: lower a request whose 90th percentile uses under 60% of
// it; raise one whose median uses over 125% of it.
const (
	cpuLowerUse = 0.6
	cpuRaiseUse = 1.25
)

// Disk: lower when the largest job plus a quarter would fit in half the
// request.
const (
	diskHeadroom    = 1.25
	diskLowerShare  = 0.5
	memoryLowerCost = 0.8
)

// GPU thresholds. "Unused" is practically zero for practically every job,
// which usually means the program never found the GPU; "idle" is a
// median under 15%, which usually means it is waiting on something else.
const (
	gpuUnusedLevel = 0.01
	gpuUnusedShare = 0.9
	gpuIdleMedian  = 0.15
)

// adviseWorkflow builds a workflow's advice, most important first.
func adviseWorkflow(w *Workflow, jobs []*Job, plan *memoryPlan, completedWalls []float64) []Advice {
	var out []Advice
	if a := memoryAdvice(plan, w.Holds.Memory); a != nil {
		out = append(out, *a)
	}
	out = append(out, cpuAdvice(w, jobs)...)
	if a := diskAdvice(w, jobs); a != nil {
		out = append(out, *a)
	}
	if a := gpuAdvice(w, jobs); a != nil {
		out = append(out, *a)
	}
	if a := shortJobsAdvice(completedWalls); a != nil {
		out = append(out, *a)
	}
	if a := restartsAdvice(w); a != nil {
		out = append(out, *a)
	}
	slices.SortStableFunc(out, func(a, b Advice) int {
		if c := cmp.Compare(severityRank(a.Severity), severityRank(b.Severity)); c != 0 {
			return c
		}
		return cmp.Compare(savedAmount(b), savedAmount(a))
	})
	if out == nil {
		out = []Advice{}
	}
	return out
}

func severityRank(s string) int {
	switch s {
	case SeverityWarn:
		return 0
	case SeveritySuggest:
		return 1
	default:
		return 2
	}
}

func savedAmount(a Advice) float64 {
	if a.Saves == nil {
		return -1
	}
	return a.Saves.Amount
}

// memoryAdvice turns a memory plan into advice. holds is how many of the
// workflow's jobs were held for using more memory than they requested.
func memoryAdvice(plan *memoryPlan, holds int) *Advice {
	if plan == nil {
		return nil
	}
	hasRetry := plan.retry > 0
	a := &Advice{
		Resource:   ResourceMemory,
		Confidence: confidence(plan.n),
		Submit:     []string{"request_memory = " + submitSize(plan.recommended)},
	}
	if hasRetry {
		a.Submit = append(a.Submit, "retry_request_memory = "+submitSize(plan.retry))
	}
	if plan.currentCost > plan.recommendedCost {
		a.Saves = &Savings{Unit: UnitGiBHours, Amount: round((plan.currentCost-plan.recommendedCost)/1024, 1)}
	}

	evidence := fmt.Sprintf("95%% of %s jobs peaked at or below %s; the largest peaked at %s.",
		count(plan.n), sizeMiB(plan.p95), sizeMiB(plan.maxPeak))
	retryNote := ""
	if hasRetry {
		retryNote = fmt.Sprintf(" With the retry, about %s of jobs would run a second time with more memory.", percent(plan.retryFraction))
	}
	title := "Request " + submitSize(plan.recommended) + " of memory"
	if hasRetry {
		title += " and retry at " + submitSize(plan.retry)
	}

	switch {
	case holds > 0 || plan.maxPeak > plan.typical:
		// Some jobs did not fit. That is the urgent case: those jobs were
		// held or restarted, and everything they had done was lost.
		a.ID, a.Severity, a.Title = "memory-raise", SeverityWarn, title
		if hasRetry {
			a.ID = "memory-retry"
		}
		if holds > 0 {
			a.Detail = fmt.Sprintf("%s %s held for using more memory than requested. %s",
				count(holds), jobsWere(holds), evidence)
		} else {
			a.Detail = fmt.Sprintf("%s That is more than the %s most jobs requested.", evidence, sizeMiB(plan.typical))
		}
		a.Detail += retryNote
	case plan.recommendedCost < memoryLowerCost*plan.currentCost:
		a.ID, a.Severity, a.Title = "memory-lower", SeveritySuggest, title
		if hasRetry {
			a.ID = "memory-retry"
		}
		a.Detail = fmt.Sprintf("%s Most jobs requested %s.%s", evidence, sizeMiB(plan.typical), retryNote)
	default:
		a.ID, a.Severity = "memory-ok", SeverityInfo
		a.Title = "Memory request fits your jobs"
		a.Detail = fmt.Sprintf("%s Most jobs requested %s, close to what they need.", evidence, sizeMiB(plan.typical))
		a.Submit = []string{}
		a.Saves = nil
	}
	return a
}

// cpuAdvice compares the cores jobs kept busy with the cores they asked
// for.
func cpuAdvice(w *Workflow, jobs []*Job) []Advice {
	req, used := w.CPU.Request, w.CPU.CoresUsed
	if req == nil || used == nil || used.N < minAdviceJobs || req.Typical <= 0 {
		return nil
	}
	typical := req.Typical
	switch {
	case typical > 1 && used.P90 < cpuLowerUse*typical:
		rec := math.Max(1, math.Ceil(used.P90*headroom))
		if rec >= typical {
			return nil
		}
		// What the measured jobs would have reserved at the lower
		// request, over the same wall clock.
		saved := 0.0
		for _, j := range jobs {
			if j.coresUsed() != nil && j.RequestCpus != nil && *j.RequestCpus > rec {
				saved += (*j.RequestCpus - rec) * hours(j.Wall)
			}
		}
		return []Advice{{
			ID:       "cpus-lower",
			Resource: ResourceCPU,
			Severity: SeveritySuggest,
			Title:    fmt.Sprintf("Request %s %s", number(rec), plural(rec, "CPU", "CPUs")),
			Detail: fmt.Sprintf("90%% of %s jobs kept %s or fewer cores busy of the %s requested.",
				count(used.N), number(round(used.P90, 1)), number(typical)),
			Submit:     []string{"request_cpus = " + number(rec)},
			Saves:      &Savings{Unit: UnitCoreHours, Amount: round(saved, 1)},
			Confidence: confidence(used.N),
		}}
	case used.P50 > cpuRaiseUse*typical:
		rec := math.Max(math.Round(used.P75), typical+1)
		return []Advice{{
			ID:       "cpus-raise",
			Resource: ResourceCPU,
			Severity: SeverityWarn,
			Title:    fmt.Sprintf("Request %s CPUs, or limit threads to %s", number(rec), number(typical)),
			Detail: fmt.Sprintf("Half of %s jobs kept more than %s cores busy with %s requested, so they compete for cores they did not reserve. Setting OMP_NUM_THREADS or your program's thread option to the request also works.",
				count(used.N), number(round(used.P50, 1)), number(typical)),
			Submit:     []string{"request_cpus = " + number(rec)},
			Confidence: confidence(used.N),
		}}
	}
	return nil
}

// diskAdvice compares peak disk use with the disk requested.
func diskAdvice(w *Workflow, jobs []*Job) *Advice {
	req := w.Disk.Request
	if req == nil || req.Typical <= 0 {
		return nil
	}
	// The largest disk use of a finished job, counting a job held for
	// outgrowing its disk as having used at least its request.
	largest, n := 0.0, 0
	for _, j := range jobs {
		switch {
		case j.HeldForDisk && j.RequestDisk != nil:
			largest = math.Max(largest, math.Max(orZero(j.DiskUsage), *j.RequestDisk))
			n++
		case j.Status == statusCompleted && j.DiskUsage != nil:
			largest = math.Max(largest, *j.DiskUsage)
			n++
		}
	}
	if n < minAdviceJobs && w.Holds.Disk == 0 {
		return nil
	}
	rec := niceMiB(largest*diskHeadroom/1024) * 1024
	if w.Holds.Disk > 0 {
		return &Advice{
			ID:       "disk-raise",
			Resource: ResourceDisk,
			Severity: SeverityWarn,
			Title:    "Request " + submitSize(rec/1024) + " of disk",
			Detail: fmt.Sprintf("%s %s held for using more disk than requested; the largest used at least %s. retry_request_disk can raise the request for only the jobs that need it.",
				count(w.Holds.Disk), jobsWere(w.Holds.Disk), sizeMiB(largest/1024)),
			Submit:     []string{"request_disk = " + submitSize(rec/1024)},
			Confidence: confidence(n),
		}
	}
	if rec < diskLowerShare*req.Typical {
		return &Advice{
			ID:       "disk-lower",
			Resource: ResourceDisk,
			Severity: SeveritySuggest,
			Title:    "Request " + submitSize(rec/1024) + " of disk",
			Detail: fmt.Sprintf("The largest of %s jobs used %s of disk; most requested %s.",
				count(n), sizeMiB(largest/1024), sizeMiB(req.Typical/1024)),
			Submit:     []string{"request_disk = " + submitSize(rec/1024)},
			Confidence: confidence(n),
		}
	}
	return nil
}

// gpuAdvice looks for GPUs that were reserved and left idle.
func gpuAdvice(w *Workflow, jobs []*Job) *Advice {
	if w.GPU == nil || w.GPU.Utilization == nil || w.GPU.Utilization.N < minAdviceJobs {
		return nil
	}
	util := w.GPU.Utilization
	idle, reserved := 0, 0.0
	gpuMem := 0.0
	for _, j := range jobs {
		u := j.GPUUtilization()
		if u == nil {
			continue
		}
		if *u < gpuUnusedLevel {
			idle++
		}
		reserved += *j.RequestGPUs * hours(j.Wall)
		gpuMem = math.Max(gpuMem, orZero(j.GPUsMemoryUsage))
	}
	memNote := ""
	if gpuMem > 0 {
		memNote = fmt.Sprintf(" The most GPU memory any job used was %s.", sizeMiB(gpuMem))
	}
	if float64(idle) >= gpuUnusedShare*float64(util.N) {
		return &Advice{
			ID:       "gpu-unused",
			Resource: ResourceGPU,
			Severity: SeverityWarn,
			Title:    "Check whether these jobs use their GPUs",
			Detail: fmt.Sprintf("%s of %s jobs kept their GPUs busy less than 1%% of the time.%s If the program does not use a GPU, removing request_gpus lets the jobs run on far more machines.",
				count(idle), count(util.N), memNote),
			Submit:     []string{},
			Saves:      &Savings{Unit: UnitGPUHours, Amount: round(reserved, 1)},
			Confidence: confidence(util.N),
		}
	}
	if util.P50 < gpuIdleMedian {
		return &Advice{
			ID:       "gpu-idle",
			Resource: ResourceGPU,
			Severity: SeveritySuggest,
			Title:    "Keep the GPU busier",
			Detail: fmt.Sprintf("Half of %s jobs kept their GPUs busy %s of the time or less.%s The GPU is usually waiting on input, on the CPU, or on code that has not been moved to it.",
				count(util.N), percent(util.P50), memNote),
			Submit:     []string{},
			Confidence: confidence(util.N),
		}
	}
	return nil
}

// shortJobsAdvice suggests batching work when most jobs are brief.
func shortJobsAdvice(completedWalls []float64) *Advice {
	n := len(completedWalls)
	if n < minShortJobsAdvice {
		return nil
	}
	walls := slices.Clone(completedWalls)
	slices.Sort(walls)
	p50 := percentile(walls, 50)
	if p50 >= shortJobWall {
		return nil
	}
	return &Advice{
		ID:       "short-jobs",
		Resource: ResourceRuntime,
		Severity: SeveritySuggest,
		Title:    "Combine short tasks into fewer jobs",
		Detail: fmt.Sprintf("Half of %s jobs finished in %s or less. Every job waits to be scheduled and moves its files, so running several tasks in each job usually finishes the whole set sooner.",
			count(n), duration(p50)),
		Submit:     []string{},
		Confidence: confidence(n),
	}
}

// restartsAdvice reports wall clock lost to runs that were restarted.
func restartsAdvice(w *Workflow) *Advice {
	if w.Restarts.Jobs == 0 || w.WallHours <= 0 || w.Restarts.LostHours <= restartLossShare*w.WallHours {
		return nil
	}
	return &Advice{
		ID:       "restarts",
		Resource: ResourceRuntime,
		Severity: SeverityInfo,
		Title:    "Restarts are costing running time",
		Detail: fmt.Sprintf("%s %s restarted, losing %s hours, %s of the running time. A job that saves its progress (checkpoints) picks up where it left off instead of starting over.",
			count(w.Restarts.Jobs), jobsWere(w.Restarts.Jobs), number(round(w.Restarts.LostHours, 1)), percent(w.Restarts.LostHours/w.WallHours)),
		Submit:     []string{},
		Confidence: confidence(w.Jobs),
	}
}

// sizeMiB writes a MiB amount for reading: MB under a GiB, GB to one
// decimal above. HTCondor's MB and GB are MiB and GiB, and so are these.
func sizeMiB(mib float64) string {
	mib = math.Ceil(mib - 1e-9)
	if mib >= 1024 {
		return strconv.FormatFloat(round(mib/1024, 1), 'f', -1, 64) + " GB"
	}
	return strconv.FormatFloat(mib, 'f', 0, 64) + " MB"
}

// submitSize writes a MiB amount exactly, for a submit line: whole GiB in
// GB, anything else in MB. "1.3 GB" would be read by HTCondor as 1331
// MiB, not the 1280 that was meant.
func submitSize(mib float64) string {
	mib = math.Ceil(mib - 1e-9)
	if mib >= 1024 && math.Mod(mib, 1024) == 0 {
		return strconv.FormatFloat(mib/1024, 'f', -1, 64) + " GB"
	}
	return strconv.FormatFloat(mib, 'f', 0, 64) + " MB"
}

// count writes an integer with thousands separators.
func count(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	lead := len(s) % 3
	if lead > 0 {
		b.WriteString(s[:lead])
	}
	for i := lead; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// number writes a figure without trailing zeros.
func number(x float64) string {
	return strconv.FormatFloat(x, 'f', -1, 64)
}

// percent writes a fraction as a whole percentage, or "under 1%".
func percent(f float64) string {
	p := f * 100
	if p > 0 && p < 1 {
		return "under 1%"
	}
	return fmt.Sprintf("%.0f%%", p)
}

// duration writes seconds as minutes or seconds.
func duration(seconds float64) string {
	if seconds >= 120 {
		return fmt.Sprintf("%.0f minutes", seconds/60)
	}
	return fmt.Sprintf("%.0f seconds", seconds)
}

func plural(n float64, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func jobsWere(n int) string {
	if n == 1 {
		return "job was"
	}
	return "jobs were"
}
