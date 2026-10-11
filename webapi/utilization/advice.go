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
	// gpuBusySlack lets a job that keeps 1.04 GPUs busy count as one.
	gpuBusySlack = 0.05
	// gpuCPUBoundUtil and cpuSaturated: a median GPU under half busy
	// while the median job uses 90% of its cores is starved for CPU.
	gpuCPUBoundUtil = 0.5
	cpuSaturated    = 0.9
	// gpuMemoryHeadroom is the margin over the largest GPU memory peak.
	gpuMemoryHeadroom = 1.25
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
	out = append(out, gpuAdvice(w, jobs, out)...)
	if a := shortJobsAdvice(completedWalls); a != nil {
		out = append(out, *a)
	}
	if a := restartsAdvice(w); a != nil {
		out = append(out, *a)
	}
	// Most urgent first; then GPU-hours saved ahead of any other saving,
	// because a GPU is by far the scarcest and dearest thing a job
	// reserves; then the larger saving.
	slices.SortStableFunc(out, func(a, b Advice) int {
		if c := cmp.Compare(severityRank(a.Severity), severityRank(b.Severity)); c != 0 {
			return c
		}
		if c := cmp.Compare(savesGPU(b), savesGPU(a)); c != 0 {
			return c
		}
		return cmp.Compare(savedAmount(b), savedAmount(a))
	})
	for i := range out {
		if attr, value, ok := out[i].RequestChange(); ok {
			out[i].Applies = true
			out[i].Change = &Change{Attribute: attr, Value: value}
		}
	}
	if out == nil {
		out = []Advice{}
	}
	return out
}

// appliesToQueue reports whether the advice is a new value for one of
// the Request* attributes and nothing else. A memory recommendation that
// comes with a retry_request_memory does not qualify: the retry is set
// up by condor_submit as an on-evict transform, which cannot be added to
// a job already in the queue, and the lower request without its retry
// would hold the jobs it was sized to retry.
func (a Advice) appliesToQueue() bool {
	if a.request <= 0 || a.changes == "" {
		return false
	}
	return a.ID != "memory-retry"
}

// RequestChange is the Request* attribute an advice changes and its new
// value, in the attribute's own units; ok is false for advice that does
// not apply to queued jobs (see Applies).
func (a Advice) RequestChange() (attr string, value float64, ok bool) {
	if !a.appliesToQueue() {
		return "", 0, false
	}
	switch a.changes {
	case changesMemory:
		return "RequestMemory", a.request, true
	case changesCpus:
		return "RequestCpus", a.request, true
	case changesDisk:
		return "RequestDisk", a.request, true
	case changesGPUs:
		return "RequestGPUs", a.request, true
	}
	return "", 0, false
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

func savesGPU(a Advice) int {
	if a.Saves != nil && a.Saves.Unit == UnitGPUHours {
		return 1
	}
	return 0
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
		request:    plan.recommended,
		changes:    changesMemory,
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
	if plan.adaptiveJobs*2 > plan.n {
		// The jobs' request is a formula that starts small and grows
		// after a hold; say so, since "most jobs requested X" would be
		// wrong about every job that grew.
		evidence = fmt.Sprintf("Your request starts at %s and grows after a memory hold; %s of %s jobs outgrew the start and were held once. %s",
			sizeMiB(plan.typical), count(plan.outgrewStart), count(plan.n), evidence)
	}
	retryNote := ""
	if hasRetry {
		retryNote = fmt.Sprintf(" With the retry, about %s of jobs would run a second time with more memory.", percent(plan.retryFraction))
	}
	title := "Request " + submitSize(plan.recommended) + " of memory"
	if hasRetry {
		title += " and retry at " + submitSize(plan.retry)
	}

	switch {
	case holds > 0 || plan.exceeded > 0 || plan.maxPeak > plan.typical:
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
		a.request = 0
		// Every job fits the current request (the case above catches any
		// that did not), so it is what the curve marks: a page showing
		// "fits" beside a different recommended point contradicts itself.
		plan.keepCurrent()
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
			if _, ok := j.coresUsed(); ok && j.RequestCpus.OK() && j.RequestCpus.V() > rec {
				saved += (j.RequestCpus.V() - rec) * hours(j.Wall)
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
			request:    rec,
			changes:    changesCpus,
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
			request:    rec,
			changes:    changesCpus,
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
		case j.HeldForDisk && j.RequestDisk.OK():
			largest = math.Max(largest, math.Max(orZero(j.DiskUsage), j.RequestDisk.V()))
			n++
		case j.Status == statusCompleted && j.DiskUsage.OK():
			largest = math.Max(largest, j.DiskUsage.V())
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
			request:    rec,
			changes:    changesDisk,
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
			request:    rec,
			changes:    changesDisk,
		}
	}
	return nil
}

// gpuAdvice is advice about the GPUs a workflow reserved. prior is the
// advice already given, so the GPU advice does not repeat a CPU change.
//
// Utilization-based advice needs utilization, which many jobs do not
// have (see GPUStats); the GPU-memory requirement check does not.
func gpuAdvice(w *Workflow, jobs []*Job, prior []Advice) []Advice {
	g := w.GPU
	if g == nil {
		return nil
	}
	var out []Advice
	memNote := ""
	if g.MemoryPeakMiB != nil && g.MemoryPeakMiB.Max > 0 {
		memNote = fmt.Sprintf(" The most GPU memory any job used was %s.", sizeMiB(g.MemoryPeakMiB.Max))
	}

	if g.Utilization != nil && g.Utilization.N >= minAdviceJobs {
		util := g.Utilization
		var busy []float64
		idle, reserved := 0, 0.0
		for _, j := range jobs {
			u, ok := j.GPUUtilization()
			if !ok {
				continue
			}
			if u < gpuUnusedLevel {
				idle++
			}
			reserved += j.RequestGPUs.V() * hours(j.Wall)
			busy = append(busy, j.GPUsAverageUsage.V())
		}
		slices.Sort(busy)

		if float64(idle) >= gpuUnusedShare*float64(util.N) {
			out = append(out, Advice{
				ID:       "gpu-unused",
				Resource: ResourceGPU,
				Severity: SeverityWarn,
				Title:    "Check whether these jobs use their GPUs",
				Detail: fmt.Sprintf("%s of %s jobs kept their GPUs busy less than 1%% of the time.%s If the program does not use a GPU, removing request_gpus lets the jobs run on far more machines.",
					count(idle), count(util.N), memNote),
				Submit:     []string{},
				Saves:      &Savings{Unit: UnitGPUHours, Amount: round(reserved, 1)},
				Confidence: confidence(util.N),
			})
			return append(out, gpuMemoryAdvice(g, jobs)...)
		}

		explained := false
		if a := gpusLowerAdvice(g, jobs, busy); a != nil {
			out = append(out, *a)
			explained = true
		}
		if a := gpuCPUBoundAdvice(w, prior); a != nil {
			out = append(out, *a)
			explained = true
		}
		if !explained && util.P50 < gpuIdleMedian {
			out = append(out, Advice{
				ID:       "gpu-idle",
				Resource: ResourceGPU,
				Severity: SeveritySuggest,
				Title:    "Keep the GPU busier",
				Detail: fmt.Sprintf("Half of %s jobs kept their GPUs busy %s of the time or less.%s The GPU is usually waiting on input, on the CPU, or on code that has not been moved to it.",
					count(util.N), percent(util.P50), memNote),
				Submit:     []string{},
				Confidence: confidence(util.N),
			})
		}
	}
	return append(out, gpuMemoryAdvice(g, jobs)...)
}

// gpusLowerAdvice: jobs that ask for several GPUs and keep about one of
// them busy. GPUsAverageUsage sums over a job's GPUs, so it reads
// directly as "GPUs kept busy"; the advice is the 90th percentile of that,
// rounded up, with a little slack so 1.02 busy is still one GPU.
func gpusLowerAdvice(g *GPUStats, jobs []*Job, busy []float64) *Advice {
	if g.Request == nil || g.Request.Typical <= 1 || len(busy) == 0 {
		return nil
	}
	p90 := percentile(busy, 90)
	rec := math.Max(1, math.Ceil(p90-gpuBusySlack))
	if rec >= g.Request.Typical {
		return nil
	}
	saved := 0.0
	for _, j := range jobs {
		if _, ok := j.GPUUtilization(); ok && j.RequestGPUs.V() > rec {
			saved += (j.RequestGPUs.V() - rec) * hours(j.Wall)
		}
	}
	return &Advice{
		ID:       "gpus-lower",
		Resource: ResourceGPU,
		Severity: SeveritySuggest,
		Title:    fmt.Sprintf("Request %s %s", number(rec), plural(rec, "GPU", "GPUs")),
		Detail: fmt.Sprintf("90%% of %s jobs kept %s or fewer GPUs busy of the %s requested.",
			count(len(busy)), number(round(p90, 1)), number(g.Request.Typical)),
		Submit:     []string{"request_gpus = " + number(rec)},
		Saves:      &Savings{Unit: UnitGPUHours, Amount: round(saved, 1)},
		Confidence: confidence(len(busy)),
		request:    rec,
		changes:    changesGPUs,
	}
}

// gpuCPUBoundAdvice: the GPU waits while the job's CPUs are flat out.
// A GPU is only as busy as the cores preparing its work; when the job
// keeps every core it asked for busy and the GPU mostly idle, more cores
// is the cheap fix. Not given when the CPU advice already raises cores.
func gpuCPUBoundAdvice(w *Workflow, prior []Advice) *Advice {
	g := w.GPU
	if g.Utilization == nil || g.Utilization.P50 >= gpuCPUBoundUtil || g.CoresUsedWhileGPU == nil ||
		g.CoresUsedWhileGPU.N < minAdviceJobs || w.CPU.Request == nil || w.CPU.Request.Typical <= 0 {
		return nil
	}
	requested := w.CPU.Request.Typical
	if g.CoresUsedWhileGPU.P50 < cpuSaturated*requested {
		return nil
	}
	for _, a := range prior {
		if a.ID == "cpus-raise" {
			return nil
		}
	}
	rec := math.Max(requested+1, requested*2)
	return &Advice{
		ID:       "gpu-cpu-bound",
		Resource: ResourceGPU,
		Severity: SeveritySuggest,
		Title:    fmt.Sprintf("Request %s CPUs to keep the GPU busy", number(rec)),
		Detail: fmt.Sprintf("Half of %s jobs kept their GPUs busy %s of the time or less while using %s of the %s CPU cores they requested, so the GPU is likely waiting on the CPU.",
			count(g.Utilization.N), percent(g.Utilization.P50), number(round(g.CoresUsedWhileGPU.P50, 1)), number(requested)),
		Submit:     []string{"request_cpus = " + number(rec)},
		Confidence: confidence(g.CoresUsedWhileGPU.N),
		request:    rec,
		changes:    changesCpus,
	}
}

// gpuMemoryAdvice: jobs that require GPUs with more memory than they use.
// Only a requirement the jobs actually state counts -- gpus_minimum_memory
// (GPUsMinMemory) -- since that is the line to change; the GPU a job
// merely happened to land on says nothing about what it needed.
func gpuMemoryAdvice(g *GPUStats, jobs []*Job) []Advice {
	if g.MemoryPeakMiB == nil || g.MemoryPeakMiB.N < minAdviceJobs {
		return nil
	}
	var mins []float64
	for _, j := range jobs {
		if j.RequestGPUs.OK() && j.RequestGPUs.V() > 0 && j.GPUsMinMemory.OK() {
			mins = append(mins, j.GPUsMinMemory.V())
		}
	}
	required := summarizeRequest(mins)
	if required == nil {
		return nil
	}
	rec := niceMiB(g.MemoryPeakMiB.Max * gpuMemoryHeadroom)
	if rec >= required.Typical {
		return nil
	}
	return []Advice{{
		ID:       "gpu-memory-small",
		Resource: ResourceGPU,
		Severity: SeveritySuggest,
		Title:    "Require GPUs with " + submitSize(rec) + " of memory",
		Detail: fmt.Sprintf("These jobs require GPUs with at least %s of memory; the most any of %s jobs used was %s. A lower requirement lets them run on more GPUs.",
			sizeMiB(required.Typical), count(g.MemoryPeakMiB.N), sizeMiB(g.MemoryPeakMiB.Max)),
		Submit:     []string{"gpus_minimum_memory = " + submitSize(rec)},
		Confidence: confidence(g.MemoryPeakMiB.N),
	}}
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
