package utilization

import (
	"cmp"
	"math"
	"slices"

	"github.com/PelicanPlatform/classad/classad"
)

// Throughput: how many more of these jobs could run at once with the
// suggested requests.
//
// A request is a reservation, so its size decides how many copies of a
// job fit on the pool's machines at once. An 8 GB request on a machine
// with 16 GB and four cores fits twice, leaving two cores idle; at 1 GB
// the same machine fits four. Over the same work, the smaller request
// occupies the pool for half as long, which is the gain.
//
// This is an UP-TO estimate, and deliberately so. It counts what fits on
// an empty pool; a real pool is shared, and how much of it one user gets
// is decided by fair share, which by default charges a slot by its cores
// (SLOT_WEIGHT = Cpus). A memory-only change therefore does not change
// what a user's share buys; it changes how much of the pool their jobs
// CAN use when the share is not the limit -- which is the case worth
// knowing about when jobs sit idle waiting for a slot big enough. The
// wait figures are there so the page can tell those cases apart.

// Machine is the capacity of one execute slot that holds jobs: the whole
// of a partitionable slot, or a static slot.
type Machine struct {
	Cpus      float64
	MemoryMiB float64
	DiskKiB   float64
	GPUs      float64
}

// MachineProjection is every startd attribute MachineFromAd reads.
func MachineProjection() []string {
	return []string{
		"Name", "SlotType", "PartitionableSlot", "DynamicSlot", "BackfillSlot", "State",
		"Cpus", "Memory", "Disk", "GPUs",
		"TotalSlotCpus", "TotalSlotMemory", "TotalSlotDisk", "TotalSlotGPUs",
	}
}

// MachineFromAd reads a startd slot ad. ok is false for a slot that adds
// no capacity of its own: a dynamic slot is carved out of a partitionable
// slot that is already counted at its full size, and a backfill slot
// re-advertises cores another slot owns.
//
// A partitionable slot's size is TotalSlot*, not Cpus/Memory, which shrink
// as dynamic slots are carved off: the question is what the machine could
// hold, not what it has free this minute.
func MachineFromAd(ad *classad.ClassAd) (Machine, bool) {
	slotType, _ := ad.EvaluateAttrString("SlotType")
	state, _ := ad.EvaluateAttrString("State")
	dynamic, _ := ad.EvaluateAttrBool("DynamicSlot")
	backfill, _ := ad.EvaluateAttrBool("BackfillSlot")
	if dynamic || slotType == "Dynamic" || backfill || state == "Backfill" {
		return Machine{}, false
	}
	partitionable, _ := ad.EvaluateAttrBool("PartitionableSlot")
	partitionable = partitionable || slotType == "Partitionable"
	get := func(total, static string) float64 {
		if partitionable {
			if v, ok := ad.EvaluateAttrNumber(total); ok {
				return v
			}
		}
		return orZero(numAttr(ad, static))
	}
	m := Machine{
		Cpus:      get("TotalSlotCpus", "Cpus"),
		MemoryMiB: get("TotalSlotMemory", "Memory"),
		DiskKiB:   get("TotalSlotDisk", "Disk"),
		GPUs:      get("TotalSlotGPUs", "GPUs"),
	}
	if m.Cpus <= 0 || m.MemoryMiB <= 0 {
		return Machine{}, false
	}
	return m, true
}

// fitOne is how many copies of shape fit on one machine, and which
// resource runs out first. Only what the shape asks for counts: a job
// that requests no GPU is not limited by a machine having none.
func fitOne(m Machine, s Shape) (int, string) {
	least, by := math.Inf(1), ""
	consider := func(name string, capacity, request float64) {
		if request <= 0 {
			return
		}
		if n := capacity / request; n < least {
			least, by = n, name
		}
	}
	consider(ResourceCPU, m.Cpus, s.Cpus)
	consider(ResourceMemory, m.MemoryMiB, s.MemoryMiB)
	consider(ResourceDisk, m.DiskKiB, s.DiskKiB)
	if s.GPUs > 0 {
		consider(ResourceGPU, m.GPUs, s.GPUs)
	}
	if by == "" {
		return 0, ""
	}
	return int(math.Floor(least + 1e-9)), by
}

// fit is how many copies of shape the pool holds at once, and the
// resource that runs out first on the most machines. A GPU shape counts
// only machines with GPUs.
func fit(machines []Machine, s Shape) (int, string) {
	total := 0
	limits := map[string]int{}
	for _, m := range machines {
		if s.GPUs > 0 && m.GPUs <= 0 {
			continue
		}
		n, by := fitOne(m, s)
		total += n
		if by != "" {
			limits[by]++
		}
	}
	limitedBy, most := "", 0
	for _, r := range []string{ResourceCPU, ResourceMemory, ResourceDisk, ResourceGPU} {
		if limits[r] > most {
			limitedBy, most = r, limits[r]
		}
	}
	return total, limitedBy
}

// slotsLimitedWait is the median wait to start beyond which a workflow
// is taken to have been waiting for slots.
const slotsLimitedWait = 900

// minLastBatchJobs is the smallest batch the time estimate is made for;
// a handful of jobs finishes when its slowest job does.
const minLastBatchJobs = 20

// occupancyPair is a workflow's pool occupancy -- wall hours divided by
// how many copies fit -- at the current and the suggested requests.
type occupancyPair struct{ current, suggested float64 }

// workflowThroughput estimates the throughput gain of a workflow's
// advice. It also returns the workflow's occupancy for the overall
// figure, which counts workflows the advice leaves alone at the same
// occupancy on both sides.
func workflowThroughput(w *Workflow, jobs []*Job, plan *memoryPlan, memJobs []memoryJob, machines []Machine) (*Throughput, occupancyPair) {
	if len(machines) == 0 || w.Memory.Request == nil {
		return nil, occupancyPair{}
	}
	current := Shape{
		Cpus:      typicalOr(w.CPU.Request, 1),
		MemoryMiB: w.Memory.Request.Typical,
		DiskKiB:   typicalOr(w.Disk.Request, 0),
	}
	if w.GPU != nil {
		current.GPUs = typicalOr(w.GPU.Request, 0)
	}
	fitCurrent, limitedBy := fit(machines, current)
	if fitCurrent == 0 {
		// Nothing in the pool holds these jobs as they are; there is no
		// ratio to report, and nothing for this workflow to add.
		return nil, occupancyPair{}
	}

	// The same jobs and walls the memory sizing used, so the gain and the
	// memory curve describe the same work. Without a memory plan, every
	// job's wall clock, for the overall figure only.
	var walls []float64
	if plan != nil {
		for _, j := range memJobs {
			walls = append(walls, j.wallHours)
		}
	} else {
		for _, j := range jobs {
			walls = append(walls, hours(j.Wall))
		}
	}
	occCurrent := 0.0
	for _, wh := range walls {
		occCurrent += wh / float64(fitCurrent)
	}
	unchanged := occupancyPair{occCurrent, occCurrent}
	if plan == nil {
		return nil, unchanged
	}

	suggested := current
	for _, a := range w.Advice {
		if a.request <= 0 {
			continue
		}
		switch a.Resource {
		case ResourceMemory:
			suggested.MemoryMiB = a.request
		case ResourceCPU:
			suggested.Cpus = a.request
		case ResourceDisk:
			suggested.DiskKiB = a.request
		}
	}
	retry := plan.retry
	if suggested == current && retry == 0 {
		return nil, unchanged
	}
	fitSuggested, _ := fit(machines, suggested)
	if fitSuggested == 0 {
		return nil, unchanged
	}
	retryShape := suggested
	retryShape.MemoryMiB = retry
	fitRetry := 0
	if retry > 0 {
		if fitRetry, _ = fit(machines, retryShape); fitRetry == 0 {
			return nil, unchanged
		}
	}

	// A job that outgrows the suggested memory runs twice: once at the
	// suggested request until it is stopped, and again at the retry. The
	// first run is charged its full wall clock, as the memory curve does
	// (see expectedCost) -- memory tends to peak at the end, so the job
	// is stopped late.
	occSuggested := 0.0
	for _, j := range memJobs {
		occSuggested += j.wallHours / float64(fitSuggested)
		if retry > 0 && j.outgrows(suggested.MemoryMiB) {
			occSuggested += j.wallHours / float64(fitRetry)
		}
	}
	if occSuggested <= 0 || occCurrent <= 0 {
		return nil, unchanged
	}
	gain := occCurrent / occSuggested

	t := &Throughput{
		Current:      current,
		Suggested:    suggested,
		FitCurrent:   fitCurrent,
		FitSuggested: fitSuggested,
		Gain:         round(gain, 3),
		LimitedBy:    limitedBy,
		LastBatch:    lastBatch(jobs, gain),
	}
	if retry > 0 {
		t.RetryMemoryMiB = ptr(retry, 0)
	}
	t.WaitP50 = medianWait(jobs)
	t.SlotsLimited = t.WaitP50 >= slotsLimitedWait
	return t, occupancyPair{occCurrent, occSuggested}
}

func typicalOr(r *Request, def float64) float64 {
	if r == nil || r.Typical <= 0 {
		return def
	}
	return r.Typical
}

// medianWait is the median seconds from submission to first start over
// the completed jobs that record both.
func medianWait(jobs []*Job) float64 {
	var waits []float64
	for _, j := range jobs {
		if j.Status != statusCompleted || j.FirstStart <= 0 || j.QDate <= 0 || j.FirstStart < j.QDate {
			continue
		}
		waits = append(waits, float64(j.FirstStart-j.QDate))
	}
	if len(waits) == 0 {
		return 0
	}
	slices.Sort(waits)
	return percentile(waits, 50)
}

// lastBatch turns the gain into time for the most recently submitted
// batch of at least minLastBatchJobs jobs.
//
// The estimate divides the batch's elapsed time by the gain, but a batch
// can never finish before its longest job does, however many of its jobs
// run at once -- so that is the floor.
func lastBatch(jobs []*Job, gain float64) *LastBatch {
	type batch struct {
		id                 int64
		jobs               int
		first, end         int64
		longest            float64
		hasFirst, hasEnded bool
	}
	byID := map[int64]*batch{}
	for _, j := range jobs {
		id := batchOf(j)
		b := byID[id]
		if b == nil {
			b = &batch{id: id}
			byID[id] = b
		}
		b.jobs++
		if j.QDate > 0 && (!b.hasFirst || j.QDate < b.first) {
			b.first, b.hasFirst = j.QDate, true
		}
		end := j.Completion
		if end <= 0 {
			end = j.Entered
		}
		if end > 0 && (!b.hasEnded || end > b.end) {
			b.end, b.hasEnded = end, true
		}
		b.longest = math.Max(b.longest, j.Wall)
	}
	var latest *batch
	for _, b := range byID {
		if b.jobs < minLastBatchJobs || !b.hasFirst || !b.hasEnded || b.end <= b.first {
			continue
		}
		if latest == nil || cmp.Or(cmp.Compare(b.first, latest.first), cmp.Compare(b.id, latest.id)) > 0 {
			latest = b
		}
	}
	if latest == nil || gain <= 0 {
		return nil
	}
	elapsed := float64(latest.end - latest.first)
	return &LastBatch{
		ID:        latest.id,
		Jobs:      latest.jobs,
		Elapsed:   elapsed,
		Estimated: math.Round(math.Max(latest.longest, elapsed/gain)),
	}
}
