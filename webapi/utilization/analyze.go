package utilization

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
)

// Options describes the window the jobs were read over and how the
// result will be shown.
type Options struct {
	Since, Until int64
	Days         int
	// Truncated says the read hit its cap.
	Truncated bool
	// ShowOwner names each workflow's owner, and lists the owners, for a
	// scope that covers more than one person's jobs.
	ShowOwner bool
	// Limit and MaxLimit are reported back as given.
	Limit, MaxLimit int
	// Machines is the pool's execute capacity, for the throughput
	// estimate; nil when it is not known.
	Machines []Machine
}

// Output bounds per workflow.
const (
	maxSamples = 400
	maxBatches = 50
)

// shortJobWall is the wall clock below which a job is "short": it spends
// a noticeable share of its life being scheduled and moving files rather
// than computing.
const shortJobWall = 600

// Thresholds for runtime advice.
const (
	minShortJobsAdvice = 100
	restartLossShare   = 0.10
)

// Analyze turns finished jobs into the utilization answer. Jobs that are
// not finished, or that reserve nothing on an execute point, are ignored
// -- see Job.finished and Job.reservesNothing.
func Analyze(jobs []Job, opts Options) *Response {
	return AnalyzeChunks([][]Job{jobs}, opts)
}

// AnalyzeChunks is Analyze over jobs held in several slices -- a
// Decoder's, one per worker -- without first copying them into one.
func AnalyzeChunks(chunks [][]Job, opts Options) *Response {
	resp := &Response{
		Since:     opts.Since,
		Until:     opts.Until,
		Days:      opts.Days,
		Truncated: opts.Truncated,
		Limit:     opts.Limit,
		MaxLimit:  opts.MaxLimit,
		Workflows: []Workflow{},
		Overall:   Overall{Resources: []ResourceSummary{}},
	}

	// Keyed on the identity tuple itself; the opaque key is hashed once
	// per workflow rather than once per job.
	groups := map[identity]*group{}
	var all []*Job
	for _, jobs := range chunks {
		for i := range jobs {
			j := &jobs[i]
			if !j.finished() || j.reservesNothing() {
				continue
			}
			all = append(all, j)
			id, isDAG := identify(j)
			g := groups[id]
			if g == nil {
				g = &group{id: id, key: id.hash()}
				groups[id] = g
			}
			g.jobs = append(g.jobs, j)
			g.isDAG = g.isDAG || isDAG
		}
	}

	resp.JobsConsidered = len(all)
	resp.Overall.Jobs = len(all)
	for _, j := range all {
		resp.Overall.WallHours += hours(j.Wall)
		resp.Overall.BadputHours += hours(badput(j))
	}
	resp.Overall.WallHours = round(resp.Overall.WallHours, 3)
	resp.Overall.BadputHours = round(resp.Overall.BadputHours, 3)
	resp.Overall.Resources = resourceSummaries(all)
	if opts.ShowOwner {
		resp.Owners = ownerSummaries(all)
	}

	var occCurrent, occSuggested float64
	anyThroughput := false
	for _, g := range groups {
		w, occ := buildWorkflow(g, opts)
		resp.Workflows = append(resp.Workflows, w)
		occCurrent += occ.current
		occSuggested += occ.suggested
		anyThroughput = anyThroughput || w.Throughput != nil
	}
	if anyThroughput && occSuggested > 0 {
		resp.Overall.ThroughputGain = ptr(occCurrent/occSuggested, 3)
	}
	slices.SortFunc(resp.Workflows, func(a, b Workflow) int {
		if c := cmp.Compare(b.WallHours, a.WallHours); c != 0 {
			return c
		}
		if c := cmp.Compare(b.Jobs, a.Jobs); c != 0 {
			return c
		}
		return strings.Compare(a.Key, b.Key)
	})
	return resp
}

// ownerSummaries is each owner's jobs and wall clock, most wall first.
func ownerSummaries(jobs []*Job) []OwnerSummary {
	index := map[string]int{}
	out := []OwnerSummary{}
	for _, j := range jobs {
		k, ok := index[j.Owner]
		if !ok {
			k = len(out)
			index[j.Owner] = k
			out = append(out, OwnerSummary{Owner: j.Owner})
		}
		out[k].Jobs++
		out[k].WallHours += hours(j.Wall)
	}
	for i := range out {
		out[i].WallHours = round(out[i].WallHours, 3)
	}
	slices.SortFunc(out, func(a, b OwnerSummary) int {
		if c := cmp.Compare(b.WallHours, a.WallHours); c != 0 {
			return c
		}
		return strings.Compare(a.Owner, b.Owner)
	})
	return out
}

// group is one workflow's jobs.
type group struct {
	id    identity
	key   string
	isDAG bool
	jobs  []*Job
}

// identity is what makes two jobs the same workflow.
type identity struct {
	name, exe, owner, schedd string
}

// hash is the workflow's opaque, stable key.
func (id identity) hash() string {
	sum := sha256.Sum256([]byte(id.owner + "\x00" + id.name + "\x00" + id.exe + "\x00" + id.schedd))
	return hex.EncodeToString(sum[:6])
}

// dagSuffix splits what DAGMan appends to a node's JobBatchName: "+" and
// the root DAG's cluster id. condor_submit_dag names the batch after the
// DAG file and this suffix, so without stripping it every run of the
// same DAG would be a different workflow.
func dagSuffix(batch string) (name string, root int64, ok bool) {
	i := strings.LastIndexByte(batch, '+')
	if i < 0 || i == len(batch)-1 {
		return batch, 0, false
	}
	n, err := strconv.ParseInt(batch[i+1:], 10, 64)
	if err != nil || n < 0 {
		return batch, 0, false
	}
	return batch[:i], n, true
}

// identify works out which workflow a job belongs to.
//
// The key is (owner, name, program, access point), where program is what
// the job runs (see Program) and name is the
// batch name with a DAG run's suffix removed, or the executable when the
// job has no batch name. Advice is about the next submission, so the unit
// is what gets resubmitted: the same script submitted daily as a fresh
// cluster is one workflow, and a DAG whose nodes run three executables is
// three, because each node type has its own profile and its own submit
// file to change.
func identify(j *Job) (id identity, isDAG bool) {
	id = identity{exe: j.Program, owner: j.Owner, schedd: j.Schedd}
	if id.exe == "" {
		// A Job built without reading an ad: derive it from Cmd alone.
		id.exe = Program(j.Cmd, "")
	}
	if id.exe == "" {
		id.exe = "(unknown)"
	}
	name, _, suffixed := dagSuffix(j.BatchName)
	id.name = name
	isDAG = suffixed || j.DAGManJobID > 0
	if id.name == "" {
		id.name = id.exe
	}
	return id, isDAG
}

// batchOf is the submission a job belongs to: its cluster, or for a DAG
// node the root DAG's cluster, which DAGMan writes into the batch-name
// suffix. A DAG submitted with its own batch name has no suffix; its
// nodes are grouped by the DAGMan job that ran them.
func batchOf(j *Job) int64 {
	if _, root, ok := dagSuffix(j.BatchName); ok {
		return root
	}
	if j.DAGManJobID > 0 {
		return j.DAGManJobID
	}
	return j.Cluster
}

func hours(seconds float64) float64 { return seconds / 3600 }

// badput is the wall clock that produced nothing kept: all of a failed or
// removed job, and the evicted runs of a successful one.
func badput(j *Job) float64 {
	if !j.succeeded() {
		return j.Wall
	}
	return lostToRestarts(j)
}

// lostToRestarts is wall clock spent on runs that were thrown away.
// CommittedTime is the wall clock of runs that counted, so the rest was
// evicted without a checkpoint.
func lostToRestarts(j *Job) float64 {
	if !j.CommittedTime.OK() {
		return 0
	}
	lost := j.Wall - j.CommittedTime.V()
	if lost < 1 {
		return 0
	}
	return lost
}

// resourceSummaries is the time-weighted reserved-versus-used figure for
// each resource. GPU appears only when some job asked for one.
func resourceSummaries(jobs []*Job) []ResourceSummary {
	type acc struct {
		alloc, used, allocMeasured float64
		measured                   int
	}
	var cpu, mem, disk, gpu acc
	anyGPU := false
	for _, j := range jobs {
		wh := hours(j.Wall)
		if j.RequestCpus.OK() {
			cpu.alloc += j.RequestCpus.V() * wh
			if c, ok := j.coresUsed(); ok {
				cpu.used += c * wh
				cpu.allocMeasured += j.RequestCpus.V() * wh
				cpu.measured++
			}
		}
		if j.RequestMemory.OK() {
			mem.alloc += j.RequestMemory.V() * wh
			if j.MemoryUsage.OK() {
				mem.used += j.MemoryUsage.V() * wh
				mem.allocMeasured += j.RequestMemory.V() * wh
				mem.measured++
			}
		}
		if j.RequestDisk.OK() {
			disk.alloc += j.RequestDisk.V() * wh
			if j.DiskUsage.OK() {
				disk.used += j.DiskUsage.V() * wh
				disk.allocMeasured += j.RequestDisk.V() * wh
				disk.measured++
			}
		}
		if j.RequestGPUs.OK() && j.RequestGPUs.V() > 0 {
			anyGPU = true
			gpu.alloc += j.RequestGPUs.V() * wh
			if _, ok := j.GPUUtilization(); ok {
				gpu.used += j.GPUsAverageUsage.V() * wh
				gpu.allocMeasured += j.RequestGPUs.V() * wh
				gpu.measured++
			}
		}
	}
	summary := func(name string, a acc) ResourceSummary {
		s := ResourceSummary{
			Resource:               name,
			AllocatedHours:         round(a.alloc, 3),
			AllocatedHoursMeasured: round(a.allocMeasured, 3),
			JobsMeasured:           a.measured,
		}
		if a.measured > 0 {
			s.UsedHours = ptr(a.used, 3)
		}
		return s
	}
	out := []ResourceSummary{
		summary(ResourceCPU, cpu),
		summary(ResourceMemory, mem),
		summary(ResourceDisk, disk),
	}
	if anyGPU {
		out = append(out, summary(ResourceGPU, gpu))
	}
	return out
}

// buildWorkflow analyses one workflow's jobs. It also returns the pool
// occupancy of its work, for the overall throughput figure.
func buildWorkflow(g *group, opts Options) (Workflow, occupancyPair) {
	// A stable order, so samples and batches do not reshuffle between
	// two reads of the same history.
	slices.SortFunc(g.jobs, func(a, b *Job) int {
		if c := cmp.Compare(a.QDate, b.QDate); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Cluster, b.Cluster); c != 0 {
			return c
		}
		return cmp.Compare(a.Proc, b.Proc)
	})

	w := Workflow{
		Key:        g.key,
		Name:       g.id.name,
		Executable: g.id.exe,
		Schedd:     g.id.schedd,
		IsDAG:      g.isDAG,
		Jobs:       len(g.jobs),
		Resources:  resourceSummaries(g.jobs),
	}
	if opts.ShowOwner {
		w.Owner = g.id.owner
	}

	// Sized for the workflow up front: at a million jobs, growing a dozen
	// slices by doubling is most of the garbage an analysis makes.
	n := len(g.jobs)
	walls, memReq, peaks := make([]float64, 0, n), make([]float64, 0, n), make([]float64, 0, n)
	cpuReq, cores, eff := make([]float64, 0, n), make([]float64, 0, n), make([]float64, 0, n)
	diskReq, diskUsed := make([]float64, 0, n), make([]float64, 0, n)
	memJobs := make([]memoryJob, 0, n)
	var restartLost float64
	for _, j := range g.jobs {
		w.WallHours += hours(j.Wall)
		switch {
		case j.Status == statusRemoved:
			w.Removed++
		case j.succeeded():
			w.Succeeded++
		default:
			w.Failed++
		}
		if j.HeldForMemory {
			w.Holds.Memory++
		}
		if j.HeldForDisk {
			w.Holds.Disk++
		}
		if j.Status == statusCompleted {
			walls = append(walls, j.Wall)
			if j.Wall < shortJobWall {
				w.ShortJobs++
			}
			if lost := lostToRestarts(j); lost > 0 || (!j.CommittedTime.OK() && j.NumJobStarts > 1) {
				w.Restarts.Jobs++
				restartLost += lost
			}
		}

		if start := j.startMemory(); start.OK() {
			memReq = append(memReq, start.V())
		}
		if mj, ok := memorySample(j); ok {
			memJobs = append(memJobs, mj)
			peaks = append(peaks, mj.peak)
		}
		if j.RequestCpus.OK() {
			cpuReq = append(cpuReq, j.RequestCpus.V())
		}
		if c, ok := j.coresUsed(); ok {
			cores = append(cores, c)
			if j.RequestCpus.OK() && j.RequestCpus.V() > 0 {
				eff = append(eff, c/j.RequestCpus.V())
			}
		}
		if start := j.startDisk(); start.OK() {
			diskReq = append(diskReq, start.V())
		}
		if j.DiskUsage.OK() {
			diskUsed = append(diskUsed, j.DiskUsage.V())
		}
	}
	w.WallHours = round(w.WallHours, 3)
	w.Restarts.LostHours = round(hours(restartLost), 3)
	w.Wall = distribution(walls)
	w.Memory = MemoryStats{Request: summarizeRequest(memReq), PeakMiB: distribution(peaks)}
	w.CPU = CPUStats{Request: summarizeRequest(cpuReq), CoresUsed: distribution(cores), Efficiency: distribution(eff)}
	w.Disk = DiskStats{Request: summarizeRequest(diskReq), UsedKiB: distribution(diskUsed)}
	markAdaptive(w.Memory.Request, g.jobs, AdaptiveMemory)
	markAdaptive(w.CPU.Request, g.jobs, AdaptiveCpus)
	markAdaptive(w.Disk.Request, g.jobs, AdaptiveDisk)
	w.GPU = gpuStats(g.jobs)

	plan := planMemory(memJobs)
	w.MemoryCurve = []MemoryCurvePoint{}
	if plan != nil {
		w.MemoryCurve = plan.curve
	}
	w.Advice = adviseWorkflow(&w, g.jobs, plan, walls)
	w.Batches = batches(g)
	w.Samples = samples(g.jobs)
	var occ occupancyPair
	w.Throughput, occ = workflowThroughput(&w, g.jobs, plan, memJobs, opts.Machines)
	return w, occ
}

// markAdaptive flags a request summary as adaptive when most of the jobs
// behind it wrote that request as a formula, and names the formula.
func markAdaptive(r *Request, jobs []*Job, bit uint8) {
	if r == nil {
		return
	}
	adaptive, total := 0, 0
	formulas := map[string]int{}
	for _, j := range jobs {
		total++
		if j.isAdaptive(bit) {
			adaptive++
			if bit == AdaptiveMemory && j.MemoryFormula != "" {
				formulas[j.MemoryFormula]++
			}
		}
	}
	r.Adaptive = adaptive*2 > total
	if !r.Adaptive {
		return
	}
	best := 0
	for f, n := range formulas {
		if n > best || (n == best && f < r.Expression) {
			r.Expression, best = f, n
		}
	}
}

// gpuStats summarizes the jobs that requested GPUs; nil when none did.
func gpuStats(jobs []*Job) *GPUStats {
	var req, util, mem, device, cores []float64
	for _, j := range jobs {
		if !j.RequestGPUs.OK() || j.RequestGPUs.V() <= 0 {
			continue
		}
		req = append(req, j.RequestGPUs.V())
		if u, ok := j.GPUUtilization(); ok {
			util = append(util, u)
		}
		if j.GPUsMemoryUsage.OK() {
			mem = append(mem, j.GPUsMemoryUsage.V())
		}
		if j.GPUDeviceMemory.OK() {
			device = append(device, j.GPUDeviceMemory.V())
		}
		if c, ok := j.coresUsed(); ok {
			cores = append(cores, c)
		}
	}
	if len(req) == 0 {
		return nil
	}
	g := &GPUStats{
		Request:           summarizeRequest(req),
		Jobs:              len(req),
		Measured:          len(util),
		Utilization:       distribution(util),
		MemoryPeakMiB:     distribution(mem),
		CoresUsedWhileGPU: distribution(cores),
	}
	if r := summarizeRequest(device); r != nil {
		g.DeviceMemoryMiB = ptr(r.Typical, 0)
	}
	return g
}

// memorySample is the job as memory sizing sees it, if it should see it
// at all.
//
// Only FINISHED jobs, and of those only the ones whose peak is the whole
// story. A completed job's MemoryUsage is its true peak. A removed job's
// is not -- it stopped early, before whatever its last minutes would have
// needed -- so it is left out, with one exception: a job stopped for
// outgrowing its request. That job's peak is not known either, but it is
// known to be AT LEAST the request it outgrew, and leaving it out would
// size the next submission from the jobs that happened to fit, which is
// exactly the mistake that got it stopped.
//
// An adaptive request is sized from where it starts: that is the request
// the user chose, and the one each job's first run held. Its value in
// force is what a rerun after a hold held (see planMemory).
func memorySample(j *Job) (memoryJob, bool) {
	start := j.startMemory()
	if !start.OK() || !j.RequestMemory.OK() {
		return memoryJob{}, false
	}
	mj := memoryJob{wallHours: hours(j.Wall), request: start.V(), inForce: j.RequestMemory.V(),
		adaptive: j.isAdaptive(AdaptiveMemory), held: j.HeldForMemory}
	switch {
	case j.Status == statusCompleted && j.MemoryUsage.OK():
		mj.peak = j.MemoryUsage.V()
	case j.Status == statusRemoved && j.ExceededMemory:
		mj.peak = max(orZero(j.MemoryUsage), start.V())
		mj.atLeast = true
	default:
		return memoryJob{}, false
	}
	return mj, true
}

// batches is one point per submission, the most recent maxBatches,
// oldest first.
func batches(g *group) []BatchPoint {
	// Which batches: only the most recent maxBatches are reported, so
	// their summaries are all that is computed. A workflow of a million
	// jobs in ten thousand clusters would otherwise build ten thousand
	// summaries to keep fifty.
	type seen struct {
		id        int64
		submitted int64
		jobs      int
	}
	index := map[int64]int{}
	var all []seen
	for _, j := range g.jobs {
		id := batchOf(j)
		k, ok := index[id]
		if !ok {
			k = len(all)
			index[id] = k
			all = append(all, seen{id: id, submitted: j.QDate})
		}
		b := &all[k]
		b.jobs++
		if j.QDate > 0 && (b.submitted <= 0 || j.QDate < b.submitted) {
			b.submitted = j.QDate
		}
	}
	slices.SortStableFunc(all, func(a, b seen) int {
		if c := cmp.Compare(a.submitted, b.submitted); c != 0 {
			return c
		}
		return cmp.Compare(a.id, b.id)
	})
	if len(all) > maxBatches {
		all = all[len(all)-maxBatches:]
	}
	keep := make(map[int64]int, len(all))
	members := make([][]*Job, len(all))
	for k, b := range all {
		keep[b.id] = k
		members[k] = make([]*Job, 0, b.jobs)
	}
	for _, j := range g.jobs {
		if k, ok := keep[batchOf(j)]; ok {
			members[k] = append(members[k], j)
		}
	}

	out := make([]BatchPoint, 0, len(all))
	for k, b := range all {
		jobs := members[k]
		p := BatchPoint{ID: b.id, Jobs: b.jobs, Submitted: b.submitted}
		var memReq, peaks, cpuReq, cores, gpuReq, gpuUtil []float64
		walls := make([]float64, 0, len(jobs))
		for _, j := range jobs {
			if start := j.startMemory(); start.OK() {
				memReq = append(memReq, start.V())
			}
			if mj, ok := memorySample(j); ok {
				peaks = append(peaks, mj.peak)
			}
			if j.RequestCpus.OK() {
				cpuReq = append(cpuReq, j.RequestCpus.V())
			}
			if c, ok := j.coresUsed(); ok {
				cores = append(cores, c)
			}
			walls = append(walls, j.Wall)
			if j.RequestGPUs.OK() && j.RequestGPUs.V() > 0 {
				gpuReq = append(gpuReq, j.RequestGPUs.V())
				if u, ok := j.GPUUtilization(); ok {
					gpuUtil = append(gpuUtil, u)
				}
			}
		}
		if r := summarizeRequest(gpuReq); r != nil {
			p.GPURequest = ptr(r.Typical, 3)
		}
		if len(gpuUtil) > 0 {
			slices.Sort(gpuUtil)
			p.GPUUtilP50 = ptr(percentile(gpuUtil, 50), 3)
		}
		if r := summarizeRequest(memReq); r != nil {
			p.MemoryRequestMiB = ptr(r.Typical, 3)
		}
		if len(peaks) > 0 {
			slices.Sort(peaks)
			p.MemoryP95MiB = ptr(percentile(peaks, 95), 3)
		}
		if r := summarizeRequest(cpuReq); r != nil {
			p.CPURequest = ptr(r.Typical, 3)
		}
		if len(cores) > 0 {
			slices.Sort(cores)
			p.CPUCoresP50 = ptr(percentile(cores, 50), 3)
		}
		slices.Sort(walls)
		p.WallP50 = ptr(percentile(walls, 50), 1)
		out = append(out, p)
	}
	return out
}

// samples picks at most maxSamples jobs, evenly spaced through the
// workflow's (submission-ordered) jobs. Deterministic, so the scatter
// plot does not change between two loads of the same history.
func samples(jobs []*Job) []Sample {
	n := len(jobs)
	k := min(n, maxSamples)
	out := make([]Sample, 0, k)
	for i := range k {
		j := jobs[i*n/k]
		s := Sample{Job: j.id(), Wall: round(j.Wall, 1), Outcome: j.outcome()}
		if j.MemoryUsage.OK() {
			s.MemoryMiB = ptr(j.MemoryUsage.V(), 1)
		}
		if c, ok := j.coresUsed(); ok {
			s.Cores = ptr(c, 3)
		}
		if j.DiskUsage.OK() {
			s.DiskKiB = ptr(j.DiskUsage.V(), 0)
		}
		out = append(out, s)
	}
	return out
}
