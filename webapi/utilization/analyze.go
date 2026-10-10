package utilization

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
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
	// ShowOwner names each workflow's owner, for a scope that covers
	// more than one person's jobs.
	ShowOwner bool
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
	resp := &Response{
		Since:     opts.Since,
		Until:     opts.Until,
		Days:      opts.Days,
		Truncated: opts.Truncated,
		Workflows: []Workflow{},
		Overall:   Overall{Resources: []ResourceSummary{}},
	}

	groups := map[string]*group{}
	var all []*Job
	for i := range jobs {
		j := &jobs[i]
		if !j.finished() || j.reservesNothing() {
			continue
		}
		all = append(all, j)
		id := identify(j)
		g := groups[id.key]
		if g == nil {
			g = &group{id: id}
			groups[id.key] = g
		}
		g.jobs = append(g.jobs, j)
		g.isDAG = g.isDAG || id.isDAG
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

	for _, g := range groups {
		resp.Workflows = append(resp.Workflows, buildWorkflow(g, opts))
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

// group is one workflow's jobs.
type group struct {
	id    identity
	isDAG bool
	jobs  []*Job
}

// identity is what makes two jobs the same workflow.
type identity struct {
	key, name, exe, owner, schedd string
	isDAG                         bool
}

// dagSuffix is what DAGMan appends to a node's JobBatchName: "+" and the
// root DAG's cluster id. condor_submit_dag names the batch after the DAG
// file and this suffix, so without stripping it every run of the same
// DAG would be a different workflow.
var dagSuffix = regexp.MustCompile(`\+(\d+)$`)

// identify works out which workflow a job belongs to.
//
// The key is (owner, name, executable, access point), where name is the
// batch name with a DAG run's suffix removed, or the executable when the
// job has no batch name. Advice is about the next submission, so the unit
// is what gets resubmitted: the same script submitted daily as a fresh
// cluster is one workflow, and a DAG whose nodes run three executables is
// three, because each node type has its own profile and its own submit
// file to change.
func identify(j *Job) identity {
	id := identity{exe: executableBase(j.Cmd), owner: j.Owner, schedd: j.Schedd}
	if id.exe == "" {
		id.exe = "(unknown)"
	}
	id.name = j.BatchName
	if m := dagSuffix.FindStringIndex(j.BatchName); m != nil {
		id.name = j.BatchName[:m[0]]
		id.isDAG = true
	}
	if j.DAGManJobID > 0 {
		id.isDAG = true
	}
	if id.name == "" {
		id.name = id.exe
	}
	sum := sha256.Sum256([]byte(id.owner + "\x00" + id.name + "\x00" + id.exe + "\x00" + id.schedd))
	id.key = hex.EncodeToString(sum[:6])
	return id
}

// batchOf is the submission a job belongs to: its cluster, or for a DAG
// node the root DAG's cluster, which DAGMan writes into the batch-name
// suffix. A DAG submitted with its own batch name has no suffix; its
// nodes are grouped by the DAGMan job that ran them.
func batchOf(j *Job) int64 {
	if m := dagSuffix.FindStringSubmatch(j.BatchName); m != nil {
		if root, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			return root
		}
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
	if j.CommittedTime == nil {
		return 0
	}
	lost := j.Wall - *j.CommittedTime
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
		if j.RequestCpus != nil {
			cpu.alloc += *j.RequestCpus * wh
			if c := j.coresUsed(); c != nil {
				cpu.used += *c * wh
				cpu.allocMeasured += *j.RequestCpus * wh
				cpu.measured++
			}
		}
		if j.RequestMemory != nil {
			mem.alloc += *j.RequestMemory * wh
			if j.MemoryUsage != nil {
				mem.used += *j.MemoryUsage * wh
				mem.allocMeasured += *j.RequestMemory * wh
				mem.measured++
			}
		}
		if j.RequestDisk != nil {
			disk.alloc += *j.RequestDisk * wh
			if j.DiskUsage != nil {
				disk.used += *j.DiskUsage * wh
				disk.allocMeasured += *j.RequestDisk * wh
				disk.measured++
			}
		}
		if j.RequestGPUs != nil && *j.RequestGPUs > 0 {
			anyGPU = true
			gpu.alloc += *j.RequestGPUs * wh
			if j.GPUUtilization() != nil {
				gpu.used += *j.GPUsAverageUsage * wh
				gpu.allocMeasured += *j.RequestGPUs * wh
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

// buildWorkflow analyses one workflow's jobs.
func buildWorkflow(g *group, opts Options) Workflow {
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
		Key:        g.id.key,
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

	var walls, memReq, peaks, cpuReq, cores, eff, diskReq, diskUsed, gpuReq, gpuUtil []float64
	var memJobs []memoryJob
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
			if lost := lostToRestarts(j); lost > 0 || (j.CommittedTime == nil && j.NumJobStarts > 1) {
				w.Restarts.Jobs++
				restartLost += lost
			}
		}

		if j.RequestMemory != nil {
			memReq = append(memReq, *j.RequestMemory)
		}
		if mj, ok := memorySample(j); ok {
			memJobs = append(memJobs, mj)
			peaks = append(peaks, mj.peak)
		}
		if j.RequestCpus != nil {
			cpuReq = append(cpuReq, *j.RequestCpus)
		}
		if c := j.coresUsed(); c != nil {
			cores = append(cores, *c)
			if j.RequestCpus != nil && *j.RequestCpus > 0 {
				eff = append(eff, *c / *j.RequestCpus)
			}
		}
		if j.RequestDisk != nil {
			diskReq = append(diskReq, *j.RequestDisk)
		}
		if j.DiskUsage != nil {
			diskUsed = append(diskUsed, *j.DiskUsage)
		}
		if j.RequestGPUs != nil && *j.RequestGPUs > 0 {
			gpuReq = append(gpuReq, *j.RequestGPUs)
			if u := j.GPUUtilization(); u != nil {
				gpuUtil = append(gpuUtil, *u)
			}
		}
	}
	w.WallHours = round(w.WallHours, 3)
	w.Restarts.LostHours = round(hours(restartLost), 3)
	w.Wall = distribution(walls)
	w.Memory = MemoryStats{Request: summarizeRequest(memReq), PeakMiB: distribution(peaks)}
	w.CPU = CPUStats{Request: summarizeRequest(cpuReq), CoresUsed: distribution(cores), Efficiency: distribution(eff)}
	w.Disk = DiskStats{Request: summarizeRequest(diskReq), UsedKiB: distribution(diskUsed)}
	if len(gpuReq) > 0 {
		w.GPU = &GPUStats{Request: summarizeRequest(gpuReq), Utilization: distribution(gpuUtil)}
	}

	plan := planMemory(memJobs)
	w.MemoryCurve = []MemoryCurvePoint{}
	if plan != nil {
		w.MemoryCurve = plan.curve
	}
	w.Advice = adviseWorkflow(&w, g.jobs, plan, walls)
	w.Batches = batches(g)
	w.Samples = samples(g.jobs)
	return w
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
func memorySample(j *Job) (memoryJob, bool) {
	if j.RequestMemory == nil {
		return memoryJob{}, false
	}
	mj := memoryJob{wallHours: hours(j.Wall), request: *j.RequestMemory}
	switch {
	case j.Status == statusCompleted && j.MemoryUsage != nil:
		mj.peak = *j.MemoryUsage
	case j.Status == statusRemoved && j.ExceededMemory:
		mj.peak = max(orZero(j.MemoryUsage), *j.RequestMemory)
		mj.atLeast = true
	default:
		return memoryJob{}, false
	}
	return mj, true
}

// batches is one point per submission, the most recent maxBatches,
// oldest first.
func batches(g *group) []BatchPoint {
	byID := map[int64][]*Job{}
	var order []int64
	for _, j := range g.jobs {
		id := batchOf(j)
		if _, ok := byID[id]; !ok {
			order = append(order, id)
		}
		byID[id] = append(byID[id], j)
	}
	out := make([]BatchPoint, 0, len(order))
	for _, id := range order {
		jobs := byID[id]
		p := BatchPoint{ID: id, Jobs: len(jobs), Submitted: jobs[0].QDate}
		var memReq, peaks, cpuReq, cores, walls []float64
		for _, j := range jobs {
			if j.QDate > 0 && (p.Submitted <= 0 || j.QDate < p.Submitted) {
				p.Submitted = j.QDate
			}
			if j.RequestMemory != nil {
				memReq = append(memReq, *j.RequestMemory)
			}
			if mj, ok := memorySample(j); ok {
				peaks = append(peaks, mj.peak)
			}
			if j.RequestCpus != nil {
				cpuReq = append(cpuReq, *j.RequestCpus)
			}
			if c := j.coresUsed(); c != nil {
				cores = append(cores, *c)
			}
			walls = append(walls, j.Wall)
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
	slices.SortStableFunc(out, func(a, b BatchPoint) int {
		if c := cmp.Compare(a.Submitted, b.Submitted); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
	if len(out) > maxBatches {
		out = out[len(out)-maxBatches:]
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
		s := Sample{Wall: round(j.Wall, 1), Outcome: j.outcome()}
		if j.MemoryUsage != nil {
			s.MemoryMiB = ptr(*j.MemoryUsage, 1)
		}
		if c := j.coresUsed(); c != nil {
			s.Cores = ptr(*c, 3)
		}
		if j.DiskUsage != nil {
			s.DiskKiB = ptr(*j.DiskUsage, 0)
		}
		out = append(out, s)
	}
	return out
}
