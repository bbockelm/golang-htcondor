package utilization

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strconv"
)

// The jobs of one workflow, one row each, for a person who wants to see
// which jobs are behind a number on the summary.

// JobRow is one job as the jobs listing shows it.
type JobRow struct {
	ID           string     `json:"id"`
	Cluster      int64      `json:"cluster"`
	Proc         int64      `json:"proc"`
	Schedd       string     `json:"schedd,omitempty"`
	Owner        string     `json:"owner"`
	Submitted    *int64     `json:"submitted"`
	Started      *int64     `json:"started"`
	Completed    *int64     `json:"completed"`
	Outcome      string     `json:"outcome"`
	ExitCode     *int64     `json:"exit_code"`
	ExitBySignal bool       `json:"exit_by_signal"`
	Wall         float64    `json:"wall"`
	Request      JobRequest `json:"request"`
	// MemoryPeakMiB is MemoryUsage, the high-water mark.
	MemoryPeakMiB    *float64 `json:"memory_peak_mib"`
	CoresUsed        *float64 `json:"cores_used"`
	CPUEfficiency    *float64 `json:"cpu_efficiency"`
	DiskUsedKiB      *float64 `json:"disk_used_kib"`
	GPUUtilization   *float64 `json:"gpu_utilization"`
	GPUMemoryPeakMiB *float64 `json:"gpu_memory_peak_mib"`
	Restarts         int      `json:"restarts"`
	HeldForMemory    bool     `json:"held_for_memory"`
	HeldForDisk      bool     `json:"held_for_disk"`
}

// JobRequest is what a job asked for.
type JobRequest struct {
	MemoryMiB *float64 `json:"memory_mib"`
	Cpus      *float64 `json:"cpus"`
	DiskKiB   *float64 `json:"disk_kib"`
	// GPUs is nil when the job requested none.
	GPUs *float64 `json:"gpus"`
}

// Job sort orders.
const (
	SortCompleted  = "completed"
	SortSubmitted  = "submitted"
	SortWall       = "wall"
	SortMemory     = "memory"
	SortCores      = "cores"
	SortEfficiency = "efficiency"
	SortDisk       = "disk"
	SortGPU        = "gpu"
)

// sortValues is how each order reads a job; ok is false for a job with
// no value, which sorts last either way.
var sortValues = map[string]func(j *Job) (float64, bool){
	SortCompleted: func(j *Job) (float64, bool) {
		t := j.leftQueue()
		return float64(t), t > 0
	},
	SortSubmitted: func(j *Job) (float64, bool) { return float64(j.QDate), j.QDate > 0 },
	SortWall:      func(j *Job) (float64, bool) { return j.Wall, true },
	SortMemory:    func(j *Job) (float64, bool) { return j.MemoryUsage.V(), j.MemoryUsage.OK() },
	SortCores:     func(j *Job) (float64, bool) { return j.coresUsed() },
	SortEfficiency: func(j *Job) (float64, bool) {
		return j.cpuEfficiency()
	},
	SortDisk: func(j *Job) (float64, bool) { return j.DiskUsage.V(), j.DiskUsage.OK() },
	SortGPU:  func(j *Job) (float64, bool) { return j.GPUUtilization() },
}

// ValidSort reports whether sort names a job order.
func ValidSort(sort string) bool {
	_, ok := sortValues[sort]
	return ok
}

// WorkflowJobs is the jobs of jobs that Analyze would put in the workflow
// with the given key -- by the same filter and the same grouping, not a
// second derivation of either.
func WorkflowJobs(jobs []Job, key string) []Job {
	keys := map[identity]string{}
	var out []Job
	for i := range jobs {
		j := &jobs[i]
		if !j.finished() || j.reservesNothing() {
			continue
		}
		id, _ := identify(j)
		k, ok := keys[id]
		if !ok {
			k = id.hash()
			keys[id] = k
		}
		if k == key {
			out = append(out, *j)
		}
	}
	return out
}

// PageJobs sorts jobs and returns one page of rows. desc puts the largest
// values first; jobs with no value for the sort come last either way, and
// ties go by (cluster, proc) so a page boundary never moves. jobs is not
// modified.
//
// The sort is redone for every page. A million-job workflow sorts in a
// fraction of a second, and keeping one ordering per sort column per
// cached workflow would cost four bytes a job per column for a page that
// may never be asked for again.
func PageJobs(jobs []Job, sort string, desc bool, offset, size int) ([]JobRow, error) {
	value, ok := sortValues[sort]
	if !ok {
		return nil, fmt.Errorf("unknown sort %q", sort)
	}
	type keyed struct {
		v   float64
		ok  bool
		idx int32
	}
	order := make([]keyed, len(jobs))
	for i := range jobs {
		v, ok := value(&jobs[i])
		order[i] = keyed{v: v, ok: ok, idx: int32(i)} //nolint:gosec // a slice index fits: jobs are capped well below 2^31
	}
	slices.SortFunc(order, func(a, b keyed) int {
		if a.ok != b.ok {
			if a.ok {
				return -1
			}
			return 1
		}
		if a.ok && a.v != b.v {
			if desc {
				return cmp.Compare(b.v, a.v)
			}
			return cmp.Compare(a.v, b.v)
		}
		ja, jb := &jobs[a.idx], &jobs[b.idx]
		return cmp.Or(cmp.Compare(ja.Cluster, jb.Cluster), cmp.Compare(ja.Proc, jb.Proc), cmp.Compare(ja.Schedd, jb.Schedd))
	})
	if offset >= len(order) {
		return []JobRow{}, nil
	}
	end := min(offset+size, len(order))
	rows := make([]JobRow, 0, end-offset)
	for _, k := range order[offset:end] {
		rows = append(rows, Row(&jobs[k.idx]))
	}
	return rows, nil
}

// Row is one job's row.
func Row(j *Job) JobRow {
	r := JobRow{
		ID:            j.id(),
		Cluster:       j.Cluster,
		Proc:          j.Proc,
		Schedd:        j.Schedd,
		Owner:         j.Owner,
		Submitted:     positive(j.QDate),
		Started:       positive(j.FirstStart),
		Completed:     positive(j.leftQueue()),
		Outcome:       j.outcome(),
		ExitBySignal:  j.ExitBySignal,
		Wall:          round(j.Wall, 1),
		MemoryPeakMiB: numPtr(j.MemoryUsage, 1),
		DiskUsedKiB:   numPtr(j.DiskUsage, 0),
		Request: JobRequest{
			MemoryMiB: numPtr(j.RequestMemory, 3),
			Cpus:      numPtr(j.RequestCpus, 3),
			DiskKiB:   numPtr(j.RequestDisk, 0),
		},
		GPUMemoryPeakMiB: numPtr(j.GPUsMemoryUsage, 1),
		Restarts:         int(max(j.NumJobStarts-1, 0)),
		HeldForMemory:    j.HeldForMemory,
		HeldForDisk:      j.HeldForDisk,
	}
	if j.ExitCode.OK() {
		code := int64(j.ExitCode.V())
		r.ExitCode = &code
	}
	if j.RequestGPUs.OK() && j.RequestGPUs.V() > 0 {
		r.Request.GPUs = ptr(j.RequestGPUs.V(), 3)
	}
	if c, ok := j.coresUsed(); ok {
		r.CoresUsed = ptr(c, 3)
	}
	if e, ok := j.cpuEfficiency(); ok {
		r.CPUEfficiency = ptr(e, 3)
	}
	if u, ok := j.GPUUtilization(); ok {
		r.GPUUtilization = ptr(u, 3)
	}
	return r
}

// id is "cluster.proc".
func (j *Job) id() string {
	return strconv.FormatInt(j.Cluster, 10) + "." + strconv.FormatInt(j.Proc, 10)
}

// leftQueue is when the job left the queue: its CompletionDate, or for a
// removed job, which has none, when it entered history.
func (j *Job) leftQueue() int64 {
	if j.Completion > 0 {
		return j.Completion
	}
	return j.Entered
}

// cpuEfficiency is cores used over cores requested.
func (j *Job) cpuEfficiency() (float64, bool) {
	c, ok := j.coresUsed()
	if !ok || !j.RequestCpus.OK() || j.RequestCpus.V() <= 0 {
		return 0, false
	}
	return c / j.RequestCpus.V(), true
}

func positive(t int64) *int64 {
	if t <= 0 {
		return nil
	}
	return &t
}

func numPtr(n Num, places int) *float64 {
	if !n.OK() || math.IsNaN(n.V()) {
		return nil
	}
	return ptr(n.V(), places)
}

// InWorkflow reports whether a job -- finished or not -- belongs to the
// workflow with the given key: the grouping WorkflowJobs and Analyze use,
// without their finished-jobs filter, for finding a workflow's jobs still
// in the queue.
func InWorkflow(j *Job, key string) bool {
	id, _ := identify(j)
	return id.hash() == key
}

// WorkflowOf is the workflow a job belongs to -- finished or not -- as
// the analysis would name it: its key, name and program.
func WorkflowOf(j *Job) (key, name, program string) {
	id, _ := identify(j)
	return id.hash(), id.name, id.exe
}

// Finished reports whether a job is one the analysis counts: completed or
// removed, and run on an execute point.
func Finished(j *Job) bool {
	return j.finished() && !j.reservesNothing()
}
