package utilization

// The response shape. Field names and units are a contract with the web
// UI's Utilization page: memory is MiB, disk KiB, time seconds unless a
// name says hours, because those are the units HTCondor itself records
// and the units a person will see in their own job ads.

// Resource names used in summaries and advice.
const (
	ResourceCPU     = "cpu"
	ResourceMemory  = "memory"
	ResourceDisk    = "disk"
	ResourceGPU     = "gpu"
	ResourceRuntime = "runtime"
)

// Sample outcomes.
const (
	OutcomeOK             = "ok"
	OutcomeFailed         = "failed"
	OutcomeRemoved        = "removed"
	OutcomeMemoryExceeded = "memory_exceeded"
)

// Advice severities, most urgent first.
const (
	SeverityWarn    = "warn"
	SeveritySuggest = "suggest"
	SeverityInfo    = "info"
)

// Savings units.
const (
	UnitCoreHours = "core_hours"
	UnitGiBHours  = "gib_hours"
	UnitGPUHours  = "gpu_hours"
)

// Response is the whole answer for one scope and window.
type Response struct {
	Since          int64 `json:"since"`
	Until          int64 `json:"until"`
	Days           int   `json:"days"`
	JobsConsidered int   `json:"jobs_considered"`
	// Truncated says the read stopped at the job cap, so the analysis
	// covers only the most recent JobsConsidered jobs of the window.
	Truncated bool `json:"truncated"`
	// Limit is the most jobs this analysis would read; MaxLimit is the
	// most any analysis may.
	Limit     int        `json:"limit"`
	MaxLimit  int        `json:"max_limit"`
	Overall   Overall    `json:"overall"`
	Workflows []Workflow `json:"workflows"`
	// Owners is everyone whose jobs were analysed, by wall clock, for a
	// scope that covers more than one person's jobs.
	Owners []OwnerSummary `json:"owners,omitempty"`
}

// OwnerSummary is one person's share of the analysed jobs.
type OwnerSummary struct {
	Owner     string  `json:"owner"`
	Jobs      int     `json:"jobs"`
	WallHours float64 `json:"wall_hours"`
}

// Overall summarizes every job in the window.
type Overall struct {
	Jobs      int     `json:"jobs"`
	WallHours float64 `json:"wall_hours"`
	// BadputHours is wall clock spent on runs that did not count: the
	// whole of a failed or removed job, and the evicted runs of one that
	// eventually succeeded.
	BadputHours float64           `json:"badput_hours"`
	Resources   []ResourceSummary `json:"resources"`
	// ThroughputGain is every workflow together: the pool occupancy of
	// the same work at the current requests over that at the suggested
	// ones. Nil when no workflow has a throughput estimate.
	ThroughputGain *float64 `json:"throughput_gain"`
}

// ResourceSummary is time-weighted: of what was reserved, how much was
// used. AllocatedHoursMeasured is the honest denominator for UsedHours --
// the reservation of only the jobs whose usage was measured.
type ResourceSummary struct {
	Resource               string   `json:"resource"`
	AllocatedHours         float64  `json:"allocated_hours"`
	UsedHours              *float64 `json:"used_hours"`
	AllocatedHoursMeasured float64  `json:"allocated_hours_measured"`
	JobsMeasured           int      `json:"jobs_measured"`
}

// Distribution is a set of values summarized by exact nearest-rank
// percentiles and a histogram.
type Distribution struct {
	N         int     `json:"n"`
	Min       float64 `json:"min"`
	P10       float64 `json:"p10"`
	P25       float64 `json:"p25"`
	P50       float64 `json:"p50"`
	P75       float64 `json:"p75"`
	P90       float64 `json:"p90"`
	P95       float64 `json:"p95"`
	P99       float64 `json:"p99"`
	Max       float64 `json:"max"`
	Histogram []Bin   `json:"histogram"`
}

// Bin is one histogram bucket; Lo is inclusive, Hi exclusive.
type Bin struct {
	Lo    float64 `json:"lo"`
	Hi    float64 `json:"hi"`
	Count int     `json:"count"`
}

// Request describes what a workflow asked for.
type Request struct {
	// Typical is the most common requested value.
	Typical  float64 `json:"typical"`
	Min      float64 `json:"min"`
	Max      float64 `json:"max"`
	Distinct int     `json:"distinct"`
}

// BatchPoint is one submission: a cluster, or for a DAG the whole run of
// one root DAG.
type BatchPoint struct {
	ID               int64    `json:"id"`
	Submitted        int64    `json:"submitted"`
	Jobs             int      `json:"jobs"`
	MemoryRequestMiB *float64 `json:"memory_request_mib"`
	MemoryP95MiB     *float64 `json:"memory_p95_mib"`
	CPURequest       *float64 `json:"cpu_request"`
	CPUCoresP50      *float64 `json:"cpu_cores_p50"`
	WallP50          *float64 `json:"wall_p50"`
	// GPURequest is the typical request_gpus of the batch's GPU jobs, and
	// GPUUtilP50 their median fraction of those GPUs kept busy.
	GPURequest *float64 `json:"gpu_request"`
	GPUUtilP50 *float64 `json:"gpu_util_p50"`
}

// Sample is one job, for scatter plots.
type Sample struct {
	// Job is "cluster.proc", as JobRow.ID.
	Job       string   `json:"job"`
	MemoryMiB *float64 `json:"memory_mib"`
	Wall      float64  `json:"wall"`
	Cores     *float64 `json:"cores"`
	DiskKiB   *float64 `json:"disk_kib"`
	Outcome   string   `json:"outcome"`
}

// MemoryCurvePoint is the expected reservation at one candidate
// request_memory.
type MemoryCurvePoint struct {
	RequestMiB float64 `json:"request_mib"`
	// RetryMiB is the retry_request_memory paired with RequestMiB: the
	// request that fits every job, for any request below it. Nil at and
	// above that request, and at the current request when the advice is
	// to keep it.
	RetryMiB         *float64 `json:"retry_mib"`
	ReservedMiBHours float64  `json:"reserved_mib_hours"`
	RetryFraction    float64  `json:"retry_fraction"`
	IsCurrent        bool     `json:"is_current"`
	IsRecommended    bool     `json:"is_recommended"`
}

// Savings is what following a piece of advice would have saved over the
// same volume of work.
type Savings struct {
	Unit   string  `json:"unit"`
	Amount float64 `json:"amount"`
}

// Advice is one concrete change for the next submission.
type Advice struct {
	ID         string   `json:"id"`
	Resource   string   `json:"resource"`
	Severity   string   `json:"severity"`
	Title      string   `json:"title"`
	Detail     string   `json:"detail"`
	Submit     []string `json:"submit"`
	Saves      *Savings `json:"saves"`
	Confidence string   `json:"confidence"`

	// request is the new request the advice asks for, in the units of
	// the request named by changes (cores, MiB, KiB, GPUs); zero when it
	// changes no request.
	request float64
	changes string
}

// What a piece of advice changes, for the throughput estimate.
const (
	changesCpus   = "cpus"
	changesMemory = "memory"
	changesDisk   = "disk"
	changesGPUs   = "gpus"
)

// Restarts is wall clock lost to runs that were thrown away.
type Restarts struct {
	Jobs      int     `json:"jobs"`
	LostHours float64 `json:"lost_hours"`
}

// Holds counts jobs held at least once for exceeding a request.
type Holds struct {
	Memory int `json:"memory"`
	Disk   int `json:"disk"`
}

// MemoryStats is a workflow's memory request and measured peaks.
type MemoryStats struct {
	Request *Request      `json:"request"`
	PeakMiB *Distribution `json:"peak_mib"`
}

// CPUStats is a workflow's CPU request and measured core use.
type CPUStats struct {
	Request   *Request      `json:"request"`
	CoresUsed *Distribution `json:"cores_used"`
	// Efficiency is cores used divided by cores requested, per job.
	Efficiency *Distribution `json:"efficiency"`
}

// DiskStats is a workflow's disk request and measured use.
type DiskStats struct {
	Request *Request      `json:"request"`
	UsedKiB *Distribution `json:"used_kib"`
}

// GPUStats is a workflow's GPU request and measured utilization.
//
// Jobs and Measured are always filled in, because GPU utilization is
// often not recorded at all: only an execute point running HTCondor's
// GPU monitor (use feature:GPUs, which includes GPUsMonitor) reports it,
// and only for a run long enough to span two of its samples. A workflow
// with no measurement still reserved its GPUs, and says so.
type GPUStats struct {
	Request *Request `json:"request"`
	// Jobs requested at least one GPU; Measured of them have a
	// utilization measurement.
	Jobs     int `json:"jobs"`
	Measured int `json:"measured"`
	// Utilization is the fraction of the requested GPUs kept busy.
	Utilization *Distribution `json:"utilization"`
	// MemoryPeakMiB is each job's peak GPU memory (GPUsMemoryUsage).
	MemoryPeakMiB *Distribution `json:"memory_peak_mib"`
	// DeviceMemoryMiB is the typical memory of the GPUs the jobs ran on,
	// when the pool records it in the job ad (see FromAd).
	DeviceMemoryMiB *float64 `json:"device_memory_mib"`
	// CoresUsedWhileGPU is the CPU cores the GPU jobs kept busy: a GPU
	// job is often only as fast as the cores feeding it.
	CoresUsedWhileGPU *Distribution `json:"cores_used_while_gpu"`
}

// Workflow is the unit advice is about: what the user will submit next.
type Workflow struct {
	Key        string            `json:"key"`
	Name       string            `json:"name"`
	Executable string            `json:"executable"`
	Owner      string            `json:"owner,omitempty"`
	Schedd     string            `json:"schedd,omitempty"`
	IsDAG      bool              `json:"is_dag"`
	Jobs       int               `json:"jobs"`
	Succeeded  int               `json:"succeeded"`
	Failed     int               `json:"failed"`
	Removed    int               `json:"removed"`
	WallHours  float64           `json:"wall_hours"`
	Wall       *Distribution     `json:"wall"`
	ShortJobs  int               `json:"short_jobs"`
	Restarts   Restarts          `json:"restarts"`
	Holds      Holds             `json:"holds"`
	Resources  []ResourceSummary `json:"resources"`
	Memory     MemoryStats       `json:"memory"`
	CPU        CPUStats          `json:"cpu"`
	Disk       DiskStats         `json:"disk"`
	GPU        *GPUStats         `json:"gpu"`
	// MemoryCurve is empty when there is too little history to size
	// memory from.
	MemoryCurve []MemoryCurvePoint `json:"memory_curve"`
	Advice      []Advice           `json:"advice"`
	Batches     []BatchPoint       `json:"batches"`
	Samples     []Sample           `json:"samples"`
	// Throughput is nil when no advice changes the request, there are
	// too few jobs to size memory from, or nothing is known about the
	// pool.
	Throughput *Throughput `json:"throughput"`
}

// Shape is one job's request.
type Shape struct {
	Cpus      float64 `json:"cpus"`
	MemoryMiB float64 `json:"memory_mib"`
	DiskKiB   float64 `json:"disk_kib"`
	GPUs      float64 `json:"gpus"`
}

// Throughput estimates how many more of a workflow's jobs could run at
// once with the suggested requests.
type Throughput struct {
	Current        Shape    `json:"current"`
	Suggested      Shape    `json:"suggested"`
	RetryMemoryMiB *float64 `json:"retry_memory_mib"`
	// FitCurrent and FitSuggested are how many copies of each shape the
	// pool's execute machines could hold at once.
	FitCurrent   int `json:"fit_current"`
	FitSuggested int `json:"fit_suggested"`
	// Gain is pool occupancy per unit of work, current over suggested,
	// reruns included.
	Gain float64 `json:"gain"`
	// LimitedBy is the resource that caps the current shape on the most
	// machines.
	LimitedBy string `json:"limited_by"`
	// WaitP50 is the median seconds from submission to first start.
	WaitP50      float64    `json:"wait_p50"`
	SlotsLimited bool       `json:"slots_limited"`
	LastBatch    *LastBatch `json:"last_batch"`
}

// LastBatch turns the gain into time for the most recent sizeable batch.
type LastBatch struct {
	ID   int64 `json:"id"`
	Jobs int   `json:"jobs"`
	// Elapsed is first submission to last completion, seconds.
	Elapsed float64 `json:"elapsed"`
	// Estimated is the same at the suggested requests: never shorter
	// than its longest job.
	Estimated float64 `json:"estimated"`
}
