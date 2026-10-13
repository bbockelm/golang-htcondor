// Package utilization answers "how well did my jobs use what they
// reserved?" and turns the answer into submit-file lines for the next
// submission.
//
// A job reserves a slot of a given size for its whole run whether it uses
// it or not, so an over-request is paid for in throughput: fewer jobs fit
// on a machine, and a job asking for more memory than most machines have
// free waits longer to start. An under-request is paid for differently --
// the job is held or restarted when it crosses the line, and everything
// it did up to then is thrown away. Both are invisible from the queue,
// which shows requests, not use.
//
// The unit of analysis is the workflow rather than the cluster, because
// the advice is about what the user submits NEXT: the same executable
// submitted every day as a fresh cluster is one thing to size, and a DAG
// that runs three different executables is three. See WorkflowKey.
//
// Everything here is pure: records in, analysis out. The HTTP server reads
// the records (from the htcondordb mirror or the schedd's history) and
// caches the result; anything else that wants the same analysis -- an MCP
// tool, a report -- can call Analyze with records it read itself.
package utilization

import (
	"math"
	"slices"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// HTCondor job states that can appear in history.
const (
	statusRemoved   = 3
	statusCompleted = 4
)

// Universes that reserve nothing on an execute point. DAGMan itself runs
// in the scheduler universe; local-universe jobs run on the access point.
const (
	universeScheduler = 7
	universeLocal     = 12
)

// Hold and vacate codes for a job that outgrew its request. Code 34
// (JobOutOfResources) is what the starter uses; 21 (StartdHeldJob) is
// what a machine policy that enforces memory uses. The subcode says which
// resource. The retry_request_memory transform keys on exactly this pair,
// so a pool that holds or evicts for memory either way is understood the
// same way here.
const (
	holdOutOfResources = 34
	holdStartdHeldJob  = 21
	subcodeMemory      = 102
	subcodeDisk        = 104
)

// Projection is every attribute Analyze reads, for the history query.
//
// Deliberately narrow: an access point's history can run to ~90k records
// a day, and a whole ad is tens of kilobytes. ResidentSetSize rides along
// because MemoryUsage is normally recorded as an expression over it,
// ((ResidentSetSize+1023)/1024), and evaluates to nothing without it.
// The Last* and Vacate* pairs are where a released or retried job's
// reason for being stopped survives (see FromAd).
func Projection() []string {
	return []string{
		"ClusterId", "ProcId", "Owner", "JobBatchName", "DAGManJobId",
		"Cmd", "Args", "Arguments", "JobUniverse", "QDate", "CompletionDate", "EnteredHistoryTime",
		"EnteredCurrentStatus", "JobStartDate", "JobCurrentStartDate",
		"JobStatus", "ExitCode", "ExitBySignal",
		"RequestMemory", "RequestCpus", "RequestDisk", "RequestGPUs",
		"MemoryUsage", "ResidentSetSize", "ResidentSetSize_RAW", "DiskUsage", "DiskUsage_RAW",
		"RemoteWallClockTime", "RemoteUserCpu", "RemoteSysCpu",
		"CumulativeRemoteUserCpu", "CumulativeRemoteSysCpu", "CommittedTime",
		"NumJobStarts", "NumHoldsByReason",
		"HoldReasonCode", "HoldReasonSubCode", "LastHoldReasonCode", "LastHoldReasonSubCode",
		"VacateReasonCode", "VacateReasonSubCode",
		"GPUsAverageUsage", "GPUsUsage", "GPUsMemoryUsage", "GPUsMinMemory", "MachineAttrGPUs_GlobalMemoryMb0",
		"GPUsProvisioned", "AssignedGPUs",
	}
}

// Job is the part of one history record the analysis uses.
//
// Kept small, because an analysis can hold a million of them: optional
// numbers are a Num (8 bytes, no allocation) rather than a pointer to a
// float, the strings are shared between jobs when read through a
// JobReader, and nothing the analysis does not read is kept.
type Job struct {
	Cluster, Proc int64
	Owner         string
	// Schedd is the access point that ran the job, in multi-AP mode.
	Schedd      string
	BatchName   string
	Cmd         string
	DAGManJobID int64
	QDate       int64
	// Entered is when the job entered history (see FromAd).
	Entered int64
	// Completion is CompletionDate; zero for a removed job.
	Completion int64
	// FirstStart is when the job first began running, zero if unknown.
	FirstStart   int64
	Universe     int16
	Status       int16
	NumJobStarts int32
	ExitCode     Num

	// Wall is RemoteWallClockTime: seconds on an execute point, summed
	// over every run.
	Wall float64

	// Requests, evaluated against the ad: RequestMemory MiB, RequestDisk
	// KiB, RequestCpus and RequestGPUs counts.
	RequestMemory Num
	RequestCpus   Num
	RequestDisk   Num
	RequestGPUs   Num

	// MemoryUsage is the peak in MiB -- a high-water mark, and the max
	// across every run of the job. DiskUsage is KiB.
	MemoryUsage Num
	DiskUsage   Num

	// CPUSeconds is user+system CPU over the same span as Wall, absent
	// when no such pair exists (see FromAd).
	CPUSeconds    Num
	CommittedTime Num

	// GPUsAverageUsage is GPU-seconds busy per second of the run, summed
	// over the job's GPUs -- 2.0 is two GPUs fully busy. See GPUUtilization.
	// FromAd falls back to GPUsUsage, and leaves out a figure more GPUs
	// than the job held could not produce (see PlausibleGPUUsage).
	GPUsAverageUsage Num
	// GPUsHeld is how many GPUs the job had (see GPUsHeld); absent means
	// "as many as it requested".
	GPUsHeld Num
	// GPUsMemoryUsage is the peak GPU memory in MiB.
	GPUsMemoryUsage Num
	// GPUsMinMemory is the job's gpus_minimum_memory, MiB: how much memory
	// a GPU must have to run it.
	GPUsMinMemory Num
	// GPUDeviceMemory is the memory of the GPU the job last ran on, MiB,
	// when the pool records it in the job (see FromAd).
	GPUDeviceMemory Num

	ExitBySignal  bool
	HeldForMemory bool
	HeldForDisk   bool
	// ExceededMemory is HeldForMemory, or evicted for memory by a
	// retry_request_memory policy.
	ExceededMemory bool
	// Adaptive marks requests written as formulas over the job's own
	// usage (see FromAd); one bit per Adaptive* constant.
	Adaptive uint8

	// Program is what the job runs, for naming its workflow (see Program).
	// Empty means "derive it from Cmd".
	Program string
	// RequestMemoryStart and RequestDiskStart are an adaptive request's
	// STARTING value; the Request* field is the value in force for the
	// run that finished. Absent when the request is a plain number.
	RequestMemoryStart Num
	RequestDiskStart   Num
	// MemoryFormula is an adaptive RequestMemory as written.
	MemoryFormula string
}

// Num is an optional number: present with a value, or absent. Absent is
// the zero value, so a Job literal that leaves a field out means "not
// recorded", not "zero".
//
// It is a float64 whose bits are XORed with one particular quiet NaN.
// That NaN is the only value that cannot be stored, and nothing HTCondor
// records is a NaN.
type Num uint64

const numAbsentBits = 0x7ff8000000000001

// NumOf is a present number.
func NumOf(x float64) Num { return Num(math.Float64bits(x) ^ numAbsentBits) }

// OK reports whether the number is present.
func (n Num) OK() bool { return n != 0 }

// V is the number's value; NaN when absent.
func (n Num) V() float64 { return math.Float64frombits(uint64(n) ^ numAbsentBits) }

// JobReader reads Jobs from ads, sharing equal strings between them. A
// million jobs from a few workflows repeat the same owner, batch name and
// executable a million times; read one at a time they would be a million
// copies.
type JobReader struct {
	strs map[string]string
	// requests remembers what is known about each Request* expression,
	// by its text, and recent the last few seen, by structure: a million
	// jobs of one workflow share one formula, and printing it (to find
	// the text), searching it for eleven names, and evaluating it with
	// the usage taken out of the ad cost more than the rest of FromAd.
	requests map[string]*knownRequest
	recent   []*knownRequest
}

// knownRequest is what a JobReader knows about one Request* expression.
type knownRequest struct {
	expr     *classad.Expr
	text     string
	adaptive bool
	// fixed is an adaptive expression that refers to nothing but usage
	// attributes, so starts the same in every job: start, once
	// hasStart.
	fixed    bool
	hasStart bool
	start    Num
}

// recentRequests is how many expressions a JobReader compares a new one
// against by structure before printing it.
const recentRequests = 8

// request is what is known about expr, a Request* expression in ad.
func (r *JobReader) request(ad *classad.ClassAd, expr *classad.Expr) *knownRequest {
	if r == nil {
		text := expr.String()
		return &knownRequest{expr: expr, text: text, adaptive: IsAdaptive(text)}
	}
	for i, k := range r.recent {
		if k.expr.Equal(expr) {
			copy(r.recent[1:i+1], r.recent[:i])
			r.recent[0] = k
			return k
		}
	}
	text := expr.String()
	k := r.requests[text]
	if k == nil {
		k = &knownRequest{expr: expr, text: text, adaptive: IsAdaptive(text)}
		k.fixed = k.adaptive && onlyUsage(ad, expr)
		if r.requests == nil {
			r.requests = make(map[string]*knownRequest)
		}
		if len(r.requests) < maxInterned {
			r.requests[text] = k
		}
	}
	if len(r.recent) < recentRequests {
		r.recent = append(r.recent, nil)
	}
	copy(r.recent[1:], r.recent[:len(r.recent)-1])
	r.recent[0] = k
	return k
}

// onlyUsage reports whether expr refers to no attribute but the job's
// usage, so evaluates the same with the usage taken away in any ad.
func onlyUsage(ad *classad.ClassAd, expr *classad.Expr) bool {
	for _, refs := range [][]string{ad.ExternalRefs(expr), ad.InternalRefs(expr)} {
		for _, ref := range refs {
			if !slices.Contains(usageAttrsLower, strings.ToLower(ref)) {
				return false
			}
		}
	}
	return true
}

// FromAd is the package FromAd, with strings shared.
func (r *JobReader) FromAd(ad *classad.ClassAd, schedd string) Job {
	j := fromAd(ad, schedd, r)
	j.Owner = r.intern(j.Owner)
	j.Schedd = r.intern(j.Schedd)
	j.BatchName = r.intern(j.BatchName)
	j.Cmd = r.intern(j.Cmd)
	j.Program = r.intern(j.Program)
	j.MemoryFormula = r.intern(j.MemoryFormula)
	return j
}

// maxInterned bounds the table: past it, strings are kept as they come,
// so a pathological history of all-different names costs what it would
// have without the table.
const maxInterned = 100000

func (r *JobReader) intern(s string) string {
	if r.strs == nil {
		r.strs = make(map[string]string)
	}
	if v, ok := r.strs[s]; ok {
		return v
	}
	if len(r.strs) < maxInterned {
		r.strs[s] = s
	}
	return s
}

// FromAd extracts a Job from a history ad. schedd names the access point
// in multi-AP mode and is empty otherwise.
//
// Every numeric attribute is EVALUATED rather than looked up: a request
// can be an expression (request_memory = 2048 * RequestCpus) and
// MemoryUsage normally is one. One that does not evaluate to a number is
// left absent and the job drops out of that resource's numbers only.
func FromAd(ad *classad.ClassAd, schedd string) Job {
	return fromAd(ad, schedd, nil)
}

// fromAd is FromAd, remembering per-expression decisions in r when there
// is one.
func fromAd(ad *classad.ClassAd, schedd string, r *JobReader) Job {
	j := Job{Schedd: schedd}
	j.Cluster = intAttr(ad, "ClusterId")
	j.Proc = intAttr(ad, "ProcId")
	j.Owner, _ = ad.EvaluateAttrString("Owner")
	j.BatchName, _ = ad.EvaluateAttrString("JobBatchName")
	j.DAGManJobID = intAttr(ad, "DAGManJobId")
	j.Cmd, _ = ad.EvaluateAttrString("Cmd")
	args, ok := ad.EvaluateAttrString("Arguments")
	if !ok {
		args, _ = ad.EvaluateAttrString("Args")
	}
	j.Program = Program(j.Cmd, args)
	j.Universe = small[int16](intAttr(ad, "JobUniverse"))
	j.QDate = intAttr(ad, "QDate")
	// A schedd need not record EnteredHistoryTime (HTCondor 25.8 does
	// not). The fallback is the one htcondordb stamps it from: the
	// transition to completed or removed, then CompletionDate.
	j.Entered = intAttr(ad, "EnteredHistoryTime")
	if j.Entered <= 0 {
		j.Entered = intAttr(ad, "EnteredCurrentStatus")
	}
	if j.Entered <= 0 {
		j.Entered = intAttr(ad, "CompletionDate")
	}
	j.Completion = intAttr(ad, "CompletionDate")
	j.Status = small[int16](intAttr(ad, "JobStatus"))
	j.ExitCode = numAttr(ad, "ExitCode")
	j.ExitBySignal, _ = ad.EvaluateAttrBool("ExitBySignal")

	j.RequestMemory = numAttr(ad, "RequestMemory")
	j.RequestCpus = numAttr(ad, "RequestCpus")
	j.RequestDisk = numAttr(ad, "RequestDisk")
	j.RequestGPUs = numAttr(ad, "RequestGPUs")
	// The peak memory and disk are read from the _RAW attributes when the
	// job has them. HTCondor rounds ResidentSetSize and DiskUsage UP for
	// display -- 1,070,200 KiB becomes 1,250,000 -- and keeps the measured
	// value in *_RAW. Rounded, a workflow's peaks pile up on a few round
	// numbers, every percentile lands on one of them, and the memory
	// sizing recommends requests a sixth larger than the jobs needed.
	if raw := numAttr(ad, "ResidentSetSize_RAW"); raw.OK() {
		j.MemoryUsage = NumOf(raw.V() / 1024)
	} else {
		j.MemoryUsage = numAttr(ad, "MemoryUsage")
	}
	if raw := numAttr(ad, "DiskUsage_RAW"); raw.OK() {
		j.DiskUsage = raw
	} else {
		j.DiskUsage = numAttr(ad, "DiskUsage")
	}
	j.readAdaptive(ad, r)
	if w := numAttr(ad, "RemoteWallClockTime"); w.OK() && w.V() > 0 {
		j.Wall = w.V()
	}
	j.CommittedTime = numAttr(ad, "CommittedTime")
	j.NumJobStarts = small[int32](intAttr(ad, "NumJobStarts"))
	// JobStartDate is the first start. JobCurrentStartDate is the latest,
	// which is the same thing only for a job that started once.
	j.FirstStart = intAttr(ad, "JobStartDate")
	if j.FirstStart == 0 && j.NumJobStarts <= 1 {
		j.FirstStart = intAttr(ad, "JobCurrentStartDate")
	}

	// CPU time has to cover the same runs as the wall clock it is divided
	// by. RemoteWallClockTime sums every run, but RemoteUserCpu and
	// RemoteSysCpu are zeroed when a run starts, so on a job that ran
	// twice they describe only the last run; dividing them by the total
	// wall would report half the cores actually used. The Cumulative*
	// pair spans every run like RemoteWallClockTime does. Without it, the
	// per-run pair is only usable when there was only one run.
	if user := numAttr(ad, "CumulativeRemoteUserCpu"); user.OK() {
		j.CPUSeconds = NumOf(user.V() + orZero(numAttr(ad, "CumulativeRemoteSysCpu")))
	} else if user := numAttr(ad, "RemoteUserCpu"); user.OK() && j.NumJobStarts <= 1 {
		j.CPUSeconds = NumOf(user.V() + orZero(numAttr(ad, "RemoteSysCpu")))
	}

	if held, ok := GPUsHeldFromAd(ad); ok {
		j.GPUsHeld = NumOf(held)
	}
	j.GPUsAverageUsage = numAttr(ad, "GPUsAverageUsage")
	if !j.GPUsAverageUsage.OK() {
		j.GPUsAverageUsage = numAttr(ad, "GPUsUsage")
	}
	if u := j.GPUsAverageUsage; u.OK() && j.GPUsHeld.OK() && !PlausibleGPUUsage(u.V(), j.GPUsHeld.V()) {
		j.GPUsAverageUsage = 0
	}
	j.GPUsMemoryUsage = numAttr(ad, "GPUsMemoryUsage")
	j.GPUsMinMemory = numAttr(ad, "GPUsMinMemory")
	// A GPU's memory reaches the job ad only if the pool asks for it:
	// SYSTEM_JOB_MACHINE_ATTRS (or the job's job_machine_attrs) naming
	// GPUs_GlobalMemoryMb -- the property condor_gpu_discovery publishes
	// for a machine whose GPUs all match -- records it as
	// MachineAttrGPUs_GlobalMemoryMb0. The default records only Cpus and
	// SlotWeight.
	j.GPUDeviceMemory = numAttr(ad, "MachineAttrGPUs_GlobalMemoryMb0")

	j.HeldForMemory, j.HeldForDisk = holdsFromAd(ad)
	vacated := numAttr(ad, "VacateReasonCode")
	vacatedSub := numAttr(ad, "VacateReasonSubCode")
	j.ExceededMemory = j.HeldForMemory || outgrew(vacated, vacatedSub, subcodeMemory)
	return j
}

// holdsFromAd reports whether a job was held at least once for exceeding
// its memory or its disk request.
//
// No one attribute says so. HoldReasonCode/SubCode describe the job's
// current hold and survive into history when a held job is removed; on a
// release the schedd moves them to LastHoldReasonCode/SubCode, so a job
// that was held for memory, given more and released still shows it
// there. Both describe only the most recent hold. NumHoldsByReason counts
// every hold, but by label -- JobOutOfResources -- without the subcode
// that says which resource. A JobOutOfResources count with no recorded
// subcode is taken to be memory: until disk enforcement arrived it was
// the only meaning that code had, and memory is still by far the common
// one. A recorded disk subcode says otherwise.
func holdsFromAd(ad *classad.ClassAd) (memory, disk bool) {
	code := numAttr(ad, "HoldReasonCode")
	sub := numAttr(ad, "HoldReasonSubCode")
	lastCode := numAttr(ad, "LastHoldReasonCode")
	lastSub := numAttr(ad, "LastHoldReasonSubCode")
	memory = outgrew(code, sub, subcodeMemory) || outgrew(lastCode, lastSub, subcodeMemory)
	disk = outgrew(code, sub, subcodeDisk) || outgrew(lastCode, lastSub, subcodeDisk)
	if !memory && !disk {
		if v := ad.EvaluateAttr("NumHoldsByReason"); v.IsClassAd() {
			if inner, err := v.ClassAdValue(); err == nil && inner != nil {
				if n, ok := inner.EvaluateAttrNumber("JobOutOfResources"); ok && n > 0 {
					memory = true
				}
			}
		}
	}
	return memory, disk
}

// outgrew reports whether a (code, subcode) pair records exceeding the
// resource named by subcode.
func outgrew(code, sub Num, subcode int) bool {
	if !code.OK() || !sub.OK() {
		return false
	}
	c := int(code.V())
	return (c == holdOutOfResources || c == holdStartdHeldJob) && int(sub.V()) == subcode
}

// numAttr evaluates an attribute to a number, or absent.
func numAttr(ad *classad.ClassAd, name string) Num {
	v, ok := ad.EvaluateAttrNumber(name)
	if !ok {
		return 0
	}
	return NumOf(v)
}

// intAttr evaluates an attribute to an integer, or 0.
func intAttr(ad *classad.ClassAd, name string) int64 {
	v, ok := ad.EvaluateAttrNumber(name)
	if !ok {
		return 0
	}
	return int64(v)
}

// Adaptive request bits.
const (
	AdaptiveMemory uint8 = 1 << iota
	AdaptiveCpus
	AdaptiveDisk
	AdaptiveGPUs
)

// usageAttrs are the job's own measurements. A request that refers to
// one is a formula that adapts to what the job used, and before the job
// has run they are all undefined.
var usageAttrs = [...]string{
	"MemoryUsage", "ResidentSetSize", "ResidentSetSize_RAW", "ProportionalSetSizeKb",
	"ImageSize", "ImageSize_RAW", "DiskUsage", "DiskUsage_RAW",
	"CpusUsage", "GPUsUsage", "GPUsMemoryUsage",
}

// IsAdaptive reports whether an expression refers to the job's usage.
// A textual test, deliberately: the attribute names are distinctive, and
// a false positive only means the request is described as a formula.
func IsAdaptive(expr string) bool {
	lower := strings.ToLower(expr)
	for _, a := range usageAttrsLower {
		if strings.Contains(lower, a) {
			return true
		}
	}
	return false
}

// usageAttrsLower is usageAttrs, lowercased once.
var usageAttrsLower = func() []string {
	out := make([]string, len(usageAttrs))
	for i, a := range usageAttrs {
		out[i] = strings.ToLower(a)
	}
	return out
}()

// readAdaptive finds requests written as formulas over the job's usage
// and records their STARTING value.
//
// A request like RequestMemory = ifThenElse(MemoryUsage isnt undefined,
// max({2048, 3*MemoryUsage/2}), 2048) starts at 2 GB and grows after a
// memory hold. Evaluated against the finished job it gives 1.5x the
// peak -- a request nobody made. What the user chose, and what advice
// should be compared with, is the value before any usage was known:
// the formula evaluated with every usage attribute undefined. The
// Request* field keeps the value in force for the run that finished --
// the start, or the grown value for a job that outgrew it -- which is
// what the time-weighted "allocated" hours count: that run really did
// hold that much.
func (j *Job) readAdaptive(ad *classad.ClassAd, reader *JobReader) {
	var found []adaptiveReq
	var known []*knownRequest
	for _, r := range []adaptiveReq{
		{"RequestMemory", AdaptiveMemory, &j.RequestMemoryStart},
		{"RequestCpus", AdaptiveCpus, nil},
		{"RequestDisk", AdaptiveDisk, &j.RequestDiskStart},
		{"RequestGPUs", AdaptiveGPUs, nil},
	} {
		expr, ok := ad.Lookup(r.name)
		if !ok || expr == nil {
			continue
		}
		k := reader.request(ad, expr)
		if !k.adaptive {
			continue
		}
		j.Adaptive |= r.bit
		if r.bit == AdaptiveMemory {
			j.MemoryFormula = k.text
		}
		switch {
		case r.start == nil:
		case k.hasStart:
			*r.start = k.start
		default:
			found = append(found, r)
			known = append(known, k)
		}
	}
	if len(found) > 0 {
		j.evalStarts(ad, found, known)
	}
	j.settleRequests()
}

// adaptiveReq is one Request* attribute readAdaptive looks at.
type adaptiveReq struct {
	name  string
	bit   uint8
	start *Num
}

// evalStarts evaluates each request in found with the usage attributes
// removed, then puts them back: the ad is the caller's. A fixed
// expression's start is remembered for the next job.
func (j *Job) evalStarts(ad *classad.ClassAd, found []adaptiveReq, known []*knownRequest) {
	var saved [len(usageAttrs)]*classad.Expr
	for i, a := range usageAttrs {
		if e, ok := ad.Lookup(a); ok {
			saved[i] = e
			ad.Delete(a)
		}
	}
	for i, r := range found {
		*r.start = numAttr(ad, r.name)
		if known[i].fixed {
			known[i].start, known[i].hasStart = *r.start, true
		}
	}
	for i, e := range saved {
		if e != nil {
			ad.InsertExpr(usageAttrs[i], e)
		}
	}
}

// settleRequests sets each adaptive request to the one in force for the
// run that finished.
func (j *Job) settleRequests() {
	// Evaluated against the finished job, the formula gives what it WOULD
	// request now -- 1.5x the peak even for a job that never outgrew its
	// start, which ran its one run at the start. The request in force for
	// the run that finished is therefore the start, unless the job peaked
	// above it (and so was held and rerun at the grown value).
	for _, r := range []struct {
		bit   uint8
		start Num
		used  Num
		dst   *Num
	}{
		{AdaptiveMemory, j.RequestMemoryStart, j.MemoryUsage, &j.RequestMemory},
		{AdaptiveDisk, j.RequestDiskStart, j.DiskUsage, &j.RequestDisk},
	} {
		if j.isAdaptive(r.bit) && r.start.OK() && (!r.used.OK() || r.used.V() <= r.start.V()) {
			*r.dst = r.start
		}
	}
}

// isAdaptive reports whether bit is set in the job's adaptive requests.
func (j *Job) isAdaptive(bit uint8) bool { return j.Adaptive&bit != 0 }

// startMemory is the request the job started with: the formula's
// starting value for an adaptive request, else the request itself.
func (j *Job) startMemory() Num {
	if j.isAdaptive(AdaptiveMemory) && j.RequestMemoryStart.OK() {
		return j.RequestMemoryStart
	}
	return j.RequestMemory
}

// startDisk is startMemory for disk.
func (j *Job) startDisk() Num {
	if j.isAdaptive(AdaptiveDisk) && j.RequestDiskStart.OK() {
		return j.RequestDiskStart
	}
	return j.RequestDisk
}

// small narrows a count or code to a smaller integer, saturating rather
// than wrapping: a universe, status or start count out of range is
// nonsense either way, and saturating keeps it from aliasing a real one.
func small[T int16 | int32](v int64) T {
	lo, hi := int64(math.MinInt16), int64(math.MaxInt16)
	var t T
	if _, wide := any(t).(int32); wide {
		lo, hi = math.MinInt32, math.MaxInt32
	}
	return T(min(max(v, lo), hi))
}

// orZero is the value, or 0 when there is none.
func orZero(n Num) float64 {
	if !n.OK() {
		return 0
	}
	return n.V()
}

// executableBase is the last path element of Cmd.
func executableBase(cmd string) string {
	if i := strings.LastIndexAny(cmd, `/\`); i >= 0 {
		return cmd[i+1:]
	}
	return cmd
}

// reservesNothing reports whether a job ran somewhere other than an
// execute point -- DAGMan itself, or a local-universe job -- and so has
// no reservation worth analysing.
func (j *Job) reservesNothing() bool {
	if j.Universe == universeScheduler || j.Universe == universeLocal {
		return true
	}
	return executableBase(j.Cmd) == "condor_dagman"
}

// finished reports whether the job left the queue: completed or removed.
// Nothing else has a final answer for what it used.
func (j *Job) finished() bool {
	return j.Status == statusCompleted || j.Status == statusRemoved
}

// succeeded is JobStatus 4, no signal, exit 0.
func (j *Job) succeeded() bool {
	return j.Status == statusCompleted && !j.ExitBySignal && j.ExitCode.OK() && j.ExitCode.V() == 0
}

// outcome classifies the job for a sample.
func (j *Job) outcome() string {
	switch {
	case j.Status == statusRemoved && j.ExceededMemory:
		return OutcomeMemoryExceeded
	case j.Status == statusRemoved:
		return OutcomeRemoved
	case j.succeeded():
		return OutcomeOK
	default:
		return OutcomeFailed
	}
}

// minCPUWall is the shortest run whose CPU rate is believed. A job that
// lasts seconds is dominated by process startup and file staging, and
// its cores-used figure says more about the sampling than the program.
const minCPUWall = 60

// coresUsed is CPU seconds per wall second; ok is false when it cannot
// be measured honestly.
func (j *Job) coresUsed() (float64, bool) {
	if !j.CPUSeconds.OK() || j.Wall < minCPUWall {
		return 0, false
	}
	return j.CPUSeconds.V() / j.Wall, true
}

// gpus is how many GPUs the job had: GPUsHeld, or the request for a Job
// that does not record it.
func (j *Job) gpus() float64 {
	if j.GPUsHeld.OK() && j.GPUsHeld.V() > 0 {
		return j.GPUsHeld.V()
	}
	if j.RequestGPUs.OK() && j.RequestGPUs.V() > 0 {
		return j.RequestGPUs.V()
	}
	return 0
}

// gpusBusy is GPUsAverageUsage when it can be believed: a run long
// enough to measure, a job that requested GPUs, and no more GPUs kept
// busy than it had.
func (j *Job) gpusBusy() (float64, bool) {
	held := j.gpus()
	if !j.GPUsAverageUsage.OK() || !j.RequestGPUs.OK() || j.RequestGPUs.V() <= 0 || held <= 0 || j.Wall < minCPUWall {
		return 0, false
	}
	u := j.GPUsAverageUsage.V()
	if !PlausibleGPUUsage(u, held) {
		return 0, false
	}
	return u, true
}

// GPUUtilization is the fraction of the job's GPUs kept busy.
//
// HTCondor's GPUsAverageUsage is computed on the execute point as
// (UptimeGPUsSeconds - StartOfJobUptimeGPUsSeconds) / (LastUpdate -
// FirstUpdate): busy GPU-seconds per second, where the busy seconds are
// SUMMED over every GPU assigned to the slot. Two GPUs fully busy is 2.0,
// so it is divided by the GPUs the job had -- which can be more than it
// requested, when it matched a larger slot -- to get a fraction. It
// covers the job's last run, which is a rate and so comparable across
// runs of different lengths.
func (j *Job) GPUUtilization() (float64, bool) {
	u, ok := j.gpusBusy()
	if !ok {
		return 0, false
	}
	return u / j.gpus(), true
}
