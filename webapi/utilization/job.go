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
		"ClusterId", "ProcId", "Owner", "JobBatchName", "DAGManJobId", "DAGNodeName",
		"Cmd", "JobUniverse", "QDate", "CompletionDate", "EnteredHistoryTime",
		"JobStartDate", "JobCurrentStartDate",
		"JobStatus", "ExitCode", "ExitBySignal",
		"RequestMemory", "RequestCpus", "RequestDisk", "RequestGPUs",
		"MemoryUsage", "ResidentSetSize", "DiskUsage",
		"RemoteWallClockTime", "RemoteUserCpu", "RemoteSysCpu",
		"CumulativeRemoteUserCpu", "CumulativeRemoteSysCpu", "CommittedTime",
		"NumJobStarts", "NumHoldsByReason",
		"HoldReasonCode", "HoldReasonSubCode", "LastHoldReasonCode", "LastHoldReasonSubCode",
		"VacateReasonCode", "VacateReasonSubCode",
		"GPUsAverageUsage", "GPUsMemoryUsage",
	}
}

// Job is the part of one history record the analysis uses. A nil pointer
// is a value that was absent or did not evaluate to a number, which is
// different from zero: a job that used no memory and a job whose memory
// was never measured must not average together.
type Job struct {
	Cluster, Proc int64
	Owner         string
	// Schedd is the access point that ran the job, in multi-AP mode.
	Schedd      string
	BatchName   string
	DAGManJobID int64
	DAGNodeName string
	Cmd         string
	Universe    int64
	QDate       int64
	Entered     int64
	// Completion is CompletionDate; zero for a removed job.
	Completion int64
	// FirstStart is when the job first began running, zero if unknown.
	FirstStart   int64
	Status       int64
	ExitCode     *int64
	ExitBySignal bool

	// Requests, evaluated against the ad: RequestMemory MiB, RequestDisk
	// KiB, RequestCpus and RequestGPUs counts.
	RequestMemory *float64
	RequestCpus   *float64
	RequestDisk   *float64
	RequestGPUs   *float64

	// MemoryUsage is the peak in MiB -- a high-water mark, and the max
	// across every run of the job. DiskUsage is KiB.
	MemoryUsage *float64
	DiskUsage   *float64

	// Wall is RemoteWallClockTime: seconds on an execute point, summed
	// over every run.
	Wall float64
	// CPUSeconds is user+system CPU over the same span as Wall, or nil
	// when no such pair exists (see FromAd).
	CPUSeconds    *float64
	CommittedTime *float64
	NumJobStarts  int64

	HeldForMemory bool
	HeldForDisk   bool
	// ExceededMemory is HeldForMemory, or evicted for memory by a
	// retry_request_memory policy.
	ExceededMemory bool

	// GPUsAverageUsage is GPU-seconds busy per second of the run, summed
	// over the job's GPUs -- 2.0 is two GPUs fully busy. See GPUUtilization.
	GPUsAverageUsage *float64
	// GPUsMemoryUsage is the peak GPU memory in MiB.
	GPUsMemoryUsage *float64
}

// FromAd extracts a Job from a history ad. schedd names the access point
// in multi-AP mode and is empty otherwise.
//
// Every numeric attribute is EVALUATED rather than looked up: a request
// can be an expression (request_memory = 2048 * RequestCpus) and
// MemoryUsage normally is one. One that does not evaluate to a number is
// left nil and the job drops out of that resource's numbers only.
func FromAd(ad *classad.ClassAd, schedd string) Job {
	j := Job{Schedd: schedd}
	j.Cluster = intAttr(ad, "ClusterId")
	j.Proc = intAttr(ad, "ProcId")
	j.Owner, _ = ad.EvaluateAttrString("Owner")
	j.BatchName, _ = ad.EvaluateAttrString("JobBatchName")
	j.DAGManJobID = intAttr(ad, "DAGManJobId")
	j.DAGNodeName, _ = ad.EvaluateAttrString("DAGNodeName")
	j.Cmd, _ = ad.EvaluateAttrString("Cmd")
	j.Universe = intAttr(ad, "JobUniverse")
	j.QDate = intAttr(ad, "QDate")
	j.Entered = intAttr(ad, "EnteredHistoryTime")
	j.Completion = intAttr(ad, "CompletionDate")
	j.Status = intAttr(ad, "JobStatus")
	if v, ok := ad.EvaluateAttrNumber("ExitCode"); ok {
		code := int64(v)
		j.ExitCode = &code
	}
	j.ExitBySignal, _ = ad.EvaluateAttrBool("ExitBySignal")

	j.RequestMemory = numAttr(ad, "RequestMemory")
	j.RequestCpus = numAttr(ad, "RequestCpus")
	j.RequestDisk = numAttr(ad, "RequestDisk")
	j.RequestGPUs = numAttr(ad, "RequestGPUs")
	j.MemoryUsage = numAttr(ad, "MemoryUsage")
	j.DiskUsage = numAttr(ad, "DiskUsage")
	if w := numAttr(ad, "RemoteWallClockTime"); w != nil && *w > 0 {
		j.Wall = *w
	}
	j.CommittedTime = numAttr(ad, "CommittedTime")
	j.NumJobStarts = intAttr(ad, "NumJobStarts")
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
	if user := numAttr(ad, "CumulativeRemoteUserCpu"); user != nil {
		cpu := *user + orZero(numAttr(ad, "CumulativeRemoteSysCpu"))
		j.CPUSeconds = &cpu
	} else if user := numAttr(ad, "RemoteUserCpu"); user != nil && j.NumJobStarts <= 1 {
		cpu := *user + orZero(numAttr(ad, "RemoteSysCpu"))
		j.CPUSeconds = &cpu
	}

	j.GPUsAverageUsage = numAttr(ad, "GPUsAverageUsage")
	j.GPUsMemoryUsage = numAttr(ad, "GPUsMemoryUsage")

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
func outgrew(code, sub *float64, subcode int) bool {
	if code == nil || sub == nil {
		return false
	}
	c := int(*code)
	return (c == holdOutOfResources || c == holdStartdHeldJob) && int(*sub) == subcode
}

// numAttr evaluates an attribute to a number, or nil.
func numAttr(ad *classad.ClassAd, name string) *float64 {
	v, ok := ad.EvaluateAttrNumber(name)
	if !ok {
		return nil
	}
	return &v
}

// intAttr evaluates an attribute to an integer, or 0.
func intAttr(ad *classad.ClassAd, name string) int64 {
	v, ok := ad.EvaluateAttrNumber(name)
	if !ok {
		return 0
	}
	return int64(v)
}

// orZero is the value, or 0 when there is none.
func orZero(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
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
	return j.Status == statusCompleted && !j.ExitBySignal && j.ExitCode != nil && *j.ExitCode == 0
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

// coresUsed is CPU seconds per wall second, or nil when it cannot be
// measured honestly.
func (j *Job) coresUsed() *float64 {
	if j.CPUSeconds == nil || j.Wall < minCPUWall {
		return nil
	}
	c := *j.CPUSeconds / j.Wall
	return &c
}

// GPUUtilization is the fraction of the requested GPUs kept busy.
//
// HTCondor's GPUsAverageUsage is computed on the execute point as
// (UptimeGPUsSeconds - StartOfJobUptimeGPUsSeconds) / (LastUpdate -
// FirstUpdate): busy GPU-seconds per second, where the busy seconds are
// SUMMED over every GPU assigned to the slot. Two GPUs fully busy is 2.0,
// so it is divided by the request to get a fraction. It covers the job's
// last run, which is a rate and so comparable across runs of different
// lengths.
func (j *Job) GPUUtilization() *float64 {
	if j.GPUsAverageUsage == nil || j.RequestGPUs == nil || *j.RequestGPUs <= 0 || j.Wall < minCPUWall {
		return nil
	}
	u := *j.GPUsAverageUsage / *j.RequestGPUs
	return &u
}
