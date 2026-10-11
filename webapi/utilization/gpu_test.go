package utilization

import (
	"slices"
	"testing"
)

// gpuJobs is n one-hour jobs asking for gpus GPUs, peaking at 900 MB of a
// requestMiB memory request.
func gpuJobs(n int, gpus, requestMiB float64) []Job {
	jobs := jobsAt(n, 1, 900, requestMiB)
	for i := range jobs {
		jobs[i].RequestGPUs = f(gpus)
	}
	return jobs
}

func adviceIDs(w Workflow) []string {
	var ids []string
	for _, a := range w.Advice {
		ids = append(ids, a.ID)
	}
	return ids
}

func adviceByID(w Workflow, id string) *Advice {
	for i := range w.Advice {
		if w.Advice[i].ID == id {
			return &w.Advice[i]
		}
	}
	return nil
}

// GPU utilization is often not recorded at all. The GPUs were reserved
// regardless: the block, the job counts and the GPU-hours still show.
func TestGPUUnmeasuredStillReported(t *testing.T) {
	w := onlyWorkflow(t, gpuJobs(25, 2, 1024))
	g := w.GPU
	if g == nil || g.Jobs != 25 || g.Measured != 0 || g.Utilization != nil || g.Request.Typical != 2 {
		t.Fatalf("gpu = %+v", g)
	}
	var sum *ResourceSummary
	for i := range w.Resources {
		if w.Resources[i].Resource == ResourceGPU {
			sum = &w.Resources[i]
		}
	}
	// 25 jobs, 2 GPUs, an hour each.
	if sum == nil || sum.AllocatedHours != 50 || sum.UsedHours != nil || sum.JobsMeasured != 0 {
		t.Errorf("gpu summary = %+v", sum)
	}
	if a := adviceByResource(w, ResourceGPU); a != nil {
		t.Errorf("utilization advice without utilization: %+v", a)
	}
}

// Twenty jobs ask for 4 GPUs and keep one busy (GPUsAverageUsage 1.0,
// 25% of what they asked for -- not "idle"). The advice is 1 GPU, saving
// 3 GPUs for 20 hours: 60 GPU-hours. It ranks above the memory advice
// even though that saves a larger number (140 GiB-hours): a GPU-hour is
// the dearer thing. On two 4-GPU machines four such jobs fit today and
// sixteen after: gain 4.
func TestGPUsLower(t *testing.T) {
	jobs := gpuJobs(20, 4, 8192)
	for i := range jobs {
		jobs[i].GPUsAverageUsage = f(1.0)
	}
	pool := machines(2, 32, 256*1024, 4)
	resp := Analyze(jobs, Options{Machines: pool})
	w := resp.Workflows[0]
	a := adviceByID(w, "gpus-lower")
	if a == nil || !slices.Equal(a.Submit, []string{"request_gpus = 1"}) || a.Saves == nil || a.Saves.Unit != UnitGPUHours || a.Saves.Amount != 60 {
		t.Fatalf("gpus-lower = %+v", a)
	}
	if adviceByID(w, "gpu-idle") != nil {
		t.Errorf("gpu-idle given beside gpus-lower: %v", adviceIDs(w))
	}
	if w.Advice[0].ID != "gpus-lower" || adviceByID(w, "memory-lower") == nil {
		t.Errorf("advice order = %v, want gpus-lower first, memory-lower after", adviceIDs(w))
	}
	if tp := w.Throughput; tp == nil || tp.Suggested.GPUs != 1 || tp.FitCurrent != 2 || tp.FitSuggested != 8 || tp.Gain != 4 {
		t.Errorf("throughput = %+v", w.Throughput)
	}
}

// A GPU mostly idle while the job uses every core it asked for is waiting
// on the CPU: 4 cores, 3.8 busy, GPU 20% busy. The advice is to double
// the cores. With the CPUs not saturated, nothing is said.
func TestGPUCPUBound(t *testing.T) {
	build := func(cores float64) Workflow {
		var jobs []Job
		for _, j := range gpuJobs(20, 1, 1024) {
			j = withCores(j, 4, cores)
			j.GPUsAverageUsage = f(0.2)
			jobs = append(jobs, j)
		}
		return onlyWorkflow(t, jobs)
	}
	w := build(3.8)
	a := adviceByID(w, "gpu-cpu-bound")
	if a == nil || !slices.Equal(a.Submit, []string{"request_cpus = 8"}) || a.Resource != ResourceGPU {
		t.Fatalf("advice = %v / %+v", adviceIDs(w), a)
	}
	if w.GPU.CoresUsedWhileGPU == nil || w.GPU.CoresUsedWhileGPU.P50 != 3.8 {
		t.Errorf("cores while GPU = %+v", w.GPU.CoresUsedWhileGPU)
	}
	if w := build(1.0); adviceByID(w, "gpu-cpu-bound") != nil {
		t.Errorf("CPU-bound with a quarter of the cores busy: %v", adviceIDs(w))
	}
}

// Jobs that require 40 GB GPUs and peak at 9.5 GB: 9.5 GB plus a quarter
// is 11.9 GB, rounded up to 12 GB. Given whether or not utilization was
// measured, and only when the jobs state a requirement.
func TestGPUMemorySmall(t *testing.T) {
	jobs := gpuJobs(20, 1, 1024)
	for i := range jobs {
		jobs[i].GPUsMinMemory = f(40960)
		jobs[i].GPUsMemoryUsage = f(float64(8000 + i*91)) // up to 9729 MiB
		jobs[i].GPUDeviceMemory = f(81920)
	}
	jobs[19].GPUsMemoryUsage = f(9728)
	w := onlyWorkflow(t, jobs)
	a := adviceByID(w, "gpu-memory-small")
	if a == nil || !slices.Equal(a.Submit, []string{"gpus_minimum_memory = 12 GB"}) {
		t.Fatalf("advice = %v / %+v", adviceIDs(w), a)
	}
	if w.GPU.DeviceMemoryMiB == nil || *w.GPU.DeviceMemoryMiB != 81920 || w.GPU.MemoryPeakMiB.Max != 9728 {
		t.Errorf("gpu = %+v", w.GPU)
	}
	for i := range jobs {
		jobs[i].GPUsMinMemory = 0
	}
	if w := onlyWorkflow(t, jobs); adviceByID(w, "gpu-memory-small") != nil {
		t.Errorf("advised without a stated requirement: %v", adviceIDs(w))
	}
}

func TestFromAdGPUAttributes(t *testing.T) {
	j := FromAd(parseAd(t, "JobStatus = 4\nRequestGPUs = 1\nGPUsMinMemory = 40960\nMachineAttrGPUs_GlobalMemoryMb0 = 81920\nGPUsMemoryUsage = 9000"), "")
	if j.GPUsMinMemory.V() != 40960 || j.GPUDeviceMemory.V() != 81920 || j.GPUsMemoryUsage.V() != 9000 {
		t.Errorf("job = %+v", j)
	}
	// The attribute names are case-insensitive, as ClassAds are.
	j = FromAd(parseAd(t, "JobStatus = 4\nRequestGpus = 2\ngpusaverageusage = 1.5\nRemoteWallClockTime = 600"), "")
	if u, ok := j.GPUUtilization(); !ok || u != 0.75 {
		t.Errorf("utilization = %v %v", u, ok)
	}
}
