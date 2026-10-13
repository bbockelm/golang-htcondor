package utilization

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// gpuAd is a finished GPU job's history record as an access point writes
// it: RequestGPUs, GPUsProvisioned and AssignedGPUs always; the usage
// figures only when the execute point measured them (avg or mem < 0
// leaves them out). GPUsUsage is never written to history, and the GPU's
// own memory almost never is.
func gpuAd(cluster, proc int, batch string, req, prov int, assigned []string, avg, mem float64) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ClusterId = %d\nProcId = %d\nOwner = \"user%d\"\nJobBatchName = %q\n", cluster, proc, cluster%3, batch)
	fmt.Fprintf(&b, "Cmd = \"/home/user/%s.sh\"\nJobUniverse = 5\nJobStatus = 4\nExitCode = 0\n", batch)
	fmt.Fprintf(&b, "QDate = %d\nCompletionDate = %d\n", 1000+cluster, 5000+cluster)
	b.WriteString("RequestCpus = 4\nRequestMemory = 16384\nRequestDisk = 10485760\nRemoteWallClockTime = 7200\n")
	b.WriteString("RemoteUserCpu = 10800\nRemoteSysCpu = 0\nResidentSetSize_RAW = 8000000\nNumJobStarts = 1\n")
	fmt.Fprintf(&b, "RequestGPUs = %d\nGPUsProvisioned = %d\nAssignedGPUs = %q\n", req, prov, strings.Join(assigned, ","))
	if avg >= 0 {
		fmt.Fprintf(&b, "GPUsAverageUsage = %g\n", avg)
	}
	if mem >= 0 {
		fmt.Fprintf(&b, "GPUsMemoryUsage = %g\n", mem)
	}
	return b.String()
}

func gpuID(cluster, proc, k int) string {
	return fmt.Sprintf("GPU-%04x%02x%02x", cluster, proc, k)
}

// realisticGPUWorkload is two workflows shaped like a campus access
// point's GPU history:
//
//   - train: 30 single-GPU jobs keeping their GPU busy 15-35% of the time
//     (median 25%), peaking at 9.0-12.0 GB of GPU memory, stating no GPU
//     memory requirement. Two of them landed on a 2-GPU slot and kept
//     1.8 GPUs busy, which is real.
//   - sweep: 12 two-GPU jobs keeping about one GPU busy, two of which
//     report usage no 2-GPU job can have (12973.47 and 53.67).
func realisticGPUWorkload(t *testing.T) []Job {
	t.Helper()
	var jobs []Job
	for i := range 30 {
		prov, ids := 1, []string{gpuID(100, i, 0)}
		avg := 0.15 + 0.2*float64(i)/29
		if i == 3 || i == 17 {
			prov, ids, avg = 2, []string{gpuID(100, i, 0), gpuID(100, i, 1)}, 1.8
		}
		mem := 9216 + 3072*float64(i)/29
		if i == 5 {
			avg = -1 // not measured
		}
		jobs = append(jobs, FromAd(parseAd(t, gpuAd(100, i, "train", 1, prov, ids, avg, mem)), ""))
	}
	for i := range 12 {
		avg := 0.9 + 0.01*float64(i)
		switch i {
		case 4:
			avg = 12973.47
		case 9:
			avg = 53.67
		}
		ids := []string{gpuID(200, i, 0), gpuID(200, i, 1)}
		jobs = append(jobs, FromAd(parseAd(t, gpuAd(200, i, "sweep", 2, 2, ids, avg, 20480)), ""))
	}
	return jobs
}

func workflowNamed(t *testing.T, resp *Response, name string) Workflow {
	t.Helper()
	for _, w := range resp.Workflows {
		if w.Name == name {
			return w
		}
	}
	t.Fatalf("no workflow %q", name)
	return Workflow{}
}

// GPU jobs that use their GPUs poorly, and use a known amount of GPU
// memory, get GPU advice -- from the attributes such jobs actually have.
func TestRealisticGPUWorkloadGetsGPUAdvice(t *testing.T) {
	resp := Analyze(realisticGPUWorkload(t), Options{Days: 7})

	train := workflowNamed(t, resp, "train")
	if train.GPU == nil || train.GPU.Jobs != 30 || train.GPU.Measured != 29 {
		t.Fatalf("train gpu = %+v", train.GPU)
	}
	idle := adviceByID(train, "gpu-idle")
	if idle == nil {
		t.Fatalf("train: no GPU utilization advice; got %v", adviceIDs(train))
	}
	if !strings.Contains(idle.Detail, "Half of 29 jobs") {
		t.Errorf("gpu-idle detail = %q", idle.Detail)
	}
	mem := adviceByID(train, "gpu-memory-require")
	if mem == nil {
		t.Fatalf("train: no GPU memory advice; got %v", adviceIDs(train))
	}
	// 12 GB plus a quarter is 15 GB.
	if !slices.Equal(mem.Submit, []string{"gpus_minimum_memory = 15 GB"}) || mem.Title != "Require GPUs with 15 GB of memory" {
		t.Errorf("gpu-memory-require = %q %v", mem.Title, mem.Submit)
	}

	sweep := workflowNamed(t, resp, "sweep")
	if sweep.GPU == nil || sweep.GPU.Measured != 10 {
		t.Fatalf("sweep gpu = %+v, want the two impossible readings left out", sweep.GPU)
	}
	lower := adviceByID(sweep, "gpus-lower")
	if lower == nil || !slices.Equal(lower.Submit, []string{"request_gpus = 1"}) {
		t.Fatalf("sweep: gpus-lower = %+v; got %v", lower, adviceIDs(sweep))
	}
	if adviceByID(sweep, "gpu-memory-require") == nil {
		t.Errorf("sweep: no GPU memory advice; got %v", adviceIDs(sweep))
	}

	// And the ranked list across workflows carries them.
	var ids []string
	for _, s := range Summarize(resp).Suggestions {
		if s.Resource == ResourceGPU {
			ids = append(ids, s.ID)
		}
	}
	for _, want := range []string{"gpu-idle", "gpu-memory-require", "gpus-lower"} {
		if !slices.Contains(ids, want) {
			t.Errorf("suggestions %v lack %s", ids, want)
		}
	}
}

// The shapes history really has. Usage beyond the GPUs a job held is
// missing, not clamped; a job holding more GPUs than it asked for is not
// suspect.
func TestPlausibleGPUUsageShapes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ad          string
		held        float64
		utilization float64 // 0 means none
	}{
		{"req 2, prov 2, avg 12973.47", "RequestGPUs = 2\nGPUsProvisioned = 2\nAssignedGPUs = \"GPU-0a,GPU-0b\"\nGPUsAverageUsage = 12973.47", 2, 0},
		{"req 2, prov 2, avg 53.67", "RequestGPUs = 2\nGPUsProvisioned = 2\nGPUsAverageUsage = 53.67", 2, 0},
		{"req 4, prov 4, avg 110688.3", "RequestGPUs = 4\nGPUsProvisioned = 4\nGPUsAverageUsage = 110688.3", 4, 0},
		{"req 1, prov 2, two ids, avg 1.8", "RequestGPUs = 1\nGPUsProvisioned = 2\nAssignedGPUs = \"GPU-1a,GPU-1b\"\nGPUsAverageUsage = 1.8", 2, 0.9},
		{"req 1, two ids, no prov, avg 1.8", "RequestGPUs = 1\nAssignedGPUs = \"GPU-1a, GPU-1b\"\nGPUsAverageUsage = 1.8", 2, 0.9},
		{"req 4, prov 4, avg 3.2", "RequestGPUs = 4\nGPUsProvisioned = 4\nGPUsAverageUsage = 3.2", 4, 0.8},
		{"req 1, avg 1.004 (jitter)", "RequestGPUs = 1\nGPUsAverageUsage = 1.004", 1, 1.004},
		{"req 1, avg 1.2", "RequestGPUs = 1\nGPUsAverageUsage = 1.2", 1, 0},
		{"req 2, GPUsUsage only", "RequestGPUs = 2\nGPUsProvisioned = 2\nGPUsUsage = 1.5", 2, 0.75},
		{"req 2, GPUsUsage 9", "RequestGPUs = 2\nGPUsProvisioned = 2\nGPUsUsage = 9", 2, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := parseAd(t, "JobStatus = 4\nRemoteWallClockTime = 3600\n"+tc.ad)
			if held, ok := GPUsHeldFromAd(ad); !ok || held != tc.held {
				t.Errorf("held = %v %v, want %v", held, ok, tc.held)
			}
			j := FromAd(ad, "")
			u, ok := j.GPUUtilization()
			switch {
			case tc.utilization == 0 && (ok || j.GPUsAverageUsage.OK()):
				t.Errorf("implausible usage kept: utilization %v, raw %v", u, j.GPUsAverageUsage.V())
			case tc.utilization != 0 && (!ok || u != tc.utilization):
				t.Errorf("utilization = %v %v, want %v", u, ok, tc.utilization)
			}
			if bad := ImplausibleGPUUsage(ad); (len(bad) > 0) != (tc.utilization == 0) {
				t.Errorf("ImplausibleGPUUsage = %v", bad)
			}
		})
	}
}

// A Job built directly, without FromAd, is held to the same bound.
func TestGPUUtilizationBoundsLiteralJobs(t *testing.T) {
	j := gpuJobs(1, 2, 1024)[0]
	j.GPUsAverageUsage = f(234.6)
	if u, ok := j.GPUUtilization(); ok {
		t.Errorf("utilization = %v from 234.6 GPUs busy of 2", u)
	}
	w := onlyWorkflow(t, []Job{j})
	for _, r := range w.Resources {
		if r.Resource == ResourceGPU && (r.UsedHours != nil || r.JobsMeasured != 0) {
			t.Errorf("gpu summary counts the implausible job: %+v", r)
		}
	}
	if rows := Row(&j); rows.GPUUtilization != nil {
		t.Errorf("job row gpu_utilization = %v", *rows.GPUUtilization)
	}
}

// A job matched to a slot with more GPUs than it asked for held them all,
// and its GPU-hours say so.
func TestGPUHoursCountGPUsHeld(t *testing.T) {
	ad := gpuAd(300, 0, "wide", 1, 2, []string{gpuID(300, 0, 0), gpuID(300, 0, 1)}, 1.8, -1)
	w := onlyWorkflow(t, []Job{FromAd(parseAd(t, ad), "")})
	for _, r := range w.Resources {
		if r.Resource == ResourceGPU {
			// Two GPUs for two hours, 1.8 of them busy.
			if r.AllocatedHours != 4 || r.UsedHours == nil || *r.UsedHours != 3.6 {
				t.Errorf("gpu summary = %+v", r)
			}
		}
	}
}

// The sample filter is the same rule over a job_metrics sample, which
// carries RequestGpus and, when recorded, GPUsProvisioned.
func TestGPUUsageSampleFilter(t *testing.T) {
	filter := GPUUsageSampleFilter("GpuUtil")
	for _, tc := range []struct {
		sample string
		keep   bool
	}{
		{"RequestGpus = 2\nGpuUtil = 1.0", true},
		{"RequestGpus = 2\nGpuUtil = 2.01", true},
		{"RequestGpus = 2\nGpuUtil = 12973.47", false},
		{"RequestGpus = 1\nGpuUtil = 1.8", false},
		{"RequestGpus = 1\nGPUsProvisioned = 2\nGpuUtil = 1.8", true},
		{"RequestGpus = 1\nGpuUtil = -0.5", false},
		{"RequestGpus = 1", false},
	} {
		ad := parseAd(t, tc.sample+"\nKeep = "+filter)
		keep, ok := ad.EvaluateAttrBool("Keep")
		if (ok && keep) != tc.keep {
			t.Errorf("%q: keep = %v %v, want %v", strings.ReplaceAll(tc.sample, "\n", "; "), keep, ok, tc.keep)
		}
	}
}

// When no minimum is stated and the jobs need little GPU memory, any GPU
// will do and nothing is said. A minimum below what jobs used is raised.
// A known card size is reported beside the peak.
func TestGPUMemoryRequireAndRaise(t *testing.T) {
	small := gpuJobs(10, 1, 1024)
	for i := range small {
		small[i].GPUsMemoryUsage = f(3000)
	}
	if w := onlyWorkflow(t, small); adviceByResource(w, ResourceGPU) != nil {
		t.Errorf("advice for 3 GB peaks with no minimum: %v", adviceIDs(w))
	}

	raise := gpuJobs(10, 1, 1024)
	for i := range raise {
		raise[i].GPUsMemoryUsage = f(20000)
		raise[i].GPUsMinMemory = f(16384)
		raise[i].GPUDeviceMemory = f(40960)
	}
	w := onlyWorkflow(t, raise)
	a := adviceByID(w, "gpu-memory-raise")
	if a == nil || !slices.Equal(a.Submit, []string{"gpus_minimum_memory = 25 GB"}) || a.Title != "Raise the GPU memory minimum to 25 GB" {
		t.Fatalf("advice = %v / %+v", adviceIDs(w), a)
	}
	if !strings.Contains(a.Detail, "19.5 GB, 49% of the 40 GB their GPUs had") {
		t.Errorf("detail = %q", a.Detail)
	}
	if a.Applies || a.Confidence != "medium" {
		t.Errorf("applies = %v, confidence = %q", a.Applies, a.Confidence)
	}

	// A minimum is written in whole GB: 4.1 GB plus a quarter is 6 GB.
	lower := gpuJobs(10, 1, 1024)
	for i := range lower {
		lower[i].GPUsMemoryUsage = f(4198)
		lower[i].GPUsMinMemory = f(40960)
	}
	w = onlyWorkflow(t, lower)
	if a := adviceByID(w, "gpu-memory-small"); a == nil || !slices.Equal(a.Submit, []string{"gpus_minimum_memory = 6 GB"}) ||
		a.Title != "Lower the GPU memory minimum to 6 GB" {
		t.Errorf("advice = %v / %+v", adviceIDs(w), a)
	}
}
