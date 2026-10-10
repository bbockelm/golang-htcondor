package utilization

import (
	"math"
	"testing"
)

// machines is n identical execute machines.
func machines(n int, cpus, memoryMiB, gpus float64) []Machine {
	out := make([]Machine, n)
	for i := range out {
		out[i] = Machine{Cpus: cpus, MemoryMiB: memoryMiB, DiskKiB: 100 * 1024 * 1024, GPUs: gpus}
	}
	return out
}

func analyzeOn(t *testing.T, jobs []Job, pool []Machine) (*Response, Workflow) {
	t.Helper()
	resp := Analyze(jobs, Options{Machines: pool})
	if len(resp.Workflows) != 1 {
		t.Fatalf("got %d workflows, want 1", len(resp.Workflows))
	}
	return resp, resp.Workflows[0]
}

// On 4-core/16 GB machines a 1-core/8 GB job is memory-limited: two fit
// per machine, leaving two cores idle. Its 100 jobs peak at 900 MB, so
// the advice is 1 GB, which fits four per machine (now core-limited).
// Ten machines hold 20 jobs today and 40 after: the same 100 hours of
// work occupies the pool for 100/20 = 5 against 100/40 = 2.5, a gain of 2.
func TestThroughputMemoryLimitedDoubles(t *testing.T) {
	resp, w := analyzeOn(t, jobsAt(100, 1, 900, 8192), machines(10, 4, 16384, 0))
	tp := w.Throughput
	if tp == nil {
		t.Fatal("no throughput estimate")
	}
	if tp.Current != (Shape{Cpus: 1, MemoryMiB: 8192}) || tp.Suggested != (Shape{Cpus: 1, MemoryMiB: 1024}) {
		t.Errorf("shapes = %+v -> %+v", tp.Current, tp.Suggested)
	}
	if tp.FitCurrent != 20 || tp.FitSuggested != 40 || tp.Gain != 2 || tp.LimitedBy != ResourceMemory {
		t.Errorf("throughput = %+v, want fit 20 -> 40, gain 2, memory-limited", tp)
	}
	if tp.RetryMemoryMiB != nil {
		t.Errorf("retry = %v, want none", *tp.RetryMemoryMiB)
	}
	if resp.Overall.ThroughputGain == nil || *resp.Overall.ThroughputGain != 2 {
		t.Errorf("overall gain = %v, want 2", resp.Overall.ThroughputGain)
	}
}

// Reruns cost slots too. The long-tail workflow (95 jobs at 800 MB, 2 at
// 1500, 3 at 6 GB, all asking 8 GB) is advised 896 MB with a retry at
// 7 GB. On the same 4-core/16 GB machines: today 2 per machine (20);
// at 896 MB, 4 per machine (40); the retry at 7 GB, 2 per machine (20).
// The five jobs that outgrow 896 MB occupy 40-wide slots for their full
// hour and then 20-wide ones again: 100/40 + 5/20 = 2.75 against 100/20
// = 5, a gain of 1.818 rather than 2.
func TestThroughputReruns(t *testing.T) {
	var jobs []Job
	jobs = append(jobs, jobsAt(95, 1, 800, 8192)...)
	jobs = append(jobs, jobsAt(2, 200, 1500, 8192)...)
	jobs = append(jobs, jobsAt(3, 300, 6144, 8192)...)
	_, w := analyzeOn(t, jobs, machines(10, 4, 16384, 0))
	tp := w.Throughput
	if tp == nil {
		t.Fatal("no throughput estimate")
	}
	if tp.Suggested.MemoryMiB != 896 || tp.RetryMemoryMiB == nil || *tp.RetryMemoryMiB != 7168 {
		t.Errorf("suggested = %+v retry %v", tp.Suggested, tp.RetryMemoryMiB)
	}
	if tp.FitCurrent != 20 || tp.FitSuggested != 40 || tp.Gain != 1.818 {
		t.Errorf("throughput = %+v, want fit 20 -> 40 and gain 5/2.75 = 1.818", tp)
	}
}

// 8-core jobs keeping 1.5 cores busy are advised 2 cores. On 32-core/
// 256 GB machines they are core-limited: 4 per machine today, 16 after.
func TestThroughputCPUsLower(t *testing.T) {
	var jobs []Job
	for i := range 20 {
		jobs = append(jobs, withCores(completed(int64(i+1), 900, 1024, 3600), 8, 1.5))
	}
	_, w := analyzeOn(t, jobs, machines(10, 32, 256*1024, 0))
	tp := w.Throughput
	if tp == nil {
		t.Fatal("no throughput estimate")
	}
	if tp.Current.Cpus != 8 || tp.Suggested.Cpus != 2 || tp.Suggested.MemoryMiB != 1024 {
		t.Errorf("shapes = %+v -> %+v", tp.Current, tp.Suggested)
	}
	if tp.FitCurrent != 40 || tp.FitSuggested != 160 || tp.Gain != 4 || tp.LimitedBy != ResourceCPU {
		t.Errorf("throughput = %+v, want 40 -> 160, gain 4, cpu-limited", tp)
	}
}

// Asking for more cores than requested lowers throughput, and the
// estimate says so rather than hiding it.
func TestThroughputCPUsRaiseLowersIt(t *testing.T) {
	var jobs []Job
	for i := range 20 {
		jobs = append(jobs, withCores(completed(int64(i+1), 900, 1024, 3600), 1, 3.6))
	}
	_, w := analyzeOn(t, jobs, machines(10, 32, 256*1024, 0))
	if tp := w.Throughput; tp == nil || tp.Gain != 0.25 || tp.Suggested.Cpus != 4 {
		t.Errorf("throughput = %+v, want 1 -> 4 cores, gain 0.25", tp)
	}
}

// A GPU job fits only machines with GPUs. Two 16-core/64 GB/4-GPU
// machines hold four each, GPU-limited; the ten CPU-only machines hold
// none. Right-sizing memory does not change a GPU-limited fit: gain 1.
func TestThroughputGPUShapeCountsGPUMachines(t *testing.T) {
	pool := append(machines(10, 4, 16384, 0), machines(2, 16, 65536, 4)...)
	jobs := jobsAt(25, 1, 900, 8192)
	for i := range jobs {
		jobs[i].RequestGPUs = f(1)
	}
	_, w := analyzeOn(t, jobs, pool)
	tp := w.Throughput
	if tp == nil {
		t.Fatal("no throughput estimate")
	}
	if tp.FitCurrent != 8 || tp.FitSuggested != 8 || tp.Gain != 1 || tp.LimitedBy != ResourceGPU {
		t.Errorf("throughput = %+v, want 8 -> 8 on the GPU machines only, gpu-limited", tp)
	}

	n, by := fit(pool, Shape{Cpus: 1, MemoryMiB: 1024, GPUs: 1})
	if n != 8 || by != ResourceGPU {
		t.Errorf("fit = %d by %s", n, by)
	}
	// What limits a GPU job is decided on the GPU machines alone. On
	// 16 GB GPU machines an 8 GB job fits twice, memory-limited; counting
	// the ten machines with no GPU would call it GPU-limited.
	small := append(machines(10, 4, 16384, 0), machines(2, 16, 16384, 4)...)
	if n, by := fit(small, Shape{Cpus: 1, MemoryMiB: 8192, GPUs: 1}); n != 4 || by != ResourceMemory {
		t.Errorf("fit = %d by %s, want 4 by memory", n, by)
	}
}

func TestThroughputWait(t *testing.T) {
	for _, tc := range []struct {
		wait    int64
		limited bool
	}{{899, false}, {900, true}, {7200, true}} {
		jobs := jobsAt(25, 1, 900, 8192)
		for i := range jobs {
			jobs[i].FirstStart = jobs[i].QDate + tc.wait
		}
		_, w := analyzeOn(t, jobs, machines(10, 4, 16384, 0))
		if w.Throughput == nil || w.Throughput.WaitP50 != float64(tc.wait) || w.Throughput.SlotsLimited != tc.limited {
			t.Errorf("wait %d: throughput = %+v, want slots_limited=%v", tc.wait, w.Throughput, tc.limited)
		}
	}
}

func batchJobs(cluster int64, n int, qdate, completion int64, wall float64) []*Job {
	var out []*Job
	for i := range n {
		j := completed(cluster, 900, 1024, wall)
		j.Proc, j.QDate, j.Completion = int64(i), qdate, completion
		out = append(out, &j)
	}
	return out
}

// The most recent batch of 20 or more: first submission to last
// completion is the elapsed time, divided by the gain -- but never less
// than the batch's longest job.
func TestLastBatch(t *testing.T) {
	var jobs []*Job
	jobs = append(jobs, batchJobs(100, 30, 1000, 37000, 3600)...)  // older
	jobs = append(jobs, batchJobs(200, 25, 50000, 86000, 3600)...) // the most recent big one
	jobs = append(jobs, batchJobs(300, 5, 90000, 95000, 3600)...)  // too small
	jobs[len(jobs)-6].Completion = 0                               // a removed job: no completion
	jobs[len(jobs)-6].Entered = 80000

	b := lastBatch(jobs, 2)
	if b == nil || b.ID != 200 || b.Jobs != 25 || b.Elapsed != 36000 || b.Estimated != 18000 {
		t.Errorf("last batch = %+v, want 200: 25 jobs, 36000 s, 18000 s at gain 2", b)
	}
	// At gain 20, 36000/20 = 1800 is shorter than the hour each job
	// takes: the estimate is the longest job.
	if b := lastBatch(jobs, 20); b == nil || b.Estimated != 3600 {
		t.Errorf("last batch at gain 20 = %+v, want the 3600 s floor", b)
	}
	if b := lastBatch(batchJobs(1, 19, 0, 100, 10), 2); b != nil {
		t.Errorf("19 jobs is not a batch to estimate: %+v", b)
	}
}

func TestThroughputNull(t *testing.T) {
	pool := machines(10, 4, 16384, 0)
	// The request already fits: nothing changes.
	resp, w := analyzeOn(t, jobsAt(25, 1, 900, 1024), pool)
	if w.Throughput != nil || resp.Overall.ThroughputGain != nil {
		t.Errorf("no change: throughput %+v, overall %v", w.Throughput, resp.Overall.ThroughputGain)
	}
	// Nothing known about the pool (multi-AP, or the collector could
	// not be read).
	resp, w = analyzeOn(t, jobsAt(100, 1, 900, 8192), nil)
	if w.Throughput != nil || resp.Overall.ThroughputGain != nil {
		t.Errorf("no pool: throughput %+v, overall %v", w.Throughput, resp.Overall.ThroughputGain)
	}
	// Too few jobs to size memory.
	if _, w = analyzeOn(t, jobsAt(19, 1, 900, 8192), pool); w.Throughput != nil {
		t.Errorf("19 jobs: throughput %+v", w.Throughput)
	}
	// No machine in the pool holds the job at all.
	if _, w = analyzeOn(t, jobsAt(100, 1, 900, 32768), pool); w.Throughput != nil {
		t.Errorf("nothing fits: throughput %+v", w.Throughput)
	}
}

// Overall: the 100-job workflow occupies 5 today and 2.5 suggested; a
// second, unchanged workflow of 25 one-hour 1 GB jobs (4 per machine, 40
// in the pool) occupies 0.625 on both sides. (5 + 0.625) / (2.5 + 0.625)
// = 1.8.
func TestThroughputOverallCountsUnchangedWorkflows(t *testing.T) {
	jobs := jobsAt(100, 1, 900, 8192)
	other := jobsAt(25, 1000, 900, 1024)
	for i := range other {
		other[i].Cmd = "/home/alice/other"
	}
	resp := Analyze(append(jobs, other...), Options{Machines: machines(10, 4, 16384, 0)})
	if g := resp.Overall.ThroughputGain; g == nil || math.Abs(*g-1.8) > 1e-9 {
		t.Errorf("overall gain = %v, want 1.8", g)
	}
}

// A partitionable slot is counted at its full size, a static slot at its
// own, and dynamic and backfill slots not at all: they are carved out of,
// or re-advertise, capacity already counted.
func TestMachineFromAd(t *testing.T) {
	for _, tc := range []struct {
		name string
		ad   string
		want *Machine
	}{
		{
			name: "partitionable at its total size",
			ad:   "SlotType = \"Partitionable\"\nPartitionableSlot = true\nCpus = 1\nMemory = 512\nDisk = 1000\nTotalSlotCpus = 32\nTotalSlotMemory = 131072\nTotalSlotDisk = 900000000\nTotalSlotGPUs = 4\nGPUs = 1",
			want: &Machine{Cpus: 32, MemoryMiB: 131072, DiskKiB: 900000000, GPUs: 4},
		},
		{
			name: "static",
			ad:   "SlotType = \"Static\"\nCpus = 2\nMemory = 4096\nDisk = 50000000\nTotalSlotCpus = 2",
			want: &Machine{Cpus: 2, MemoryMiB: 4096, DiskKiB: 50000000},
		},
		{name: "dynamic", ad: "SlotType = \"Dynamic\"\nDynamicSlot = true\nCpus = 4\nMemory = 8192\nDisk = 1000"},
		{name: "dynamic by flag", ad: "DynamicSlot = true\nCpus = 4\nMemory = 8192\nDisk = 1000"},
		{name: "backfill", ad: "SlotType = \"Partitionable\"\nBackfillSlot = true\nTotalSlotCpus = 32\nTotalSlotMemory = 131072\nCpus = 32\nMemory = 131072"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := MachineFromAd(parseAd(t, tc.ad))
			switch {
			case tc.want == nil && ok:
				t.Errorf("counted %+v; it adds no capacity", m)
			case tc.want != nil && (!ok || m != *tc.want):
				t.Errorf("machine = %+v ok=%v, want %+v", m, ok, *tc.want)
			}
		})
	}
}

func TestFromAdFirstStart(t *testing.T) {
	for _, tc := range []struct {
		ad   string
		want int64
	}{
		{"JobStatus = 4\nJobStartDate = 100\nJobCurrentStartDate = 500\nNumJobStarts = 2", 100},
		{"JobStatus = 4\nJobCurrentStartDate = 500\nNumJobStarts = 1", 500},
		// The latest start of a restarted job is not its first.
		{"JobStatus = 4\nJobCurrentStartDate = 500\nNumJobStarts = 2", 0},
	} {
		if got := FromAd(parseAd(t, tc.ad), "").FirstStart; got != tc.want {
			t.Errorf("%q: first start %d, want %d", tc.ad, got, tc.want)
		}
	}
}
