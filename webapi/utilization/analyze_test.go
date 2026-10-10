package utilization

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func dagNode(cluster int64, batch, cmd string, dagman int64) Job {
	j := completed(cluster, 900, 1024, 3600)
	j.BatchName, j.Cmd, j.DAGManJobID = batch, cmd, dagman
	return j
}

// A DAG's nodes carry "<dag file>+<root DAG cluster>" as their batch
// name, so every run of the same DAG would be its own workflow unless the
// suffix is dropped. Within a DAG, node types with different executables
// have different profiles and different submit files, so they split.
func TestWorkflowsStripDAGSuffixAndSplitByExecutable(t *testing.T) {
	jobs := []Job{
		dagNode(102, "pipeline.dag+101", "/home/alice/prep.sh", 101),
		dagNode(103, "pipeline.dag+101", "/home/alice/prep.sh", 101),
		dagNode(104, "pipeline.dag+101", "analyze.py", 101),
		// The next day's run of the same DAG.
		dagNode(206, "pipeline.dag+205", "/other/path/prep.sh", 205),
		// A sub-DAG node: its DAGManJobId is the sub-DAG, its batch
		// name still names the root.
		dagNode(301, "pipeline.dag+205", "prep.sh", 300),
		// DAGMan itself reserves nothing.
		{Cluster: 101, Owner: "alice", Cmd: "/usr/bin/condor_dagman", Universe: 7, Status: statusCompleted, BatchName: "pipeline.dag+101", Wall: 0},
	}
	resp := Analyze(jobs, Options{Days: 7})
	if resp.JobsConsidered != 5 {
		t.Errorf("jobs_considered = %d, want 5 (DAGMan's own job excluded)", resp.JobsConsidered)
	}
	got := map[string]Workflow{}
	for _, w := range resp.Workflows {
		got[w.Name+"|"+w.Executable] = w
	}
	if len(got) != 2 {
		t.Fatalf("workflows = %v, want pipeline.dag split into prep.sh and analyze.py", keys(got))
	}
	prep, ok := got["pipeline.dag|prep.sh"]
	if !ok {
		t.Fatalf("no pipeline.dag|prep.sh in %v", keys(got))
	}
	if !prep.IsDAG || prep.Jobs != 4 {
		t.Errorf("prep = dag %v jobs %d, want a DAG workflow of 4", prep.IsDAG, prep.Jobs)
	}
	var ids []int64
	for _, b := range prep.Batches {
		ids = append(ids, b.ID)
	}
	if !slices.Equal(ids, []int64{101, 205}) {
		t.Errorf("batches = %v, want one per root DAG run: [101 205]", ids)
	}
	if a, ok := got["pipeline.dag|analyze.py"]; !ok || a.Jobs != 1 {
		t.Errorf("analyze.py workflow = %+v", a)
	}
	if prep.Key == got["pipeline.dag|analyze.py"].Key || len(prep.Key) != 12 {
		t.Errorf("keys %q and %q should be distinct 12-character ids", prep.Key, got["pipeline.dag|analyze.py"].Key)
	}
	// Stable across calls.
	again := Analyze(jobs, Options{Days: 7})
	for _, w := range again.Workflows {
		if got[w.Name+"|"+w.Executable].Key != w.Key {
			t.Errorf("key for %s changed between calls", w.Name)
		}
	}
}

func keys(m map[string]Workflow) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Without a batch name, the executable names the workflow, and separate
// clusters of it are one workflow with one batch each.
func TestWorkflowFallsBackToExecutable(t *testing.T) {
	jobs := []Job{completed(10, 900, 1024, 3600), completed(11, 900, 1024, 3600)}
	jobs[1].Proc = 0
	w := onlyWorkflow(t, jobs)
	if w.Name != "sim" || w.Executable != "sim" || w.IsDAG {
		t.Errorf("workflow = %q/%q dag=%v", w.Name, w.Executable, w.IsDAG)
	}
	if len(w.Batches) != 2 || w.Batches[0].ID != 10 || w.Batches[1].ID != 11 {
		t.Errorf("batches = %+v", w.Batches)
	}
}

// Owners only appear when the scope covers more than one person.
func TestShowOwner(t *testing.T) {
	jobs := []Job{completed(1, 900, 1024, 3600)}
	if w := Analyze(jobs, Options{}).Workflows[0]; w.Owner != "" {
		t.Errorf("owner shown in a personal scope: %q", w.Owner)
	}
	if w := Analyze(jobs, Options{ShowOwner: true}).Workflows[0]; w.Owner != "alice" {
		t.Errorf("owner = %q, want alice", w.Owner)
	}
}

func withCores(j Job, requested, cores float64) Job {
	j.RequestCpus = f(requested)
	cpu := cores * j.Wall
	j.CPUSeconds = &cpu
	return j
}

// 8 cores requested, the 90th percentile job keeps 1.5 busy: request
// ceil(1.5*1.1) = 2. Twenty jobs of an hour each would have reserved
// 6 fewer cores apiece: 120 core-hours.
func TestCPULower(t *testing.T) {
	var jobs []Job
	for i := range 20 {
		jobs = append(jobs, withCores(completed(int64(i+1), 900, 1024, 3600), 8, 1.5))
	}
	w := onlyWorkflow(t, jobs)
	a := adviceByResource(w, ResourceCPU)
	if a == nil || a.ID != "cpus-lower" {
		t.Fatalf("cpu advice = %+v", a)
	}
	if !slices.Equal(a.Submit, []string{"request_cpus = 2"}) || a.Saves == nil || a.Saves.Amount != 120 || a.Saves.Unit != UnitCoreHours {
		t.Errorf("advice = %+v saves %+v", a, a.Saves)
	}
	if w.CPU.Efficiency == nil || w.CPU.Efficiency.P50 != 0.1875 {
		t.Errorf("efficiency = %+v, want 1.5/8", w.CPU.Efficiency)
	}
	// Time-weighted summary: 160 core-hours reserved, 30 used.
	cpu := w.Resources[0]
	if cpu.Resource != ResourceCPU || cpu.AllocatedHours != 160 || cpu.UsedHours == nil || *cpu.UsedHours != 30 || cpu.JobsMeasured != 20 {
		t.Errorf("cpu summary = %+v", cpu)
	}
}

func TestCPURaise(t *testing.T) {
	var jobs []Job
	for i := range 20 {
		jobs = append(jobs, withCores(completed(int64(i+1), 900, 1024, 3600), 1, 3.6))
	}
	w := onlyWorkflow(t, jobs)
	a := adviceByResource(w, ResourceCPU)
	if a == nil || a.ID != "cpus-raise" || a.Severity != SeverityWarn {
		t.Fatalf("cpu advice = %+v", a)
	}
	if !slices.Equal(a.Submit, []string{"request_cpus = 4"}) {
		t.Errorf("submit = %q", a.Submit)
	}
}

func TestShortJobsAndRestarts(t *testing.T) {
	var jobs []Job
	for i := range 120 {
		j := completed(int64(i+1), 900, 1024, 120)
		j.CommittedTime = f(120)
		jobs = append(jobs, j)
	}
	w := onlyWorkflow(t, jobs)
	if w.ShortJobs != 120 {
		t.Errorf("short_jobs = %d", w.ShortJobs)
	}
	if a := adviceByResource(w, ResourceRuntime); a == nil || a.ID != "short-jobs" {
		t.Errorf("runtime advice = %+v", a)
	}

	// Ten one-hour jobs that each lost 30 minutes to an eviction.
	jobs = nil
	for i := range 10 {
		j := completed(int64(i+1), 900, 1024, 3600)
		j.CommittedTime = f(1800)
		j.NumJobStarts = 2
		jobs = append(jobs, j)
	}
	resp := Analyze(jobs, Options{})
	w = resp.Workflows[0]
	if w.Restarts.Jobs != 10 || w.Restarts.LostHours != 5 {
		t.Errorf("restarts = %+v, want 10 jobs and 5 hours", w.Restarts)
	}
	if a := adviceByResource(w, ResourceRuntime); a == nil || a.ID != "restarts" || a.Severity != SeverityInfo {
		t.Errorf("runtime advice = %+v", a)
	}
	if resp.Overall.BadputHours != 5 || resp.Overall.WallHours != 10 {
		t.Errorf("overall = %+v", resp.Overall)
	}
}

// Failed and removed jobs are badput whole.
func TestOutcomesAndBadput(t *testing.T) {
	ok := completed(1, 900, 1024, 3600)
	failed := completed(2, 900, 1024, 3600)
	code := int64(1)
	failed.ExitCode = &code
	signalled := completed(3, 900, 1024, 3600)
	signalled.ExitBySignal = true
	removed := completed(4, 900, 1024, 1800)
	removed.Status, removed.ExitCode = statusRemoved, nil

	resp := Analyze([]Job{ok, failed, signalled, removed}, Options{})
	w := resp.Workflows[0]
	if w.Succeeded != 1 || w.Failed != 2 || w.Removed != 1 {
		t.Errorf("succeeded/failed/removed = %d/%d/%d", w.Succeeded, w.Failed, w.Removed)
	}
	if resp.Overall.BadputHours != 2.5 {
		t.Errorf("badput = %v, want 2.5 hours", resp.Overall.BadputHours)
	}
}

func TestGPUAdvice(t *testing.T) {
	var jobs []Job
	for i := range 20 {
		j := completed(int64(i+1), 900, 1024, 3600)
		j.RequestGPUs = f(1)
		j.GPUsAverageUsage = f(0.001)
		jobs = append(jobs, j)
	}
	resp := Analyze(jobs, Options{})
	w := resp.Workflows[0]
	if a := adviceByResource(w, ResourceGPU); a == nil || a.ID != "gpu-unused" || a.Saves == nil || a.Saves.Amount != 20 {
		t.Errorf("gpu advice = %+v", a)
	}
	if len(resp.Overall.Resources) != 4 || resp.Overall.Resources[3].Resource != ResourceGPU {
		t.Errorf("overall resources = %+v, want gpu included", resp.Overall.Resources)
	}

	for i := range jobs {
		jobs[i].GPUsAverageUsage = f(0.1)
	}
	w = Analyze(jobs, Options{}).Workflows[0]
	if a := adviceByResource(w, ResourceGPU); a == nil || a.ID != "gpu-idle" {
		t.Errorf("gpu advice = %+v", a)
	}

	// No GPU requested: no GPU summary at all.
	if r := Analyze(jobsAt(3, 1, 900, 1024), Options{}).Overall.Resources; len(r) != 3 {
		t.Errorf("resources = %+v, want cpu, memory, disk only", r)
	}
}

func TestDiskLower(t *testing.T) {
	var jobs []Job
	for i := range 20 {
		j := completed(int64(i+1), 900, 1024, 3600)
		j.RequestDisk = f(10 * 1024 * 1024) // 10 GiB
		j.DiskUsage = f(400 * 1024)         // 400 MiB
		jobs = append(jobs, j)
	}
	w := onlyWorkflow(t, jobs)
	a := adviceByResource(w, ResourceDisk)
	// 400 MiB * 1.25 = 500, rounded up to 512 MiB.
	if a == nil || a.ID != "disk-lower" || !slices.Equal(a.Submit, []string{"request_disk = 512 MB"}) {
		t.Errorf("disk advice = %+v", a)
	}
}

// Advice is ordered by severity, then by what it saves.
func TestAdviceOrder(t *testing.T) {
	var jobs []Job
	for i := range 120 {
		j := withCores(completed(int64(i+1), 900, 8192, 300), 1, 3)
		jobs = append(jobs, j)
	}
	w := onlyWorkflow(t, jobs)
	var sev []int
	for _, a := range w.Advice {
		sev = append(sev, severityRank(a.Severity))
	}
	if !slices.IsSorted(sev) || len(sev) < 2 {
		t.Errorf("advice order = %+v", w.Advice)
	}
}

func TestPercentileIsNearestRank(t *testing.T) {
	xs := []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	for _, tc := range []struct{ p, want float64 }{
		{10, 10}, {25, 30}, {50, 50}, {90, 90}, {95, 100}, {99, 100}, {0, 10},
	} {
		if got := percentile(xs, tc.p); got != tc.want {
			t.Errorf("p%v = %v, want %v", tc.p, got, tc.want)
		}
	}
}

func TestHistogramIsContiguousAndBounded(t *testing.T) {
	for _, values := range [][]float64{
		{1},
		{5, 5, 5},
		{0, 0.01, 0.4, 0.99},
		{100, 2000, 6144},
		{3, 7, 7, 8, 1000000},
	} {
		d := distribution(slices.Clone(values))
		h := d.Histogram
		if len(h) < minBins || len(h) > maxBins {
			t.Errorf("%v: %d bins", values, len(h))
		}
		total := 0
		for i, b := range h {
			total += b.Count
			if i > 0 && b.Lo != h[i-1].Hi {
				t.Errorf("%v: bin %d starts at %v, previous ends at %v", values, i, b.Lo, h[i-1].Hi)
			}
			if b.Hi <= b.Lo {
				t.Errorf("%v: empty bin %+v", values, b)
			}
		}
		if total != len(values) {
			t.Errorf("%v: histogram counts %d values", values, total)
		}
		if h[0].Lo > d.Min || h[len(h)-1].Hi <= d.Max {
			t.Errorf("%v: bins [%v, %v) do not cover [%v, %v]", values, h[0].Lo, h[len(h)-1].Hi, d.Min, d.Max)
		}
	}
}

func TestSamplesAndBatchesAreBounded(t *testing.T) {
	var jobs []Job
	for i := range 1000 {
		jobs = append(jobs, completed(int64(i+1), 900, 1024, 3600))
	}
	w := onlyWorkflow(t, jobs)
	if len(w.Samples) != maxSamples {
		t.Errorf("samples = %d", len(w.Samples))
	}
	if len(w.Batches) != maxBatches || w.Batches[len(w.Batches)-1].ID != 1000 || w.Batches[0].ID != 951 {
		t.Errorf("batches: %d, first %d last %d; want the most recent 50, oldest first",
			len(w.Batches), w.Batches[0].ID, w.Batches[len(w.Batches)-1].ID)
	}
	again := onlyWorkflow(t, jobs)
	if !reflect.DeepEqual(w.Samples, again.Samples) {
		t.Error("samples differ between two analyses of the same jobs")
	}
}

// Nothing to analyse is still a whole answer, and every list is a list.
func TestEmptyResponseMarshalsAsArrays(t *testing.T) {
	resp := Analyze(nil, Options{Since: 1, Until: 2, Days: 1})
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{`"jobs_considered":0`, `"workflows":[]`, `"resources":[`} {
		if !strings.Contains(s, want) {
			t.Errorf("%s missing %s", s, want)
		}
	}
	// used_hours is the one field that is null by contract when nothing
	// was measured.
	if strings.Contains(strings.ReplaceAll(s, `"used_hours":null`, ""), "null") {
		t.Errorf("empty response contains a null list: %s", s)
	}
}

// Advice text is about the jobs, in plain words.
func TestAdviceTextIsPlain(t *testing.T) {
	var jobs []Job
	jobs = append(jobs, jobsAt(1201, 1, 800, 8192)...)
	jobs = append(jobs, jobsAt(3, 5000, 5300, 8192)...)
	w := onlyWorkflow(t, jobs)
	a := adviceByResource(w, ResourceMemory)
	if a == nil {
		t.Fatal("no memory advice")
	}
	if !strings.HasPrefix(a.Detail, "95% of 1,204 jobs peaked at or below 800 MB; the largest peaked at 5.2 GB.") {
		t.Errorf("detail = %q", a.Detail)
	}
	for _, banned := range []string{"htcondordb", "mirror", "archive", "percentile", "algorithm", "schedd"} {
		if strings.Contains(strings.ToLower(a.Detail+a.Title), banned) {
			t.Errorf("advice mentions %q: %q", banned, a.Detail)
		}
	}
	if a.Confidence != "high" {
		t.Errorf("confidence = %q", a.Confidence)
	}
}
