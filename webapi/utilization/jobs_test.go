package utilization

import (
	"slices"
	"testing"
)

// The jobs listing resolves a workflow key with Analyze's own filter and
// grouping: the DAG's prep.sh nodes across two runs, without DAGMan's own
// job, analyze.py's nodes, or a job still running.
func TestWorkflowJobsMatchesAnalyze(t *testing.T) {
	jobs := []Job{
		dagNode(102, "pipeline.dag+101", "/home/alice/prep.sh", 101),
		dagNode(103, "pipeline.dag+101", "/home/alice/prep.sh", 101),
		dagNode(104, "pipeline.dag+101", "analyze.py", 101),
		dagNode(206, "pipeline.dag+205", "/other/path/prep.sh", 205),
		{Cluster: 101, Owner: "alice", Cmd: "/usr/bin/condor_dagman", Universe: 7, Status: statusCompleted, BatchName: "pipeline.dag+101"},
	}
	running := dagNode(207, "pipeline.dag+205", "prep.sh", 205)
	running.Status = 2
	jobs = append(jobs, running)

	for _, w := range Analyze(jobs, Options{}).Workflows {
		got := WorkflowJobs(jobs, w.Key)
		if len(got) != w.Jobs {
			t.Errorf("%s/%s: %d jobs listed, the analysis counted %d", w.Name, w.Executable, len(got), w.Jobs)
		}
		for _, j := range got {
			if executableBase(j.Cmd) != w.Executable {
				t.Errorf("%s listed a %s job", w.Executable, j.Cmd)
			}
		}
	}
	if got := WorkflowJobs(jobs, "nosuchkey000"); got != nil {
		t.Errorf("unknown key listed %d jobs", len(got))
	}
}

func TestPageJobs(t *testing.T) {
	var jobs []Job
	for i, peak := range []float64{500, 900, 700, 900, 300} {
		jobs = append(jobs, completed(int64(10+i), peak, 1024, 3600))
	}
	unmeasured := completed(9, 0, 1024, 3600)
	unmeasured.MemoryUsage = 0
	jobs = append(jobs, unmeasured)

	ids := func(rows []JobRow) []string {
		var out []string
		for _, r := range rows {
			out = append(out, r.ID)
		}
		return out
	}
	// Largest first, the tie on 900 by cluster, the unmeasured job last.
	all, err := PageJobs(jobs, SortMemory, true, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"11.0", "13.0", "12.0", "10.0", "14.0", "9.0"}; !slices.Equal(ids(all), want) {
		t.Errorf("desc = %v, want %v", ids(all), want)
	}
	asc, _ := PageJobs(jobs, SortMemory, false, 0, 100)
	if want := []string{"14.0", "10.0", "12.0", "11.0", "13.0", "9.0"}; !slices.Equal(ids(asc), want) {
		t.Errorf("asc = %v, want %v (the unmeasured job last either way)", ids(asc), want)
	}
	// Pages tile the whole ordering.
	var paged []JobRow
	for off := 0; off < len(jobs); off += 4 {
		page, _ := PageJobs(jobs, SortMemory, true, off, 4)
		paged = append(paged, page...)
	}
	if !slices.Equal(ids(paged), ids(all)) {
		t.Errorf("pages = %v, want %v", ids(paged), ids(all))
	}
	if page, _ := PageJobs(jobs, SortMemory, true, 50, 4); len(page) != 0 {
		t.Errorf("past the end: %v", ids(page))
	}
	if _, err := PageJobs(jobs, "colour", true, 0, 4); err == nil {
		t.Error("an unknown sort was accepted")
	}
	for _, s := range []string{SortCompleted, SortSubmitted, SortWall, SortCores, SortEfficiency, SortDisk, SortGPU} {
		if !ValidSort(s) {
			t.Errorf("%s is not a valid sort", s)
		}
	}
}

func TestRow(t *testing.T) {
	j := withCores(completed(42, 900, 2048, 3600), 2, 1.5)
	j.Proc, j.NumJobStarts, j.FirstStart, j.Completion = 3, 3, 2000, 9000
	j.RequestGPUs, j.GPUsAverageUsage = f(2), f(0.5)
	r := Row(&j)
	if r.ID != "42.3" || r.Outcome != OutcomeOK || r.ExitCode == nil || *r.ExitCode != 0 || r.Restarts != 2 {
		t.Errorf("row = %+v", r)
	}
	if *r.Submitted != 1042 || *r.Started != 2000 || *r.Completed != 9000 || r.Wall != 3600 {
		t.Errorf("times = %v %v %v %v", *r.Submitted, *r.Started, *r.Completed, r.Wall)
	}
	if *r.MemoryPeakMiB != 900 || *r.Request.MemoryMiB != 2048 || *r.CoresUsed != 1.5 || *r.CPUEfficiency != 0.75 {
		t.Errorf("usage = %+v", r)
	}
	if *r.Request.GPUs != 2 || *r.GPUUtilization != 0.25 || r.Request.DiskKiB != nil || r.DiskUsedKiB != nil {
		t.Errorf("gpu/disk = %+v", r)
	}

	removed := completed(43, 900, 1024, 600)
	removed.Status, removed.ExitCode, removed.Completion, removed.Entered = statusRemoved, 0, 0, 7777
	removed.HeldForMemory, removed.ExceededMemory = true, true
	r = Row(&removed)
	if r.Outcome != OutcomeMemoryExceeded || r.ExitCode != nil || *r.Completed != 7777 || !r.HeldForMemory || r.Request.GPUs != nil {
		t.Errorf("removed row = %+v", r)
	}
}
