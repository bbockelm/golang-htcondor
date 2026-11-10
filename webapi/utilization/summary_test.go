package utilization

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// The compact list keeps what the table and the suggestions need, ranks
// advice across workflows the way each workflow ranks its own, and
// leaves out what is usually empty.
func TestSummarize(t *testing.T) {
	gpu := gpuJobs(20, 4, 1024)
	for i := range gpu {
		gpu[i].Cmd, gpu[i].GPUsAverageUsage = "/home/alice/train.py", f(1.0)
	}
	mem := jobsAt(20, 100, 900, 8192)
	for i := range mem {
		mem[i].BatchName = "sweep"
	}
	resp := Analyze(append(gpu, mem...), Options{ShowOwner: true, Machines: machines(2, 32, 256*1024, 4)})
	s := Summarize(resp)
	if len(s.Workflows) != 2 || s.JobsConsidered != 40 || s.Owners == nil {
		t.Fatalf("summary = %+v", s)
	}
	// gpus-lower saves 60 GPU-hours, memory-lower 140 GiB-hours: the
	// GPU saving ranks first.
	if len(s.Suggestions) < 2 || s.Suggestions[0].ID != "gpus-lower" || s.Suggestions[0].Executable != "train.py" {
		t.Errorf("suggestions = %+v", s.Suggestions)
	}
	byExe := map[string]WorkflowSummary{}
	for _, w := range s.Workflows {
		byExe[w.Executable] = w
	}
	g, m := byExe["train.py"], byExe["sim"]
	if g.Name != "" || m.Name != "sweep" {
		t.Errorf("names: %q (should be omitted, equal to the executable) and %q", g.Name, m.Name)
	}
	if g.Request.GPUs == nil || *g.Request.GPUs != 4 || g.GPUHours == nil || *g.GPUHours != 80 || g.Used.GPU == nil || *g.Used.GPU != 0.25 {
		t.Errorf("gpu row = %+v", g)
	}
	if g.Gain == nil || g.SlotsLimited == nil || *g.SlotsLimited {
		t.Errorf("gain %v slots_limited %v", g.Gain, g.SlotsLimited)
	}
	if m.Request.MemoryMiB == nil || *m.Request.MemoryMiB != 8192 || m.Request.GPUs != nil {
		t.Errorf("memory row request = %+v", m.Request)
	}
	raw, _ := json.Marshal(m)
	for _, absent := range []string{`"is_dag"`, `"failed"`, `"removed"`, `"holds"`, `"gpus"`, `"gpu"`, `"gpu_hours"`} {
		if strings.Contains(string(raw), absent) {
			t.Errorf("%s present in %s", absent, raw)
		}
	}
}

func TestSummarizeCapsSuggestions(t *testing.T) {
	var jobs []Job
	for w := range 600 {
		for _, j := range jobsAt(20, int64(w*100), 900, 8192) {
			j.Cmd = fmt.Sprintf("/bin/prog%d", w)
			jobs = append(jobs, j)
		}
	}
	if s := Summarize(Analyze(jobs, Options{})); len(s.Suggestions) != maxSuggestions || len(s.Workflows) != 600 {
		t.Errorf("suggestions %d workflows %d", len(s.Suggestions), len(s.Workflows))
	}
}
