package utilization

import (
	"cmp"
	"slices"
)

// The compact answer.
//
// Every byte of a row is paid ten thousand times at a million jobs, so
// fields that are usually empty -- is_dag, failed and removed counts, a
// name that repeats the executable, the GPU request and use, an advice
// brief's savings -- are left out when they are.
//
// A full Response carries, for every workflow, histograms, samples,
// batches, a memory curve and the text of every piece of advice. At a
// million jobs that is ten thousand workflows and tens of megabytes --
// almost all of it for workflows nobody opens. Summary is what a list of
// workflows and a ranked list of suggestions need; one workflow's full
// detail is fetched when it is opened.

// Summary is the compact form of a Response.
type Summary struct {
	Since          int64             `json:"since"`
	Until          int64             `json:"until"`
	Days           int               `json:"days"`
	JobsConsidered int               `json:"jobs_considered"`
	Truncated      bool              `json:"truncated"`
	Limit          int               `json:"limit"`
	MaxLimit       int               `json:"max_limit"`
	Overall        Overall           `json:"overall"`
	Owners         []OwnerSummary    `json:"owners,omitempty"`
	Workflows      []WorkflowSummary `json:"workflows"`
	// Suggestions is every workflow's advice, ranked, at most
	// maxSuggestions.
	Suggestions []Suggestion `json:"suggestions"`
}

// WorkflowSummary is one row of the workflow list.
type WorkflowSummary struct {
	Key string `json:"key"`
	// Name is omitted when it is the executable, as it is for every
	// workflow submitted without a batch name.
	Name       string         `json:"name,omitempty"`
	Executable string         `json:"executable"`
	Owner      string         `json:"owner,omitempty"`
	Schedd     string         `json:"schedd,omitempty"`
	IsDAG      bool           `json:"is_dag,omitempty"`
	Jobs       int            `json:"jobs"`
	Succeeded  int            `json:"succeeded"`
	Failed     int            `json:"failed,omitempty"`
	Removed    int            `json:"removed,omitempty"`
	WallHours  float64        `json:"wall_hours"`
	Holds      *Holds         `json:"holds,omitempty"`
	Request    SummaryRequest `json:"request"`
	Used       SummaryUsed    `json:"used"`
	GPUHours   *float64       `json:"gpu_hours,omitempty"`
	// Gain and SlotsLimited are the throughput estimate's, when there is
	// one.
	Gain         *float64      `json:"gain,omitempty"`
	SlotsLimited *bool         `json:"slots_limited,omitempty"`
	Advice       []AdviceBrief `json:"advice"`
}

// SummaryRequest is a workflow's typical requests: the starting value of
// an adaptive one.
type SummaryRequest struct {
	MemoryMiB *float64 `json:"memory_mib"`
	Cpus      *float64 `json:"cpus"`
	DiskKiB   *float64 `json:"disk_kib"`
	GPUs      *float64 `json:"gpus,omitempty"`
	// Adaptive names the requests that are formulas.
	Adaptive []string `json:"adaptive,omitempty"`
}

// SummaryUsed is used over reserved, per resource, over the jobs where
// use was measured.
type SummaryUsed struct {
	CPU    *float64 `json:"cpu"`
	Memory *float64 `json:"memory"`
	Disk   *float64 `json:"disk"`
	GPU    *float64 `json:"gpu,omitempty"`
}

// AdviceBrief is a piece of advice as the workflow list shows it.
type AdviceBrief struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Saves    *Savings `json:"saves,omitempty"`
}

// Suggestion is one piece of advice in the ranked list across workflows.
type Suggestion struct {
	Key        string   `json:"key"`
	Name       string   `json:"name"`
	Executable string   `json:"executable"`
	Owner      string   `json:"owner,omitempty"`
	ID         string   `json:"id"`
	Resource   string   `json:"resource"`
	Severity   string   `json:"severity"`
	Title      string   `json:"title"`
	Saves      *Savings `json:"saves"`
	Confidence string   `json:"confidence"`
}

// maxSuggestions bounds the ranked list. Past a few hundred, a person is
// not reading suggestions any more; the rest are still on each
// workflow's own page.
const maxSuggestions = 500

// Summarize is the compact form of a Response.
func Summarize(r *Response) *Summary {
	s := &Summary{
		Since: r.Since, Until: r.Until, Days: r.Days, JobsConsidered: r.JobsConsidered,
		Truncated: r.Truncated, Limit: r.Limit, MaxLimit: r.MaxLimit,
		Overall: r.Overall, Owners: r.Owners,
		Workflows:   make([]WorkflowSummary, 0, len(r.Workflows)),
		Suggestions: []Suggestion{},
	}
	type ranked struct {
		s    Suggestion
		wall float64
	}
	var all []ranked
	for i := range r.Workflows {
		w := &r.Workflows[i]
		s.Workflows = append(s.Workflows, summarizeWorkflow(w))
		for _, a := range w.Advice {
			all = append(all, ranked{wall: w.WallHours, s: Suggestion{
				Key: w.Key, Name: w.Name, Executable: w.Executable, Owner: w.Owner,
				ID: a.ID, Resource: a.Resource, Severity: a.Severity, Title: a.Title,
				Saves: a.Saves, Confidence: a.Confidence,
			}})
		}
	}
	// The same order as a workflow's own advice -- most urgent, then GPU
	// hours ahead of any other saving, then the larger saving -- with the
	// busier workflow first among equals.
	slices.SortStableFunc(all, func(a, b ranked) int {
		x, y := Advice{Severity: a.s.Severity, Saves: a.s.Saves}, Advice{Severity: b.s.Severity, Saves: b.s.Saves}
		return cmp.Or(
			cmp.Compare(severityRank(x.Severity), severityRank(y.Severity)),
			cmp.Compare(savesGPU(y), savesGPU(x)),
			cmp.Compare(savedAmount(y), savedAmount(x)),
			cmp.Compare(b.wall, a.wall),
		)
	})
	for _, a := range all[:min(len(all), maxSuggestions)] {
		s.Suggestions = append(s.Suggestions, a.s)
	}
	return s
}

func summarizeWorkflow(w *Workflow) WorkflowSummary {
	name := w.Name
	if name == w.Executable {
		name = ""
	}
	ws := WorkflowSummary{
		Key: w.Key, Name: name, Executable: w.Executable, Owner: w.Owner, Schedd: w.Schedd,
		IsDAG: w.IsDAG, Jobs: w.Jobs, Succeeded: w.Succeeded, Failed: w.Failed, Removed: w.Removed,
		WallHours: round(w.WallHours, 1), Advice: make([]AdviceBrief, 0, len(w.Advice)),
	}
	if w.Holds.Memory > 0 || w.Holds.Disk > 0 {
		h := w.Holds
		ws.Holds = &h
	}
	typical := func(r *Request, name string) *float64 {
		if r == nil {
			return nil
		}
		if r.Adaptive {
			ws.Request.Adaptive = append(ws.Request.Adaptive, name)
		}
		return ptr(r.Typical, 3)
	}
	ws.Request.MemoryMiB = typical(w.Memory.Request, ResourceMemory)
	ws.Request.Cpus = typical(w.CPU.Request, "cpus")
	ws.Request.DiskKiB = typical(w.Disk.Request, ResourceDisk)
	if w.GPU != nil {
		ws.Request.GPUs = typical(w.GPU.Request, "gpus")
	}
	for _, r := range w.Resources {
		var used *float64
		if r.UsedHours != nil && r.AllocatedHoursMeasured > 0 {
			used = ptr(*r.UsedHours/r.AllocatedHoursMeasured, 3)
		}
		switch r.Resource {
		case ResourceCPU:
			ws.Used.CPU = used
		case ResourceMemory:
			ws.Used.Memory = used
		case ResourceDisk:
			ws.Used.Disk = used
		case ResourceGPU:
			ws.Used.GPU = used
			ws.GPUHours = ptr(r.AllocatedHours, 1)
		}
	}
	if t := w.Throughput; t != nil {
		gain, limited := t.Gain, t.SlotsLimited
		ws.Gain, ws.SlotsLimited = &gain, &limited
	}
	for _, a := range w.Advice {
		ws.Advice = append(ws.Advice, AdviceBrief{ID: a.ID, Severity: a.Severity, Saves: a.Saves})
	}
	return ws
}
