package batches

// Progress is how far along a batch is: lib/batchProgress.ts's
// progressOf, ported.
//
// The queue cannot answer it by counting, because a finished job leaves
// the queue; what it can answer is how many jobs each cluster started
// with (TotalSubmitProcs, or for a max_materialize factory, the procs it
// has queued so far, JobMaterializeNextProcId) and how many are still
// there, and the difference finished. A DAG is counted in nodes, from
// its root DAGMan jobs' own counts.
//
// The server reads finished jobs too, so a cluster that has left the
// queue still contributes its TotalSubmitProcs (from its history
// records), and every one of its jobs is done.
type Progress struct {
	Known bool `json:"known"`
	// Why is a key of PROGRESS_WHY, when Known is false.
	Why       string         `json:"why,omitempty"`
	Unit      string         `json:"unit,omitempty"`
	Total     int64          `json:"total"`
	Done      int64          `json:"done"`
	Failed    int64          `json:"failed"`
	Parts     []ProgressPart `json:"parts,omitempty"`
	NotQueued int64          `json:"notQueued"`
}

// ProgressPart is one segment of the bar.
type ProgressPart struct {
	Part  string `json:"part"`
	Count int64  `json:"count"`
}

// Reasons progress is unknown: PROGRESS_WHY's keys.
const (
	WhyPartial         = "partial"
	WhyNoTotal         = "noTotal"
	WhyDagNotReporting = "dagNotReporting"
	WhyDagMissing      = "dagMissing"
	WhyMixed           = "mixed"
)

func unknown(why string) Progress { return Progress{Why: why} }

// ProgressOf is one batch's progress over its jobs. complete says jobs
// holds every queued job of the batch: without that, a job missing from
// it is indistinguishable from one that finished. Where a cluster's
// attributes differ between jobs, the first job carrying one wins, so
// queue ads go first: their factory position is the current one.
func ProgressOf(jobs []Fields, complete bool) Progress {
	var roots []*Fields
	dagJobs := 0
	for i := range jobs {
		j := &jobs[i]
		if j.IsDagNode() || j.IsDagManJob() {
			dagJobs++
		}
		if j.IsDagManJob() && !j.IsDagNode() {
			roots = append(roots, j)
		}
	}
	if dagJobs > 0 {
		// A plain job sharing the workflow's batch name: nodes and jobs
		// are different units.
		if dagJobs != len(jobs) {
			return unknown(WhyMixed)
		}
		if len(roots) == 0 {
			return unknown(WhyDagMissing)
		}
		c := dagNodeCounts(roots)
		if c == nil {
			return unknown(WhyDagNotReporting)
		}
		other := max(0, c.Total-c.Done-c.Failed-c.Queued)
		return Progress{
			Known: true, Unit: "nodes", Total: c.Total, Done: c.Done, Failed: c.Failed,
			Parts: []ProgressPart{{"done", c.Done}, {"queued", c.Queued}, {"failed", c.Failed}, {"other", other}},
		}
	}
	if !complete {
		return unknown(WhyPartial)
	}
	return jobProgress(jobs)
}

func jobProgress(jobs []Fields) Progress {
	type cluster struct {
		totalProcs, nextProcID         *int64
		running, idle, held, otherLive int64
	}
	byID := map[int64]*cluster{}
	var order []int64
	for i := range jobs {
		j := &jobs[i]
		if j.ClusterID == nil {
			continue
		}
		c := byID[*j.ClusterID]
		if c == nil {
			c = &cluster{}
			byID[*j.ClusterID] = c
			order = append(order, *j.ClusterID)
		}
		if c.totalProcs == nil {
			c.totalProcs = j.TotalProcs
		}
		if c.nextProcID == nil {
			c.nextProcID = j.NextProcID
		}
		switch j.Status() {
		case StatusCompleted, StatusRemoved:
			// Finished, whether or not it has left the queue.
		case StatusRunning:
			c.running++
		case StatusIdle:
			c.idle++
		case StatusHeld:
			c.held++
		default:
			c.otherLive++
		}
	}
	p := Progress{Known: true, Unit: "jobs"}
	var running, idle, held, other int64
	for _, id := range order {
		c := byID[id]
		// One cluster without a total and the batch has none: a sum over
		// the others is a partial number dressed as a whole one.
		if c.totalProcs == nil {
			return unknown(WhyNoTotal)
		}
		total := *c.totalProcs
		queuedSoFar := total
		if c.nextProcID != nil {
			queuedSoFar = min(*c.nextProcID, total)
		}
		active := c.running + c.idle + c.held + c.otherLive
		p.Total += total
		p.Done += max(0, queuedSoFar-active)
		p.NotQueued += total - queuedSoFar
		running += c.running
		idle += c.idle
		held += c.held
		other += c.otherLive
	}
	p.Parts = []ProgressPart{
		{"done", p.Done}, {"running", running}, {"idle", idle + p.NotQueued}, {"held", held}, {"other", other},
	}
	return p
}
