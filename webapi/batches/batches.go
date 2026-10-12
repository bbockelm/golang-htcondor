// Package batches is what a "batch" is: the jobs the /jobs page shows as
// one row.
//
// The rule is groupIntoBatches in frontend/src/lib/batches.ts, ported
// once so the server can name, find and summarize the same set of jobs
// the row stands for. The two are pinned to each other by
// testdata/grouping.json, which a Go test and a vitest both check: a
// change to either side has to keep both green.
//
//   - A DAG is every job sharing the DAG's JobBatchName, "<name>+<root>":
//     node jobs, nested sub-DAGs and the DAGMan jobs alike. Its id is the
//     root DAGMan cluster, the number after the "+".
//   - A named batch that is not a DAG is every job of one owner under one
//     JobBatchName, across however many clusters; its id is the smallest
//     of them.
//   - Anything else is one cluster.
package batches

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// Kind is what sort of batch a set of jobs is.
type Kind string

// The kinds of batch.
const (
	KindDAG     Kind = "dag"
	KindNamed   Kind = "named"
	KindCluster Kind = "cluster"
)

// Fields is what the grouping reads of one job ad. The JSON names are the
// attributes', so a fixture of job ads decodes into it directly.
type Fields struct {
	ClusterID      *int64 `json:"ClusterId,omitempty"`
	ProcID         *int64 `json:"ProcId,omitempty"`
	Owner          string `json:"Owner,omitempty"`
	JobBatchName   string `json:"JobBatchName,omitempty"`
	Cmd            string `json:"Cmd,omitempty"`
	QDate          *int64 `json:"QDate,omitempty"`
	JobStatus      *int64 `json:"JobStatus,omitempty"`
	HoldReasonCode *int64 `json:"HoldReasonCode,omitempty"`
	DAGManJobID    *int64 `json:"DAGManJobId,omitempty"`
	DAGNodesTotal  *int64 `json:"DAG_NodesTotal,omitempty"`
	DAGNodesDone   *int64 `json:"DAG_NodesDone,omitempty"`
	DAGNodesFailed *int64 `json:"DAG_NodesFailed,omitempty"`
	DAGNodesQueued *int64 `json:"DAG_NodesQueued,omitempty"`
	TotalProcs     *int64 `json:"TotalSubmitProcs,omitempty"`
	NextProcID     *int64 `json:"JobMaterializeNextProcId,omitempty"`
}

// Attrs is what FieldsFromAd reads, for a projection.
var Attrs = []string{
	"ClusterId", "ProcId", "Owner", "JobBatchName", "Cmd", "QDate", "JobStatus", "HoldReasonCode",
	"DAGManJobId", "DAG_NodesTotal", "DAG_NodesDone", "DAG_NodesFailed", "DAG_NodesQueued",
	"TotalSubmitProcs", "JobMaterializeNextProcId",
}

// FieldsFromAd reads a job ad's Fields.
func FieldsFromAd(ad *classad.ClassAd) Fields {
	num := func(name string) *int64 {
		if v, ok := ad.EvaluateAttrNumber(name); ok {
			n := int64(v)
			return &n
		}
		return nil
	}
	str := func(name string) string {
		s, _ := ad.EvaluateAttrString(name)
		return s
	}
	return Fields{
		ClusterID: num("ClusterId"), ProcID: num("ProcId"),
		Owner: str("Owner"), JobBatchName: str("JobBatchName"), Cmd: str("Cmd"),
		QDate: num("QDate"), JobStatus: num("JobStatus"), HoldReasonCode: num("HoldReasonCode"),
		DAGManJobID:    num("DAGManJobId"),
		DAGNodesTotal:  num("DAG_NodesTotal"),
		DAGNodesDone:   num("DAG_NodesDone"),
		DAGNodesFailed: num("DAG_NodesFailed"),
		DAGNodesQueued: num("DAG_NodesQueued"),
		TotalProcs:     num("TotalSubmitProcs"),
		NextProcID:     num("JobMaterializeNextProcId"),
	}
}

// IsDagManJob reports whether a job is a DAG's workflow manager, root or
// nested: DAG_NodesTotal is conclusive once DAGMan has started, and
// before that the command is the only sign.
func (f *Fields) IsDagManJob() bool {
	if f.DAGNodesTotal != nil {
		return true
	}
	cmd := strings.TrimSpace(f.Cmd)
	return cmd == "condor_dagman" || strings.HasSuffix(cmd, "/condor_dagman")
}

// IsDagNode reports whether DAGMan submitted the job: a node, or a nested
// sub-DAG's DAGMan.
func (f *Fields) IsDagNode() bool { return f.DAGManJobID != nil }

// Status is how the pages name a job's state (displayJobStatus).
type Status string

// The display statuses, in the order the pages list them.
const (
	StatusRunning      Status = "running"
	StatusIdle         Status = "idle"
	StatusUploading    Status = "uploading"
	StatusTransferring Status = "transferring"
	StatusHeld         Status = "held"
	StatusSuspended    Status = "suspended"
	StatusCompleted    Status = "completed"
	StatusRemoved      Status = "removed"
	StatusUnknown      Status = "unknown"
)

// holdSpoolingInput is the hold a job sits in while its inputs upload.
const holdSpoolingInput = 16

// DisplayStatus is displayJobStatus: JobStatus, with a job held while its
// inputs upload shown as uploading.
func DisplayStatus(status, holdCode *int64) Status {
	if status == nil {
		return StatusUnknown
	}
	if *status == 5 && holdCode != nil && *holdCode == holdSpoolingInput {
		return StatusUploading
	}
	switch *status {
	case 1:
		return StatusIdle
	case 2:
		return StatusRunning
	case 3:
		return StatusRemoved
	case 4:
		return StatusCompleted
	case 5:
		return StatusHeld
	case 6:
		return StatusTransferring
	case 7:
		return StatusSuspended
	}
	return StatusUnknown
}

// Status is the job's display status.
func (f *Fields) Status() Status { return DisplayStatus(f.JobStatus, f.HoldReasonCode) }

// dagSuffix is the "+<root>" HTCondor appends to a DAG's JobBatchName.
var dagSuffix = regexp.MustCompile(`\+(\d+)\s*$`)

// Identity is a batch's name and the constraints that select it.
type Identity struct {
	Kind  Kind
	ID    int64
	Name  string
	Owner string
	// Select names the batch's jobs wherever they are, in the queue or
	// long finished (selectConstraint).
	Select string
	// Remove is what removing the batch removes (removeConstraint).
	Remove string
	// Jobs selects exactly the batch's jobs: Select, with a DAG's owner
	// too. The jobs page folds a batch by owner and name, but its
	// selectConstraint names a DAG by its name alone, which another user
	// can reuse ("+N" is the root's cluster, but nothing stops a submit
	// file from writing it).
	Jobs string
}

// identity is the batch a group of jobs under batchName and owner, whose
// smallest cluster is minCluster, makes.
func identity(batchName, owner string, minCluster int64) Identity {
	if batchName != "" {
		if m := dagSuffix.FindStringSubmatch(batchName); m != nil {
			// A root cluster too large to be one is a name, not a DAG.
			if root, err := strconv.ParseInt(m[1], 10, 64); err == nil {
				sel := `JobBatchName == "` + escape(batchName) + `"`
				jobs := sel
				if owner != "" {
					jobs += ` && Owner == "` + escape(owner) + `"`
				}
				return Identity{
					Kind: KindDAG, ID: root, Owner: owner,
					Name:   dagSuffix.ReplaceAllString(batchName, ""),
					Select: sel,
					Remove: sel + " || ClusterId == " + strconv.FormatInt(root, 10),
					Jobs:   jobs,
				}
			}
		}
		sel := `JobBatchName == "` + escape(batchName) + `"`
		if owner != "" {
			sel += ` && Owner == "` + escape(owner) + `"`
		}
		return Identity{Kind: KindNamed, ID: minCluster, Name: batchName, Owner: owner, Select: sel, Remove: sel, Jobs: sel}
	}
	c := strconv.FormatInt(minCluster, 10)
	return Identity{Kind: KindCluster, ID: minCluster, Name: c, Owner: owner, Select: "ClusterId == " + c, Remove: "ClusterId == " + c, Jobs: "ClusterId == " + c}
}

// Identify is the batch one job belongs to, as far as that job alone can
// tell: a named batch's id is the smallest of its clusters, which only
// the whole set knows, so it is this job's cluster here.
func Identify(f *Fields) (Identity, bool) {
	if f.ClusterID == nil {
		return Identity{}, false
	}
	return identity(f.JobBatchName, f.Owner, *f.ClusterID), true
}

// escape is escapeClassAdString: a string for a ClassAd string literal.
func escape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`)
}

// GroupKey is batchGroupKey: the key a job folds under, false for a job
// with no ClusterId.
func GroupKey(f *Fields) (string, bool) {
	if f.ClusterID == nil {
		return "", false
	}
	if f.JobBatchName != "" {
		return f.Owner + "\x00" + f.JobBatchName, true
	}
	return "cluster\x00" + strconv.FormatInt(*f.ClusterID, 10), true
}

// Batch is one row's worth of jobs.
type Batch struct {
	Identity
	GroupKey  string
	JobCount  int
	Submitted *int64
	// Clusters is every ClusterId in the batch, in the order first seen.
	Clusters     []int64
	StatusCounts map[Status]int
	// DagNodes is the root DAGMan jobs' node counts, nil when there is
	// none or one has not reported.
	DagNodes *DagNodeCounts
	// Members indexes the jobs Group was given that are in this batch.
	Members []int
}

// DagNodeCounts is a DAG's node counts as its root DAGMan jobs publish
// them.
type DagNodeCounts struct {
	Total, Done, Failed, Queued int64
}

// dagNodeCounts sums the roots' counts; nil when there is no root, or one
// has not reported.
func dagNodeCounts(roots []*Fields) *DagNodeCounts {
	if len(roots) == 0 {
		return nil
	}
	var c DagNodeCounts
	for _, r := range roots {
		if r.DAGNodesTotal == nil {
			return nil
		}
		c.Total += *r.DAGNodesTotal
		c.Done += val(r.DAGNodesDone)
		c.Failed += val(r.DAGNodesFailed)
		c.Queued += val(r.DAGNodesQueued)
	}
	return &c
}

func val(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// Group is groupIntoBatches: the jobs folded into batches, newest batch
// (largest id) first.
func Group(jobs []Fields) []Batch {
	type acc struct {
		batchName, owner string
		b                Batch
		minCluster       int64
		roots            []*Fields
	}
	byKey := map[string]*acc{}
	var order []string
	for i := range jobs {
		j := &jobs[i]
		key, ok := GroupKey(j)
		if !ok {
			continue
		}
		cluster := *j.ClusterID
		a := byKey[key]
		if a == nil {
			a = &acc{batchName: j.JobBatchName, owner: j.Owner, minCluster: cluster,
				b: Batch{GroupKey: key, StatusCounts: map[Status]int{}}}
			byKey[key] = a
			order = append(order, key)
		}
		a.b.JobCount++
		if !slices.Contains(a.b.Clusters, cluster) {
			a.b.Clusters = append(a.b.Clusters, cluster)
		}
		a.minCluster = min(a.minCluster, cluster)
		a.b.StatusCounts[j.Status()]++
		if j.QDate != nil && (a.b.Submitted == nil || *j.QDate < *a.b.Submitted) {
			q := *j.QDate
			a.b.Submitted = &q
		}
		if a.owner == "" {
			a.owner = j.Owner
		}
		if j.IsDagManJob() && !j.IsDagNode() {
			a.roots = append(a.roots, j)
		}
		a.b.Members = append(a.b.Members, i)
	}
	out := make([]Batch, 0, len(order))
	for _, key := range order {
		a := byKey[key]
		a.b.Identity = identity(a.batchName, a.owner, a.minCluster)
		a.b.DagNodes = dagNodeCounts(a.roots)
		out = append(out, a.b)
	}
	slices.SortStableFunc(out, func(x, y Batch) int {
		switch {
		case x.ID > y.ID:
			return -1
		case x.ID < y.ID:
			return 1
		}
		return 0
	})
	return out
}
