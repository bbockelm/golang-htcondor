package batches

import (
	"encoding/json"
	"maps"
	"os"
	"slices"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// groupingFixture is testdata/grouping.json, which the frontend's
// groupIntoBatches is checked against too.
type groupingFixture struct {
	Cases []struct {
		Name     string   `json:"name"`
		Ads      []Fields `json:"ads"`
		Expected []struct {
			BatchID          int64          `json:"batchID"`
			Name             string         `json:"name"`
			Owner            string         `json:"owner"`
			IsDag            bool           `json:"isDag"`
			JobCount         int            `json:"jobCount"`
			ClusterIDs       []int64        `json:"clusterIds"`
			SubmittedUnix    *int64         `json:"submittedUnix"`
			StatusCounts     map[Status]int `json:"statusCounts"`
			DagNodes         *DagNodesJSON  `json:"dagNodes"`
			SelectConstraint string         `json:"selectConstraint"`
			RemoveConstraint string         `json:"removeConstraint"`
		} `json:"expected"`
	} `json:"cases"`
}

// DagNodesJSON is DagNodeCounts as the fixture spells it.
type DagNodesJSON struct {
	Total, Done, Failed, Queued int64
}

// The Go grouping is the frontend's: every case of the shared fixture.
func TestGroupMatchesFrontend(t *testing.T) {
	raw, err := os.ReadFile("testdata/grouping.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx groupingFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	if len(fx.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range fx.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got := Group(c.Ads)
			if len(got) != len(c.Expected) {
				t.Fatalf("%d batches, want %d", len(got), len(c.Expected))
			}
			for i, want := range c.Expected {
				b := got[i]
				clusters := slices.Sorted(slices.Values(b.Clusters))
				var nodes *DagNodesJSON
				if b.DagNodes != nil {
					nodes = &DagNodesJSON{b.DagNodes.Total, b.DagNodes.Done, b.DagNodes.Failed, b.DagNodes.Queued}
				}
				counts := maps.Clone(b.StatusCounts)
				maps.DeleteFunc(counts, func(_ Status, n int) bool { return n == 0 })
				switch {
				case b.ID != want.BatchID, b.Name != want.Name, b.Owner != want.Owner,
					(b.Kind == KindDAG) != want.IsDag, b.JobCount != want.JobCount,
					!slices.Equal(clusters, want.ClusterIDs),
					b.Select != want.SelectConstraint, b.Remove != want.RemoveConstraint:
					t.Errorf("batch %d = %+v\nwant %+v", i, b, want)
				}
				if (b.Submitted == nil) != (want.SubmittedUnix == nil) || (b.Submitted != nil && *b.Submitted != *want.SubmittedUnix) {
					t.Errorf("batch %d submitted = %v, want %v", i, b.Submitted, want.SubmittedUnix)
				}
				if !maps.Equal(counts, want.StatusCounts) {
					t.Errorf("batch %d status counts = %v, want %v", i, counts, want.StatusCounts)
				}
				if (nodes == nil) != (want.DagNodes == nil) || (nodes != nil && *nodes != *want.DagNodes) {
					t.Errorf("batch %d dag nodes = %+v, want %+v", i, nodes, want.DagNodes)
				}
			}
		})
	}
}

// Identify, from one job, names the batch Group puts it in -- for a named
// batch, up to the id, which needs every cluster.
func TestIdentifyAgreesWithGroup(t *testing.T) {
	raw, _ := os.ReadFile("testdata/grouping.json")
	var fx groupingFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	for _, c := range fx.Cases {
		batches := Group(c.Ads)
		for i := range c.Ads {
			id, ok := Identify(&c.Ads[i])
			key, _ := GroupKey(&c.Ads[i])
			if !ok {
				continue
			}
			for _, b := range batches {
				if b.GroupKey != key {
					continue
				}
				if id.Kind != b.Kind || id.Select != b.Select || id.Name != b.Name {
					t.Errorf("%s: ad %d identified as %+v, grouped in %+v", c.Name, i, id, b.Identity)
				}
				if id.Kind != KindNamed && id.ID != b.ID {
					t.Errorf("%s: ad %d id %d, batch %d", c.Name, i, id.ID, b.ID)
				}
			}
		}
	}
}

// FieldsFromAd reads the same fields from a ClassAd as the fixture's JSON.
func TestFieldsFromAd(t *testing.T) {
	ad, err := classad.ParseOld(`ClusterId = 103
ProcId = 1
Owner = "alice"
JobBatchName = "ny50.dag+100"
DAGManJobId = 102
Cmd = "/usr/bin/condor_dagman"
JobStatus = 5
HoldReasonCode = 16
QDate = 1030
DAG_NodesTotal = 4
TotalSubmitProcs = 2
JobMaterializeNextProcId = 2`)
	if err != nil {
		t.Fatal(err)
	}
	f := FieldsFromAd(ad)
	if *f.ClusterID != 103 || *f.ProcID != 1 || f.Owner != "alice" || f.JobBatchName != "ny50.dag+100" ||
		*f.DAGManJobID != 102 || !f.IsDagNode() || !f.IsDagManJob() || f.Status() != StatusUploading ||
		*f.QDate != 1030 || *f.TotalProcs != 2 || *f.NextProcID != 2 || f.DAGNodesDone != nil {
		t.Errorf("fields = %+v", f)
	}
}

// A DAG's jobs are every job under its name; a named batch's, its owner's.
func TestIdentityJobs(t *testing.T) {
	for _, c := range []struct {
		f    Fields
		jobs string
	}{
		{Fields{ClusterID: p64(5), Owner: "alice", JobBatchName: "a.dag+5"}, `JobBatchName == "a.dag+5"`},
		{Fields{ClusterID: p64(5), Owner: "alice", JobBatchName: "x"}, `JobBatchName == "x" && Owner == "alice"`},
		{Fields{ClusterID: p64(5), Owner: "alice"}, `ClusterId == 5`},
	} {
		id, _ := Identify(&c.f)
		if id.Jobs != c.jobs {
			t.Errorf("%+v: jobs %q, want %q", c.f, id.Jobs, c.jobs)
		}
	}
}
