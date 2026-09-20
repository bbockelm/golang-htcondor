package httpserver

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// A partitionable slot on a GPU node with 6 of 8 GPUs and 96 of 128 CPUs in
// use, its primary slot reporting 6 running jobs.
func gpuPartitionable(t *testing.T) *classad.ClassAd {
	return mustAd(t, `[
		Name = "slot1@gpu1"; Machine = "gpu1"; SlotType = "Partitionable";
		PartitionableSlot = true; State = "Unclaimed"; Activity = "Idle";
		Cpus = 32; Memory = 64000; GPUs = 2;
		TotalCpus = 128; TotalMemory = 256000; TotalGPUs = 8;
		NumDynamicSlots = 6 ]`)
}

func TestParsePoolSlotGPUCasingAndTotals(t *testing.T) {
	s := parsePoolSlot(gpuPartitionable(t))
	if s.totalGpus != 8 {
		t.Errorf("totalGpus = %v, want 8 (TotalGPUs must resolve case-insensitively)", s.totalGpus)
	}
	if s.gpus != 2 || s.totalCpus != 128 {
		t.Errorf("gpus=%v totalCpus=%v, want 2 and 128", s.gpus, s.totalCpus)
	}
	if s.numDynamicSlots != 6 {
		t.Errorf("numDynamicSlots = %v, want 6", s.numDynamicSlots)
	}
}

func TestParsePoolSlotLowercaseKeys(t *testing.T) {
	// The wire may present any casing; ClassAd reads are case-insensitive.
	ad := mustAd(t, `[ name = "slot1@h"; machine = "h"; slottype = "Partitionable";
		partitionableslot = true; cpus = 4; totalcpus = 16; totalgpus = 4; gpus = 1 ]`)
	s := parsePoolSlot(ad)
	if s.totalGpus != 4 || s.totalCpus != 16 || !s.partitionable {
		t.Errorf("lowercase keys not read: %+v", s)
	}
}

func TestAggregateExcludesBackfill(t *testing.T) {
	primary := gpuPartitionable(t)
	// A backfill slot re-advertising the same cores/GPUs — must not add to
	// capacity or usage, only to the separate backfill-CPU figure.
	backfill := mustAd(t, `[ Name = "slot1_1@gpu1"; Machine = "gpu1"; SlotType = "Static";
		BackfillSlot = true; State = "Claimed"; Cpus = 96;
		TotalCpus = 128; TotalMemory = 256000; TotalGPUs = 8 ]`)

	withoutBF := aggregatePoolSummary([]*classad.ClassAd{primary})
	withBF := aggregatePoolSummary([]*classad.ClassAd{primary, backfill})

	if withBF.Summary.Usage != withoutBF.Summary.Usage {
		t.Errorf("backfill changed usage: %+v vs %+v", withBF.Summary.Usage, withoutBF.Summary.Usage)
	}
	if withBF.Summary.BackfillCpus != 96 {
		t.Errorf("BackfillCpus = %v, want 96", withBF.Summary.BackfillCpus)
	}
	if withBF.Summary.Machines != 1 {
		t.Errorf("Machines = %d, want 1 (backfill is not a separate machine)", withBF.Summary.Machines)
	}
	u := withBF.Summary.Usage
	if u.TotalCpus != 128 || u.UsedCpus != 96 || u.TotalGpus != 8 || u.UsedGpus != 6 {
		t.Errorf("usage = %+v, want used 96/128 cpu, 6/8 gpu", u)
	}
}

func TestRunningJobsAndOwner(t *testing.T) {
	part := gpuPartitionable(t) // 6 dynamic slots
	ownerNode := mustAd(t, `[ Name = "slot1@own"; Machine = "own"; SlotType = "Partitionable";
		PartitionableSlot = true; State = "Owner"; Cpus = 8; TotalCpus = 8; NumDynamicSlots = 0 ]`)
	staticClaimed := mustAd(t, `[ Name = "slot1@st"; Machine = "st"; SlotType = "Static";
		State = "Claimed"; Cpus = 4; TotalCpus = 4; Memory = 8000; TotalMemory = 8000 ]`)

	got := aggregatePoolSummary([]*classad.ClassAd{part, ownerNode, staticClaimed})
	if got.Summary.RunningJobs != 7 { // 6 dynamic + 1 claimed static
		t.Errorf("RunningJobs = %d, want 7", got.Summary.RunningJobs)
	}
	if got.Summary.OwnerNodes != 1 {
		t.Errorf("OwnerNodes = %d, want 1", got.Summary.OwnerNodes)
	}
	if got.Summary.Machines != 3 {
		t.Errorf("Machines = %d, want 3", got.Summary.Machines)
	}
	// The claimed static node's own resources count as used.
	var st *nodeSummary
	for i := range got.Nodes {
		if got.Nodes[i].Machine == "st" {
			st = &got.Nodes[i]
		}
	}
	if st == nil || st.Usage.UsedCpus != 4 || st.RunningJobs != 1 {
		t.Errorf("static-claimed node = %+v, want used 4 cpu / 1 running", st)
	}
}
