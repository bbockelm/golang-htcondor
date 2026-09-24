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

func TestAggregateCountsBackfillUsage(t *testing.T) {
	primary := gpuPartitionable(t) // 32 cpu / 2 gpu free of 128 / 8
	// The backfill partition on the same machine: a second partitionable
	// slot re-advertising the machine Total*, with 16 cpu / 1 gpu free.
	backfill := mustAd(t, `[ Name = "backfill1@gpu1"; Machine = "gpu1"; SlotType = "Partitionable";
		PartitionableSlot = true; BackfillSlot = true; State = "Unclaimed";
		Cpus = 16; GPUs = 1; TotalCpus = 128; TotalMemory = 256000; TotalGPUs = 8;
		NumDynamicSlots = 20 ]`)

	got := aggregatePoolSummary([]*classad.ClassAd{primary, backfill})

	if got.Summary.Machines != 1 {
		t.Errorf("Machines = %d, want 1 (backfill is not a separate machine)", got.Summary.Machines)
	}
	if got.Summary.RunningJobs != 26 { // primary 6 + backfill 20
		t.Errorf("RunningJobs = %d, want 26", got.Summary.RunningJobs)
	}
	if got.Summary.BackfillCpus != 112 { // 128 - 16 free
		t.Errorf("BackfillCpus = %v, want 112", got.Summary.BackfillCpus)
	}
	u := got.Summary.Usage
	// Capacity counted once; used driven by residual free = min across
	// partitions: cpu min(32,16)=16 -> 112; gpu min(2,1)=1 -> 7.
	if u.TotalCpus != 128 || u.UsedCpus != 112 || u.TotalGpus != 8 || u.UsedGpus != 7 {
		t.Errorf("usage = %+v, want used 112/128 cpu, 7/8 gpu", u)
	}
}

func TestAggregateIdlePrimaryBackfillBusy(t *testing.T) {
	// The reported bug: a node whose primary partition is idle (all free)
	// but whose backfill partition is nearly full showed 0 used.
	primary := mustAd(t, `[ Name = "slot1@e1"; Machine = "e1"; SlotType = "Partitionable";
		PartitionableSlot = true; State = "Unclaimed"; Cpus = 128; GPUs = 8;
		TotalCpus = 128; TotalGPUs = 8; NumDynamicSlots = 0 ]`)
	backfill := mustAd(t, `[ Name = "backfill1@e1"; Machine = "e1"; SlotType = "Partitionable";
		PartitionableSlot = true; BackfillSlot = true; State = "Unclaimed";
		Cpus = 4; GPUs = 1; TotalCpus = 128; TotalGPUs = 8; NumDynamicSlots = 80 ]`)

	got := aggregatePoolSummary([]*classad.ClassAd{primary, backfill})
	u := got.Summary.Usage
	if u.UsedCpus != 124 || u.TotalCpus != 128 || u.UsedGpus != 7 || u.TotalGpus != 8 {
		t.Errorf("usage = %+v, want used 124/128 cpu, 7/8 gpu", u)
	}
	if got.Summary.RunningJobs != 80 {
		t.Errorf("RunningJobs = %d, want 80", got.Summary.RunningJobs)
	}
	if got.Summary.BackfillCpus != 124 {
		t.Errorf("BackfillCpus = %v, want 124", got.Summary.BackfillCpus)
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
