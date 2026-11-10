package htcondor

import (
	"slices"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// attr is one attribute assignment for adWith.
type attr struct {
	name  string
	value any
}

// adWith builds a ClassAd from attribute assignments, in order, failing the
// test if any assignment does.
func adWith(t *testing.T, attrs ...attr) *classad.ClassAd {
	t.Helper()
	ad := classad.New()
	for _, a := range attrs {
		if err := ad.Set(a.name, a.value); err != nil {
			t.Fatalf("failed to set %s: %v", a.name, err)
		}
	}
	return ad
}

// exprOf parses a ClassAd expression for use as an attribute value.
func exprOf(t *testing.T, s string) *classad.Expr {
	t.Helper()
	expr, err := classad.ParseExpr(s)
	if err != nil {
		t.Fatalf("failed to parse expression %q: %v", s, err)
	}
	return expr
}

// wantSelected compares selectAttributes' result against the attributes it
// should have chosen, ignoring order: the order is whatever order the ClassAd
// library hands back, which is not part of this package's contract and has
// differed between classad releases. Duplicates still fail, since sorting
// preserves them.
func wantSelected(t *testing.T, label string, got []string, want ...string) {
	t.Helper()
	gotSorted := slices.Clone(got)
	wantSorted := slices.Clone(want)
	slices.Sort(gotSorted)
	slices.Sort(wantSorted)
	if !slices.Equal(gotSorted, wantSorted) {
		t.Errorf("selectAttributes(%s) = %v, want %v in any order", label, got, want)
	}
}

func TestPlacementOfIsCaseInsensitive(t *testing.T) {
	cases := map[string]attrPlacement{
		"Owner":        placeCluster,
		"owner":        placeCluster,
		"OWNER":        placeCluster,
		"JobUniverse":  placeCluster,
		"jobuniverse":  placeCluster,
		"User":         placeCluster,
		"NTDomain":     placeCluster,
		"JobSetId":     placeCluster,
		"JobSetName":   placeCluster,
		"ClusterId":    placeCluster,
		"ProcId":       placeProc,
		"procid":       placeProc,
		"JobStatus":    placeProc,
		"JOBSTATUS":    placeProc,
		"Cmd":          placeAny,
		"RequestCpus":  placeAny,
		"Requirements": placeAny,
	}
	for attr, want := range cases {
		if got := placementOf(attr); got != want {
			t.Errorf("placementOf(%q) = %v, want %v", attr, got, want)
		}
	}
}

func TestSelectAttributesForClusterAd(t *testing.T) {
	// A cluster ad keeps the attributes forced into it and drops the ones
	// forced into a proc ad. ClusterId is dropped here because
	// SendClusterAttributes sends it ahead of the loop.
	ad := adWith(t,
		attr{"ClusterId", int64(42)},
		attr{"ProcId", int64(0)},
		attr{"JobStatus", int64(1)},
		attr{"Owner", "alice"},
		attr{"User", "alice@example.com"},
		attr{"NTDomain", "EXAMPLE"},
		attr{"JobUniverse", int64(5)},
		attr{"JobSetName", "batch"},
		attr{"Cmd", "/bin/sleep"},
		attr{"RequestCpus", int64(1)},
	)

	wantSelected(t, "cluster", selectAttributes(ad, nil, placeCluster),
		"Owner", "User", "NTDomain", "JobUniverse", "JobSetName", "Cmd", "RequestCpus")
}

func TestSelectAttributesForProcAd(t *testing.T) {
	// A proc ad drops every forced attribute: ProcId and JobStatus because
	// SendProcAttributes sends them ahead of the loop, the rest because the
	// schedd will not store them on a proc.
	ad := adWith(t,
		attr{"ClusterId", int64(42)},
		attr{"ProcId", int64(3)},
		attr{"JobStatus", int64(1)},
		attr{"Owner", "alice"},
		attr{"User", "alice@example.com"},
		attr{"NTDomain", "EXAMPLE"},
		attr{"JobUniverse", int64(5)},
		attr{"JobSetName", "batch"},
		attr{"Cmd", "/bin/sleep"},
		attr{"Arguments", "3"},
	)

	wantSelected(t, "proc", selectAttributes(ad, nil, placeProc), "Cmd", "Arguments")
}

func TestSelectAttributesDeduplicatesAgainstClusterAd(t *testing.T) {
	cluster := adWith(t,
		attr{"Cmd", "/bin/sleep"},
		attr{"RequestCpus", int64(1)},
		attr{"Arguments", "0"},
		attr{"Requirements", exprOf(t, "Arch == \"X86_64\" && OpSys == \"LINUX\"")},
	)
	proc := adWith(t,
		attr{"Cmd", "/bin/sleep"},     // same as cluster: inherited
		attr{"RequestCpus", int64(2)}, // differs: must be sent
		attr{"Arguments", "7"},        // differs: must be sent
		attr{"Requirements", exprOf(t, "Arch == \"X86_64\" && OpSys == \"LINUX\"")}, // same expression tree
		attr{"Out", "job.7.out"}, // absent from cluster: must be sent
	)

	wantSelected(t, "dedup", selectAttributes(proc, cluster, placeProc),
		"RequestCpus", "Arguments", "Out")
}

func TestSelectAttributesDedupMatchesAcrossCasing(t *testing.T) {
	// ClassAd attribute names are case-insensitive, so a proc ad that spells
	// an attribute differently from the cluster ad still inherits its value.
	cluster := adWith(t, attr{"RequestMemory", int64(2048)})
	proc := adWith(t, attr{"requestmemory", int64(2048)})

	if got := selectAttributes(proc, cluster, placeProc); len(got) != 0 {
		t.Errorf("selectAttributes(dedup, differing case) = %v, want none", got)
	}
}

func TestSelectAttributesForFirstProcIsEmpty(t *testing.T) {
	// The first proc's ad *is* the cluster ad, so deduplicating it against
	// itself leaves nothing for the proc ad beyond the ProcId and JobStatus
	// that SendProcAttributes sends explicitly. This is what condor_submit
	// sends for proc 0 and the behavior issue #746 asks for.
	ad := adWith(t,
		attr{"ClusterId", int64(42)},
		attr{"ProcId", int64(0)},
		attr{"JobStatus", int64(1)},
		attr{"Owner", "alice"},
		attr{"JobUniverse", int64(5)},
		attr{"Cmd", "/bin/sleep"},
		attr{"Arguments", "0"},
		attr{"RequestCpus", int64(1)},
	)

	if got := selectAttributes(ad, ad, placeProc); len(got) != 0 {
		t.Errorf("selectAttributes(proc 0 against itself) = %v, want none", got)
	}
}

func TestSelectAttributesDoesNotMutateAd(t *testing.T) {
	// SubmitRemote hands the generated proc ads back to its caller for file
	// spooling, which reads Cmd and the transfer lists off them. Selection
	// must decide what to send without taking anything out of the ad.
	cluster := adWith(t, attr{"Cmd", "/bin/sleep"}, attr{"TransferInput", "data.txt"})
	proc := adWith(t,
		attr{"Cmd", "/bin/sleep"},
		attr{"TransferInput", "data.txt"},
		attr{"Arguments", "1"},
	)

	before := proc.GetAttributes()
	if got := selectAttributes(proc, cluster, placeProc); !slices.Equal(got, []string{"Arguments"}) {
		t.Fatalf("selectAttributes = %v, want [Arguments]", got)
	}
	if after := proc.GetAttributes(); !slices.Equal(before, after) {
		t.Errorf("selectAttributes mutated the ad: %v -> %v", before, after)
	}
	if _, ok := proc.Lookup("Cmd"); !ok {
		t.Error("selectAttributes removed Cmd from the proc ad")
	}
}

func TestSelectAttributesNilAd(t *testing.T) {
	if got := selectAttributes(nil, nil, placeProc); got != nil {
		t.Errorf("selectAttributes(nil) = %v, want nil", got)
	}
}

// The resource requests ride on the cluster ad, which is where condor_submit
// puts them: measured against the oracle in placement mode, a `queue 2`
// submission carries RequestCpus, RequestMemory and RequestDisk at proc id
// -1 and nothing at proc 1, and gives proc 1 its own RequestDisk only when
// the value actually differs there (`request_disk = $(Process)GB`).
//
// Here that falls out of the dedup rather than a forced placement: proc 0's
// ad becomes the cluster ad, and a later proc whose value matches the
// cluster's is skipped. The requests are placeAny, so this test is what says
// they land in one place and not on every proc -- one copy in the queue, and
// a `condor_qedit <clusterid> RequestMemory=...` that reaches the whole
// cluster instead of being shadowed by each proc's own copy.
func TestResourceRequestsRideOnTheClusterAd(t *testing.T) {
	cluster := adWith(t,
		attr{"ClusterId", int64(42)},
		attr{"ProcId", int64(0)},
		attr{"Cmd", "/bin/sleep"},
		attr{"RequestCpus", int64(1)},
		attr{"RequestMemory", int64(128)},
		attr{"RequestDisk", exprOf(t, "MAX({1024, (TransferInputSizeMB+1) * 1.25}) * 1024")},
	)
	wantSelected(t, "cluster", selectAttributes(cluster, nil, placeCluster),
		"Cmd", "RequestCpus", "RequestMemory", "RequestDisk")

	// A proc that asks for the same resources adds nothing.
	same := adWith(t,
		attr{"ProcId", int64(1)},
		attr{"Cmd", "/bin/sleep"},
		attr{"RequestCpus", int64(1)},
		attr{"RequestMemory", int64(128)},
		attr{"RequestDisk", exprOf(t, "MAX({1024, (TransferInputSizeMB+1) * 1.25}) * 1024")},
	)
	wantSelected(t, "proc-same", selectAttributes(same, cluster, placeProc))

	// A proc that asks for more carries only what differs, as condor_submit's
	// proc 1 carries only its own RequestDisk.
	differs := adWith(t,
		attr{"ProcId", int64(1)},
		attr{"Cmd", "/bin/sleep"},
		attr{"RequestCpus", int64(1)},
		attr{"RequestMemory", int64(128)},
		attr{"RequestDisk", int64(1048576)},
	)
	wantSelected(t, "proc-differs", selectAttributes(differs, cluster, placeProc), "RequestDisk")
}
