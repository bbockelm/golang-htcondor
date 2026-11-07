package htcondor

import (
	"strings"
	"testing"
)

// behaviorRequirements parses one submit file under one behavior and returns
// the Requirements expression it produced.
func behaviorRequirements(t *testing.T, src string, b SubmitBehavior) string {
	t.Helper()
	sf, err := ParseSubmitFileWithOptions(strings.NewReader(src), SubmitParseOptions{Behavior: b})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	expr, ok := ad.Lookup("Requirements")
	if !ok || expr == nil {
		t.Fatal("no Requirements in the job ad")
	}
	return expr.String()
}

const vanillaJob = "executable = /bin/true\nrequest_disk = 1024\nqueue\n"

// TestOmitVanillaDiskClause pins both shapes. The clause is only dropped for
// the vanilla universe, so the other universes are checked to still carry it:
// a gate that reached them would stop every job of those kinds from asking
// for the disk it needs.
func TestOmitVanillaDiskClause(t *testing.T) {
	on := SubmitBehavior{OmitVanillaDiskClause: true}

	if got := behaviorRequirements(t, vanillaJob, SubmitBehavior{}); !strings.Contains(got, "25.12.0") {
		t.Errorf("by default the versioned disk clause should be there, got %s", got)
	}
	if got := behaviorRequirements(t, vanillaJob, on); strings.Contains(got, "RequestDisk") {
		t.Errorf("with the gate the vanilla job should ask nothing about disk, got %s", got)
	}

	grid := "executable = /bin/true\nuniverse = grid\ngrid_resource = condor a b\nrequest_disk = 1024\nqueue\n"
	if got := behaviorRequirements(t, grid, on); !strings.Contains(got, "TARGET.Disk >= RequestDisk") {
		t.Errorf("the gate is vanilla-only and this universe must keep its clause, got %s", got)
	}
}

// TestOmitTransferVersionCheck pins the 8.9.7 clause, which only appears for
// a job whose transfer settings a pre-8.9.7 startd could not honor.
func TestOmitTransferVersionCheck(t *testing.T) {
	src := "executable = /bin/true\nwhen_to_transfer_output = ON_SUCCESS\ntransfer_output_files = out\nqueue\n"

	if got := behaviorRequirements(t, src, SubmitBehavior{}); !strings.Contains(got, "8.9.7") {
		t.Fatalf("by default this job should carry the version clause, got %s", got)
	}
	if got := behaviorRequirements(t, src, SubmitBehavior{OmitTransferVersionCheck: true}); strings.Contains(got, "8.9.7") {
		t.Errorf("with the gate the version clause should be gone, got %s", got)
	}
}

// TestOmitLocalAndSchedulerMachineChecks pins the universes on both sides of
// the gate. A clause removed from vanilla by mistake would stop jobs matching
// anywhere, so vanilla is checked to keep what local and scheduler lose.
func TestOmitLocalAndSchedulerMachineChecks(t *testing.T) {
	on := SubmitBehavior{OmitLocalAndSchedulerMachineChecks: true}

	for _, u := range []string{"local", "scheduler"} {
		src := "executable = /bin/true\nuniverse = " + u + "\nqueue\n"
		def := behaviorRequirements(t, src, SubmitBehavior{})
		if !strings.Contains(def, "TARGET.Arch") || !strings.Contains(def, "TARGET.OpSys") {
			t.Errorf("%s: by default Arch and OpSys should be there, got %s", u, def)
		}
		got := behaviorRequirements(t, src, on)
		for _, gone := range []string{"TARGET.Arch", "TARGET.OpSys"} {
			if strings.Contains(got, gone) {
				t.Errorf("%s: %s should be gone with the gate, got %s", u, gone, got)
			}
		}
	}

	// The scheduler universe additionally loses its disk clause, but only
	// with BOTH halves of HTCONDOR-3926 set. The branch that suppresses it
	// is the one for a job with no RequestDisk at all, and a job only
	// reaches it once the resource-default gate has stopped supplying one.
	// They are separate fields because they are separate decisions; this is
	// the shape upstream actually ships, so it is the one pinned here.
	both := SubmitBehavior{
		OmitLocalAndSchedulerMachineChecks:    true,
		OmitLocalAndSchedulerResourceDefaults: true,
	}
	schedSrc := "executable = /bin/true\nuniverse = scheduler\nqueue\n"
	if got := behaviorRequirements(t, schedSrc, both); strings.Contains(got, "TARGET.Disk") {
		t.Errorf("a scheduler job has no TARGET.Disk to compare against, got %s", got)
	}
	// Local universe keeps a disk clause: only the scheduler branch is
	// suppressed upstream.
	localSrc := "executable = /bin/true\nuniverse = local\nqueue\n"
	if got := behaviorRequirements(t, localSrc, both); !strings.Contains(got, "TARGET.Disk") {
		t.Errorf("the local universe keeps its disk clause, got %s", got)
	}

	vanilla := behaviorRequirements(t, vanillaJob, on)
	for _, kept := range []string{"TARGET.Arch", "TARGET.OpSys"} {
		if !strings.Contains(vanilla, kept) {
			t.Errorf("the gate is local/scheduler only and vanilla must keep %s, got %s", kept, vanilla)
		}
	}
}

// TestOmitLocalAndSchedulerResourceDefaults checks the other half of
// HTCONDOR-3926: with no startd to read them, the configured defaults are not
// applied at all.
func TestOmitLocalAndSchedulerResourceDefaults(t *testing.T) {
	params := SubmitParamMap{
		"JOB_DEFAULT_REQUESTCPUS":   "3",
		"JOB_DEFAULT_REQUESTMEMORY": "321",
	}
	parse := func(u string, b SubmitBehavior) map[string]bool {
		t.Helper()
		sf, err := ParseSubmitFileWithOptions(
			strings.NewReader("executable = /bin/true\nuniverse = "+u+"\nqueue\n"),
			SubmitParseOptions{Behavior: b, Params: params})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
		if err != nil {
			t.Fatalf("MakeJobAd: %v", err)
		}
		have := map[string]bool{}
		for _, n := range ad.GetAttributes() {
			have[strings.ToLower(n)] = true
		}
		return have
	}

	on := SubmitBehavior{OmitLocalAndSchedulerResourceDefaults: true}
	for _, u := range []string{"local", "scheduler"} {
		if !parse(u, SubmitBehavior{})["requestcpus"] {
			t.Errorf("%s: the configured default should apply by default", u)
		}
		if got := parse(u, on); got["requestcpus"] || got["requestmemory"] {
			t.Errorf("%s: no default request should be written with the gate", u)
		}
	}
	if !parse("vanilla", on)["requestcpus"] {
		t.Error("vanilla is not local or scheduler and must keep its defaults")
	}
}
