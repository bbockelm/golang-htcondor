package htcondor

import (
	"strings"
	"testing"
)

// TestSchedulerUniverseTakesNoTransferClauses pins the fix for a job that
// submits cleanly and then never runs.
//
// The schedd does not matchmake a scheduler- or local-universe job. It
// evaluates the job's Requirements against its OWN ad (Scheduler::jobCanRun,
// with Scheduler::publish's ad as TARGET), and treats undefined as false.
//
// That ad does carry Arch, OpSys, Memory, Disk and Cpus -- Scheduler::publish
// assigns all of them -- so the clause that actually broke DAGMan was
// TARGET.HasFileTransfer, which the schedd ad does not have (nor
// FileSystemDomain, nor the GPU attributes). condor_submit does not emit the
// transfer clauses here either: SetRequirements gates them on
// mightTransfer(JobUniverse), true only for vanilla/mpi/parallel/java/vm.
//
// This test used to drop the remaining machine clauses as well, and to say in
// its failure message that a schedd ad does not have them. That was more than
// the bug called for and the reason given was wrong: measured against
// condor_submit, a scheduler-universe job gets
// `(TARGET.Arch == ...) && (TARGET.OpSys == ...) && (TARGET.Disk >= RequestDisk)
// && (TARGET.Memory >= RequestMemory)` and nothing else, and every one of those
// attributes is on the schedd ad. So the clauses are kept now, and what this
// test pins is the part that actually broke: the transfer clauses.
//
// The only symptom of getting this wrong is the job sitting Idle with
// "SchedUniverseJobsIdle = 1" repeating in the schedd log, which is why this is
// worth a test rather than a comment.
func TestSchedulerUniverseTakesNoTransferClauses(t *testing.T) {
	for _, universe := range []string{"scheduler", "local"} {
		t.Run(universe, func(t *testing.T) {
			sf, err := ParseSubmitFile(strings.NewReader(
				"universe = " + universe + "\n" +
					"executable = /usr/bin/condor_dagman\n" +
					"transfer_executable = false\n" +
					"should_transfer_files = YES\n" +
					"when_to_transfer_output = ON_EXIT\n" +
					"transfer_input_files = wf.dag\n" +
					"request_memory = 64\n" +
					"queue\n"))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
			if err != nil {
				t.Fatalf("MakeJobAd: %v", err)
			}
			expr, ok := ad.Lookup("Requirements")
			if !ok {
				// Omitting the attribute used to look ideal -- the schedd
				// skips the check when it is absent. It is not: a schedd
				// can carry SUBMIT_REQUIREMENT expressions that reference
				// Requirements, and an absent attribute makes those
				// non-boolean and fails the submit outright. See
				// TestSchedulerUniverseRequirementsAreTrueNotAbsent.
				t.Fatal("Requirements is absent; it must be present and TRUE")
			}
			got := expr.String()
			for _, forbidden := range []string{"HasFileTransfer", "HasJobTransferPlugins", "FileSystemDomain"} {
				if strings.Contains(got, forbidden) {
					t.Errorf("Requirements = %s\ncontains %s, which a schedd ad does not have: "+
						"the clause is undefined, Requirements goes false, and the job never starts", got, forbidden)
				}
			}
			// The clauses condor_submit does emit here are kept, so this job
			// is matched against the schedd ad on the same terms.
			for _, wanted := range []string{"TARGET.Arch", "TARGET.OpSys"} {
				if !strings.Contains(got, wanted) {
					t.Errorf("Requirements = %s\nis missing %s, which condor_submit emits here", got, wanted)
				}
			}
		})
	}
}

// TestVanillaUniverseKeepsItsMachineRequirements is the other half: the
// skip above must not leak into the universe that does get matched, or
// every ordinary job loses the clauses that keep it off unsuitable slots.
func TestVanillaUniverseKeepsItsMachineRequirements(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(
		"universe = vanilla\nexecutable = /bin/true\nshould_transfer_files = YES\n" +
			"when_to_transfer_output = ON_EXIT\nrequest_memory = 64\nqueue\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	expr, ok := ad.Lookup("Requirements")
	if !ok {
		t.Fatal("a vanilla job lost its Requirements entirely")
	}
	got := expr.String()
	for _, want := range []string{"HasFileTransfer", "TARGET.Memory"} {
		if !strings.Contains(got, want) {
			t.Errorf("Requirements = %s, missing %s", got, want)
		}
	}
}

// TestSchedulerUniverseKeepsUserRequirements: what the user wrote IS
// evaluated against the schedd ad, so a site that constrains scheduler
// jobs that way must keep working.
func TestSchedulerUniverseKeepsUserRequirements(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(
		"universe = scheduler\nexecutable = /bin/true\nrequirements = TotalSchedulerJobsRunning < 10\nqueue\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	expr, ok := ad.Lookup("Requirements")
	if !ok {
		t.Fatal("the user's requirements were dropped")
	}
	if !strings.Contains(expr.String(), "TotalSchedulerJobsRunning") {
		t.Errorf("Requirements = %s, lost what the user wrote", expr.String())
	}
}

// TestSchedulerUniverseRequirementsAreTrueNotAbsent pins a submit that
// fails before the job ever reaches the queue.
//
// A schedd may carry SUBMIT_REQUIREMENT_<name> expressions, and they are
// allowed to reference the job's own Requirements. The OSPool access
// point has one:
//
//	SUBMIT_REQUIREMENT_ModulesWarning = ! unresolved(Requirements, "HAS_MODULES")
//
// With no Requirements attribute that reads `! undefined`, which is not a
// boolean, and the schedd rejects the transaction: "CommitTransaction
// failed: Submit requirement ModulesWarning evaluated to non-boolean".
// Every DAGMan submission to that access point failed this way, because
// the manager job is precisely the case that asks for nothing.
//
// What matters is that the attribute is THERE for such an expression to read.
// It was TRUE when this universe took no clauses at all; now it carries the
// same clauses condor_submit emits, so the test asserts presence and a
// well-defined boolean rather than a particular expression.
func TestSchedulerUniverseRequirementsAreNotAbsent(t *testing.T) {
	for _, universe := range []string{"scheduler", "local"} {
		t.Run(universe, func(t *testing.T) {
			sf, err := ParseSubmitFile(strings.NewReader(
				"universe = " + universe + "\n" +
					"executable = /usr/bin/condor_dagman\n" +
					"transfer_executable = false\n" +
					"queue\n"))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
			if err != nil {
				t.Fatalf("MakeJobAd: %v", err)
			}
			expr, ok := ad.Lookup("Requirements")
			if !ok {
				t.Fatal("Requirements is absent: a SUBMIT_REQUIREMENT that " +
					"references it evaluates to non-boolean and the submit is refused")
			}
			if strings.TrimSpace(expr.String()) == "" {
				t.Errorf("Requirements = %s, want an expression a SUBMIT_REQUIREMENT can read", expr.String())
			}
		})
	}
}

// A user who writes their own requirements on a scheduler-universe job
// must keep them -- the default must not overwrite what was asked for.
func TestSchedulerUniverseUserRequirementsBeatTheDefault(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(
		"universe = scheduler\n" +
			"executable = /usr/bin/condor_dagman\n" +
			"transfer_executable = false\n" +
			"requirements = (MY.Owner == \"alice\")\n" +
			"queue\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	expr, ok := ad.Lookup("Requirements")
	if !ok {
		t.Fatal("Requirements is absent")
	}
	if !strings.Contains(expr.String(), "alice") {
		t.Errorf("Requirements = %s, want the user's own expression", expr.String())
	}
}
