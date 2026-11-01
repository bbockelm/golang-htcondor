package htcondor

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// reqOf builds proc 0 and returns its Requirements as text.
func reqOf(t *testing.T, submit string) string {
	t.Helper()
	sf, err := ParseSubmitFileWithOptions(strings.NewReader(submit), SubmitParseOptions{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	expr, ok := ad.Lookup("Requirements")
	if !ok {
		t.Fatal("no Requirements on the ad")
	}
	return expr.String()
}

func wantsClause(t *testing.T, req, clause string) {
	t.Helper()
	if !strings.Contains(req, clause) {
		t.Errorf("Requirements %s\n  is missing %s", req, clause)
	}
}

func wantsNoClause(t *testing.T, req, clause string) {
	t.Helper()
	if strings.Contains(req, clause) {
		t.Errorf("Requirements %s\n  should not contain %s", req, clause)
	}
}

const reqVanilla = "executable = /bin/true\nqueue\n"

// Arch and OpSys are pinned to the submitting machine's platform, as
// SetRequirements pins them: a submit host's binaries do not run on another
// platform. Requiring merely that the attributes be defined -- which is what
// this parser used to do -- lets a job match a machine that cannot run it.
func TestRequirementsPinsArchAndOpSys(t *testing.T) {
	req := reqOf(t, reqVanilla)
	wantsClause(t, req, "TARGET.Arch == ")
	wantsClause(t, req, "TARGET.OpSys == ")
	wantsNoClause(t, req, "isnt undefined")
}

// A clause is dropped when the submitter's own requirements already names the
// machine attribute it would be about, so their expression replaces the
// generated one instead of being ANDed with it.
//
// Which attributes work that way is not uniform, and the asymmetry is
// condor_submit's: Arch, OpSys, Disk, Cpus and the custom resource tags are
// each suppressed by a reference to them, but MEMORY IS NOT. SetRequirements
// computes checks_mem and then uses it for nothing but a deprecation warning,
// so `requirements = TARGET.Memory > 8000` is ANDed with the generated
// `TARGET.Memory >= RequestMemory` rather than replacing it.
func TestRequirementsUserClauseSuppressesGenerated(t *testing.T) {
	req := reqOf(t, "requirements = TARGET.Arch == \"X86_64\" && TARGET.Memory > 8000\n"+reqVanilla)
	// Exactly one Arch clause: the submitter's.
	if n := strings.Count(req, "TARGET.Arch"); n != 1 {
		t.Errorf("Requirements %s\n  has %d Arch clauses, want 1", req, n)
	}
	// Memory is the exception -- both clauses are present.
	wantsClause(t, req, "TARGET.Memory > 8000")
	wantsClause(t, req, "TARGET.Memory >= RequestMemory")
	// An attribute they did not name is still generated.
	wantsClause(t, req, "TARGET.OpSys == ")
}

// Cpus, unlike Memory, IS suppressed by a reference to it.
func TestRequirementsCpuClauseSuppressedByUserReference(t *testing.T) {
	req := reqOf(t, "requirements = TARGET.Cpus > 4\nrequest_cpus = 8\n"+reqVanilla)
	wantsClause(t, req, "TARGET.Cpus > 4")
	wantsNoClause(t, req, "TARGET.Cpus >= RequestCpus")
}

// A MY-scoped reference is the JOB's attribute, not a machine's, so it does
// not suppress the machine clause of the same name.
func TestRequirementsMyScopeIsNotAMachineReference(t *testing.T) {
	req := reqOf(t, "requirements = MY.Memory > 0\n"+reqVanilla)
	wantsClause(t, req, "TARGET.Memory >= RequestMemory")
}

// The resource clauses carry a floor: a request of one CPU excludes no
// machine, so condor_submit adds no clause for it, and neither does this.
func TestRequirementsCpuClauseOnlyAboveOne(t *testing.T) {
	wantsNoClause(t, reqOf(t, reqVanilla), "TARGET.Cpus")
	wantsNoClause(t, reqOf(t, "request_cpus = 1\n"+reqVanilla), "TARGET.Cpus")
	wantsClause(t, reqOf(t, "request_cpus = 2\n"+reqVanilla), "TARGET.Cpus >= RequestCpus")
	// An expression has no number to compare, so it always gets its clause.
	wantsClause(t, reqOf(t, "request_cpus = CpusUsage\n"+reqVanilla), "TARGET.Cpus >= RequestCpus")
}

// The transfer clause offers the machine a choice -- share the submitter's
// filesystem, or be able to transfer -- and which halves appear depends on
// should_transfer_files.
func TestRequirementsTransferClauseFollowsTransferMode(t *testing.T) {
	ifNeeded := reqOf(t, reqVanilla)
	wantsClause(t, ifNeeded, "TARGET.FileSystemDomain == MY.FileSystemDomain")
	wantsClause(t, ifNeeded, "TARGET.HasFileTransfer")

	yes := reqOf(t, "should_transfer_files = YES\n"+reqVanilla)
	wantsClause(t, yes, "TARGET.HasFileTransfer")
	wantsNoClause(t, yes, "FileSystemDomain")

	no := reqOf(t, "should_transfer_files = NO\n"+reqVanilla)
	wantsClause(t, no, "TARGET.FileSystemDomain == MY.FileSystemDomain")
	wantsNoClause(t, no, "HasFileTransfer")
}

// A scheduler-universe job is run by the schedd and matched against the
// SCHEDD's ad, which advertises no HasFileTransfer at all. A transfer clause
// there evaluates to undefined, Requirements goes false, and the job sits Idle
// forever with nothing in the log but "SchedUniverseJobsIdle = 1" -- which is
// how every DAGMan submission to such an access point failed. condor_submit
// gates these clauses on mightTransfer() for the same reason.
func TestSchedulerUniverseTakesNoTransferClauseHere(t *testing.T) {
	for _, u := range []string{"scheduler", "local"} {
		req := reqOf(t, "universe = "+u+"\n"+reqVanilla)
		wantsNoClause(t, req, "HasFileTransfer")
		wantsNoClause(t, req, "FileSystemDomain")
	}
}

// A custom resource request becomes its own clause, which is also where the
// GPU clause comes from -- there is no GPU-specific code path.
func TestRequirementsCustomResourceClauses(t *testing.T) {
	// The tag keeps the casing the submitter used, because the attribute is
	// built from the keyword's own suffix: request_fpgas makes Requestfpgas
	// and asks about TARGET.fpgas, and request_FPGAs makes RequestFPGAs.
	req := reqOf(t, "request_fpgas = 2\n"+reqVanilla)
	wantsClause(t, req, "TARGET.fpgas >= Requestfpgas")

	upper := reqOf(t, "request_FPGAs = 2\n"+reqVanilla)
	wantsClause(t, upper, "TARGET.FPGAs >= RequestFPGAs")

	gpus := reqOf(t, "request_gpus = 1\n"+reqVanilla)
	wantsClause(t, gpus, "TARGET.Gpus >= RequestGpus")

	// A request of zero asks for nothing and takes no clause.
	none := reqOf(t, "request_fpgas = 0\n"+reqVanilla)
	wantsNoClause(t, none, "fpgas")
}

// A deferred job needs a starter that can defer and a window test, and the
// window test names ScheddInterval -- which is the only reason condor_submit
// writes that attribute, and the only reason this does.
func TestDeferralRequirementWritesScheddInterval(t *testing.T) {
	sf, err := ParseSubmitFileWithOptions(strings.NewReader("deferral_time = 1700000000\n"+reqVanilla), SubmitParseOptions{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	req, _ := ad.Lookup("Requirements")
	wantsClause(t, req.String(), "TARGET.HasJobDeferral")
	wantsClause(t, req.String(), "ScheddInterval")
	if _, ok := ad.Lookup("ScheddInterval"); !ok {
		t.Error("Requirements names ScheddInterval but the job does not carry it, so the expression is undefined")
	}
}

// A forced Requirements is the whole expression: nothing is generated and
// nothing is appended to it.
func TestForcedRequirementsWins(t *testing.T) {
	sf, err := ParseSubmitFileWithOptions(strings.NewReader("+Requirements = TARGET.Cpus > 4\n"+reqVanilla), SubmitParseOptions{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	req, _ := ad.Lookup("Requirements")
	if got := req.String(); strings.Contains(got, "TARGET.Arch") {
		t.Errorf("Requirements %s has generated clauses, want only the forced expression", got)
	}
}

// machineRefs classifies a reference the way GetExprReferences does for
// SetRequirements, which is what decides whether a generated clause is
// suppressed.
func TestMachineRefsClassification(t *testing.T) {
	refs := machineRefs(`TARGET.Memory > 0 && Cpus > 1 && MY.Owner == "x" && RequestMemory > 0`)
	for _, want := range []string{"memory", "cpus"} {
		if !refs[want] {
			t.Errorf("machineRefs: %q should be a machine reference", want)
		}
	}
	for _, notWanted := range []string{"owner", "requestmemory"} {
		if refs[notWanted] {
			t.Errorf("machineRefs: %q is the job's, not a machine's", notWanted)
		}
	}
}

// A whole-number real is a literal, and an expression that merely evaluates to
// a number is not -- which is what the resource floors turn on.
func TestLiteralNumberOnlyMatchesLiterals(t *testing.T) {
	ad := classad.New()
	_ = ad.Set("A", int64(2))
	_ = ad.Set("B", 2.0)
	for _, attr := range []string{"A", "B"} {
		e, _ := ad.Lookup(attr)
		if n, ok := literalNumber(e); !ok || n != 2 {
			t.Errorf("literalNumber(%s) = %v, %v; want 2, true", attr, n, ok)
		}
	}
	expr, err := classad.ParseExpr("1 + 1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := literalNumber(expr); ok {
		t.Error("literalNumber(1 + 1) reported a literal; an expression's value is not known at submit time")
	}
}
