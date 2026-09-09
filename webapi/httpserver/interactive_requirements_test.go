package httpserver

import (
	"strings"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

const noPrivilegedSingularity = `GWMS_SINGULARITY_MODE =!= "privileged"`

// The operator's expression has to reach the submit file, or the job
// matches machines it cannot be attached to and the terminal starts and
// then refuses every shell.
func TestInteractiveSubmitCarriesOperatorRequirements(t *testing.T) {
	out := buildInteractiveTerminalSubmitFile(interactiveTerminalSubmitArgs{
		InstanceID:   "abc123",
		BatchName:    "interactive-abc123",
		Cpus:         1,
		MemoryMB:     1024,
		DiskMB:       1024,
		Requirements: noPrivilegedSingularity,
	})

	if !strings.Contains(out, "requirements = ("+noPrivilegedSingularity+")") {
		t.Fatalf("the requirement is not in the submit file:\n%s", out)
	}
}

// Unset must stay unset: emitting an empty `requirements = ()` would not
// parse, turning an unconfigured server into one that cannot submit.
func TestInteractiveSubmitOmitsEmptyRequirements(t *testing.T) {
	for _, raw := range []string{"", "   ", "\n\t "} {
		out := buildInteractiveTerminalSubmitFile(interactiveTerminalSubmitArgs{
			InstanceID: "abc123", BatchName: "b", Cpus: 1, MemoryMB: 1024, DiskMB: 1024,
			Requirements: raw,
		})
		if strings.Contains(out, "requirements") {
			t.Errorf("empty requirements %q still emitted a line:\n%s", raw, out)
		}
	}
}

// The operator's verbatim extra block is spliced after, so it still wins
// if it sets requirements itself. That is the precedence an escape hatch
// should have, and it is only true if the ordering is right.
func TestOperatorExtraBlockStillOverridesRequirements(t *testing.T) {
	out := buildInteractiveTerminalSubmitFile(interactiveTerminalSubmitArgs{
		InstanceID: "abc123", BatchName: "b", Cpus: 1, MemoryMB: 1024, DiskMB: 1024,
		Requirements:     noPrivilegedSingularity,
		ExtraSubmitLines: "requirements = (TARGET.Machine == \"pinned.example.org\")",
	})

	ours := strings.Index(out, "requirements = ("+noPrivilegedSingularity+")")
	theirs := strings.Index(out, `requirements = (TARGET.Machine == "pinned.example.org")`)
	if ours < 0 || theirs < 0 {
		t.Fatalf("expected both requirement lines:\n%s", out)
	}
	if theirs < ours {
		t.Error("the operator's extra block comes first, so ours would win instead")
	}
}

// The whole point is that this NARROWS the match rather than replacing
// what submit derives for itself. Parsing the submit file proves it:
// the operator's expression must appear in the job ad's Requirements
// alongside the machine-suitability clauses, not instead of them.
func TestOperatorRequirementsAreAndedIntoTheJobAd(t *testing.T) {
	out := buildInteractiveTerminalSubmitFile(interactiveTerminalSubmitArgs{
		InstanceID: "abc123", BatchName: "b", Cpus: 2, MemoryMB: 2048, DiskMB: 1024,
		Requirements: noPrivilegedSingularity,
	})

	sf, err := htcondor.ParseSubmitFile(strings.NewReader(out))
	if err != nil {
		t.Fatalf("the generated submit file does not parse: %v\n%s", err, out)
	}
	ad, err := sf.MakeJobAd(htcondor.JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("failed to build the job ad: %v", err)
	}
	req, ok := ad.Lookup("Requirements")
	if !ok {
		t.Fatal("the job ad has no Requirements")
	}
	got := req.String()

	if !strings.Contains(got, "GWMS_SINGULARITY_MODE") {
		t.Errorf("the operator's expression is missing from Requirements: %s", got)
	}
	// A clause submit adds for itself. Its presence is what shows the
	// operator's expression was ANDed in rather than substituted.
	if !strings.Contains(got, "RequestCpus") {
		t.Errorf("submit's own clauses were replaced rather than extended: %s", got)
	}
}
