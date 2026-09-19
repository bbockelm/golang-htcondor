package htcondor

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// Expected values here come from condor_submit -dry-run on identical
// submit files. The quoting rules are condor's, including the asymmetry
// between input and output on an empty list, which looks like an
// oversight until you check it against the real thing.

func TestTrimSubmitQuotes(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`"a.txt"`, `a.txt`},
		{`"a.txt, b.txt"`, `a.txt, b.txt`},
		{`a.txt`, `a.txt`},
		{`""`, ``},
		{`  "a.txt"  `, `a.txt`},
		{``, ``},
		// Only a matching pair, and only one. strings.Trim would eat
		// runs from each end independently and accept these.
		{`"a.txt`, `"a.txt`},
		{`a.txt"`, `a.txt"`},
		{`""a""`, `"a"`},
		// A quote in the middle is part of the value.
		{`a"b`, `a"b`},
	} {
		if got := trimSubmitQuotes(tc.in); got != tc.want {
			t.Errorf("trimSubmitQuotes(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTransferFileListQuoting(t *testing.T) {
	tests := []struct {
		name string
		line string
		attr string
		want string
		set  bool // is the attribute expected on the ad at all?
	}{
		// The bug: quotes survived into the ad, so the shadow looked for
		// a file whose name began with a quote character.
		{"quoted single output", `transfer_output_files = "a.txt"`, "TransferOutput", "a.txt", true},
		{"quoted output list", `transfer_output_files = "a.txt, b.txt"`, "TransferOutput", "a.txt,b.txt", true},
		{"unquoted output list", `transfer_output_files = a.txt, b.txt`, "TransferOutput", "a.txt,b.txt", true},

		// Explicitly empty means "transfer nothing", and must be SET.
		// Skipping it leaves HTCondor's default of transferring every
		// new file in the scratch directory.
		{"empty output is set to empty", `transfer_output_files = ""`, "TransferOutput", "", true},

		{"quoted single input", `transfer_input_files = "in.dat"`, "TransferInput", "in.dat", true},
		{"quoted input list", `transfer_input_files = "a.dat, b.dat"`, "TransferInput", "a.dat,b.dat", true},

		// condor emits no TransferInput for an empty input list.
		{"empty input stays unset", `transfer_input_files = ""`, "TransferInput", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ad := mustQuotingJobAd(t, "universe = vanilla\nexecutable = /bin/echo\n"+tc.line+"\n")

			got, ok := ad.EvaluateAttrString(tc.attr)
			if ok != tc.set {
				t.Fatalf("%s present = %v, want %v (value %q)", tc.attr, ok, tc.set, got)
			}
			if tc.set && got != tc.want {
				t.Errorf("%s = %q, want %q", tc.attr, got, tc.want)
			}
		})
	}
}

// TestSuccessExitCodeAttribute covers the wrong-attribute-name bug.
// "SuccessExitCode" is not read by HTCondor, so the setting did nothing,
// and when_to_transfer_output = ON_SUCCESS is gated on the real one.
func TestSuccessExitCodeAttribute(t *testing.T) {
	ad := mustQuotingJobAd(t, `
universe = vanilla
executable = /bin/echo
success_exit_code = 0
when_to_transfer_output = ON_SUCCESS
`)

	got, ok := ad.EvaluateAttrInt("JobSuccessExitCode")
	if !ok {
		t.Fatal("JobSuccessExitCode not set; ON_SUCCESS transfer gating depends on it")
	}
	if got != 0 {
		t.Errorf("JobSuccessExitCode = %d, want 0", got)
	}

	// It must be an integer, not the raw string: the shadow compares it
	// against ExitCode.
	if s, ok := ad.EvaluateAttrString("JobSuccessExitCode"); ok {
		t.Errorf("JobSuccessExitCode evaluated as the string %q; it must be an integer", s)
	}

	if _, ok := ad.EvaluateAttrInt("SuccessExitCode"); ok {
		t.Error("SuccessExitCode is still being set; HTCondor does not read that attribute")
	}

	if w, _ := ad.EvaluateAttrString("WhenToTransferOutput"); w != "ON_SUCCESS" {
		t.Errorf("WhenToTransferOutput = %q, want ON_SUCCESS", w)
	}
}

func TestSuccessExitCodeNonZero(t *testing.T) {
	ad := mustQuotingJobAd(t,
		"universe = vanilla\nexecutable = /bin/echo\nsuccess_exit_code = 42\n")
	if got, ok := ad.EvaluateAttrInt("JobSuccessExitCode"); !ok || got != 42 {
		t.Errorf("JobSuccessExitCode = %d (ok=%v), want 42", got, ok)
	}
}

func mustQuotingJobAd(t *testing.T, submit string) *classad.ClassAd {
	t.Helper()
	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("ParseSubmitFile: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, map[string]string{})
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	return ad
}
