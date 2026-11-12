package htcondor

import (
	"strings"
	"testing"
)

// commonFilesAd builds proc 0 for a submit file, for the tests below.
func commonFilesAd(t *testing.T, src string) map[string]string {
	t.Helper()
	sf, err := ParseSubmitFile(strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	out := map[string]string{}
	if v, ok := ad.EvaluateAttrString("CommonInputFiles"); ok {
		out["CommonInputFiles"] = v
	}
	// Requirements is a boolean expression, not a string: it has to be read
	// unparsed. Evaluating it yields nothing, which silently makes every
	// "the clause is absent" assertion below pass for the wrong reason.
	if v, ok := ad.Lookup("Requirements"); ok {
		out["Requirements"] = v.String()
	}
	return out
}

// TestCommonInputFilesIsWritten covers both spellings condor_submit accepts
// for the list, and the canonical form it stores them in.
//
// The canonicalization is the point: the schedd compares these lists between
// jobs to work out what it can transfer once for a whole cluster, so the same
// files written with different spacing have to come out byte-identical.
func TestCommonInputFilesIsWritten(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"transfer_common_input", "executable = /bin/sleep\ntransfer_common_input = a.txt\nqueue\n", "a.txt"},
		{"common_input_files", "executable = /bin/sleep\ncommon_input_files = a.txt\nqueue\n", "a.txt"},
		{"attribute spelling", "executable = /bin/sleep\nCommonInputFiles = a.txt\nqueue\n", "a.txt"},
		{"spacing is canonicalized", "executable = /bin/sleep\ntransfer_common_input =  a.txt ,  b.txt \nqueue\n", "a.txt,b.txt"},
		{"empty entries are dropped", "executable = /bin/sleep\ntransfer_common_input = a.txt,,b.txt\nqueue\n", "a.txt,b.txt"},
		{"quotes are stripped", "executable = /bin/sleep\ntransfer_common_input = \"a.txt,b.txt\"\nqueue\n", "a.txt,b.txt"},
		// An empty primary counts as unset, so it falls through to the
		// newer spelling rather than suppressing it.
		{"empty primary falls through", "executable = /bin/sleep\ncommon_input_files =\ntransfer_common_input = b.txt\nqueue\n", "b.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := commonFilesAd(t, tc.src)
			if got["CommonInputFiles"] != tc.want {
				t.Errorf("CommonInputFiles = %q, want %q", got["CommonInputFiles"], tc.want)
			}
		})
	}
}

// TestCommonInputFilesAbsentWhenNotAsked keeps the attribute off a job that
// never mentioned common files. Writing it unconditionally would tell the
// schedd to look for a shared transfer that nothing asked for.
func TestCommonInputFilesAbsentWhenNotAsked(t *testing.T) {
	got := commonFilesAd(t, "executable = /bin/sleep\nqueue\n")
	if v, ok := got["CommonInputFiles"]; ok {
		t.Errorf("CommonInputFiles = %q on a job that asked for none", v)
	}
}

// TestRequireCommonFilesNeedsBothHalves pins the gate on the machine
// requirement. condor_submit adds the clause only when the job both asks to
// insist on common-files transfer AND has files to transfer in common.
//
// This is the divergence the generated fuzzer found once the oracle was
// rebuilt: the clause was gated on an ad attribute named
// RequireCommonFilesTransfer, which exists nowhere in HTCondor, so no submit
// file could reach it and a job asking for common files was free to match a
// machine that could not honour them.
func TestRequireCommonFilesNeedsBothHalves(t *testing.T) {
	const clause = "TARGET.HasCommonFilesTransfer >= 2"
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "both halves",
			src:  "executable = /bin/sleep\ntransfer_common_input = a.txt\nrequire_common_files = true\nqueue\n",
			want: true,
		},
		{
			name: "files but no flag",
			src:  "executable = /bin/sleep\ntransfer_common_input = a.txt\nqueue\n",
			want: false,
		},
		{
			name: "flag but no files",
			src:  "executable = /bin/sleep\nrequire_common_files = true\nqueue\n",
			want: false,
		},
		{
			name: "flag explicitly off",
			src:  "executable = /bin/sleep\ntransfer_common_input = a.txt\nrequire_common_files = false\nqueue\n",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := commonFilesAd(t, tc.src)
			present := strings.Contains(got["Requirements"], clause)
			if present != tc.want {
				t.Errorf("clause present = %v, want %v\nRequirements = %s",
					present, tc.want, got["Requirements"])
			}
		})
	}
}
