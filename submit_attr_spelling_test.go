package htcondor

import (
	"testing"
)

// TestKeywordsReadUnderTheirAttributeName pins the spelling rule for the
// accounting-group family: condor_submit reads each of these with
// submit_param(name, attr), so the job ATTRIBUTE's name is an accepted
// spelling of the submit command.
//
// It matters most for nice_user. `NiceUser = true` is how a submit file asks
// for a nice-user job under that spelling, and reading only `nice_user` left
// the job with no accounting group -- charged to the submitter directly and
// not preemptable, so not nice at all, while the submit file looked like it
// had asked.
func TestKeywordsReadUnderTheirAttributeName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		src   string
		attrs map[string]string
	}{
		{
			name: "nice_user",
			src:  "executable = /bin/true\nnice_user = true\nqueue\n",
			attrs: map[string]string{
				"AcctGroup":            `"nice-user"`,
				"MaxJobRetirementTime": "0",
			},
		},
		{
			name: "nice_user under the attribute name",
			src:  "executable = /bin/true\nNiceUser = true\nqueue\n",
			attrs: map[string]string{
				"AcctGroup":            `"nice-user"`,
				"MaxJobRetirementTime": "0",
			},
		},
		{
			name:  "accounting_group under the attribute name",
			src:   "executable = /bin/true\nAccountingGroup = grp\nqueue\n",
			attrs: map[string]string{"AcctGroup": `"grp"`},
		},
		{
			name: "accounting_group_user under the attribute name",
			src:  "executable = /bin/true\naccounting_group = grp\nAcctGroupUser = someone\nqueue\n",
			attrs: map[string]string{
				"AcctGroupUser":   `"someone"`,
				"AccountingGroup": `"grp.someone"`,
			},
		},
		{
			name:  "project_name",
			src:   "executable = /bin/true\nproject_name = Proj\nqueue\n",
			attrs: map[string]string{"ProjectName": `"Proj"`},
		},
		{
			name:  "project_name under the attribute name",
			src:   "executable = /bin/true\nProjectName = Proj\nqueue\n",
			attrs: map[string]string{"ProjectName": `"Proj"`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := adFor(t, tc.src)
			for attr, want := range tc.attrs {
				got, ok := ad[attr]
				if !ok {
					t.Errorf("%s is missing from the job ad", attr)
					continue
				}
				if got != want {
					t.Errorf("%s = %s, want %s", attr, got, want)
				}
			}
		})
	}
}

// TestScitokensFile covers the four ways a submit file decides whether the
// job carries a SciToken path, which condor_submit crosses `use_scitokens`
// with whether a file was named.
//
// BEARER_TOKEN_FILE is not exercised: reading the submitting process's
// environment is host access, so this parser answers it only when the parse
// was given AllowLocalAccess.
func TestScitokensFile(t *testing.T) {
	t.Run("a named file is stored", func(t *testing.T) {
		ad := adFor(t, "executable = /bin/true\nscitokens_file = /abs/tok\nqueue\n")
		if got := ad["ScitokensFile"]; got != `"/abs/tok"` {
			t.Errorf("ScitokensFile = %q, want /abs/tok", got)
		}
	})
	t.Run("the attribute name is the alternate spelling", func(t *testing.T) {
		ad := adFor(t, "executable = /bin/true\nScitokensFile = /abs/tok\nqueue\n")
		if got := ad["ScitokensFile"]; got != `"/abs/tok"` {
			t.Errorf("ScitokensFile = %q, want /abs/tok", got)
		}
	})
	t.Run("use_scitokens = false suppresses a named file", func(t *testing.T) {
		ad := adFor(t, "executable = /bin/true\nuse_scitokens = false\nscitokens_file = /abs/tok\nqueue\n")
		if got, ok := ad["ScitokensFile"]; ok {
			t.Errorf("ScitokensFile = %q, want it absent", got)
		}
	})
	t.Run("auto with nothing to point at writes nothing", func(t *testing.T) {
		ad := adFor(t, "executable = /bin/true\nuse_scitokens = auto\nqueue\n")
		if got, ok := ad["ScitokensFile"]; ok {
			t.Errorf("ScitokensFile = %q, want it absent", got)
		}
	})
	// condor_submit aborts the submission over both of these.
	t.Run("use_scitokens = true with no file is an error", func(t *testing.T) {
		mustReject(t, "executable = /bin/true\nuse_scitokens = true\nqueue\n")
	})
	t.Run("a value that is neither a boolean nor auto is an error", func(t *testing.T) {
		mustReject(t, "executable = /bin/true\nuse_scitokens = maybe\nqueue\n")
	})
}

// TestDelegateJobGSICredentialsLifetime pins the value shape: condor_submit
// reads it with strtol and requires the whole string to be an integer, so it
// is neither an expression nor a time with a unit.
func TestDelegateJobGSICredentialsLifetime(t *testing.T) {
	ad := adFor(t, "executable = /bin/true\ndelegate_job_GSI_credentials_lifetime = 60\nqueue\n")
	if got := ad["DelegateJobGSICredentialsLifetime"]; got != "60" {
		t.Errorf("DelegateJobGSICredentialsLifetime = %q, want 60", got)
	}
	ad = adFor(t, "executable = /bin/true\nDelegateJobGSICredentialsLifetime = 60\nqueue\n")
	if got := ad["DelegateJobGSICredentialsLifetime"]; got != "60" {
		t.Errorf("under the attribute name: DelegateJobGSICredentialsLifetime = %q, want 60", got)
	}
	mustReject(t, "executable = /bin/true\ndelegate_job_GSI_credentials_lifetime = 60s\nqueue\n")
	mustReject(t, "executable = /bin/true\ndelegate_job_GSI_credentials_lifetime = abc\nqueue\n")
}

// TestWantParallelSchedulingTakesTheMachineCountPath covers the keyword that
// hands a job of any universe to the dedicated scheduler.
//
// Setting it puts the job on SetParallelParams' machine-count path, so the
// count is read for a vanilla job too -- and, like a parallel or MPI job, a
// job on that path with no count is a submit error.
func TestWantParallelSchedulingTakesTheMachineCountPath(t *testing.T) {
	ad := adFor(t, "executable = /bin/true\nWantParallelScheduling = true\nmachine_count = 2\nqueue\n")
	if got := ad["WantParallelScheduling"]; got != "true" {
		t.Errorf("WantParallelScheduling = %q, want true", got)
	}
	for _, attr := range []string{"MinHosts", "MaxHosts"} {
		if got := ad[attr]; got != "2" {
			t.Errorf("%s = %q, want 2", attr, got)
		}
	}

	// False is not written at all, matching SetUniverse.
	ad = adFor(t, "executable = /bin/true\nWantParallelScheduling = false\nqueue\n")
	if got, ok := ad["WantParallelScheduling"]; ok {
		t.Errorf("WantParallelScheduling = %q, want it absent", got)
	}

	mustReject(t, "executable = /bin/true\nWantParallelScheduling = true\nqueue\n")
	mustReject(t, "universe = parallel\nexecutable = /bin/true\nqueue\n")
	mustReject(t, "universe = mpi\nexecutable = /bin/true\nqueue\n")
	// SetParallelParams runs before the `+Attr` pass, so a +MaxHosts is not
	// yet in the ad and does not satisfy the requirement.
	mustReject(t, "universe = parallel\nexecutable = /bin/true\n+MaxHosts = 3\nqueue\n")
}
