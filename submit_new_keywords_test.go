package htcondor

import (
	"strings"
	"testing"
)

func keywordAd(t *testing.T, src string) map[string]string {
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
	for _, n := range ad.GetAttributes() {
		if e, ok := ad.Lookup(n); ok && e != nil {
			out[strings.ToLower(n)] = e.String()
		}
	}
	return out
}

// TestAnnexKeywords pins the two annex submit commands onto the attributes
// HTCondor writes them to.
func TestAnnexKeywords(t *testing.T) {
	ad := keywordAd(t, "executable = /bin/true\nannex_name = my-annex\nrestrict_to_annex = true\nqueue\n")
	if got := ad["targetannexname"]; got != `"my-annex"` {
		t.Errorf("TargetAnnexName = %s, want the annex name as a string", got)
	}
	if got := ad["restricttoannex"]; got != "true" {
		t.Errorf("RestrictToAnnex = %s, want true", got)
	}

	// Neither keyword invents an attribute for a job that does not use it.
	plain := keywordAd(t, "executable = /bin/true\nqueue\n")
	for _, attr := range []string{"targetannexname", "restricttoannex"} {
		if _, ok := plain[attr]; ok {
			t.Errorf("%s appears in a job that says nothing about annexes", attr)
		}
	}
}

// TestCondorVersionKeywords pins both the attributes and the Requirements
// clauses, including the two cases where condor_submit deliberately writes no
// clause: a submitter who already said something about TARGET.CondorVersion,
// and a universe where no EP version is ever compared.
func TestCondorVersionKeywords(t *testing.T) {
	const both = "executable = /bin/true\nmin_condor_version = 24.0.0\nmax_condor_version = 26.0.0\nqueue\n"

	ad := keywordAd(t, both)
	if got := ad["mincondorversion"]; got != `"24.0.0"` {
		t.Errorf("MinCondorVersion = %s", got)
	}
	if got := ad["maxcondorversion"]; got != `"26.0.0"` {
		t.Errorf("MaxCondorVersion = %s", got)
	}
	req := ad["requirements"]
	for _, want := range []string{
		"versionGE(split(TARGET.CondorVersion)[1], MinCondorVersion)",
		"versionLT(split(TARGET.CondorVersion)[1], MaxCondorVersion)",
	} {
		if !strings.Contains(req, want) {
			t.Errorf("Requirements is missing %q: %s", want, req)
		}
	}

	// The submitter's own clause wins: an automatic one is not added on top.
	own := keywordAd(t, "executable = /bin/true\nmin_condor_version = 24.0.0\n"+
		"requirements = TARGET.CondorVersion =!= undefined\nqueue\n")
	if strings.Contains(own["requirements"], "MinCondorVersion") {
		t.Errorf("the submitter named TARGET.CondorVersion, so no clause is added: %s", own["requirements"])
	}
	if own["mincondorversion"] != `"24.0.0"` {
		t.Error("the attribute is still written even when the clause is not")
	}

	// Local and scheduler jobs are run by the schedd; there is no EP version
	// to compare, and a clause there would make the job unmatchable.
	for _, u := range []string{"local", "scheduler"} {
		got := keywordAd(t, "executable = /bin/true\nuniverse = "+u+"\nmin_condor_version = 24.0.0\nqueue\n")
		if strings.Contains(got["requirements"], "MinCondorVersion") {
			t.Errorf("%s universe should carry no version clause: %s", u, got["requirements"])
		}
		if got["mincondorversion"] != `"24.0.0"` {
			t.Errorf("%s universe still records the attribute", u)
		}
	}
}
