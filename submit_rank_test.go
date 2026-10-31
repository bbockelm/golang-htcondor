package htcondor

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// rankOf parses a submit file and returns proc 0's Rank attribute.
func rankOf(t *testing.T, text string) (*classad.Expr, *classad.ClassAd) {
	t.Helper()
	sf, err := ParseSubmitFile(strings.NewReader(text))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	expr, ok := ad.Lookup("Rank")
	if !ok {
		t.Fatal("Rank is missing from the job ad")
	}
	return expr, ad
}

// TestRankIsAnExpression pins a job's machine preference actually being
// expressed.
//
// The negotiator evaluates Rank against each candidate machine ad and sorts
// the matches by the number it gets back (matchmaker.cpp). A string is not a
// number: `rank = Memory` stored as the STRING "Memory" ranks every machine
// identically, so the submitter's preference is silently discarded and the
// job takes whatever machine comes first. This library stored the text of
// the keyword, which is why these assertions are about the attribute's TYPE
// and not only its text -- the same failure the job policy expressions had.
func TestRankIsAnExpression(t *testing.T) {
	for _, tc := range []struct {
		name string
		rank string
	}{
		{"attribute reference", "Memory"},
		{"arithmetic", "KFlops / 1000"},
		{"comparison", "TARGET.Mips > 1000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expr, ad := rankOf(t, "executable = /bin/true\nrank = "+tc.rank+"\nqueue\n")
			if text := expr.String(); strings.HasPrefix(text, `"`) {
				t.Errorf("Rank = %s: stored as a string literal, which the negotiator cannot rank by", text)
			}
			if _, isString := ad.EvaluateAttrString("Rank"); isString {
				t.Error("Rank evaluates to a string; the negotiator requires a number")
			}
		})
	}
}

// TestRankDefaultsToRealZero pins the default's ClassAd TYPE, not just its
// value. condor_submit writes the real 0.0 (AssignJobVal in SetRank), and an
// integer 0 is a different ClassAd value even though it compares equal --
// anything diffing a Go-built ad against an HTCondor-built one sees a
// mismatch. An empty `rank =` takes the same default: submit_param hands
// SetRank an empty string, which falls through to the default rather than
// being parsed.
func TestRankDefaultsToRealZero(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"no rank", "executable = /bin/true\nqueue\n"},
		{"empty rank", "executable = /bin/true\nrank = \nqueue\n"},
		{"blank rank", "executable = /bin/true\nrank =    \nqueue\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ad := rankOf(t, tc.text)
			v := ad.EvaluateAttr("Rank")
			if !v.IsReal() {
				t.Errorf("default Rank is %v, not the real 0.0 condor_submit writes", v)
			}
			if r, _ := v.RealValue(); r != 0 {
				t.Errorf("default Rank = %v, want 0", r)
			}
		})
	}
}

// TestPreferencesSpellsRank covers the keyword's historical name, which
// SetRank still reads as the alternate of `rank`.
func TestPreferencesSpellsRank(t *testing.T) {
	expr, _ := rankOf(t, "executable = /bin/true\npreferences = Memory\nqueue\n")
	if text := expr.String(); !strings.Contains(text, "Memory") {
		t.Errorf("Rank = %s, want the expression `preferences` named", text)
	}
}

// TestRankRejectsUnparseableText makes sure a malformed rank is reported
// rather than quietly stored as a string. condor_submit aborts the
// submission over one.
func TestRankRejectsUnparseableText(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(
		"executable = /bin/true\nrank = not an expression ]]\nqueue\n"))
	if err != nil {
		// Rejecting at parse time is just as good.
		return
	}
	if _, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil); err == nil {
		t.Error("MakeJobAd accepted a rank that is not a ClassAd expression")
	}
}
