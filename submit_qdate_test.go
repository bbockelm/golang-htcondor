package htcondor

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func qdateOf(t *testing.T, ad *classad.ClassAd, where string) int64 {
	t.Helper()
	v, ok := ad.EvaluateAttrInt("QDate")
	if !ok {
		t.Fatalf("%s: no QDate on the ad", where)
	}
	return v
}

// TestQDateIsOneValuePerSubmission: condor_submit reads the clock once and
// hands that value to init_base_ad, so every proc of a cluster carries the
// same QDate. Reading the clock per proc gave a multi-proc submission two
// QDates whenever it crossed a second boundary. That is rare enough that the
// only thing which caught it was an unrelated cluster-ad folding test, and
// only on the runs where the clock happened to tick -- so this asserts the
// invariant directly rather than waiting for the timing to cooperate.
func TestQDateIsOneValuePerSubmission(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader("executable = /bin/sleep\nqueue 3\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := sf.Submit(1)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if len(res.ProcAds) != 3 {
		t.Fatalf("got %d proc ads, want 3", len(res.ProcAds))
	}
	want := qdateOf(t, res.ProcAds[0], "proc 0")
	for i, ad := range res.ProcAds[1:] {
		if got := qdateOf(t, ad, "a later proc"); got != want {
			t.Errorf("proc %d has QDate %d, proc 0 has %d: one submission carries one QDate", i+1, got, want)
		}
	}
}

// TestQDateIsSharedAcrossACallerDrivenCluster covers the other shape: a
// caller that builds the cluster ad and the proc ads itself, rather than
// going through Submit. Those calls are separate, so the stamp has to live on
// the SubmitFile for them to agree.
func TestQDateIsSharedAcrossACallerDrivenCluster(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader("executable = /bin/sleep\nqueue 2\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	clusterAd, err := sf.MakeClusterAd(7)
	if err != nil {
		t.Fatalf("MakeClusterAd: %v", err)
	}
	procAd, err := sf.MakeProcAd(7, 1, map[string]string{})
	if err != nil {
		t.Fatalf("MakeProcAd: %v", err)
	}
	if c, p := qdateOf(t, clusterAd, "cluster ad"), qdateOf(t, procAd, "proc ad"); c != p {
		t.Errorf("cluster ad QDate %d, proc ad QDate %d: both belong to one submission", c, p)
	}
}
