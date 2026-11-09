package htcondor

import (
	"strings"
	"testing"
)

// The custom-resource clauses in Requirements come out in the order
// condor_submit walks the job ad, and a ClassAd's attributes live in a map
// keyed case-insensitively -- so they are ordered case-insensitively by
// tag, whatever case the submit file spelled them with and whatever order
// it listed them in.
//
// Measured against HTCondor's own SubmitHash through the oracle in
// fuzz/submit: request_Zz, request_aa, request_MM and request_bb produce
// their clauses in the order aa, bb, MM, Zz.
func TestCustomResourceClausesAreOrderedCaseInsensitively(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want []string
	}{
		{"request_Zz = 1\nrequest_aa = 1\nrequest_MM = 1\nrequest_bb = 1\n",
			[]string{"TARGET.aa", "TARGET.bb", "TARGET.MM", "TARGET.Zz"}},
		{"Request_X0 = 1\nrequest_a0 = 1\n",
			[]string{"TARGET.a0", "TARGET.X0"}},
		// The same tags listed the other way round give the same order.
		{"request_a0 = 1\nRequest_X0 = 1\n",
			[]string{"TARGET.a0", "TARGET.X0"}},
	} {
		t.Run(strings.ReplaceAll(strings.TrimSpace(tc.src), "\n", "; "), func(t *testing.T) {
			ad := submitProcAd(t, "executable = /bin/true\n"+tc.src+"queue\n")
			expr, ok := ad.Lookup("Requirements")
			if !ok {
				t.Fatal("the job ad has no Requirements")
			}
			req := expr.String()
			at := -1
			for _, clause := range tc.want {
				i := strings.Index(req, clause)
				if i < 0 {
					t.Fatalf("Requirements has no clause for %s: %s", clause, req)
				}
				if i < at {
					t.Errorf("%s comes before the clause it should follow: %s", clause, req)
				}
				at = i
			}
		})
	}
}
