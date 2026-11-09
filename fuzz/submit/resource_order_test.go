//go:build libcondor_utils

package fuzzsubmit

import (
	"strings"
	"testing"
)

// The order the custom-resource clauses come out in is the order
// condor_submit WALKS THE JOB AD, and a ClassAd's attributes live in a map
// keyed case-insensitively. So the clauses are in case-insensitive
// alphabetical order by tag, whatever order the submit file listed them in
// and whatever case it spelled them with.
//
// Requirements is one string. A reordering is the same expression and a
// different attribute, so a transform or a test that compares it sees two
// different job ads -- which is why this is compared rather than left to
// an expression-equivalence check.
var resourceOrderFiles = []string{
	// Capitals sort before lower case by byte and after it case-
	// insensitively, so these two disagree under the wrong sort.
	"executable = /bin/true\nRequest_X0 = 1\nrequest_a0 = 1\nqueue\n",
	// ...in either order in the file, because the walk is over a sorted
	// map rather than over the submit commands.
	"executable = /bin/true\nrequest_a0 = 1\nRequest_X0 = 1\nqueue\n",
	// Enough tags that a byte sort splits them into two runs.
	"executable = /bin/true\nrequest_Zz = 1\nrequest_aa = 1\nrequest_MM = 1\nrequest_bb = 1\nqueue\n",
	// Mixed with the three built-in requests, which have clauses of their
	// own ahead of these.
	"executable = /bin/true\nrequest_memory = 1\nrequest_Bb = 1\nrequest_aa = 1\nqueue\n",
	// A tag spelled two ways is ONE attribute, so it gets one clause.
	"executable = /bin/true\nrequest_aa = 1\nRequest_AA = 2\nqueue\n",
}

func TestCustomResourceClauseOrderMatchesOracle(t *testing.T) {
	requireOracle(t)
	for _, src := range resourceOrderFiles {
		t.Run(strings.ReplaceAll(strings.TrimSpace(src), "\n", "; "), func(t *testing.T) {
			fresh, _, skip := check(t, src)
			if skip {
				t.Fatalf("not comparable; one side rejected:\n%s", src)
			}
			for _, d := range fresh {
				t.Errorf("%s\n--- submit file ---\n%s", d, src)
			}
		})
	}
}
