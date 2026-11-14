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

// TransformOnEvict lists the two built-in on-evict transforms in the order
// condor_submit set them, and that order turns on how the submit file
// SPELLED the disk request -- not on the order it writes the two commands
// in, and not on how it spelled the memory request.
//
// SetRequestResources walks the submit macro set for keys with the
// "request_" prefix and dispatches each as it goes, so request_disk is set
// during the walk, ahead of memory. The RequestDisk alias carries no such
// prefix, misses the walk, and is set after memory has appended its tag.
//
// Measured against HTCondor's own SubmitHash through the oracle in
// fuzz/submit, over both spellings of each request in both file orders.
func TestEvictTransformOrderFollowsTheDiskSpelling(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want string
	}{
		{"request_disk takes the walk, so disk is first",
			"request_memory = 0,10\nrequest_disk = 0,10\n", "RequestDisk RequestMemory"},
		{"...in either file order",
			"request_disk = 0,10\nrequest_memory = 0,10\n", "RequestDisk RequestMemory"},
		{"...whatever case it is spelled with",
			"requestmemory = 0,10\nREQUEST_DISK = 0,10\n", "RequestDisk RequestMemory"},
		{"the RequestDisk alias misses the walk, so memory is first",
			"request_memory = 0,10\nrequestdisk = 0,10\n", "RequestMemory RequestDisk"},
		{"...in either file order",
			"requestdisk = 0,10\nrequest_memory = 0,10\n", "RequestMemory RequestDisk"},
		{"...and however memory is spelled",
			"requestmemory = 0,10\nRequestDisk = 0,10\n", "RequestMemory RequestDisk"},
		{"retry_request_disk reaches it the same way",
			"request_memory = 0,10\nrequestdisk = 5\nretry_request_disk = 9\n",
			"RequestMemory RequestDisk"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := submitProcAd(t, "executable = /bin/true\n"+tc.src+"queue\n")
			expr, ok := ad.Lookup("TransformOnEvict")
			if !ok {
				t.Fatal("the job ad has no TransformOnEvict")
			}
			got := strings.Trim(expr.String(), `"`)
			if got != tc.want {
				t.Errorf("TransformOnEvict = %q, want %q", got, tc.want)
			}
		})
	}
}
