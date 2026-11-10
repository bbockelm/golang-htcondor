package htcondor

import (
	"strings"
	"testing"
)

// TestBatchCpuNodeKeywords pins the four submit commands HTCONDOR-4053 added
// onto the attributes HTCondor writes them to, and pins that they are
// EXPRESSIONS.
//
// batch_whole_nodes is the one worth checking: HTCondor's keyword table marks
// it as a bool, but SetGridParams assigns it with AssignJobExpr like the
// other three, so a value that is not a literal has to survive rather than be
// flattened to true or false.
func TestBatchCpuNodeKeywords(t *testing.T) {
	src := "executable = /bin/true\nuniverse = grid\ngrid_resource = batch slurm\n" +
		"batch_cpu_count = 4\nbatch_cpus_per_node = 2 * 2\n" +
		"batch_node_count = 8\nbatch_whole_nodes = true\nqueue\n"

	ad := batchAd(t, src)
	for attr, want := range map[string]string{
		"batchcpucount": "4",
		// Parenthesised by the unparser, which is itself the point: the
		// value was kept as an expression rather than flattened.
		"batchcpuspernode": "(2 * 2)",
		"batchnodecount":   "8",
		"batchwholenodes":  "true",
	} {
		if got := ad[attr]; got != want {
			t.Errorf("%s = %q, want %q", attr, got, want)
		}
	}
}

// TestBatchKeywordsAreGridOnly holds the universe gate: SetGridParams returns
// before it reads any of them unless the job is grid universe, so a vanilla
// job naming one gets nothing.
func TestBatchKeywordsAreGridOnly(t *testing.T) {
	ad := batchAd(t, "executable = /bin/true\nbatch_node_count = 8\nqueue\n")
	if _, ok := ad["batchnodecount"]; ok {
		t.Errorf("a vanilla job should not carry BatchNodeCount, got %q", ad["batchnodecount"])
	}
}

// TestBatchKeywordsInventNothing checks a grid job that names none of them
// gets none of them.
func TestBatchKeywordsInventNothing(t *testing.T) {
	ad := batchAd(t, "executable = /bin/true\nuniverse = grid\ngrid_resource = batch slurm\nqueue\n")
	for _, attr := range []string{"batchcpucount", "batchcpuspernode", "batchnodecount", "batchwholenodes"} {
		if _, ok := ad[attr]; ok {
			t.Errorf("%s appears in a job that says nothing about it", attr)
		}
	}
}

func batchAd(t *testing.T, src string) map[string]string {
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
