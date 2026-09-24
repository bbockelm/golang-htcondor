package issues

import (
	"fmt"
	"strings"
	"testing"
)

// The corpus is modelled on real ap40 hold reasons -- the same shapes,
// with the site names, paths and usernames replaced. What matters about
// them is reproduced exactly: one root cause appears as many distinct
// strings because the execute node, the sandbox path, the plugin version
// and the output filename all vary between occurrences.

func memoryHolds(n int) []Record {
	slots := []string{
		"slot1_40@glidein_181693_77062752@n529.cluster.example.edu",
		"slot1_13@SITE-Backfill.green-7b499568d4-pbfjk",
		"slot1_2@OTHER-EP.698b098b8a9c",
		"slot1_41@THIRD-EP.docker-pilot-665dff69c8-phctx",
	}
	out := make([]Record, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Record{
			Kind:    "hold",
			Owner:   fmt.Sprintf("user%d", i%3),
			Cluster: int64(100 + i),
			Code:    21, SubCode: 102,
			At:      int64(1000 + i),
			Message: fmt.Sprintf("Error from %s: memory usage exceeded request_memory", slots[i%len(slots)]),
		})
	}
	return out
}

func transferHolds(n int, direction string) []Record {
	sites := []string{"Site-A", "Site-B", "Site-C"}
	sandboxes := []string{"/tmp/glide_AGd9bW", "/scratch/glide_grwizP", "/var/lib/condor/execute/dir_260525/glide_UOCQRW"}
	out := make([]Record, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Record{
			Kind:    "hold",
			Owner:   "transferuser",
			Cluster: int64(200 + i),
			Code:    12, SubCode: 256,
			At: int64(2000 + i),
			Message: fmt.Sprintf(
				"Transfer %s files failure at execution point slot1_%d@glidein_1257_741607740@compute%d using protocol osdf. "+
					"Details: Client Error: remote object already exists, upload aborted (Version: 7.26.%d; Site: %s) "+
					"( URL file = osdf:///project/data/2025-09-29/out_%d.root )||FILETRANSFER:1:non-zero exit (1) from %s/main/condor/libexec/stash_plugin. |",
				direction, i, i, i%2, sites[i%3], i, sandboxes[i%3]),
		})
	}
	return out
}

func clusterAll(t *testing.T, granularity float64, groups ...[]Record) []Cluster {
	t.Helper()
	c := NewClusterer()
	for _, g := range groups {
		for _, r := range g {
			c.Add(r)
		}
	}
	return c.Clusters(granularity, nil)
}

func find(clusters []Cluster, substr string) *Cluster {
	for i := range clusters {
		if strings.Contains(clusters[i].Template, substr) {
			return &clusters[i]
		}
	}
	return nil
}

func TestMaskRemovesPerOccurrenceDetail(t *testing.T) {
	cases := []struct{ in, want string }{
		// The whole premise: two occurrences of one problem differ only
		// in the execute node, and must mask to the same string.
		{"Error from slot1_40@glidein_181693_77062752@n529.cluster.example.edu: memory usage exceeded request_memory",
			"Error from <slot> memory usage exceeded request_memory"},
		{"Error from slot1_2@OTHER-EP.698b098b8a9c: memory usage exceeded request_memory",
			"Error from <slot> memory usage exceeded request_memory"},
		// A duration keeps a placeholder a person can read as a number.
		{"The job exceeded allowed execute duration of 20:00:00",
			"The job exceeded allowed execute duration of <num>:<num>:<num>"},
	}
	for _, c := range cases {
		got := strings.Join(tokenize(Mask(c.in)), " ")
		want := strings.Join(tokenize(c.want), " ")
		if got != want {
			t.Errorf("Mask(%q)\n got %q\nwant %q", c.in, got, want)
		}
	}
}

func TestOneRootCauseIsOneCluster(t *testing.T) {
	// 40 occurrences, 40 distinct strings, one problem. Grouping on the
	// text would report 40 issues; this is the whole reason the page
	// clusters at all.
	recs := memoryHolds(40)
	seen := map[string]bool{}
	for _, r := range recs {
		seen[r.Message] = true
	}
	if len(seen) < 4 {
		t.Fatalf("fixture is not varied enough to be a test: %d distinct messages", len(seen))
	}

	got := clusterAll(t, 1.0, recs)
	if len(got) != 1 {
		for _, g := range got {
			t.Logf("  %d: %s", g.Count, g.Template)
		}
		t.Fatalf("expected one cluster, got %d", len(got))
	}
	if got[0].Count != 40 {
		t.Errorf("count = %d, want 40", got[0].Count)
	}
	if got[0].Users != 3 {
		t.Errorf("users = %d, want 3", got[0].Users)
	}
}

func TestDifferentProblemsStayApart(t *testing.T) {
	// At the finest granularity nothing is merged, so each problem is
	// its own row -- including two that are both about file transfer.
	got := clusterAll(t, 1.0, memoryHolds(10), transferHolds(8, "output"), transferHolds(5, "input"))
	if len(got) != 3 {
		for _, g := range got {
			t.Logf("  %d: %s", g.Count, g.Template)
		}
		t.Fatalf("expected 3 clusters at granularity 1.0, got %d", len(got))
	}
}

func TestGranularityMergesRelatedProblems(t *testing.T) {
	// The slider's whole job. Coarse: one row about file transfer.
	// Fine: input and output failures are separate problems.
	coarse := clusterAll(t, 0.0, memoryHolds(10), transferHolds(8, "output"), transferHolds(5, "input"))
	if len(coarse) != 2 {
		for _, g := range coarse {
			t.Logf("  %d: %s", g.Count, g.Template)
		}
		t.Fatalf("expected 2 clusters at granularity 0, got %d", len(coarse))
	}
	transfer := find(coarse, "Transfer")
	if transfer == nil {
		t.Fatal("no transfer cluster")
	}
	if transfer.Count != 13 {
		t.Errorf("merged transfer count = %d, want 13", transfer.Count)
	}
	// A merge that hid what it had folded together would be worse than
	// no merge: the card has to be able to say "and this other thing".
	if len(transfer.Variants) != 2 {
		t.Errorf("variants = %d, want 2", len(transfer.Variants))
	}
	// Named after the bigger of the two, not whichever was parsed first.
	if !strings.Contains(transfer.Template, "output") {
		t.Errorf("merged cluster named %q, want the dominant (output) template", transfer.Template)
	}
	// Memory holds share almost no vocabulary with transfer failures, so
	// even the coarsest setting must not fold them in. A granularity
	// control that collapses everything into one row at one end is not a
	// control.
	if mem := find(coarse, "memory usage exceeded"); mem == nil || mem.Count != 10 {
		t.Errorf("memory cluster did not survive the coarsest setting: %+v", mem)
	}
}

func TestKindsNeverShareACluster(t *testing.T) {
	// Identical text, different kind. The page has separate sections for
	// them, and one row that meant both would belong to neither.
	same := "Error from <host>: something went wrong"
	got := clusterAll(t, 0.0, []Record{
		{Kind: "hold", Message: same, Owner: "a"},
		{Kind: "shadow_exception", Message: same, Owner: "a"},
	})
	if len(got) != 2 {
		t.Fatalf("expected the kinds to stay apart, got %d clusters", len(got))
	}
}

func TestExamplesSpreadAcrossUsers(t *testing.T) {
	// One user with a hundred failures and four others with one each.
	// A facilitator reads the examples to decide whether this is one
	// person's broken submit file or everybody's problem, so a list that
	// is a hundred rows of the loudest user answers that wrongly.
	recs := make([]Record, 0, 104)
	for i := 0; i < 100; i++ {
		recs = append(recs, Record{Kind: "hold", Owner: "loud", Cluster: int64(i), At: int64(i),
			Message: "Error from slot1_1@a.b.example.edu: memory usage exceeded request_memory"})
	}
	for i, o := range []string{"quiet1", "quiet2", "quiet3", "quiet4"} {
		recs = append(recs, Record{Kind: "hold", Owner: o, Cluster: int64(500 + i), At: int64(500 + i),
			Message: "Error from slot1_2@c.d.example.edu: memory usage exceeded request_memory"})
	}

	got := clusterAll(t, 1.0, recs)
	if len(got) != 1 {
		t.Fatalf("expected one cluster, got %d", len(got))
	}
	owners := map[string]bool{}
	for _, e := range got[0].Examples {
		owners[e.Owner] = true
	}
	if len(owners) != 5 {
		t.Errorf("examples covered %d users, want all 5: %v", len(owners), owners)
	}
	// The representative case is from whoever this is mostly happening
	// to, so the first example is the one to read.
	if got[0].Examples[0].Owner != "loud" {
		t.Errorf("first example owner = %q, want the dominant user", got[0].Examples[0].Owner)
	}
	if got[0].Users != 5 {
		t.Errorf("users = %d, want 5", got[0].Users)
	}
}

func TestEmptyMessageIsKept(t *testing.T) {
	// A hold with no reason is itself something to look at; dropping it
	// would make the page's total disagree with the queue's.
	got := clusterAll(t, 1.0, []Record{{Kind: "hold", Owner: "a", Message: ""}})
	if len(got) != 1 || got[0].Count != 1 {
		t.Fatalf("empty message was dropped: %+v", got)
	}
	if !strings.Contains(got[0].Template, "no message") {
		t.Errorf("template = %q, want it to say there was no message", got[0].Template)
	}
}

func TestOrderingIsStableAcrossRuns(t *testing.T) {
	// The page polls. Rows that reshuffle between two renders of the
	// same data are unreadable, and Go's map iteration is a real source
	// of that.
	var first []string
	for run := 0; run < 5; run++ {
		got := clusterAll(t, 0.5, memoryHolds(9), transferHolds(9, "output"), transferHolds(9, "input"))
		var order []string
		for _, g := range got {
			order = append(order, fmt.Sprintf("%d/%s", g.Count, g.Template))
		}
		if run == 0 {
			first = order
			continue
		}
		if strings.Join(order, "|") != strings.Join(first, "|") {
			t.Fatalf("ordering changed between runs:\n %v\n %v", first, order)
		}
	}
}

func TestCodesAreReportedWithoutGroupingOnThem(t *testing.T) {
	// The cluster did not group on the code, but it still has to be able
	// to report it: the code is how a facilitator looks the problem up.
	got := clusterAll(t, 1.0, memoryHolds(6))
	if len(got[0].Codes) != 1 || got[0].Codes[0].Code != 21 || got[0].Codes[0].SubCode != 102 {
		t.Errorf("codes = %+v, want the 21/102 pair", got[0].Codes)
	}
}

func TestTemplateWidensOverAnUnmaskedDifference(t *testing.T) {
	// Real case from ap40: a user-requested pause carries the username,
	// which no masking rule catches because it is an ordinary word. Drain
	// is what handles it -- the messages are identical but for that one
	// token, so they join and the template widens to a wildcard there.
	//
	// Without the widening these are two problems on the page, and on an
	// access point where a dozen people paused their work it is a dozen.
	var recs []Record
	for _, who := range []string{"anzheng", "maria", "kwame", "yuki"} {
		recs = append(recs, Record{
			Kind: "hold", Owner: who, Code: 1,
			Message: "User requested pause new work; let current running jobs finish; no automatic restart (by user " + who + ")",
		})
	}
	got := clusterAll(t, 1.0, recs)
	if len(got) != 1 {
		for _, g := range got {
			t.Logf("  %d: %s", g.Count, g.Template)
		}
		t.Fatalf("expected one cluster, got %d", len(got))
	}
	if !strings.Contains(got[0].Template, wildcard) {
		t.Errorf("template = %q, want a wildcard where the username was", got[0].Template)
	}
	// And the wildcard must be where the name was, not smeared over the
	// sentence: a template of all wildcards would "match" anything.
	if !strings.Contains(got[0].Template, "User requested pause new work") {
		t.Errorf("template lost the words that identify the problem: %q", got[0].Template)
	}
}
