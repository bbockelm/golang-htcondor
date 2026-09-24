package issues

import (
	"fmt"
	"testing"
)

// A corpus shaped like ap40's: a handful of root causes, each appearing
// as a distinct string per occurrence, spread over many resources and
// users.
func corpus(n int, resources, users int) []Record {
	families := []func(i int) string{
		func(i int) string {
			return fmt.Sprintf("Error from slot1_%d@glidein_%d_%d@n%d.cluster.example.edu: memory usage exceeded request_memory", i%64, i*7%900000, i*13%900000, i%400)
		},
		func(i int) string {
			return fmt.Sprintf("Transfer output files failure at execution point slot1_%d@glidein_%d_%d@c%d using protocol osdf. Details: Client Error: remote object already exists, upload aborted (Version: 7.26.%d; Site: Site-%d) ( URL file = osdf:///project/data/2025-09-29/out_%d.root )||FILETRANSFER:1:non-zero exit (1) from /tmp/glide_%x/main/condor/libexec/stash_plugin. |", i%64, i*3%900000, i*11%900000, i%400, i%3, i%40, i, i*2654435761%0xffffff)
		},
		func(int) string { return "The job exceeded allowed execute duration of 20:00:00" },
		func(i int) string {
			return fmt.Sprintf("Transfer input files failure at execution point slot1_%d@c%d using protocol osdf. Details: Client Error: object not found ( URL file = osdf:///project/in_%d.tar.gz )|", i%64, i%400, i)
		},
		func(i int) string {
			return fmt.Sprintf("User requested pause new work; let current running jobs finish; no automatic restart (by user user%d)", i%users)
		},
	}
	out := make([]Record, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Record{
			Kind:    KindHold,
			Message: families[i%len(families)](i),
			Owner:   fmt.Sprintf("user%d", i%users),
			Cluster: int64(i), Proc: int64(i % 7),
			At:   1790000000 + int64(i%86400),
			Code: int64(12 + i%13), SubCode: int64(i % 5),
			Facets: map[string]string{
				"resource": fmt.Sprintf("Resource-%d-CE1", i%resources),
				"site":     fmt.Sprintf("Resource-%d", i%resources),
			},
		})
	}
	return out
}

// The cost of one answer, by phase. Masking was 38us a record before it
// ran per token instead of per message -- 1.1 seconds for a 30,000-record
// window, which is the difference between a page and a wait.
func BenchmarkParse(b *testing.B) {
	recs := corpus(7500, 100, 200)
	b.ReportAllocs()
	for b.Loop() {
		c := NewClusterer()
		for _, r := range recs {
			c.Add(r)
		}
	}
}

// Rendering runs again on every request -- it is what the granularity
// slider re-does -- so it is the one that has to stay small.
func BenchmarkRender(b *testing.B) {
	recs := corpus(7500, 100, 200)
	c := NewClusterer()
	for _, r := range recs {
		c.Add(r)
	}
	b.ReportAllocs()
	for b.Loop() {
		c.Clusters(RenderOptions{
			Granularity: 0.5, LabelCode: HoldReasonLabel,
			Start: 1790000000, End: 1790086400, Buckets: 24,
		})
	}
}

func BenchmarkMaskedTokens(b *testing.B) {
	recs := corpus(1000, 100, 200)
	b.ReportAllocs()
	for b.Loop() {
		for _, r := range recs {
			_ = MaskedTokens(r.Message)
		}
	}
}
