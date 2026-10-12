package utilization

import (
	"fmt"
	"slices"
	"testing"
)

// A Decoder returns every record it was given, whether as text or as an
// ad, across however many batches and workers, and skips one it cannot
// parse.
func TestDecoder(t *testing.T) {
	const n = 3*decodeBatch + 17
	d := NewDecoder(3)
	for i := range n {
		text := fmt.Sprintf("ClusterId = %d\nProcId = 0\nJobStatus = 4", i)
		if i%2 == 0 {
			d.Row(text)
		} else {
			d.Ad(parseAd(t, text), "ap1")
		}
		if i == 100 {
			d.Row("this is [ not an ad")
		}
	}
	chunks, _ := d.Finish()
	if got := Count(chunks); got != n {
		t.Fatalf("decoded %d jobs, want %d", got, n)
	}
	var clusters []int
	for _, c := range chunks {
		if len(c) == 0 {
			t.Error("an empty chunk")
		}
		for _, j := range c {
			clusters = append(clusters, int(j.Cluster))
			if want := map[bool]string{true: "", false: "ap1"}[j.Cluster%2 == 0]; j.Schedd != want {
				t.Errorf("job %d: schedd %q, want %q", j.Cluster, j.Schedd, want)
			}
		}
	}
	slices.Sort(clusters)
	for i, c := range clusters {
		if c != i {
			t.Fatalf("job %d decoded as cluster %d", i, c)
		}
	}
}

// Finish on a Decoder given nothing returns nothing and stops its
// workers.
func TestDecoderEmpty(t *testing.T) {
	if chunks, _ := NewDecoder(0).Finish(); len(chunks) != 0 {
		t.Errorf("chunks = %v", chunks)
	}
}
