package runtimeest

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
)

// seeded is a reproducible random source for a test workload.
func seeded(a, b uint64) *rand.Rand {
	return rand.New(rand.NewPCG(a, b)) //nolint:gosec // G404: a seeded, reproducible test workload
}

// benchHistory is an estimator that has read a busy owner's week: many
// clusters of a few programs with varying arguments, plus other owners,
// so every level holds samples and the bounds are drawn from pooled
// errors -- the path a listing exercises.
func benchHistory() *Estimator {
	rng := seeded(1, 2)
	e := New(Config{})
	b := NewBatch()
	at := t0
	for c := range 400 {
		owner := "alice"
		if c%4 == 3 {
			owner = fmt.Sprintf("user%d", c%10)
		}
		cmd := fmt.Sprintf("/home/%s/sim%d", owner, c%7)
		for p := range 25 {
			at = at.Add(7 * time.Second)
			b.Add(Completion{
				Features: Features{
					Owner: owner, ClusterID: int64(1000 + c), Cmd: cmd,
					Args:      []string{"--seed", fmt.Sprint(p), "--in", fmt.Sprintf("data%d.csv", c%13)},
					Iwd:       fmt.Sprintf("/home/%s/run%d", owner, c%5),
					BatchName: fmt.Sprintf("sweep-%d", c%9),
				},
				ProcID:    int64(p),
				Runtime:   lognormal(rng, 600*float64(1+c%7), 0.5),
				Submitted: at.Add(-2 * time.Hour),
				Started:   at.Add(-time.Hour),
				Completed: at,
			})
		}
	}
	e.Ingest(b)
	return e
}

// benchQueries is what a listing asks about: 1000 procs of one cluster
// with the same arguments (half of them running), and 1000 jobs of
// distinct clusters and arguments.
func benchQueries() []Query {
	var qs []Query
	for p := range 1000 {
		qs = append(qs, Query{
			Features: Features{
				Owner: "alice", ClusterID: 1100, Cmd: "/home/alice/sim2",
				Args:      []string{"--in", "data7.csv"},
				Iwd:       "/home/alice/run1",
				BatchName: "sweep-3",
			},
			Running: p%2 == 0,
			Elapsed: float64(p * 3),
		})
	}
	for i := range 1000 {
		qs = append(qs, Query{
			Features: Features{
				Owner: "alice", ClusterID: int64(5000 + i), Cmd: fmt.Sprintf("/home/alice/sim%d", i%9),
				Args:      []string{"--seed", fmt.Sprint(i), "--in", fmt.Sprintf("data%d.csv", i)},
				Iwd:       fmt.Sprintf("/home/alice/run%d", i%6),
				BatchName: fmt.Sprintf("sweep-%d", i%11),
			},
			Running: i%3 == 0,
			Elapsed: float64(i),
		})
	}
	return qs
}

// BenchmarkEstimate is one Estimate call per job of a listing.
func BenchmarkEstimate(b *testing.B) {
	e := benchHistory()
	qs := benchQueries()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		for _, q := range qs {
			_ = e.Estimate(q)
		}
	}
}

// BenchmarkEstimateMany is the same listing in one call.
func BenchmarkEstimateMany(b *testing.B) {
	e := benchHistory()
	qs := benchQueries()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = e.EstimateMany(qs)
	}
}
