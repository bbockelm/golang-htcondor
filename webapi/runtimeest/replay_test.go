package runtimeest

import (
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"testing"
	"time"
)

// TestReplayBeatsLastTwo replays a synthetic access point and compares
// the estimator with the baseline it replaced: the mean of the owner's
// last two jobs.
//
// Each owner runs several templates -- the same program with different
// numeric arguments -- whose runtimes differ by template, are noisy, and
// drift over the run. Jobs of different templates interleave, which is
// what defeats Last2: the owner's last two jobs are usually of some
// other template. Each job is predicted at submit with only the jobs
// that had finished by then visible.
func TestReplayBeatsLastTwo(t *testing.T) {
	rng := rand.New(rand.NewPCG(42, 1)) //nolint:gosec // G404: a seeded, reproducible test workload
	type sim struct {
		f        Features
		submit   time.Time
		done     time.Time
		runtime  float64
		template int
	}
	var jobs []sim
	owners := []string{"ann", "ben", "cat", "dan"}
	for oi, owner := range owners {
		nTemplates := 3 + oi
		base := make([]float64, nTemplates)
		drift := make([]float64, nTemplates)
		for k := range base {
			base[k] = 60 * math.Pow(4, float64(k)) * (0.5 + rng.Float64())
			drift[k] = (rng.Float64() - 0.5) * 2 // up to e^1 over the run
		}
		cluster := int64(oi * 100_000)
		at := t0
		for range 600 {
			k := rng.IntN(nTemplates)
			cluster++
			frac := at.Sub(t0).Hours() / (24 * 14)
			rt := lognormal(rng, base[k]*math.Exp(drift[k]*frac), 0.35)
			jobs = append(jobs, sim{
				f: Features{
					Owner: owner, ClusterID: cluster, Cmd: fmt.Sprintf("/home/%s/tool%d", owner, k),
					Args: []string{"--seed", fmt.Sprint(rng.IntN(1000)), "--out", fmt.Sprintf("/scratch/%s/out%d.dat", owner, cluster)},
				},
				submit:   at,
				done:     at.Add(time.Duration(rt) * time.Second),
				runtime:  rt,
				template: k,
			})
			at = at.Add(time.Duration(rng.IntN(1800)+60) * time.Second)
		}
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].submit.Before(jobs[j].submit) })
	byDone := append([]sim(nil), jobs...)
	sort.Slice(byDone, func(i, j int) bool { return byDone[i].done.Before(byDone[j].done) })

	e := New(Config{})
	last2 := map[string][]float64{}
	di := 0
	var estHit, l2Hit, n int
	within := func(p, a float64) bool { return p/a >= 0.5 && p/a <= 2 }
	for _, j := range jobs {
		b := NewBatch()
		for di < len(byDone) && byDone[di].done.Before(j.submit) {
			d := byDone[di]
			b.Add(Completion{Features: d.f, Runtime: d.runtime, Submitted: d.submit, Completed: d.done})
			l := last2[d.f.Owner]
			l = append(l, d.runtime)
			if len(l) > 2 {
				l = l[1:]
			}
			last2[d.f.Owner] = l
			di++
		}
		e.Ingest(b)
		l := last2[j.f.Owner]
		if len(l) < 2 {
			continue
		}
		r := e.Estimate(Query{Features: j.f})
		if !r.Available {
			continue
		}
		n++
		if within(r.EstimateSeconds, j.runtime) {
			estHit++
		}
		if within((l[0]+l[1])/2, j.runtime) {
			l2Hit++
		}
	}
	if n < 1000 {
		t.Fatalf("only %d jobs were compared", n)
	}
	est, l2 := float64(estHit)/float64(n), float64(l2Hit)/float64(n)
	t.Logf("within 2x over %d jobs: estimator %.3f, last2 %.3f", n, est, l2)
	if est < l2+0.15 {
		t.Errorf("estimator %.3f does not clearly beat last2 %.3f", est, l2)
	}
	st := e.Stats()
	if st.Scored == 0 || st.Within2x == 0 {
		t.Errorf("self-evaluation recorded nothing: %+v", st)
	}
}
