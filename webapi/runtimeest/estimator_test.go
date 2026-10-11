package runtimeest

import (
	"encoding/json"
	"math"
	"math/rand/v2"
	"sync"
	"testing"
	"time"
)

var t0 = time.Unix(1_700_000_000, 0)

// job is a completed job for a test batch.
type job struct {
	f       Features
	runtime float64
	at      time.Time
}

func ingest(e *Estimator, jobs ...job) {
	b := NewBatch()
	for i, j := range jobs {
		b.Add(j.f, int64(i), j.runtime, j.at)
	}
	e.Ingest(b)
}

func feat(owner, cmd string) Features {
	return Features{Owner: owner, Cmd: cmd}
}

func TestWarmingUpUntilFirstIngest(t *testing.T) {
	e := New(Config{})
	r := e.Estimate(Query{Features: feat("alice", "x")})
	if r.Available || r.Reason != ReasonWarmingUp {
		t.Fatalf("before any ingest: %+v", r)
	}
	e.Ingest(NewBatch())
	r = e.Estimate(Query{Features: feat("alice", "x")})
	if r.Available || r.Reason != ReasonInsufficientHistory {
		t.Fatalf("after an empty ingest: %+v", r)
	}
	if !e.Stats().Loaded {
		t.Error("an empty ingest did not mark the estimator loaded")
	}
}

// A level needs three samples to answer, and global thirty.
func TestMinimumSamples(t *testing.T) {
	e := New(Config{})
	ingest(e, job{feat("alice", "x"), 100, t0}, job{feat("alice", "x"), 100, t0.Add(time.Second)})
	if r := e.Estimate(Query{Features: feat("alice", "x")}); r.Available {
		t.Fatalf("two samples answered: %+v", r)
	}
	ingest(e, job{feat("alice", "x"), 100, t0.Add(2 * time.Second)})
	r := e.Estimate(Query{Features: feat("alice", "x")})
	if !r.Available || r.EstimateSeconds != 100 {
		t.Fatalf("three samples: %+v", r)
	}
	// Bob has nothing of his own and global has only three jobs.
	if r := e.Estimate(Query{Features: feat("bob", "x")}); r.Available || r.Reason != ReasonInsufficientHistory {
		t.Fatalf("bob with a thin global: %+v", r)
	}
	var more []job
	for i := range 30 {
		more = append(more, job{feat("carol", "y"), 500, t0.Add(time.Duration(10+i) * time.Second)})
	}
	ingest(e, more...)
	r = e.Estimate(Query{Features: feat("bob", "x")})
	if !r.Available || r.Basis.Level != "global" {
		t.Fatalf("bob with a full global: %+v", r)
	}
}

// With no track record the most specific available level answers.
func TestMostSpecificLevelAnswersByDefault(t *testing.T) {
	e := New(Config{})
	var jobs []job
	for i := range 3 {
		// Same cluster, same command.
		f := Features{Owner: "alice", ClusterID: 5, Cmd: "sim", Args: []string{"--n", "1"}}
		jobs = append(jobs, job{f, 1000, t0.Add(time.Duration(i) * time.Second)})
	}
	for i := range 3 {
		// Other runs of the same command, much shorter.
		f := Features{Owner: "alice", ClusterID: int64(10 + i), Cmd: "sim", Args: []string{"--n", "2"}}
		jobs = append(jobs, job{f, 10, t0.Add(time.Duration(10+i) * time.Second)})
	}
	ingest(e, jobs...)
	r := e.Estimate(Query{Features: Features{Owner: "alice", ClusterID: 5, Cmd: "sim", Args: []string{"--n", "1"}}})
	if r.Basis == nil || r.Basis.Level != "cluster" || r.EstimateSeconds != 1000 {
		t.Fatalf("got %+v, want the cluster level", r)
	}
	r = e.Estimate(Query{Features: Features{Owner: "alice", ClusterID: 99, Cmd: "sim", Args: []string{"--n", "7"}}})
	if r.Basis == nil || r.Basis.Level != "template" || r.Basis.SampleCount != 6 {
		t.Fatalf("got %+v, want the template level over all six", r)
	}
}

func TestChooseSwitchesOnScores(t *testing.T) {
	preds := [numLevels]float64{}
	for i := range preds {
		preds[i] = math.NaN()
	}
	preds[LevelExact], preds[LevelCmd] = 100, 200
	own := &ownerState{}
	for i := range own.score {
		own.score[i] = scorePrior
	}
	if l, _ := choose(own, &preds); l != LevelExact {
		t.Errorf("equal scores chose %s", l)
	}
	own.score[LevelCmd] = scorePrior - scoreMargin/2
	if l, _ := choose(own, &preds); l != LevelExact {
		t.Errorf("a near-tie chose %s; it belongs to the more specific level", l)
	}
	own.score[LevelCmd] = scorePrior - 2*scoreMargin
	if l, _ := choose(own, &preds); l != LevelCmd {
		t.Errorf("a clearly better level was not chosen: %s", l)
	}
	if l, _ := choose(nil, &preds); l != LevelExact {
		t.Errorf("no owner state chose %s", l)
	}
}

// End to end: a cluster's completed siblings are biased short -- the
// short procs finish first -- so the cluster level keeps
// underestimating, while the same program across clusters does not. The
// owner's scores learn that and stop asking the cluster.
func TestScoresMoveSelectionToTheBetterLevel(t *testing.T) {
	e := New(Config{})
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // G404: a seeded, reproducible test workload
	var jobs []job
	for c := range 60 {
		start := t0.Add(time.Duration(c) * 10_000 * time.Second)
		for i, p := range rng.Perm(10) {
			rt := float64(100 * (p + 1))
			jobs = append(jobs, job{Features{Owner: "alice", ClusterID: int64(c + 1), Cmd: "sim"},
				rt, start.Add(time.Duration(rt) * time.Second).Add(time.Duration(i) * time.Millisecond)})
		}
	}
	ingest(e, jobs...)
	own := e.st.owners["alice"]
	if own.score[LevelCluster] < own.score[LevelExact]+scoreMargin {
		t.Fatalf("cluster score %.3f is not clearly worse than exact %.3f", own.score[LevelCluster], own.score[LevelExact])
	}

	// A new cluster with four short procs done.
	var sibs []job
	start := t0.Add(61 * 10_000 * time.Second)
	for p := range 4 {
		rt := float64(100 * (p + 1))
		sibs = append(sibs, job{Features{Owner: "alice", ClusterID: 99, Cmd: "sim"}, rt, start.Add(time.Duration(rt) * time.Second)})
	}
	ingest(e, sibs...)
	r := e.Estimate(Query{Features: Features{Owner: "alice", ClusterID: 99, Cmd: "sim"}})
	if !r.Available || r.Basis.Level == "cluster" {
		t.Errorf("the cluster level still answers: %+v (scores %v)", r, own.score)
	}
}

// Jobs are applied in completion order whatever order the batch holds
// them in, and a job is scored before it is added, so it never sees
// itself.
func TestPrequentialOrder(t *testing.T) {
	e := New(Config{})
	f := feat("alice", "x")
	// The newest first: applied in batch order, the 1000s job would be
	// scored against nothing, and the third 100s job against two.
	ingest(e,
		job{f, 1000, t0.Add(3 * time.Second)},
		job{f, 100, t0},
		job{f, 200, t0.Add(2 * time.Second)},
		job{f, 100, t0.Add(time.Second)},
	)
	st := e.Stats()
	if st.Scored != 1 {
		t.Fatalf("scored = %d, want 1: only the last job had three before it", st.Scored)
	}
	if st.Within2x != 0 {
		t.Errorf("within2x = %d: 1000s against a median of 100s is not within 2x", st.Within2x)
	}
	// The residual is against the median of the three before it (100),
	// not of all four (150), which is what it would be had it seen itself.
	res := e.st.owners["alice"].resid.ring
	if len(res) != 1 {
		t.Fatalf("residuals = %v", res)
	}
	if want := math.Log(1000.0 / 100); math.Abs(float64(res[0])-want) > 1e-5 {
		t.Errorf("residual = %v, want log(1000/100) = %v", res[0], want)
	}
	if st.ScoredByLevel["exact"] != 1 {
		t.Errorf("scored by level = %v", st.ScoredByLevel)
	}
}

// lognormal draws exp(N(mu, sigma)).
func lognormal(rng *rand.Rand, median, sigma float64) float64 {
	return median * math.Exp(sigma*rng.NormFloat64())
}

// The calibrated 90th percentile covers about 90% of a lognormal
// workload. The group's own 90th percentile would not: the estimate's
// error adds to the spread.
func TestP90Calibration(t *testing.T) {
	e := New(Config{})
	rng := rand.New(rand.NewPCG(7, 11)) //nolint:gosec // G404: a seeded, reproducible test workload
	f := feat("alice", "sim")
	at := t0
	covered, total := 0, 0
	lowCovered := 0
	for i := range 3000 {
		rt := lognormal(rng, 1000, 0.6)
		if i >= 300 {
			r := e.Estimate(Query{Features: f})
			if !r.Available {
				t.Fatalf("job %d: %+v", i, r)
			}
			if r.P90Seconds < r.EstimateSeconds || r.P10Seconds > r.EstimateSeconds {
				t.Fatalf("bounds out of order: %+v", r)
			}
			total++
			if rt <= r.P90Seconds {
				covered++
			}
			if rt >= r.P10Seconds {
				lowCovered++
			}
		}
		ingest(e, job{f, rt, at})
		at = at.Add(time.Second)
	}
	cov := float64(covered) / float64(total)
	if cov < 0.85 || cov > 0.95 {
		t.Errorf("p90 coverage = %.3f, want 0.85-0.95", cov)
	}
	low := float64(lowCovered) / float64(total)
	t.Logf("coverage over %d jobs: p90 %.3f, p10 %.3f", total, cov, low)
	if low < 0.85 || low > 0.95 {
		t.Errorf("p10 coverage = %.3f, want 0.85-0.95", low)
	}
}

func TestRunningJobs(t *testing.T) {
	e := New(Config{})
	f := feat("alice", "sim")
	var jobs []job
	for i := range 11 {
		jobs = append(jobs, job{f, float64(100 + 10*i), t0.Add(time.Duration(i) * time.Second)})
	}
	ingest(e, jobs...) // 100..200, median 150

	r := e.Estimate(Query{Features: f, Running: true, Elapsed: 50})
	if r.EstimateSeconds != 150 || r.RemainingSeconds == nil || *r.RemainingSeconds != 100 || r.ExceededHistory {
		t.Errorf("early: %+v", r)
	}
	if r.P10Seconds < 50 {
		t.Errorf("p10 %v is below the elapsed time", r.P10Seconds)
	}

	// Past the median: re-estimated from the runs longer than 170s
	// (180, 190, 200).
	r = e.Estimate(Query{Features: f, Running: true, Elapsed: 170})
	if r.EstimateSeconds != 190 || r.RemainingSeconds == nil || *r.RemainingSeconds != 20 || r.ExceededHistory {
		t.Errorf("past the median: %+v", r)
	}
	if r.P90Seconds < r.EstimateSeconds || r.P10Seconds < 170 {
		t.Errorf("conditioned bounds: %+v", r)
	}

	// Past all but one: no honest remaining time.
	r = e.Estimate(Query{Features: f, Running: true, Elapsed: 195})
	if !r.ExceededHistory || r.RemainingSeconds != nil {
		t.Errorf("past history: %+v", r)
	}
	if r.ElapsedSeconds == nil || *r.ElapsedSeconds != 195 {
		t.Errorf("elapsed = %v", r.ElapsedSeconds)
	}
	if r.EstimateSeconds != 150 {
		t.Errorf("an exceeded job reports estimate %v; want what history said (150)", r.EstimateSeconds)
	}

	// Not running: no elapsed, no remaining.
	r = e.Estimate(Query{Features: f})
	if r.ElapsedSeconds != nil || r.RemainingSeconds != nil {
		t.Errorf("idle job: %+v", r)
	}
}

func TestQueryFromAd(t *testing.T) {
	now := time.Unix(10_000, 0)
	q := QueryFromAd(adFrom(t, `Owner = "a"
Cmd = "x"
JobStatus = 2
JobCurrentStartDate = 9000
JobStartDate = 1000
ServerTime = 9500`), now)
	if !q.Running || q.Elapsed != 500 {
		t.Errorf("running with ServerTime: %+v", q)
	}
	q = QueryFromAd(adFrom(t, `Owner = "a"
JobStatus = 2
JobStartDate = 4000`), now)
	if !q.Running || q.Elapsed != 6000 {
		t.Errorf("running from JobStartDate: %+v", q)
	}
	q = QueryFromAd(adFrom(t, `Owner = "a"
JobStatus = 2`), now)
	if q.Running {
		t.Errorf("running with no start time: %+v", q)
	}
	q = QueryFromAd(adFrom(t, `Owner = "a"
JobStatus = 1
JobCurrentStartDate = 9000`), now)
	if q.Running {
		t.Errorf("idle job counted as running: %+v", q)
	}
}

func TestCompletedRuntime(t *testing.T) {
	base := `JobStatus = 4
ExitCode = 0
ExitBySignal = false
JobUniverse = 5
RemoteWallClockTime = 300
`
	cases := []struct {
		name  string
		extra string
		want  float64
		ok    bool
	}{
		{"wall clock", "", 300, true},
		{"committed wins", "CommittedTime = 120", 120, true},
		{"zero committed falls back", "CommittedTime = 0", 300, true},
		{"failed", "ExitCode = 1", 0, false},
		{"signal", "ExitBySignal = true", 0, false},
		{"removed", "JobStatus = 3", 0, false},
		{"dagman", "JobUniverse = 7", 0, false},
		{"local", "JobUniverse = 12", 0, false},
		{"no runtime", "RemoteWallClockTime = 0", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Later attributes override earlier ones in ParseOld.
			got, ok := CompletedRuntime(adFrom(t, base+tc.extra))
			if ok != tc.ok || got != tc.want {
				t.Errorf("got %v %v, want %v %v", got, ok, tc.want, tc.ok)
			}
		})
	}
	if _, ok := CompletedRuntime(adFrom(t, "JobStatus = 4\nRemoteWallClockTime = 5")); ok {
		t.Error("a record with no ExitCode was accepted")
	}
}

func TestBatchAddAd(t *testing.T) {
	b := NewBatch()
	if !b.AddAd(adFrom(t, `Owner = "a"
Cmd = "x"
ClusterId = 1
ProcId = 0
JobStatus = 4
ExitCode = 0
RemoteWallClockTime = 60
CompletionDate = 1000`)) {
		t.Fatal("a clean completion was refused")
	}
	if b.AddAd(adFrom(t, `Owner = "a"
JobStatus = 4
ExitCode = 0
RemoteWallClockTime = 60`)) {
		t.Error("a completion with no time was accepted")
	}
	if !b.AddAd(adFrom(t, `Owner = "a"
JobStatus = 4
ExitCode = 0
RemoteWallClockTime = 60
EnteredHistoryTime = 2000`)) {
		t.Error("EnteredHistoryTime was not used as the completion time")
	}
	if b.Len() != 2 {
		t.Errorf("len = %d", b.Len())
	}
}

func TestEvict(t *testing.T) {
	e := New(Config{})
	var jobs []job
	for i := range 40 {
		jobs = append(jobs, job{Features{Owner: "old", ClusterID: 1, Cmd: "x"}, 100, t0.Add(time.Duration(i) * time.Second)})
	}
	for i := range 3 {
		jobs = append(jobs, job{Features{Owner: "new", ClusterID: 2, Cmd: "y"}, 50, t0.Add(time.Hour + time.Duration(i)*time.Second)})
	}
	ingest(e, jobs...)
	before := e.Stats()
	n := e.Evict(t0.Add(30 * time.Minute))
	after := e.Stats()
	// old's cluster, exact, template, cmd and owner groups.
	if n != 5 {
		t.Errorf("evicted %d groups, want 5", n)
	}
	if after.Owners != 1 || before.Owners != 2 {
		t.Errorf("owners %d -> %d", before.Owners, after.Owners)
	}
	if after.JobsIngested != before.JobsIngested {
		t.Error("eviction changed the ingested count")
	}
	// old now falls back to global, which is never evicted.
	r := e.Estimate(Query{Features: Features{Owner: "old", ClusterID: 1, Cmd: "x"}})
	if !r.Available || r.Basis.Level != "global" {
		t.Errorf("after eviction: %+v", r)
	}
	r = e.Estimate(Query{Features: Features{Owner: "new", Cmd: "y"}})
	if !r.Available || r.Basis.Level != "exact" {
		t.Errorf("a recent group was evicted: %+v", r)
	}
}

// Readers run while batches are applied; -race checks the locking, and
// every answer must come from a whole batch: each batch adds ten jobs of
// one runtime, so a reader that saw half of one would see a sample
// count that is not a multiple of ten.
func TestConcurrentReadsDuringIngest(t *testing.T) {
	e := New(Config{Window: 10_000})
	f := feat("alice", "x")
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var bad sync.Once
	var badResult Result
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				r := e.Estimate(Query{Features: f, Running: true, Elapsed: 10})
				if r.Available && r.Basis.SampleCount%10 != 0 {
					bad.Do(func() { badResult = r })
				}
				_ = e.Stats()
			}
		})
	}
	for i := range 200 {
		var jobs []job
		for j := range 10 {
			jobs = append(jobs, job{f, float64(100 + i), t0.Add(time.Duration(i*10+j) * time.Second)})
		}
		ingest(e, jobs...)
		if i%50 == 0 {
			e.Evict(t0)
		}
	}
	close(stop)
	wg.Wait()
	if badResult.Available {
		t.Errorf("a reader saw a partial batch: %+v", badResult)
	}
}

// The JSON is the API. Pin its shape.
func TestResultJSON(t *testing.T) {
	elapsed, remaining := 120.0, 480.0
	r := Result{
		Available: true, EstimateSeconds: 600, P10Seconds: 300, P90Seconds: 1500,
		Basis:          &Basis{Level: "template", SampleCount: 12},
		ElapsedSeconds: &elapsed, RemainingSeconds: &remaining,
		Model: Model{TrainedThrough: "2026-10-10T12:00:00Z", JobsIngested: 5000},
	}
	got, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"available":true,"estimate_seconds":600,"p10_seconds":300,"p90_seconds":1500,` +
		`"basis":{"level":"template","sample_count":12},"elapsed_seconds":120,"remaining_seconds":480,` +
		`"exceeded_history":false,"model":{"trained_through":"2026-10-10T12:00:00Z","jobs_ingested":5000}}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	got, _ = json.Marshal(Result{Reason: ReasonWarmingUp})
	if want := `{"available":false,"reason":"model_warming_up","exceeded_history":false,"model":{"jobs_ingested":0}}`; string(got) != want {
		t.Errorf("unavailable: got %s", got)
	}
}
