package runtimeest

import (
	"cmp"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Unix(1_700_000_000, 0)

// job is a completed job for a test batch. With no submit or start
// time it is scored as of its completion.
type job struct {
	f       Features
	runtime float64
	at      time.Time
}

func ingest(e *Estimator, jobs ...job) {
	b := NewBatch()
	for i, j := range jobs {
		b.Add(Completion{Features: j.f, ProcID: int64(i), Runtime: j.runtime, Completed: j.at})
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

// A level answers from a single earlier run: they are the owner's own
// jobs.
func TestMinimumSamples(t *testing.T) {
	e := New(Config{})
	ingest(e, job{feat("alice", "x"), 100, t0})
	r := e.Estimate(Query{Features: feat("alice", "x")})
	if !r.Available || r.EstimateSeconds != 100 || r.Basis.SampleCount != 1 {
		t.Fatalf("one earlier run: %+v", r)
	}
}

// Other users' jobs never answer for an owner with none of their own,
// however many there are, and a job with no owner gets no estimate at
// all. Nor is such a job scored when it completes: it had no estimate
// to score.
func TestNoEstimateFromOtherUsersJobs(t *testing.T) {
	e := New(Config{})
	var hist []job
	for i := range 500 {
		hist = append(hist, job{feat("carol", "x"), 500, t0.Add(time.Duration(i) * time.Second)})
	}
	ingest(e, hist...)
	scored := e.Stats().Scored
	for _, q := range []Query{
		{Features: feat("bob", "x")},
		{Features: feat("bob", "x"), Running: true, Elapsed: 10},
		{Features: feat("", "x")},
	} {
		if r := e.Estimate(q); r.Available || r.Reason != ReasonInsufficientHistory || r.Basis != nil {
			t.Errorf("%+v: %+v", q, r)
		}
		if r := e.EstimateMany([]Query{q})[0]; r.Available || r.Reason != ReasonInsufficientHistory {
			t.Errorf("many %+v: %+v", q, r)
		}
	}
	ingest(e, job{feat("bob", "x"), 60, t0.Add(time.Hour)}, job{feat("", "x"), 60, t0.Add(time.Hour + time.Second)})
	st := e.Stats()
	if st.Scored != scored {
		t.Errorf("scored %d -> %d: a job with no history of its owner's was scored", scored, st.Scored)
	}
	if _, ok := st.ScoredByLevel["global"]; ok {
		t.Errorf("stats still report a global level: %v", st.ScoredByLevel)
	}
	// Bob's own job now answers for him, from his runtime alone.
	if r := e.Estimate(Query{Features: feat("bob", "x")}); !r.Available || r.Basis.Level != "exact" || r.EstimateSeconds != 60 {
		t.Errorf("bob after his own job: %+v", r)
	}
}

// choose answers only from a level that is available, and not at all
// when none is.
func TestChooseNoLevel(t *testing.T) {
	preds := [numLevels]float64{}
	for i := range preds {
		preds[i] = math.NaN()
	}
	scores := &[numLevels]float32{}
	if _, ok := choose(scores, &preds); ok {
		t.Error("chose a level with none available")
	}
	if _, ok := choose(nil, &preds); ok {
		t.Error("chose a level for no owner with none available")
	}
	preds[LevelOwner] = 100
	if l, ok := choose(scores, &preds); !ok || l != LevelOwner {
		t.Errorf("chose %s %v, want owner", l, ok)
	}
}

// With no track record the most specific available level answers.
func TestMostSpecificLevelAnswersByDefault(t *testing.T) {
	e := New(Config{})
	// One job: nothing came before it, so nothing has been scored.
	ingest(e, job{Features{Owner: "alice", ClusterID: 5, Cmd: "sim", Args: []string{"--n", "1"}}, 1000, t0})
	r := e.Estimate(Query{Features: Features{Owner: "alice", ClusterID: 5, Cmd: "sim", Args: []string{"--n", "1"}}})
	if r.Basis == nil || r.Basis.Level != "cluster" || r.EstimateSeconds != 1000 {
		t.Fatalf("got %+v, want the cluster level", r)
	}
	r = e.Estimate(Query{Features: Features{Owner: "alice", ClusterID: 6, Cmd: "sim", Args: []string{"--n", "1"}}})
	if r.Basis == nil || r.Basis.Level != "exact" {
		t.Fatalf("got %+v, want the exact level", r)
	}
	r = e.Estimate(Query{Features: Features{Owner: "alice", ClusterID: 6, Cmd: "sim", Args: []string{"--n", "7"}}})
	if r.Basis == nil || r.Basis.Level != "template" {
		t.Fatalf("got %+v, want the template level", r)
	}
}

func TestChooseSwitchesOnScores(t *testing.T) {
	preds := [numLevels]float64{}
	for i := range preds {
		preds[i] = math.NaN()
	}
	preds[LevelExact], preds[LevelCmd] = 100, 200
	own := &[numLevels]float32{}
	for i := range own {
		own[i] = scorePrior
	}
	if l, _ := choose(own, &preds); l != LevelExact {
		t.Errorf("equal scores chose %s", l)
	}
	own[LevelCmd] = scorePrior - scoreMargin/2
	if l, _ := choose(own, &preds); l != LevelExact {
		t.Errorf("a near-tie chose %s; it belongs to the more specific level", l)
	}
	own[LevelCmd] = scorePrior - 2*scoreMargin
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
	own := e.st.owners["alice"].scores(viewSubmit)
	if own[LevelCluster] < own[LevelExact]+scoreMargin {
		t.Fatalf("cluster score %.3f is not clearly worse than exact %.3f", own[LevelCluster], own[LevelExact])
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
		t.Errorf("the cluster level still answers: %+v (scores %v)", r, *own)
	}
}

// Jobs are applied in completion order whatever order the batch holds
// them in, and a job is scored before it is added, so it never sees
// itself.
func TestPrequentialOrder(t *testing.T) {
	e := New(Config{})
	f := feat("alice", "x")
	ingest(e,
		job{f, 1000, t0.Add(3 * time.Second)},
		job{f, 100, t0},
		job{f, 200, t0.Add(2 * time.Second)},
		job{f, 100, t0.Add(time.Second)},
	)
	st := e.Stats()
	if st.Scored != 3 {
		t.Fatalf("scored = %d, want 3: every job but the first had one before it", st.Scored)
	}
	// 100 against 100, 200 against 100 (exactly 2x), 1000 against 100.
	if st.Within2x != 2 {
		t.Errorf("within2x = %d, want 2", st.Within2x)
	}
	// In completion order, each against the median of the ones before
	// it -- the last against 100, not the 150 it would be had it seen
	// itself.
	res := e.st.owners["alice"].resid[viewSubmit].ring
	want := []float64{0, math.Log(2), math.Log(10)}
	if len(res) != len(want) {
		t.Fatalf("residuals = %v", res)
	}
	for i, w := range want {
		if math.Abs(float64(res[i].v)-w) > 1e-5 {
			t.Errorf("residual %d = %v, want %v", i, res[i].v, w)
		}
	}
}

// A completed job is scored as of its submit and its start, from only
// the jobs that had completed by then. Siblings that finished between
// its submit and its completion are information a waiting job never
// had: the cluster level is never available to the submit view, and is
// to the start view once earlier siblings have finished.
func TestScoringViews(t *testing.T) {
	e := New(Config{})
	b := NewBatch()
	for i := range 10 {
		// All submitted together; started in waves of two; each runs 100s.
		start := t0.Add(time.Duration(i/2) * 150 * time.Second)
		b.Add(Completion{
			Features: Features{Owner: "alice", ClusterID: 7, Cmd: "sim"}, ProcID: int64(i), Runtime: 100,
			Submitted: t0, Started: start, Completed: start.Add(100 * time.Second),
		})
	}
	e.Ingest(b)
	if n := e.st.levelResid[viewSubmit][LevelCluster].len(); n != 0 {
		t.Errorf("the submit view answered %d jobs from their own cluster", n)
	}
	if st := e.Stats(); st.ScoredByLevel["cluster"] != 0 || st.Scored != 0 {
		t.Errorf("submit-view counters credited later siblings: %+v", st)
	}
	// Waves 2-5 started after wave 1 finished.
	if n := e.st.levelResid[viewStart][LevelCluster].len(); n != 8 {
		t.Errorf("the start view answered %d jobs from their cluster, want 8", n)
	}
}

// Within 2x is judged on the same floored error the scores use, so a 3s
// job predicted as 1s is not a miss.
func TestWithin2xUsesTheFlooredError(t *testing.T) {
	e := New(Config{})
	f := feat("alice", "x")
	ingest(e, job{f, 1, t0}, job{f, 3, t0.Add(time.Second)})
	if st := e.Stats(); st.Scored != 1 || st.Within2x != 1 {
		t.Errorf("stats = %+v", st)
	}
}

// A waiting job's bounds come from the submit view's errors and a
// running job's from the start view's.
func TestBoundsFollowTheView(t *testing.T) {
	e := New(Config{})
	f := feat("alice", "x")
	ingest(e, job{f, 100, t0})
	own := e.st.owners["alice"]
	for i := range 50 {
		wide := float32(2 * (float64(i)/49 - 0.5)) // -1 .. 1
		own.resid[viewSubmit].add(wide, 0, 256, 256)
		own.resid[viewStart].add(wide/10, 0, 256, 256)
	}
	idle := e.Estimate(Query{Features: f})
	running := e.Estimate(Query{Features: f, Running: true})
	if !(idle.P90Seconds > running.P90Seconds) || !(idle.P10Seconds < running.P10Seconds) {
		t.Errorf("idle %v-%v should be wider than running %v-%v",
			idle.P10Seconds, idle.P90Seconds, running.P10Seconds, running.P90Seconds)
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
	// old has nothing left, and new's jobs do not answer for old.
	r := e.Estimate(Query{Features: Features{Owner: "old", ClusterID: 1, Cmd: "x"}})
	if r.Available || r.Reason != ReasonInsufficientHistory {
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
				for _, r := range e.EstimateMany([]Query{{Features: f}, {Features: f, Running: true, Elapsed: 10}}) {
					if r.Available && r.Basis.SampleCount%10 != 0 {
						bad.Do(func() { badResult = r })
					}
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
		`"basis":{"level":"template","sample_count":12},"rough":false,"elapsed_seconds":120,"remaining_seconds":480,` +
		`"exceeded_history":false,"model":{"trained_through":"2026-10-10T12:00:00Z","jobs_ingested":5000}}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	got, _ = json.Marshal(Result{Reason: ReasonWarmingUp})
	if want := `{"available":false,"reason":"model_warming_up","rough":false,"exceeded_history":false,"model":{"jobs_ingested":0}}`; string(got) != want {
		t.Errorf("unavailable: got %s", got)
	}
	got, _ = json.Marshal(Result{Available: true, Rough: true, Basis: &Basis{Level: "owner", SampleCount: 3, NewCommand: true}})
	if want := `{"available":true,"basis":{"level":"owner","sample_count":3,"new_command":true},"rough":true,` +
		`"exceeded_history":false,"model":{"jobs_ingested":0}}`; string(got) != want {
		t.Errorf("rough: got %s", got)
	}
}

// The broad levels are marked rough, and say when the owner has never
// run the program.
func TestRoughLevels(t *testing.T) {
	e := New(Config{})
	var hist []job
	for i := range 5 {
		hist = append(hist, job{Features{Owner: "alice", Cmd: "x", Args: []string{"1"}}, 100, t0.Add(time.Duration(i) * time.Second)})
	}
	for i := range 30 {
		hist = append(hist, job{feat("carol", "z"), 500, t0.Add(time.Duration(10+i) * time.Second)})
	}
	ingest(e, hist...)

	cases := []struct {
		name       string
		f          Features
		level      string
		rough, new bool
	}{
		{"same arguments", Features{Owner: "alice", Cmd: "x", Args: []string{"1"}}, "exact", false, false},
		{"other arguments", Features{Owner: "alice", Cmd: "x", Args: []string{"a"}}, "cmd", true, false},
		{"another program", feat("alice", "y"), "owner", true, true},
	}
	for _, c := range cases {
		r := e.Estimate(Query{Features: c.f})
		if !r.Available || r.Basis.Level != c.level || r.Rough != c.rough || r.Basis.NewCommand != c.new {
			t.Errorf("%s: level %v rough %v new_command %v, want %s %v %v",
				c.name, r.Basis, r.Rough, r.Basis != nil && r.Basis.NewCommand, c.level, c.rough, c.new)
		}
	}
	// Carol's thirty jobs do not answer for bob, who has none.
	if r := e.Estimate(Query{Features: feat("bob", "x")}); r.Available || r.Reason != ReasonInsufficientHistory {
		t.Errorf("nothing of their own: %+v", r)
	}
}

// syntheticBatch is n completed jobs of a few owners, programs and
// argument patterns, from start on, with lognormal runtimes.
func syntheticBatch(rng *rand.Rand, start time.Time, n int) *Batch {
	b := NewBatch()
	at := start
	for i := range n {
		owner := []string{"alice", "bob", "carol"}[rng.IntN(3)]
		at = at.Add(time.Duration(1+rng.IntN(20)) * time.Second)
		b.Add(Completion{
			Features: Features{
				Owner: owner, ClusterID: int64(100 + rng.IntN(40)), Cmd: "sim" + strconv.Itoa(rng.IntN(4)),
				Args:      []string{"--n", strconv.Itoa(rng.IntN(5))},
				BatchName: "b" + strconv.Itoa(rng.IntN(3)),
			},
			ProcID:    int64(i),
			Runtime:   lognormal(rng, 300*float64(1+rng.IntN(5)), 0.6),
			Submitted: at.Add(-time.Duration(rng.IntN(3600)) * time.Second),
			Started:   at.Add(-time.Duration(rng.IntN(600)) * time.Second),
			Completed: at,
		})
	}
	return b
}

// syntheticQueries are jobs like syntheticBatch's, waiting and running.
func syntheticQueries(rng *rand.Rand, n int) []Query {
	qs := make([]Query, n)
	for i := range qs {
		qs[i] = Query{
			Features: Features{
				Owner: []string{"alice", "bob", "carol", "dave"}[rng.IntN(4)], ClusterID: int64(100 + rng.IntN(50)),
				Cmd: "sim" + strconv.Itoa(rng.IntN(5)), Args: []string{"--n", strconv.Itoa(rng.IntN(7))},
				BatchName: "b" + strconv.Itoa(rng.IntN(3)),
			},
			Running: rng.IntN(2) == 0,
			Elapsed: float64(rng.IntN(3000)),
		}
	}
	return qs
}

// The residual-pool cache changes no answer, and is dropped when a
// batch or an eviction changes what it was built from: an estimator
// with the cache and one without, fed the same batches, agree after
// every one.
func TestPoolCacheMatchesUncached(t *testing.T) {
	cached := New(Config{})
	uncached := New(Config{noPoolCache: true})
	qs := syntheticQueries(seeded(7, 8), 400)
	check := func(stage string) {
		t.Helper()
		pooled := 0
		for i, q := range qs {
			a, b := cached.Estimate(q), uncached.Estimate(q)
			if !reflect.DeepEqual(a, b) {
				t.Fatalf("%s: query %d: cached %+v, uncached %+v", stage, i, a, b)
			}
			if a.Available {
				pooled++
			}
		}
		if pooled == 0 {
			t.Fatalf("%s: no query had an estimate; the test checks nothing", stage)
		}
	}
	start := t0
	for round := range 6 {
		// The same batch for both: Batch.sorted reorders in place.
		rngA, rngB := seeded(uint64(round), 1), seeded(uint64(round), 1)
		cached.Ingest(syntheticBatch(rngA, start, 300))
		uncached.Ingest(syntheticBatch(rngB, start, 300))
		start = start.Add(3 * time.Hour)
		check(fmt.Sprintf("after batch %d", round))
		if round == 3 {
			// Halfway through the batch just read: some groups go, and
			// the rest still answer.
			cutoff := start.Add(-3*time.Hour + 25*time.Minute)
			if n := cached.Evict(cutoff); n == 0 {
				t.Fatal("the eviction dropped nothing")
			}
			uncached.Evict(cutoff)
			check("after an eviction")
		}
	}
	if len(cached.st.pools) == 0 {
		t.Error("the cache was never filled; the comparison exercised nothing")
	}
}

// EstimateMany answers each job exactly as Estimate does, in any order.
func TestEstimateManyMatchesEstimate(t *testing.T) {
	e := New(Config{})
	qs := syntheticQueries(seeded(3, 4), 300)
	for _, r := range e.EstimateMany(qs) {
		if r.Reason != ReasonWarmingUp {
			t.Fatalf("before any ingest: %+v", r)
		}
	}
	e.Ingest(syntheticBatch(seeded(5, 6), t0, 2000))
	// Sorted, so neighbours share keys, and as given.
	sorted := slices.Clone(qs)
	slices.SortFunc(sorted, func(a, b Query) int {
		return cmp.Or(cmp.Compare(a.Features.ClusterID, b.Features.ClusterID), cmp.Compare(a.Features.Owner, b.Features.Owner))
	})
	for _, set := range [][]Query{qs, sorted} {
		got := e.EstimateMany(set)
		for i, q := range set {
			if want := e.Estimate(q); !reflect.DeepEqual(got[i], want) {
				t.Fatalf("query %d %+v: many %+v, one %+v", i, q, got[i], want)
			}
		}
	}
	if len(e.EstimateMany(nil)) != 0 {
		t.Error("no queries, some answers")
	}
}

// Scheduler- and local-universe jobs -- DAGMan, mostly -- are never
// estimated, alone or in a listing, however much history there is.
func TestSchedulerAndLocalUniverseNotEstimated(t *testing.T) {
	e := New(Config{})
	var jobs []job
	for i := range 40 {
		jobs = append(jobs, job{feat(fmt.Sprintf("u%d", i), "condor_dagman"), 100, t0.Add(time.Duration(i) * time.Second)})
	}
	jobs = append(jobs, job{feat("alice", "condor_dagman"), 100, t0.Add(time.Minute)})
	ingest(e, jobs...)
	dagman := Features{Owner: "alice", Cmd: "condor_dagman", Universe: UniverseScheduler}
	local := Features{Owner: "alice", Cmd: "condor_dagman", Universe: UniverseLocal}
	vanilla := Features{Owner: "alice", Cmd: "condor_dagman"}
	for _, f := range []Features{dagman, local} {
		for _, running := range []bool{false, true} {
			r := e.Estimate(Query{Features: f, Running: running, Elapsed: 10})
			if r.Available || r.Reason != ReasonNotEstimated || r.Basis != nil || r.Model.JobsIngested != 41 {
				t.Errorf("universe %d running %v: %+v", f.Universe, running, r)
			}
		}
	}
	got := e.EstimateMany([]Query{{Features: vanilla}, {Features: dagman}, {Features: vanilla}, {Features: local, Running: true}})
	for i, want := range []bool{true, false, true, false} {
		if got[i].Available != want {
			t.Errorf("EstimateMany[%d] = %+v, want available %v", i, got[i], want)
		}
		if !want && got[i].Reason != ReasonNotEstimated {
			t.Errorf("EstimateMany[%d] reason %q", i, got[i].Reason)
		}
	}
	if b, _ := json.Marshal(got[1]); !strings.Contains(string(b), `"reason":"not_estimated"`) {
		t.Errorf("JSON = %s", b)
	}
}

// A DAG node is never estimated from the same owner's standalone jobs,
// even running the same command, nor the reverse.
func TestDAGNodesAndStandaloneJobsKeptApart(t *testing.T) {
	e := New(Config{})
	node := Features{Owner: "alice", ClusterID: 1, Cmd: "sim", DAGNode: true}
	alone := Features{Owner: "alice", ClusterID: 2, Cmd: "sim"}
	ingest(e, job{node, 100, t0}, job{alone, 5000, t0.Add(time.Second)})
	node.ClusterID, alone.ClusterID = 3, 4
	if r := e.Estimate(Query{Features: node}); !r.Available || r.EstimateSeconds != 100 {
		t.Errorf("DAG node: %+v", r)
	}
	if r := e.Estimate(Query{Features: alone}); !r.Available || r.EstimateSeconds != 5000 {
		t.Errorf("standalone job: %+v", r)
	}
	// Nothing of either kind for a grid job.
	grid := alone
	grid.Universe = 9
	if r := e.Estimate(Query{Features: grid}); r.Available || r.Reason != ReasonInsufficientHistory {
		t.Errorf("grid job: %+v", r)
	}
}

// A container job is never estimated from the same owner's bare jobs,
// even running the same command, nor the reverse -- in a listing too,
// where neighbouring jobs with the same features share their keys.
func TestContainerAndBareJobsKeptApart(t *testing.T) {
	e := New(Config{})
	ctr := Features{Owner: "alice", ClusterID: 1, Cmd: "run.sh", Container: true}
	bare := Features{Owner: "alice", ClusterID: 2, Cmd: "run.sh"}
	ingest(e, job{ctr, 1600, t0}, job{bare, 700, t0.Add(time.Second)})
	ctr.ClusterID, bare.ClusterID = 3, 3
	if r := e.Estimate(Query{Features: ctr}); !r.Available || r.EstimateSeconds != 1600 {
		t.Errorf("container job: %+v", r)
	}
	if r := e.Estimate(Query{Features: bare}); !r.Available || r.EstimateSeconds != 700 {
		t.Errorf("bare job: %+v", r)
	}
	rs := e.EstimateMany([]Query{{Features: bare}, {Features: ctr}})
	if rs[0].EstimateSeconds != 700 || rs[1].EstimateSeconds != 1600 {
		t.Errorf("listing: bare %v, container %v", rs[0].EstimateSeconds, rs[1].EstimateSeconds)
	}
}

// An owner whose own errors are too few for the bounds, answered from a
// level the access point has too few errors for either, gets its bounds
// from the access point's errors at every level: calibration of an
// estimate drawn from the owner's own jobs, never another user's runtime
// as the estimate.
func TestBoundsFallBackToTheAccessPointsErrors(t *testing.T) {
	e := New(Config{})
	var hist []job
	for i := range 40 {
		// Each owner's second run takes four times the first, so every
		// error the access point records is log(4), at the exact level.
		f := feat(fmt.Sprintf("o%d", i), "x")
		hist = append(hist,
			job{f, 100, t0.Add(time.Duration(2*i) * time.Second)},
			job{f, 400, t0.Add(time.Duration(2*i+1) * time.Second)})
	}
	hist = append(hist, job{Features{Owner: "dave", BatchName: "b", Cmd: "y"}, 100, t0.Add(time.Hour)})
	ingest(e, hist...)
	if n := e.st.levelResid[viewSubmit][LevelBatch].len(); n != 0 {
		t.Fatalf("batch level has %d errors; the test needs none", n)
	}
	if n := e.st.allResid[viewSubmit].len(); n != 40 {
		t.Fatalf("access point errors = %d, want 40", n)
	}
	r := e.Estimate(Query{Features: Features{Owner: "dave", BatchName: "b", Cmd: "z"}})
	if !r.Available || r.Basis.Level != "batch" || r.EstimateSeconds != 100 {
		t.Fatalf("dave: %+v", r)
	}
	// The group's own spread is a single run; the errors widen it.
	if r.P10Seconds != 100 || r.P90Seconds != 400 {
		t.Errorf("bounds %v-%v, want 100-400 from the access point's errors", r.P10Seconds, r.P90Seconds)
	}
}
