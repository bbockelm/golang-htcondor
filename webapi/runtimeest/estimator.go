// Package runtimeest estimates how long a job will run from the runtimes
// of the same owner's similar jobs that have already finished.
//
// It is an online estimator, not a trained model. Every completed job is
// filed under a ladder of groups (see Level) -- its cluster, its exact
// command line, the same command line with the numbers masked, its batch
// name, its working directory, its program, its owner -- and an estimate
// is the median of the recent runtimes in one of the groups the new job
// falls into. Which group answers is chosen per owner, by how well each
// level has predicted that owner's jobs so far (the 3Sigma approach).
//
// That shape was chosen by replaying a real access point's history: the
// workload drifts faster than a periodically retrained model can follow,
// and an estimator that re-centres on every completion beat both a
// gradient-boosted model and "the mean of your last two jobs". Host
// speed and per-argument regressions were tried and left out; neither
// helped.
//
// The package does no I/O. A caller feeds it completed jobs (Batch,
// Ingest) and asks it about a job (Estimate); webapi/httpserver runs the
// feeding loop.
package runtimeest

import (
	"cmp"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// The reasons an estimate is unavailable. They are API: the web UI
// branches on them.
const (
	// ReasonDisabled means the access point does not run the estimator.
	// The package never returns it; a caller with no Estimator does.
	ReasonDisabled = "disabled"
	// ReasonWarmingUp means the history has not been read yet.
	ReasonWarmingUp = "model_warming_up"
	// ReasonInsufficientHistory means none of the job's groups -- not
	// even the whole access point's -- has enough finished jobs.
	ReasonInsufficientHistory = "insufficient_history"
)

// Defaults for Config.
const (
	DefaultWindow         = 100
	DefaultResidualWindow = 256
)

const (
	// minSamples is the fewest runtimes an owner-confined group needs
	// before it may answer. One: those are the owner's own jobs, so there
	// is nothing to protect, and on the replayed history a single earlier
	// run of the same command line was a far better guess than the
	// owner's jobs as a whole, which a higher floor fell back to.
	minSamples = 1
	// minGlobalSamples is the same for LevelGlobal, which is a guess
	// about a stranger's job and should at least be a well-founded one.
	minGlobalSamples = 30
	// minLonger is how many runs longer than a running job's elapsed time
	// its group needs to re-estimate it once it has outlived the median.
	minLonger = 3
	// minResiduals is how many past prediction errors the bounds need
	// before they are drawn from errors rather than the group's spread.
	minResiduals = 30

	// scoreAlpha, scorePrior and scoreMargin drive level selection: each
	// level's error is an exponentially weighted moving average of the
	// absolute log2 error (so 1.0 is "off by 2x"), starting from the
	// prior, and a less specific level must beat a more specific one by
	// more than the margin to answer in its place.
	scoreAlpha  = 0.1
	scorePrior  = 1.0
	scoreMargin = 0.05
	// errorFloor keeps very short jobs from dominating a score: 2s
	// predicted as 4s is not a meaningful miss.
	errorFloor = 10.0
)

// Config sizes an Estimator.
type Config struct {
	// Window is how many recent runtimes each group answers from.
	// Default DefaultWindow. LevelGlobal answers from four times as
	// many. Each retains more, to score completed jobs as of their
	// submit and start (see retainFactor).
	Window int
	// ResidualWindow is how many recent prediction errors each owner
	// keeps, per view, for the bounds. Default DefaultResidualWindow.
	// The access point keeps four times as many, overall and per level.
	ResidualWindow int

	// noPoolCache makes every estimate pool and sort its errors afresh,
	// so a test can check the cache changes nothing.
	noPoolCache bool
}

func (c Config) withDefaults() Config {
	if c.Window <= 0 {
		c.Window = DefaultWindow
	}
	if c.ResidualWindow <= 0 {
		c.ResidualWindow = DefaultResidualWindow
	}
	return c
}

// Result is an estimate for one job, and the JSON the API returns.
//
// It describes only aggregates: never another job's command line, id or
// owner.
type Result struct {
	Available bool `json:"available"`
	// Reason says why, when Available is false. See the Reason* constants.
	Reason string `json:"reason,omitempty"`
	// EstimateSeconds is the expected total runtime. For a running job
	// that has outlived its group's median it is re-estimated from the
	// group's runs that lasted at least as long.
	EstimateSeconds float64 `json:"estimate_seconds,omitempty"`
	// P10Seconds and P90Seconds bound the runtime: about 80% of jobs
	// finish between them. Drawn from past prediction errors made at
	// the same point in a job's life (waiting or running); see bounds.
	P10Seconds float64 `json:"p10_seconds,omitempty"`
	P90Seconds float64 `json:"p90_seconds,omitempty"`
	// Basis is which group answered.
	Basis *Basis `json:"basis,omitempty"`
	// Rough is true when one of the broad groups answered: the owner's
	// jobs running the same program whatever the arguments, the owner's
	// jobs in general, or the whole access point's. On a replayed access
	// point those were within a factor of two of the actual runtime only
	// a quarter to a third of the time, against about three quarters for
	// the specific groups, so a client should present them as a rough
	// guess rather than as an expectation.
	Rough bool `json:"rough"`
	// ElapsedSeconds is how long the job has been running, when it is.
	ElapsedSeconds *float64 `json:"elapsed_seconds,omitempty"`
	// RemainingSeconds is EstimateSeconds less ElapsedSeconds. Absent
	// when the job is not running, and when it has outrun its history.
	RemainingSeconds *float64 `json:"remaining_seconds,omitempty"`
	// ExceededHistory is true when the job has already run longer than
	// nearly every comparable job, so there is no honest remaining time
	// to give. The estimate and bounds are then what history said before
	// the job started.
	ExceededHistory bool `json:"exceeded_history"`
	// Model describes the history behind the estimate.
	Model Model `json:"model"`
}

// Basis names the group an estimate came from.
type Basis struct {
	// Level is a Level's String().
	Level string `json:"level"`
	// SampleCount is how many recent runtimes the group holds.
	SampleCount int `json:"sample_count"`
	// NewCommand is true when none of the owner's recently finished jobs
	// ran the same program (LevelCmd had nothing to answer from), which
	// is the usual reason a rough level answered.
	NewCommand bool `json:"new_command,omitempty"`
}

// Model describes what the estimator has read.
type Model struct {
	// TrainedThrough is the completion time of the newest job read,
	// RFC 3339. Absent until a job has been read.
	TrainedThrough string `json:"trained_through,omitempty"`
	// JobsIngested is how many completed jobs have been read.
	JobsIngested int64 `json:"jobs_ingested"`
}

// Query is a job to estimate.
type Query struct {
	Features Features
	// Running is whether the job is executing now, and Elapsed, in
	// seconds, how long the current execution has run.
	Running bool
	Elapsed float64
}

// QueryAttrs are the job attributes QueryFromAd reads.
//
// Clipped, so a caller that appends to it gets its own copy rather than
// writing into one shared by every request.
var QueryAttrs = slices.Clip(append(slices.Clone(FeatureAttrs), "JobStatus", "JobCurrentStartDate", "JobStartDate", "ServerTime"))

// QueryFromAd builds a Query from a live job ad. now is used when the
// ad does not carry the schedd's ServerTime.
//
// Elapsed is measured from JobCurrentStartDate -- the start of this
// execution, not the first one -- falling back to JobStartDate. A
// running job with neither is treated as not running: an elapsed time
// of zero would be a guess presented as a measurement.
func QueryFromAd(ad *classad.ClassAd, now time.Time) Query {
	q := Query{Features: FeaturesFromAd(ad)}
	status, _ := intAttr(ad, "JobStatus")
	if status != 2 {
		return q
	}
	start, _ := intAttr(ad, "JobCurrentStartDate")
	if start <= 0 {
		start, _ = intAttr(ad, "JobStartDate")
	}
	if start <= 0 {
		return q
	}
	nowUnix := now.Unix()
	if st, ok := intAttr(ad, "ServerTime"); ok && st > 0 {
		nowUnix = st
	}
	q.Running = true
	q.Elapsed = math.Max(0, float64(nowUnix-start))
	return q
}

// Estimator holds the recent runtimes of finished jobs and answers
// estimates from them.
//
// It is written by one goroutine (Ingest, Evict) and read by many
// (Estimate, Stats). A reader never sees part of a batch: a batch is
// applied under the write lock, and the very first one -- typically the
// large startup backfill -- is built off to the side and swapped in, so
// readers are not held up while it is read.
type Estimator struct {
	cfg Config
	// wmu serializes writers. A writer may read st without mu, since
	// only writers change it.
	wmu sync.Mutex
	mu  sync.RWMutex
	st  *state
}

// New returns an empty Estimator. It answers ReasonWarmingUp until the
// first Ingest, even an empty one.
func New(cfg Config) *Estimator {
	return &Estimator{cfg: cfg.withDefaults(), st: newState()}
}

// view is the moment a history record is scored as of. A job is asked
// about while it waits and while it runs, never just before it ends, so
// each completed job is scored twice -- as it would have been estimated
// at submit and at start, from only the jobs that had completed by
// then -- and Estimate answers a waiting job from what the submit view
// learned and a running one from the start view. Scoring a record
// against everything that finished before it instead credits the
// estimator with siblings a waiting job never sees: the level scores
// then favour levels that are only good late, and the error
// distribution behind the bounds is narrower than the one queries face.
type view int

const (
	viewSubmit view = iota
	viewStart
	numViews
)

// retainFactor is how many more runtimes than it answers from a group
// keeps, so that it can still answer as of a job's submit or start once
// that job finishes: by then its own siblings may have pushed the runs
// that were visible at the time out of the newest Window. Measured on a
// replayed access point, 4 recovered most of what was lost and 16
// nearly all of it.
const retainFactor = 16

type ownerState struct {
	// score is each level's moving-average error for this owner, per
	// view.
	score [numViews][numLevels]float32
	// resid is the owner's recent prediction errors, log(actual/estimate),
	// per view.
	resid [numViews]window
	// at is the newest completion seen for this owner, unix seconds.
	at int64
}

// scores is the score set a view chooses by; nil for no owner.
func (o *ownerState) scores(v view) *[numLevels]float32 {
	if o == nil {
		return nil
	}
	return &o.score[v]
}

type state struct {
	groups [LevelGlobal]map[string]*window
	global window
	owners map[string]*ownerState
	// levelResid is every owner's prediction errors per view and
	// answering level, and globalResid per view.
	levelResid  [numViews][numLevels]window
	globalResid [numViews]window

	loaded bool
	jobs   int64
	newest int64

	// The self-evaluation counters, from the submit view.
	scored, within2x   int64
	scoredBy, withinBy [numLevels]int64

	// scratch is the writer's buffer for as-of medians.
	scratch []float32

	// pools caches the sorted union of an owner's errors and a level's
	// errors that bounds draws from (see residualPool), so that a
	// listing's thousand estimates do not each concatenate and sort a
	// thousand values. Filled by readers under poolMu, and dropped
	// whenever a writer changes the errors (apply) or the owners (Evict),
	// which happens under the write lock with no reader present.
	poolMu sync.Mutex
	pools  map[poolKey][]float32
}

// poolKey names a cached residual pool.
type poolKey struct {
	owner string
	v     view
	lvl   Level
}

func newState() *state {
	s := &state{owners: make(map[string]*ownerState)}
	for i := range s.groups {
		s.groups[i] = make(map[string]*window)
	}
	return s
}

// Ingest applies a batch of completed jobs, in completion order.
//
// Each job is first scored the way it would have been estimated when it
// was submitted and when it started, from only the jobs that had
// completed by each of those moments (see view) -- which updates the
// owner's level scores, the errors behind the bounds and the
// self-evaluation counters -- and only then added to its groups. So no
// job ever contributes to its own estimate.
func (e *Estimator) Ingest(b *Batch) {
	e.wmu.Lock()
	defer e.wmu.Unlock()
	var recs []record
	if b != nil {
		recs = b.sorted()
	}
	cur := e.st
	if cur.jobs == 0 {
		fresh := newState()
		fresh.apply(recs, e.cfg)
		e.mu.Lock()
		e.st = fresh
		e.mu.Unlock()
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	cur.apply(recs, e.cfg)
}

func (s *state) apply(recs []record, cfg Config) {
	for i := range recs {
		s.ingest(&recs[i], cfg)
	}
	s.loaded = true
	s.pools = nil
}

func (s *state) ingest(r *record, cfg Config) {
	actual := float64(r.runtime)
	var own *ownerState
	if r.keys.owner != "" {
		own = s.owners[r.keys.owner]
		if own == nil {
			own = &ownerState{}
			for v := range own.score {
				for l := range own.score[v] {
					own.score[v][l] = scorePrior
				}
			}
			s.owners[r.keys.owner] = own
		}
	}

	for v := range numViews {
		preds := s.candidatesAsOf(r.keys, r.asOf(v), cfg)
		if lvl, ok := choose(own.scores(v), &preds); ok {
			chosen := preds[lvl]
			if v == viewSubmit {
				s.scored++
				s.scoredBy[lvl]++
				if logError(chosen, actual) <= 1 {
					s.within2x++
					s.withinBy[lvl]++
				}
			}
			res := float32(math.Log(math.Max(actual, 1) / math.Max(chosen, 1)))
			if own != nil {
				own.resid[v].add(res, r.at, cfg.ResidualWindow, cfg.ResidualWindow)
			}
			s.levelResid[v][lvl].add(res, r.at, 4*cfg.ResidualWindow, 4*cfg.ResidualWindow)
			s.globalResid[v].add(res, r.at, 4*cfg.ResidualWindow, 4*cfg.ResidualWindow)
		}
		// After the choice, so this job's outcome does not inform the
		// level it was predicted with.
		if sc := own.scores(v); sc != nil {
			for l, p := range preds {
				if !math.IsNaN(p) {
					sc[l] = float32((1-scoreAlpha)*float64(sc[l]) + scoreAlpha*logError(p, actual))
				}
			}
		}
	}
	if own != nil {
		own.at = max(own.at, r.at)
	}

	for l := range s.groups {
		key := r.keys.k[l]
		if key == "" {
			continue
		}
		w := s.groups[l][key]
		if w == nil {
			w = &window{}
			s.groups[l][key] = w
		}
		w.add(r.runtime, r.at, cfg.Window, retainFactor*cfg.Window)
	}
	s.global.add(r.runtime, r.at, 4*cfg.Window, retainFactor*4*cfg.Window)
	s.jobs++
	s.newest = max(s.newest, r.at)
}

// candidatesAsOf is each level's estimate for keys from only the
// runtimes recorded before t; NaN where the level does not apply or has
// too few of them.
func (s *state) candidatesAsOf(k Keys, t int64, cfg Config) [numLevels]float64 {
	var preds [numLevels]float64
	for l := range s.groups {
		preds[l] = math.NaN()
		if k.k[l] == "" {
			continue
		}
		w := s.groups[l][k.k[l]]
		if w == nil {
			continue
		}
		if vals := w.before(t, cfg.Window, &s.scratch); len(vals) >= minSamples {
			preds[l] = quantileOf(vals, 0.5)
		}
	}
	preds[LevelGlobal] = math.NaN()
	if vals := s.global.before(t, 4*cfg.Window, &s.scratch); len(vals) >= minGlobalSamples {
		preds[LevelGlobal] = quantileOf(vals, 0.5)
	}
	return preds
}

// candidates returns each level's estimate for keys from everything it
// holds, NaN where the level does not apply or has too few samples, and
// the window behind each.
func (s *state) candidates(k Keys) ([numLevels]float64, [numLevels]*window) {
	var preds [numLevels]float64
	var wins [numLevels]*window
	for l := range s.groups {
		preds[l] = math.NaN()
		if k.k[l] == "" {
			continue
		}
		if w := s.groups[l][k.k[l]]; w.len() >= minSamples {
			preds[l], wins[l] = w.median(), w
		}
	}
	preds[LevelGlobal] = math.NaN()
	if s.global.len() >= minGlobalSamples {
		preds[LevelGlobal], wins[LevelGlobal] = s.global.median(), &s.global
	}
	return preds, wins
}

// choose picks the level that answers: the most specific available
// owner-confined level, unless a less specific one has predicted this
// owner's jobs better by more than scoreMargin. With no track record
// every level carries the same prior, so the most specific answers.
// LevelGlobal answers only when no owner-confined level can: on the
// replayed history, letting it compete cost accuracy, since a job is
// nearly always more like its owner's other jobs than like the access
// point's.
func choose(scores *[numLevels]float32, preds *[numLevels]float64) (Level, bool) {
	best := -1
	for l := range LevelGlobal {
		if math.IsNaN(preds[l]) {
			continue
		}
		if best < 0 || (scores != nil && scores[l] < scores[best]-scoreMargin) {
			best = int(l)
		}
	}
	if best < 0 && !math.IsNaN(preds[LevelGlobal]) {
		best = int(LevelGlobal)
	}
	if best < 0 {
		return 0, false
	}
	return Level(best), true
}

// logError is the absolute log2 error, with very short runtimes floored
// (see errorFloor): 1 means off by a factor of two.
func logError(pred, actual float64) float64 {
	return math.Abs(math.Log2(math.Max(pred, errorFloor) / math.Max(actual, errorFloor)))
}

// Estimate answers for one job: a waiting job from what the submit view
// learned, and a running one from what the start view did.
func (e *Estimator) Estimate(q Query) Result {
	e.mu.RLock()
	defer e.mu.RUnlock()
	s := e.st
	if !s.loaded {
		return Result{Model: s.model(), Reason: ReasonWarmingUp}
	}
	p := s.prepare(DeriveKeys(q.Features), viewOf(q), !e.cfg.noPoolCache)
	return p.finish(q, s.model())
}

// EstimateMany answers for many jobs at once, each exactly as Estimate
// would, from one consistent snapshot.
//
// Jobs next to each other in qs with the same features, or the same
// keys, in the same view -- the waiting procs of one cluster, say, or
// its running ones -- share the level choice and the bounds; only what
// depends on a running job's elapsed time is worked out per job. So a
// caller should pass jobs in job id order.
func (e *Estimator) EstimateMany(qs []Query) []Result {
	out := make([]Result, len(qs))
	e.mu.RLock()
	defer e.mu.RUnlock()
	s := e.st
	m := s.model()
	if !s.loaded {
		for i := range out {
			out[i] = Result{Model: m, Reason: ReasonWarmingUp}
		}
		return out
	}
	// The previous job's work in each view.
	var last [numViews]struct {
		set bool
		f   *Features
		k   Keys
		p   prepared
	}
	for i := range qs {
		q := &qs[i]
		v := viewOf(*q)
		l := &last[v]
		if !l.set || !sameFeatures(&q.Features, l.f) {
			k := DeriveKeys(q.Features)
			if !l.set || k != l.k {
				l.k, l.p = k, s.prepare(k, v, !e.cfg.noPoolCache)
			}
			l.set, l.f = true, &q.Features
		}
		out[i] = l.p.finish(*q, m)
	}
	return out
}

// sameFeatures reports whether two jobs have the same features, and so
// the same keys, without deriving them.
func sameFeatures(a, b *Features) bool {
	return a.Owner == b.Owner && a.ClusterID == b.ClusterID && a.Cmd == b.Cmd &&
		a.Iwd == b.Iwd && a.BatchName == b.BatchName && slices.Equal(a.Args, b.Args)
}

func viewOf(q Query) view {
	if q.Running {
		return viewStart
	}
	return viewSubmit
}

// prepared is the part of an estimate that depends only on a job's keys
// and view: which level answers, its median and its bounds.
type prepared struct {
	ok         bool
	lvl        Level
	est        float64
	p10, p90   float64
	w          *window
	newCommand bool
}

// prepare chooses the level for keys in view v and works out its
// estimate and bounds. cache says whether bounds may use the pool cache.
func (s *state) prepare(keys Keys, v view, cache bool) prepared {
	preds, wins := s.candidates(keys)
	var own *ownerState
	if keys.owner != "" {
		own = s.owners[keys.owner]
	}
	lvl, ok := choose(own.scores(v), &preds)
	if !ok {
		return prepared{}
	}
	p := prepared{ok: true, lvl: lvl, est: preds[lvl], w: wins[lvl], newCommand: math.IsNaN(preds[LevelCmd])}
	p.p10, p.p90 = s.bounds(own, keys.owner, v, lvl, p.est, p.w, cache)
	return p
}

// finish turns a prepared estimate into the Result for one job, adding
// what depends on how long it has been running. The caller holds the
// read lock: a running job reads the answering window.
func (p *prepared) finish(q Query, m Model) Result {
	res := Result{Model: m}
	if !p.ok {
		res.Reason = ReasonInsufficientHistory
		return res
	}
	est, p10, p90 := p.est, p.p10, p.p90
	res.Available = true
	res.Rough = p.lvl.rough()
	res.Basis = &Basis{Level: p.lvl.String(), SampleCount: p.w.len(), NewCommand: p.newCommand}
	if q.Running {
		elapsed := q.Elapsed
		res.ElapsedSeconds = &elapsed
		if elapsed >= est {
			// The job has outlived the typical run. What history says
			// now is what the runs that lasted at least this long did.
			if longer := p.w.above(elapsed); len(longer) >= minLonger {
				est = quantileOf(longer, 0.5)
				p90 = math.Max(quantileOf(longer, 0.9), est)
				p10 = math.Min(quantileOf(longer, 0.1), est)
			} else {
				res.ExceededHistory = true
			}
		}
		if !res.ExceededHistory {
			// A lower bound below what the job has already run is not
			// a bound.
			p10 = math.Max(p10, elapsed)
			remaining := seconds(est) - seconds(elapsed)
			res.RemainingSeconds = &remaining
		}
	}
	res.EstimateSeconds = seconds(est)
	res.P10Seconds = seconds(p10)
	res.P90Seconds = seconds(p90)
	return res
}

// bounds returns the 10th and 90th percentile around est.
//
// They come from past prediction errors in the same view: est scaled by
// the 10th and 90th percentiles of log(actual/estimate). A group's own
// spread alone is a poor bound -- the estimate's error comes on top of
// it -- and so is the owner's own error history alone: it is dominated
// by their last large cluster, and the next one is often in a different
// regime entirely. So the owner's errors are pooled with the access
// point's errors for the level that answered, falling back to the access
// point's errors overall while those are too few. The bounds are then
// widened, never narrowed, to the answering group's own 10th and 90th
// percentiles, which carry its spread when that is wider than the
// errors have been. Before any errors exist the group's spread is all
// there is.
func (s *state) bounds(own *ownerState, owner string, v view, lvl Level, est float64, w *window, cache bool) (p10, p90 float64) {
	pool := s.residualPool(own, owner, v, lvl, cache)
	p10, p90 = w.quantile(0.1), w.quantile(0.9)
	if len(pool) >= minResiduals {
		p10 = math.Min(p10, est*math.Exp(quantileOf(pool, 0.1)))
		p90 = math.Max(p90, est*math.Exp(quantileOf(pool, 0.9)))
	}
	return math.Min(p10, est), math.Max(p90, est)
}

// residualPool is the sorted errors bounds draws from: the owner's
// pooled with the access point's for the level, or the access point's
// overall while those are too few. Only the union needs building, and it
// is built once per owner, view and level and kept until the errors
// change (see state.pools); the caller must not modify it.
func (s *state) residualPool(own *ownerState, owner string, v view, lvl Level, cache bool) []float32 {
	var mine []float32
	if own != nil {
		mine = own.resid[v].sorted
	}
	lr := s.levelResid[v][lvl].sorted
	var pool []float32
	switch {
	case len(lr) == 0:
		pool = mine
	case len(mine) == 0:
		pool = lr
	case !cache:
		pool = mergeSorted(mine, lr)
	default:
		k := poolKey{owner: owner, v: v, lvl: lvl}
		s.poolMu.Lock()
		pool = s.pools[k]
		if pool == nil {
			pool = mergeSorted(mine, lr)
			if s.pools == nil {
				s.pools = make(map[poolKey][]float32)
			}
			s.pools[k] = pool
		}
		s.poolMu.Unlock()
	}
	if len(pool) < minResiduals {
		pool = s.globalResid[v].sorted
	}
	return pool
}

// mergeSorted is the sorted union of two ascending slices, in a new one.
func mergeSorted(a, b []float32) []float32 {
	out := make([]float32, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if b[j] < a[i] {
			out = append(out, b[j])
			j++
		} else {
			out = append(out, a[i])
			i++
		}
	}
	out = append(out, a[i:]...)
	return append(out, b[j:]...)
}

// seconds rounds to whole seconds. Runtimes are whole seconds, and the
// fractions interpolation produces are noise.
func seconds(x float64) float64 {
	return math.Round(x)
}

func (s *state) model() Model {
	m := Model{JobsIngested: s.jobs}
	if s.newest > 0 {
		m.TrainedThrough = time.Unix(s.newest, 0).UTC().Format(time.RFC3339)
	}
	return m
}

// Evict forgets every group and owner with no completion since
// olderThan, and returns how many were dropped. LevelGlobal is never
// dropped. This is what bounds memory: without it a cluster id, once
// seen, would be kept for the life of the process.
func (e *Estimator) Evict(olderThan time.Time) int {
	e.wmu.Lock()
	defer e.wmu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	cutoff := olderThan.Unix()
	n := 0
	for _, m := range e.st.groups {
		for k, w := range m {
			if w.at < cutoff {
				delete(m, k)
				n++
			}
		}
	}
	for k, o := range e.st.owners {
		if o.at < cutoff {
			delete(e.st.owners, k)
		}
	}
	e.st.pools = nil
	return n
}

// Model describes what the estimator has read, and loaded whether it
// has read anything yet (until it has, every estimate is
// ReasonWarmingUp).
func (e *Estimator) Model() (m Model, loaded bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.st.model(), e.st.loaded
}

// Stats is the estimator's state and its running record of how well it
// has done, for metrics.
type Stats struct {
	// Loaded is whether anything has been ingested, even an empty batch.
	Loaded bool
	// JobsIngested counts completed jobs read; it is not reduced by
	// eviction.
	JobsIngested int64
	// TrainedThrough is the newest completion read; zero before any.
	TrainedThrough time.Time
	// Scored counts completed jobs that would have had an estimate when
	// they were submitted, and Within2x those whose estimate was within a
	// factor of two of what they ran (by logError, so very short jobs are
	// floored). Each is also broken down by the level that answered,
	// keyed by Level.String().
	Scored          int64
	Within2x        int64
	ScoredByLevel   map[string]int64
	Within2xByLevel map[string]int64
	// Keys is how many groups each level holds; LevelGlobal always one.
	Keys map[string]int
	// Owners is how many owners have state.
	Owners int
}

// Stats snapshots the estimator.
func (e *Estimator) Stats() Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	s := e.st
	out := Stats{
		Loaded:          s.loaded,
		JobsIngested:    s.jobs,
		Scored:          s.scored,
		Within2x:        s.within2x,
		ScoredByLevel:   make(map[string]int64, numLevels),
		Within2xByLevel: make(map[string]int64, numLevels),
		Keys:            make(map[string]int, numLevels),
		Owners:          len(s.owners),
	}
	if s.newest > 0 {
		out.TrainedThrough = time.Unix(s.newest, 0).UTC()
	}
	for l := Level(0); l < numLevels; l++ {
		out.ScoredByLevel[l.String()] = s.scoredBy[l]
		out.Within2xByLevel[l.String()] = s.withinBy[l]
		if l == LevelGlobal {
			out.Keys[l.String()] = 1
		} else {
			out.Keys[l.String()] = len(s.groups[l])
		}
	}
	return out
}

// HistoryAttrs are the attributes Batch.AddAd reads from a history
// record: the features, and what decides whether and how long it ran.
// Clipped for the same reason as QueryAttrs.
var HistoryAttrs = slices.Clip(append(slices.Clone(FeatureAttrs),
	"CommittedTime", "RemoteWallClockTime", "CompletionDate", "EnteredHistoryTime",
	"ExitCode", "ExitBySignal", "JobUniverse", "JobStatus", "QDate", "JobCurrentStartDate", "JobStartDate",
	"GlobalJobId"))

// CompletedRuntime is how long a finished job ran, and whether it is a
// job whose runtime says anything about the next one like it.
//
// The runtime is CommittedTime when set, which leaves out executions
// that were evicted and thrown away, else RemoteWallClockTime. Only jobs
// that completed normally count: a job that failed, was killed by a
// signal or was removed may have stopped at any point. Scheduler- and
// local-universe jobs (DAGMan, mostly) run as long as the work they
// manage and are left out too.
func CompletedRuntime(ad *classad.ClassAd) (float64, bool) {
	if status, _ := intAttr(ad, "JobStatus"); status != 4 {
		return 0, false
	}
	if code, ok := intAttr(ad, "ExitCode"); !ok || code != 0 {
		return 0, false
	}
	if sig, ok := ad.EvaluateAttrBool("ExitBySignal"); ok && sig {
		return 0, false
	}
	if u, _ := intAttr(ad, "JobUniverse"); u == 7 || u == 12 {
		return 0, false
	}
	runtime, ok := ad.EvaluateAttrNumber("CommittedTime")
	if !ok || runtime <= 0 {
		runtime, ok = ad.EvaluateAttrNumber("RemoteWallClockTime")
	}
	if !ok || runtime <= 0 || math.IsNaN(runtime) || math.IsInf(runtime, 0) {
		return 0, false
	}
	return runtime, true
}

// record is one completed job, reduced to what ingesting it needs.
type record struct {
	keys      Keys
	runtime   float32
	at        int64 // completed
	submitted int64
	started   int64
	cluster   int64
	proc      int64
}

// asOf is the moment a view scores the record at.
func (r *record) asOf(v view) int64 {
	if v == viewStart {
		return r.started
	}
	return r.submitted
}

// Batch collects completed jobs for one Ingest.
//
// Keys are interned as they are added: a cluster of a thousand jobs has
// one set of keys, and a startup backfill of hundreds of thousands of
// records should not hold a thousand copies of each.
type Batch struct {
	recs   []record
	intern map[string]string
}

// NewBatch returns an empty Batch.
func NewBatch() *Batch {
	return &Batch{intern: make(map[string]string)}
}

// Len is how many jobs the batch holds.
func (b *Batch) Len() int { return len(b.recs) }

// Completion is one completed job for a Batch.
type Completion struct {
	Features Features
	ProcID   int64
	// Runtime is how long it ran, in seconds; see CompletedRuntime.
	Runtime float64
	// Submitted, Started and Completed are when it was submitted, when
	// its last execution started and when it finished. Submitted and
	// Started are the moments it is scored as of (see Ingest). A missing
	// one falls back to the other, and both to Completed, which scores
	// the job against everything that finished before it did.
	Submitted, Started, Completed time.Time
}

// Add records a completed job. A non-positive runtime is ignored.
func (b *Batch) Add(c Completion) {
	if !(c.Runtime > 0) || math.IsInf(c.Runtime, 0) || c.Completed.IsZero() {
		return
	}
	k := DeriveKeys(c.Features)
	k.owner = b.interned(k.owner)
	for i := range k.k {
		k.k[i] = b.interned(k.k[i])
	}
	at := c.Completed.Unix()
	sub, start := unixOr0(c.Submitted), unixOr0(c.Started)
	if start <= 0 {
		start = sub
	}
	if sub <= 0 {
		sub = start
	}
	if sub <= 0 {
		sub, start = at, at
	}
	b.recs = append(b.recs, record{
		keys:      k,
		runtime:   float32(c.Runtime),
		at:        at,
		submitted: min(sub, at),
		started:   min(start, at),
		cluster:   c.Features.ClusterID,
		proc:      c.ProcID,
	})
}

func unixOr0(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// AddAd records a history record if CompletedRuntime accepts it, and
// reports whether it did. The completion time is CompletionDate, else
// EnteredHistoryTime; a record with neither is refused, since it cannot
// be placed in order. It is scored as of QDate and of
// JobCurrentStartDate (else JobStartDate).
func (b *Batch) AddAd(ad *classad.ClassAd) bool {
	runtime, ok := CompletedRuntime(ad)
	if !ok {
		return false
	}
	at, _ := intAttr(ad, "CompletionDate")
	if at <= 0 {
		at, _ = intAttr(ad, "EnteredHistoryTime")
	}
	if at <= 0 {
		return false
	}
	proc, _ := intAttr(ad, "ProcId")
	c := Completion{Features: FeaturesFromAd(ad), ProcID: proc, Runtime: runtime, Completed: time.Unix(at, 0)}
	if q, _ := intAttr(ad, "QDate"); q > 0 {
		c.Submitted = time.Unix(q, 0)
	}
	start, _ := intAttr(ad, "JobCurrentStartDate")
	if start <= 0 {
		start, _ = intAttr(ad, "JobStartDate")
	}
	if start > 0 {
		c.Started = time.Unix(start, 0)
	}
	n := len(b.recs)
	b.Add(c)
	return len(b.recs) > n
}

func (b *Batch) interned(s string) string {
	if s == "" {
		return ""
	}
	if v, ok := b.intern[s]; ok {
		return v
	}
	b.intern[s] = s
	return s
}

// sorted returns the records in completion order, ties broken by job id
// so a replay is deterministic.
func (b *Batch) sorted() []record {
	recs := b.recs
	slices.SortStableFunc(recs, func(x, y record) int {
		if c := cmp.Compare(x.at, y.at); c != 0 {
			return c
		}
		if c := cmp.Compare(x.cluster, y.cluster); c != 0 {
			return c
		}
		return cmp.Compare(x.proc, y.proc)
	})
	return recs
}
