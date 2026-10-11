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
	DefaultWindow         = 64
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
	// minResiduals is how many of an owner's own prediction errors the
	// calibrated bounds need before they are used instead of the access
	// point's.
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
	// Window is how many recent runtimes each group keeps. Default
	// DefaultWindow. LevelGlobal keeps four times as many.
	Window int
	// ResidualWindow is how many recent prediction errors each owner
	// keeps for the calibrated bounds. Default DefaultResidualWindow.
	// The access point as a whole keeps four times as many.
	ResidualWindow int
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
	// finish between them. Calibrated against this owner's own past
	// prediction errors once there are enough of them.
	P10Seconds float64 `json:"p10_seconds,omitempty"`
	P90Seconds float64 `json:"p90_seconds,omitempty"`
	// Basis is which group answered.
	Basis *Basis `json:"basis,omitempty"`
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

type ownerState struct {
	// score is each level's moving-average error for this owner.
	score [numLevels]float32
	// resid is the owner's recent prediction errors, log(actual/estimate).
	resid window
	// at is the newest completion seen for this owner, unix seconds.
	at int64
}

type state struct {
	groups      [LevelGlobal]map[string]*window
	global      window
	owners      map[string]*ownerState
	globalResid window

	loaded bool
	jobs   int64
	newest int64

	scored, within2x   int64
	scoredBy, withinBy [numLevels]int64
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
// Each job is first scored the way it would have been estimated had it
// been asked about just before it finished -- which updates the owner's
// level scores, the residuals behind the bounds and the self-evaluation
// counters -- and only then added to its groups. So no job ever
// contributes to its own estimate.
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
}

func (s *state) ingest(r *record, cfg Config) {
	actual := float64(r.runtime)
	preds, _ := s.candidates(r.keys)
	var own *ownerState
	if r.keys.owner != "" {
		own = s.owners[r.keys.owner]
		if own == nil {
			own = &ownerState{}
			for i := range own.score {
				own.score[i] = scorePrior
			}
			s.owners[r.keys.owner] = own
		}
	}

	if lvl, ok := choose(own, &preds); ok {
		chosen := preds[lvl]
		s.scored++
		s.scoredBy[lvl]++
		if logError(chosen, actual) <= 1 {
			s.within2x++
			s.withinBy[lvl]++
		}
		res := float32(math.Log(math.Max(actual, 1) / math.Max(chosen, 1)))
		if own != nil {
			own.resid.add(res, cfg.ResidualWindow)
		}
		s.globalResid.add(res, 4*cfg.ResidualWindow)
	}
	if own != nil {
		for l, p := range preds {
			if !math.IsNaN(p) {
				own.score[l] = float32((1-scoreAlpha)*float64(own.score[l]) + scoreAlpha*logError(p, actual))
			}
		}
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
		w.add(r.runtime, cfg.Window)
		w.at = max(w.at, r.at)
	}
	s.global.add(r.runtime, 4*cfg.Window)
	s.global.at = max(s.global.at, r.at)
	s.jobs++
	s.newest = max(s.newest, r.at)
}

// candidates returns each level's estimate for keys, NaN where the
// level does not apply or has too few samples, and the window behind
// each.
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

// choose picks the level that answers: the most specific available one,
// unless a less specific one has predicted this owner's jobs better by
// more than scoreMargin. With no track record every level carries the
// same prior, so the most specific answers.
func choose(own *ownerState, preds *[numLevels]float64) (Level, bool) {
	best := -1
	for l, p := range preds {
		if math.IsNaN(p) {
			continue
		}
		if best < 0 {
			best = l
			continue
		}
		if own != nil && own.score[l] < own.score[best]-scoreMargin {
			best = l
		}
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

// Estimate answers for one job.
func (e *Estimator) Estimate(q Query) Result {
	e.mu.RLock()
	defer e.mu.RUnlock()
	s := e.st
	res := Result{Model: s.model()}
	if !s.loaded {
		res.Reason = ReasonWarmingUp
		return res
	}
	keys := DeriveKeys(q.Features)
	preds, wins := s.candidates(keys)
	own := s.owners[keys.owner]
	if keys.owner == "" {
		own = nil
	}
	lvl, ok := choose(own, &preds)
	if !ok {
		res.Reason = ReasonInsufficientHistory
		return res
	}
	w := wins[lvl]
	est := preds[lvl]
	p10, p90 := s.bounds(own, est, w)

	res.Available = true
	res.Basis = &Basis{Level: lvl.String(), SampleCount: w.len()}
	if q.Running {
		elapsed := q.Elapsed
		res.ElapsedSeconds = &elapsed
		if elapsed >= est {
			// The job has outlived the typical run. What history says
			// now is what the runs that lasted at least this long did.
			if longer := w.above(elapsed); len(longer) >= minLonger {
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
// A group's own spread is a poor upper bound -- on the replayed history
// its 90th percentile covered only about 70% of jobs, because the
// estimate's own error comes on top of the group's spread. So the bounds
// come from the distribution of past prediction errors instead: est
// scaled by the 10th and 90th percentiles of log(actual/estimate). The
// owner's errors when there are enough of them, the access point's
// otherwise, and the group's spread only before either exists.
func (s *state) bounds(own *ownerState, est float64, w *window) (p10, p90 float64) {
	r := &s.globalResid
	if own != nil && own.resid.len() >= minResiduals {
		r = &own.resid
	}
	if r.len() >= minResiduals {
		p10 = est * math.Exp(r.quantile(0.1))
		p90 = est * math.Exp(r.quantile(0.9))
	} else {
		p10, p90 = w.quantile(0.1), w.quantile(0.9)
	}
	return math.Min(p10, est), math.Max(p90, est)
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
	return n
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
	// Scored counts jobs that had an estimate when they finished, and
	// Within2x those whose estimate was within a factor of two of what
	// they actually ran (by logError, so very short jobs are floored).
	// Each is also broken down by the level that answered, keyed by
	// Level.String().
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
	"ExitCode", "ExitBySignal", "JobUniverse", "JobStatus", "QDate", "GlobalJobId"))

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
	keys    Keys
	runtime float32
	at      int64
	cluster int64
	proc    int64
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

// Add records a completed job that ran for runtime seconds and finished
// at completed. A non-positive runtime is ignored.
func (b *Batch) Add(f Features, procID int64, runtime float64, completed time.Time) {
	if !(runtime > 0) || math.IsInf(runtime, 0) {
		return
	}
	k := DeriveKeys(f)
	k.owner = b.interned(k.owner)
	for i := range k.k {
		k.k[i] = b.interned(k.k[i])
	}
	b.recs = append(b.recs, record{
		keys:    k,
		runtime: float32(runtime),
		at:      completed.Unix(),
		cluster: f.ClusterID,
		proc:    procID,
	})
}

// AddAd records a history record if CompletedRuntime accepts it, and
// reports whether it did. The completion time is CompletionDate, else
// EnteredHistoryTime; a record with neither is refused, since it cannot
// be placed in order.
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
	n := len(b.recs)
	b.Add(FeaturesFromAd(ad), proc, runtime, time.Unix(at, 0))
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
