package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/prometheus/client_golang/prometheus"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/runtimeest"
)

// Runtime estimates: GET /api/v1/jobs/{id}/runtime-estimate and the
// runtime_estimate field of the MCP get_job tool, answered by a
// runtimeest.Estimator that a background loop here keeps fed with the
// access point's finished jobs. What an estimate is lives in
// webapi/runtimeest; this file is where the history comes from and how
// often.
//
// The history is read from the htcondordb mirror and nowhere else.
// condor_history scans the schedd's history file, and a loop that did
// that every few minutes would cost the access point more than anything
// the estimate saves anybody (the same reasoning as watchSource). With
// no usable mirror the estimator stays unavailable and the loop tries
// again next tick.

const (
	// defaultRuntimeEstimateBackfill is how far back the startup read
	// reaches, and how long a group may go without a completion before it
	// is forgotten.
	defaultRuntimeEstimateBackfill = 168 * time.Hour
	// runtimeEstimateMaxRows caps one read of the history. The archive
	// returns newest first, so hitting it drops the oldest records in the
	// window, which matter least.
	runtimeEstimateMaxRows = 500_000
	// runtimeEstimateRefreshTimeout bounds one refresh. Generous: the
	// startup read can be hundreds of thousands of rows, and nobody is
	// waiting on it.
	runtimeEstimateRefreshTimeout = 10 * time.Minute
)

// runtimeHistorySource is where the refresher reads finished jobs from.
type runtimeHistorySource interface {
	// History streams projected history records whose
	// EnteredHistoryTime is at or after since (unix seconds), newest
	// first, at most limit of them.
	History(ctx context.Context, since int64, limit int, yield func(*classad.ClassAd)) error
}

// mirrorRuntimeHistory reads the mirror's history archive.
type mirrorRuntimeHistory struct {
	locator *dbmirror.Locator
	// gate decides whether the mirror's history is fit to read. In
	// production it is the same freshness rule as any other history read
	// (runtimeHistoryGate).
	gate func(*dbmirror.Info) dbmirror.Decision
}

// runtimeHistoryGate is dbmirror.HistoryDecision for a newest-first read
// with no schedd scan semantics -- which is exactly what this is.
func runtimeHistoryGate(info *dbmirror.Info) dbmirror.Decision {
	return dbmirror.HistoryDecision(info, &htcondor.HistoryQueryOptions{Backwards: true})
}

// History reads the window with a plain "EnteredHistoryTime >= since"
// conjunct: the archive is zone-mapped on that attribute, and the pruner
// only reads top-level comparisons with a literal, so this skips every
// segment older than the window. JobStatus == 4 drops removed jobs on
// the server; everything else CompletedRuntime refuses is filtered here.
//
// A row that will not parse is skipped. Unlike a job watch, where a
// missing row reads as a finished job, a missing completion here only
// costs the estimator one sample.
func (m mirrorRuntimeHistory) History(ctx context.Context, since int64, limit int, yield func(*classad.ClassAd)) error {
	if !m.locator.Enabled() {
		return errors.New("no htcondordb mirror is configured")
	}
	info, err := m.locator.Discover(ctx)
	if err != nil {
		return err
	}
	if d := m.gate(info); !d.Use {
		return fmt.Errorf("the mirror cannot serve history (%s): %s", d.Reason, d.Note)
	}
	dbc, closer, _, err := m.locator.Client(ctx)
	if err != nil {
		return err
	}
	defer closer()
	constraint := fmt.Sprintf("EnteredHistoryTime >= %d && JobStatus == 4", since)
	return dbc.QueryRawProjectStream(ctx, "history", constraint, runtimeest.HistoryAttrs, limit, func(row string) bool {
		if ad, perr := classad.ParseOld(row); perr == nil {
			yield(ad)
		}
		return true
	})
}

// runtimeRefresher keeps an Estimator fed from the history.
//
// The first refresh reads the whole backfill window. After that each
// refresh reads from a watermark: the newest EnteredHistoryTime seen so
// far. The archive refuses sequence cursors, and EnteredHistoryTime is
// stamped by the mirror as it archives a record, so it only moves
// forward. The read is ">= watermark" rather than ">", because more
// records may land in the watermark's second after a read; the ones
// already ingested at that second are remembered and skipped.
type runtimeRefresher struct {
	est      *runtimeest.Estimator
	src      runtimeHistorySource
	interval time.Duration
	backfill time.Duration
	maxRows  int
	now      func() time.Time
	logger   *logging.Logger

	// Owned by the goroutine running Refresh.
	loaded    bool
	watermark int64
	boundary  map[string]struct{}

	mu          sync.Mutex
	lastSuccess time.Time
	errorsTotal int64
	truncations int64
}

func newRuntimeRefresher(est *runtimeest.Estimator, src runtimeHistorySource, interval, backfill time.Duration, logger *logging.Logger) *runtimeRefresher {
	if backfill <= 0 {
		backfill = defaultRuntimeEstimateBackfill
	}
	return &runtimeRefresher{
		est:      est,
		src:      src,
		interval: interval,
		backfill: backfill,
		maxRows:  runtimeEstimateMaxRows,
		now:      time.Now,
		logger:   logger,
	}
}

// Run refreshes immediately, then every interval, until ctx is
// cancelled. Reading the history is this daemon's own work, not any
// caller's.
func (r *runtimeRefresher) Run(ctx context.Context) {
	ctx = htcondor.WithDaemonCredential(ctx, "runtime estimate refresh")
	r.refreshOnce(ctx)
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.refreshOnce(ctx)
		}
	}
}

func (r *runtimeRefresher) refreshOnce(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, runtimeEstimateRefreshTimeout)
	defer cancel()
	_ = r.Refresh(ctx)
}

// Refresh reads what entered history since the last refresh and applies
// it. On error nothing is applied and the watermark does not move, so
// the estimator keeps answering from what it had and the next refresh
// reads the same window again.
func (r *runtimeRefresher) Refresh(ctx context.Context) error {
	now := r.now()
	since := now.Add(-r.backfill).Unix()
	if r.loaded {
		since = r.watermark
	}

	batch := runtimeest.NewBatch()
	newest := since
	atNewest := make(map[string]struct{})
	rows, skipped := 0, 0
	err := r.src.History(ctx, since, r.maxRows+1, func(ad *classad.ClassAd) {
		rows++
		if rows > r.maxRows {
			// The probe row past the cap: it says the cap was hit, and,
			// newest first, it is the oldest of what was read.
			return
		}
		entered := runtimeEnteredHistory(ad)
		id := runtimeJobIdentity(ad)
		if r.loaded && entered == r.watermark {
			if _, seen := r.boundary[id]; seen {
				skipped++
				return
			}
		}
		if entered > newest {
			newest = entered
			atNewest = make(map[string]struct{})
		}
		if entered == newest {
			atNewest[id] = struct{}{}
		}
		batch.AddAd(ad)
	})
	if err != nil {
		r.mu.Lock()
		r.errorsTotal++
		r.mu.Unlock()
		if r.logger != nil {
			r.logger.Warn(logging.DestinationHTTP,
				"Could not read job history for runtime estimates; keeping the previous estimates",
				"error", err, "since", since)
		}
		return err
	}

	truncated := rows > r.maxRows
	if truncated {
		r.mu.Lock()
		r.truncations++
		r.mu.Unlock()
		if r.logger != nil {
			r.logger.Warn(logging.DestinationHTTP,
				"Job history read for runtime estimates hit its row cap; the oldest records in the window were not read",
				"cap", r.maxRows, "since", since)
		}
	}

	r.est.Ingest(batch)
	if newest == r.watermark && r.loaded {
		// Nothing newer arrived: the second is still open, so what was
		// seen in it before is still worth remembering.
		for id := range r.boundary {
			atNewest[id] = struct{}{}
		}
	}
	r.watermark, r.boundary = newest, atNewest
	first := !r.loaded
	r.loaded = true
	evicted := r.est.Evict(now.Add(-r.backfill))

	r.mu.Lock()
	r.lastSuccess = now
	r.mu.Unlock()

	if r.logger != nil {
		st := r.est.Stats()
		read := rows
		if truncated {
			read = r.maxRows
		}
		args := []any{"rows", read, "ingested", batch.Len(), "duplicates", skipped,
			"evicted_groups", evicted, "jobs_total", st.JobsIngested}
		if !st.TrainedThrough.IsZero() {
			args = append(args, "trained_through", st.TrainedThrough.Format(time.RFC3339))
		}
		if first {
			r.logger.Info(logging.DestinationHTTP, "Loaded job history for runtime estimates", args...)
		} else {
			r.logger.Debug(logging.DestinationHTTP, "Refreshed runtime estimates", args...)
		}
	}
	return nil
}

// status is what the metrics report about the loop.
func (r *runtimeRefresher) status() (lastSuccess time.Time, errorsTotal, truncations int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastSuccess, r.errorsTotal, r.truncations
}

func runtimeEnteredHistory(ad *classad.ClassAd) int64 {
	v, ok := ad.EvaluateAttrNumber("EnteredHistoryTime")
	if !ok {
		return 0
	}
	return int64(v)
}

// runtimeJobIdentity names a history record for the boundary
// deduplication: GlobalJobId when present, else the job id and QDate,
// which together survive a schedd reusing cluster ids after a reset.
func runtimeJobIdentity(ad *classad.ClassAd) string {
	if g, ok := ad.EvaluateAttrString("GlobalJobId"); ok && g != "" {
		return g
	}
	c, _ := ad.EvaluateAttrNumber("ClusterId")
	p, _ := ad.EvaluateAttrNumber("ProcId")
	q, _ := ad.EvaluateAttrNumber("QDate")
	return fmt.Sprintf("%d.%d@%d", int64(c), int64(p), int64(q))
}

// initRuntimeEstimates builds the estimator and its refresher when the
// feature is on and can work: an interval, a single access point, and
// a mirror to read history from. Called from NewHandler before the MCP
// server is built, which shares the estimator.
func (h *Handler) initRuntimeEstimates(cfg HandlerConfig) {
	switch {
	case cfg.RuntimeEstimateInterval <= 0:
		h.logger.Info(logging.DestinationHTTP, "Runtime estimates disabled (HTTP_API_RUNTIME_ESTIMATE_INTERVAL = 0)")
		return
	case h.multi != nil:
		h.logger.Info(logging.DestinationHTTP, "Runtime estimates are not available in multi-AP mode")
		return
	case !h.dbMirror.Enabled():
		h.logger.Info(logging.DestinationHTTP,
			"Runtime estimates disabled: they are built from the htcondordb mirror's history, and no mirror is configured")
		return
	}
	h.runtimeEst = runtimeest.New(runtimeest.Config{})
	h.runtimeRefresher = newRuntimeRefresher(h.runtimeEst,
		mirrorRuntimeHistory{locator: h.dbMirror, gate: runtimeHistoryGate},
		cfg.RuntimeEstimateInterval, cfg.RuntimeEstimateBackfill, h.logger)
	h.logger.Info(logging.DestinationHTTP, "Runtime estimates enabled",
		"interval", cfg.RuntimeEstimateInterval, "backfill", h.runtimeRefresher.backfill)
}

// startRuntimeEstimates runs the refresher for the life of the handler.
func (h *Handler) startRuntimeEstimates(ctx context.Context) {
	if h.runtimeRefresher == nil {
		return
	}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		h.runtimeRefresher.Run(ctx)
	}()
}

// handleJobRuntimeEstimate handles GET /api/v1/jobs/{id}/runtime-estimate.
//
// The body is always a runtimeest.Result with the job id beside it. A
// server without the feature answers 200 with available false and reason
// "disabled", so a client has one shape to handle whatever the access
// point runs; it still authenticates first, and does not look the job up.
//
// The job is read with the same scope as every other job read, so a job
// that is not the caller's is "not found". The estimate is then built
// from that job's owner's history -- aggregates only, never another
// job's command line or id.
func (h *Handler) handleJobRuntimeEstimate(w http.ResponseWriter, r *http.Request, cluster, proc int) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	ctx, needsRedirect, err := h.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			h.redirectToLogin(w, r)
			return
		}
		h.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	jobID := fmt.Sprintf("%d.%d", cluster, proc)
	type response struct {
		JobID string `json:"job_id"`
		runtimeest.Result
	}
	if h.runtimeEst == nil {
		h.writeJSON(w, http.StatusOK, response{JobID: jobID, Result: runtimeest.Result{Reason: runtimeest.ReasonDisabled}})
		return
	}

	constraint, scopeErr := h.jobReadScope(ctx, r, cluster, proc)
	if scopeErr != nil {
		h.writeError(w, http.StatusBadRequest, scopeErr.Error())
		return
	}
	ads, _, err := h.getSchedd().QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Projection: runtimeest.QueryAttrs,
		Limit:      1,
	})
	if err != nil {
		h.logger.Error(logging.DestinationHTTP, "runtime-estimate: query job", "error", err, "job", jobID)
		h.writeError(w, http.StatusInternalServerError, "Failed to query job")
		return
	}
	if len(ads) == 0 {
		h.writeError(w, http.StatusNotFound, fmt.Sprintf("Job not found: %s", jobID))
		return
	}
	res := h.runtimeEst.Estimate(runtimeest.QueryFromAd(ads[0], time.Now()))
	h.writeJSON(w, http.StatusOK, response{JobID: jobID, Result: res})
}

// runtimeEstimateCollector exports the estimator and its refresher at
// scrape time. The series exist, as zeros, on a server without the
// feature, so a dashboard does not have to handle them going missing.
type runtimeEstimateCollector struct {
	h *Handler

	enabled        *prometheus.Desc
	jobs           *prometheus.Desc
	lastRefresh    *prometheus.Desc
	trainedThrough *prometheus.Desc
	errors         *prometheus.Desc
	truncations    *prometheus.Desc
	scored         *prometheus.Desc
	within2x       *prometheus.Desc
	keys           *prometheus.Desc
	owners         *prometheus.Desc
}

func newRuntimeEstimateCollector(h *Handler) *runtimeEstimateCollector {
	n := func(name, help string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc(metricsNamespace+"_runtime_estimate_"+name, help, labels, nil)
	}
	return &runtimeEstimateCollector{
		h:              h,
		enabled:        n("enabled", "1 if runtime estimates are enabled on this server."),
		jobs:           n("jobs_ingested_total", "Completed jobs read into the runtime estimator."),
		lastRefresh:    n("last_refresh_timestamp_seconds", "When the runtime estimator last read the history successfully; 0 before the first time."),
		trainedThrough: n("trained_through_timestamp_seconds", "Completion time of the newest job the runtime estimator has read."),
		errors:         n("refresh_errors_total", "Runtime estimator history reads that failed. The previous estimates stay in use."),
		truncations:    n("refresh_truncations_total", "Runtime estimator history reads that hit the row cap and dropped the oldest records."),
		scored: n("scored_total", "Completed jobs the runtime estimator would have had an estimate for at submit, "+
			"by the level that answered.", "level"),
		within2x: n("within_2x_total", "Completed jobs whose runtime estimate at submit was within a factor of two of what they ran, "+
			"by the level that answered. Divide by scored_total for live accuracy.", "level"),
		keys:   n("keys", "Groups the runtime estimator holds, by level.", "level"),
		owners: n("owners", "Owners the runtime estimator holds state for."),
	}
}

func (c *runtimeEstimateCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{c.enabled, c.jobs, c.lastRefresh, c.trainedThrough,
		c.errors, c.truncations, c.scored, c.within2x, c.keys, c.owners} {
		ch <- d
	}
}

func (c *runtimeEstimateCollector) Collect(ch chan<- prometheus.Metric) {
	gauge := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
	}
	counter := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, v, labels...)
	}
	var st runtimeest.Stats
	enabled := 0.0
	if c.h.runtimeEst != nil {
		st = c.h.runtimeEst.Stats()
		enabled = 1
	}
	var last time.Time
	var errs, truncs int64
	if c.h.runtimeRefresher != nil {
		last, errs, truncs = c.h.runtimeRefresher.status()
	}
	gauge(c.enabled, enabled)
	counter(c.jobs, float64(st.JobsIngested))
	gauge(c.lastRefresh, unixOrZero(last))
	gauge(c.trainedThrough, unixOrZero(st.TrainedThrough))
	counter(c.errors, float64(errs))
	counter(c.truncations, float64(truncs))
	for _, l := range runtimeest.Levels() {
		name := l.String()
		counter(c.scored, float64(st.ScoredByLevel[name]), name)
		counter(c.within2x, float64(st.Within2xByLevel[name]), name)
		gauge(c.keys, float64(st.Keys[name]), name)
	}
	gauge(c.owners, float64(st.Owners))
}

func unixOrZero(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.Unix())
}
