package httpserver

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/batches"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/issues"
	"github.com/bbockelm/golang-htcondor/webapi/utilization"
)

// The batch page: one row of the /jobs page -- a DAG, a named batch, or a
// cluster (see package batches) -- over its whole life, queued and
// finished.
//
// GET /api/v1/batches/{id} summarizes it and GET /api/v1/batches/{id}/jobs
// lists its jobs. Both answer from one read of the batch, kept briefly so
// paging and the summary beside it do not read it again: its jobs in the
// queue, and its records in history up to batchHistoryLimit, newest first.
// The read is projected (batchProjection) and parsed on every core, so a
// 100,000-job batch is a few seconds the first time and nothing for the
// next batchRefresh.
//
// Multi-AP mode is not served: the routes are not on its allowlist, so it
// answers 501.

const (
	// batchLiveLimit and batchHistoryLimit bound the read: the jobs in the
	// queue, and the history records, newest first.
	batchLiveLimit    = 100000
	batchHistoryLimit = 100000
	// batchRefresh is how long a read is reused.
	batchRefresh = 15 * time.Second
	// batchComputeTimeout bounds one read.
	batchComputeTimeout = 3 * time.Minute
	// batchCacheBytes bounds the reads kept, by an estimate of their size.
	batchCacheBytes = 256 << 20
	// batchRowBytes is that estimate, per job.
	batchRowBytes    = 400
	batchPageDefault = 100
	batchPageMax     = 500
	// batchExamples is how many jobs a hold reason names.
	batchExamples = 5
	// batchHoldGranularity is the Issues page's default.
	batchHoldGranularity = 0.5
)

// batchProjection is what the read asks for: the grouping's attributes,
// the Utilization analysis's (its peaks, requests and workflow), and the
// rows'.
var batchProjection = func() []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range slices.Concat(batches.Attrs, utilization.Projection(), []string{
		"DAGNodeName", "HoldReason", "LastHoldReason", "ExitSignal",
		"JobCurrentStartExecutingDate", "JobCurrentStartDate", "EnteredCurrentStatus",
	}) {
		if k := strings.ToLower(a); !seen[k] {
			seen[k] = true
			out = append(out, a)
		}
	}
	return out
}()

// BatchResponse is GET /api/v1/batches/{id}. See BATCH_CONTRACT.md.
type BatchResponse struct {
	Kind             batches.Kind           `json:"kind"`
	ID               int64                  `json:"id"`
	Name             string                 `json:"name"`
	Owner            string                 `json:"owner,omitempty"`
	Constraint       string                 `json:"constraint"`
	RemoveConstraint string                 `json:"remove_constraint"`
	Clusters         []int64                `json:"clusters"`
	DagmanJobID      string                 `json:"dagman_job_id,omitempty"`
	Submitted        *int64                 `json:"submitted,omitempty"`
	FirstStart       *int64                 `json:"first_start,omitempty"`
	LastCompletion   *int64                 `json:"last_completion,omitempty"`
	Progress         batches.Progress       `json:"progress"`
	Live             map[batches.Status]int `json:"live"`
	LiveJobs         int                    `json:"live_jobs"`
	LiveTruncated    bool                   `json:"live_truncated"`
	Finished         BatchFinished          `json:"finished"`
	HoldReasons      []BatchHoldReason      `json:"hold_reasons"`
	Dag              *BatchDag              `json:"dag,omitempty"`
	Workflows        []BatchWorkflow        `json:"workflows"`
	HasHistory       bool                   `json:"has_history"`
	FetchedAt        int64                  `json:"fetched_at"`
}

// BatchFinished is the batch's history records, summarized.
type BatchFinished struct {
	Jobs        int            `json:"jobs"`
	Truncated   bool           `json:"truncated"`
	Limit       int            `json:"limit"`
	Succeeded   int            `json:"succeeded"`
	Failed      int            `json:"failed"`
	Removed     int            `json:"removed"`
	Outcomes    []BatchOutcome `json:"outcomes"`
	Runtime     *BatchRuntime  `json:"runtime,omitempty"`
	WallHours   float64        `json:"wall_hours"`
	BadputHours float64        `json:"badput_hours"`
	CoreHours   float64        `json:"core_hours"`
	Memory      *BatchMemory   `json:"memory,omitempty"`
}

// BatchOutcome is one way the batch's jobs ended.
type BatchOutcome struct {
	Outcome string `json:"outcome"`
	Code    *int64 `json:"code,omitempty"`
	Count   int    `json:"count"`
}

// BatchRuntime is the completed jobs' runtimes, seconds.
type BatchRuntime struct {
	Count int     `json:"count"`
	P10   float64 `json:"p10"`
	P50   float64 `json:"p50"`
	P90   float64 `json:"p90"`
	Max   float64 `json:"max"`
	Mean  float64 `json:"mean"`
}

// BatchMemory is the completed jobs' memory, MiB.
type BatchMemory struct {
	Count      int     `json:"count"`
	RequestP50 float64 `json:"request_p50"`
	PeakP50    float64 `json:"peak_p50"`
	PeakP95    float64 `json:"peak_p95"`
	PeakMax    float64 `json:"peak_max"`
}

// BatchHoldReason is one kind of hold among the batch's jobs.
type BatchHoldReason struct {
	Kind     string             `json:"kind"`
	Template string             `json:"template"`
	Count    int                `json:"count"`
	Codes    []issues.CodeCount `json:"codes"`
	Examples []BatchHoldExample `json:"examples"`
}

// BatchHoldExample is one job with a hold reason.
type BatchHoldExample struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

// BatchDag is a DAG's root DAGMan job.
type BatchDag struct {
	Attributes map[string]any `json:"attributes"`
	Status     *int64         `json:"status"`
	Source     string         `json:"source"`
}

// BatchWorkflow is a Utilization workflow the batch's jobs fall in.
type BatchWorkflow struct {
	Key          string `json:"key"`
	Name         string `json:"name"`
	Executable   string `json:"executable"`
	Jobs         int    `json:"jobs"`
	FinishedJobs int    `json:"finished_jobs"`
}

// BatchJobsResponse is GET /api/v1/batches/{id}/jobs.
type BatchJobsResponse struct {
	ID               int64         `json:"id"`
	Total            int           `json:"total"`
	Offset           int           `json:"offset"`
	NextOffset       *int          `json:"next_offset"`
	LiveTruncated    bool          `json:"live_truncated"`
	HistoryTruncated bool          `json:"history_truncated"`
	Jobs             []BatchJobRow `json:"jobs"`
}

// BatchJobRow is one job of the batch, queued or finished.
type BatchJobRow struct {
	ID               string         `json:"id"`
	Cluster          int64          `json:"cluster"`
	Proc             int64          `json:"proc"`
	Source           string         `json:"source"`
	Status           batches.Status `json:"status"`
	Node             string         `json:"node,omitempty"`
	Dagman           bool           `json:"dagman,omitempty"`
	Outcome          string         `json:"outcome,omitempty"`
	ExitCode         *int64         `json:"exit_code,omitempty"`
	ExitSignal       *int64         `json:"exit_signal,omitempty"`
	Submitted        *int64         `json:"submitted,omitempty"`
	Started          *int64         `json:"started,omitempty"`
	Finished         *int64         `json:"finished,omitempty"`
	RuntimeSeconds   *float64       `json:"runtime_seconds,omitempty"`
	RequestMemoryMiB *float64       `json:"request_memory_mib,omitempty"`
	PeakMemoryMiB    *float64       `json:"peak_memory_mib,omitempty"`
	RequestCpus      *float64       `json:"request_cpus,omitempty"`
	CoresUsed        *float64       `json:"cores_used,omitempty"`
	HoldReason       string         `json:"hold_reason,omitempty"`
	HoldCode         *int64         `json:"hold_code,omitempty"`
}

const (
	sourceQueue   = "queue"
	sourceHistory = "history"

	outcomeSucceeded = "succeeded"
	outcomeFailed    = "failed"
	outcomeRemoved   = "removed"
)

// batchRecord is one job ad of the batch, read.
type batchRecord struct {
	f          batches.Fields
	j          utilization.Job
	live       bool
	node       string
	holdReason string
	holdCode   *int64
	holdSub    int64
	exitSignal *int64
	started    int64
	finished   int64
}

// newBatchRecord reads one ad. reader is the caller's, not shared.
func newBatchRecord(ad *classad.ClassAd, live bool, reader *utilization.JobReader) batchRecord {
	rec := batchRecord{f: batches.FieldsFromAd(ad), j: reader.FromAd(ad, ""), live: live}
	rec.node, _ = ad.EvaluateAttrString("DAGNodeName")
	held := live && rec.f.JobStatus != nil && *rec.f.JobStatus == 5
	if held || !live {
		code, sub, reason := "HoldReasonCode", "HoldReasonSubCode", "HoldReason"
		if r, _ := ad.EvaluateAttrString(reason); r == "" && !live {
			code, sub, reason = "LastHoldReasonCode", "LastHoldReasonSubCode", "LastHoldReason"
		}
		rec.holdReason, _ = ad.EvaluateAttrString(reason)
		if c, ok := ad.EvaluateAttrInt(code); ok {
			rec.holdCode = &c
		}
		rec.holdSub, _ = ad.EvaluateAttrInt(sub)
	}
	if rec.j.ExitBySignal {
		if s, ok := ad.EvaluateAttrInt("ExitSignal"); ok {
			rec.exitSignal = &s
		}
	}
	if s, ok := ad.EvaluateAttrInt("JobCurrentStartExecutingDate"); ok && s > 0 {
		rec.started = s
	} else if s, ok := ad.EvaluateAttrInt("JobCurrentStartDate"); ok && s > 0 {
		rec.started = s
	}
	rec.finished = rec.j.Completion
	if rec.finished <= 0 && !live {
		rec.finished = rec.j.Entered
	}
	return rec
}

func (rec *batchRecord) status() batches.Status { return rec.f.Status() }

func (rec *batchRecord) jobID() string {
	return fmt.Sprintf("%d.%d", rec.j.Cluster, rec.j.Proc)
}

// outcome is how a finished job ended; "" for one that has not.
func (rec *batchRecord) outcome() string {
	switch rec.status() {
	case batches.StatusRemoved:
		return outcomeRemoved
	case batches.StatusCompleted:
		if rec.j.ExitBySignal || (rec.j.ExitCode.OK() && rec.j.ExitCode.V() != 0) {
			return outcomeFailed
		}
		return outcomeSucceeded
	}
	return ""
}

// runtime is a finished job's runtime: the run that counted
// (CommittedTime), else all of them.
func (rec *batchRecord) runtime() (float64, bool) {
	if rec.outcome() == "" {
		return 0, false
	}
	if c := rec.j.CommittedTime; c.OK() && c.V() > 0 {
		return c.V(), true
	}
	if rec.j.Wall > 0 {
		return rec.j.Wall, true
	}
	return 0, false
}

func (rec *batchRecord) row() BatchJobRow {
	r := BatchJobRow{
		ID: rec.jobID(), Cluster: rec.j.Cluster, Proc: rec.j.Proc,
		Source: sourceHistory, Status: rec.status(), Node: rec.node,
		Dagman: rec.f.IsDagManJob(), Outcome: rec.outcome(),
		ExitSignal: rec.exitSignal, HoldReason: rec.holdReason, HoldCode: rec.holdCode,
		Submitted: positive(rec.j.QDate), Started: positive(rec.started), Finished: positive(rec.finished),
		RequestMemoryMiB: present(rec.j.RequestMemory), PeakMemoryMiB: present(rec.j.MemoryUsage),
		RequestCpus: present(rec.j.RequestCpus),
	}
	if rec.live {
		r.Source = sourceQueue
	}
	if r.Status == batches.StatusCompleted && !rec.j.ExitBySignal && rec.j.ExitCode.OK() {
		c := int64(rec.j.ExitCode.V())
		r.ExitCode = &c
	}
	if rt, ok := rec.runtime(); ok {
		r.RuntimeSeconds = &rt
	}
	if r.Outcome != "" && rec.j.CPUSeconds.OK() && rec.j.Wall > 0 {
		c := rec.j.CPUSeconds.V() / rec.j.Wall
		r.CoresUsed = &c
	}
	return r
}

func positive(v int64) *int64 {
	if v <= 0 {
		return nil
	}
	return &v
}

func present(n utilization.Num) *float64 {
	if !n.OK() {
		return nil
	}
	v := n.V()
	return &v
}

// batchSnapshot is one read of a batch.
type batchSnapshot struct {
	summary BatchResponse
	rows    []BatchJobRow
}

func (s *Handler) batchCache() *sharedCache[*batchSnapshot] {
	s.batchCacheOnce.Do(func() {
		c := newSharedCache[*batchSnapshot](batchRefresh, batchComputeTimeout)
		c.sizeOf = func(b *batchSnapshot) int { return (len(b.rows) + 1) * batchRowBytes }
		c.maxSize = batchCacheBytes
		s.batchCacheVal = c
	})
	return s.batchCacheVal
}

// errBatchNotFound is a batch the caller cannot see, or that is not there.
var errBatchNotFound = errors.New("batch not found")

// handleBatch serves /api/v1/batches/{id} and /api/v1/batches/{id}/jobs.
func (s *Handler) handleBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/batches/")
	idText, sub, _ := strings.Cut(rest, "/")
	if sub != "" && sub != "jobs" {
		s.writeError(w, http.StatusNotFound, "Not found")
		return
	}
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || id < 0 {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid batch id %q: the batch's cluster id", idText))
		return
	}
	var page batchPage
	if sub == "jobs" {
		if page, err = parseBatchPage(r); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	snap, err := s.readBatch(ctx, r, id)
	switch {
	case errors.Is(err, errBatchNotFound):
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Batch not found: %d", id))
		return
	case err != nil:
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("Could not read the batch: %v", err))
		return
	}
	if sub == "" {
		s.writeJSON(w, http.StatusOK, snap.summary)
		return
	}
	s.writeJSON(w, http.StatusOK, page.apply(snap))
}

// readBatch resolves id to its batch and reads it, or reuses a recent
// read. Any cluster of the batch names it, so the read is kept under the
// batch's own constraint, scoped to the caller.
func (s *Handler) readBatch(ctx context.Context, r *http.Request, id int64) (*batchSnapshot, error) {
	scope, err := s.jobsReadScope(ctx, r, "ClusterId == "+strconv.FormatInt(id, 10))
	if err != nil {
		return nil, err
	}
	ad, source, err := s.findBatchJob(ctx, r, scope, batches.Attrs)
	if err != nil {
		return nil, err
	}
	if ad == nil {
		return nil, errBatchNotFound
	}
	f := batches.FieldsFromAd(ad)
	ident, ok := batches.Identify(&f)
	if !ok {
		return nil, errBatchNotFound
	}
	batchScope, err := s.jobsReadScope(ctx, r, ident.Jobs)
	if err != nil {
		return nil, err
	}
	s.logger.Debug(logging.DestinationHTTP, "batch resolved", "id", id, "kind", ident.Kind, "batch", ident.ID, "from", source)
	return s.batchCache().get(ctx, batchScope, func(computeCtx context.Context) (*batchSnapshot, error) {
		return s.computeBatch(computeCtx, r, ident, batchScope, f.QDate)
	})
}

// findBatchJob reads one job matching scope: from the queue, else from
// history (the mirror, else the schedd). nil when there is none.
func (s *Handler) findBatchJob(ctx context.Context, r *http.Request, scope string, projection []string) (*classad.ClassAd, string, error) {
	ads, _, err := s.getSchedd().QueryWithOptions(ctx, scope, &htcondor.QueryOptions{Projection: projection, Limit: 1})
	if err != nil {
		return nil, "", err
	}
	if len(ads) > 0 {
		return ads[0], sourceQueue, nil
	}
	if s.mirrorAllowed(ctx, r) == nil {
		mirrorProj := projection
		if slices.Equal(projection, []string{"*"}) {
			mirrorProj = nil
		}
		if ads, err := s.mirrorRows(ctx, "history", scope, mirrorProj, 1); err == nil && len(ads) > 0 {
			return ads[0], sourceHistory, nil
		}
	}
	ads, err = s.getSchedd().QueryHistoryWithOptions(ctx, scope, &htcondor.HistoryQueryOptions{
		Source: htcondor.HistorySourceJobHistory, Limit: 1, ScanLimit: utilizationScanLimit(1),
		Projection: projection, Backwards: true,
	})
	if err != nil {
		return nil, "", err
	}
	if len(ads) > 0 {
		return ads[0], sourceHistory, nil
	}
	return nil, "", nil
}

// computeBatch reads the batch: its queue, its root DAGMan job, its
// history; and summarizes it.
func (s *Handler) computeBatch(ctx context.Context, r *http.Request, ident batches.Identity, scope string, qdate *int64) (*batchSnapshot, error) {
	live, _, err := s.getSchedd().QueryWithOptions(ctx, scope, &htcondor.QueryOptions{Projection: batchProjection, Limit: batchLiveLimit + 1})
	if err != nil {
		return nil, err
	}
	liveTruncated := len(live) > batchLiveLimit
	if liveTruncated {
		live = live[:batchLiveLimit]
	}

	var dag *BatchDag
	// Every job of a DAG or a cluster entered history after the DAG's
	// root, or the cluster, was submitted, so the history read starts
	// there and the mirror can skip everything older. A named batch's
	// clusters may be older than the one it was found by: read it all.
	var since int64
	if ident.Kind == batches.KindDAG {
		root, src, err := s.findBatchJob(ctx, r, rootScope(scope, ident.ID), []string{"*"})
		if err != nil {
			return nil, err
		}
		if root != nil {
			dag = dagInfo(root, src)
			since, _ = root.EvaluateAttrInt("QDate")
		}
	} else if ident.Kind == batches.KindCluster && qdate != nil {
		since = *qdate
	}
	history, historyTruncated, err := s.readBatchHistory(ctx, r, scope, max(since-1, 0))
	if err != nil {
		return nil, err
	}

	recs := make([]batchRecord, 0, len(live)+len(history))
	var reader utilization.JobReader
	for _, ad := range live {
		recs = append(recs, newBatchRecord(ad, true, &reader))
	}
	recs = append(recs, history...)
	snap := summarizeBatch(ident, recs, dag)
	snap.summary.LiveTruncated = liveTruncated
	snap.summary.Finished.Truncated = historyTruncated
	snap.summary.Progress = progressOf(recs, !liveTruncated)
	return snap, nil
}

// rootScope narrows a batch's scope to its root DAGMan job.
func rootScope(scope string, root int64) string {
	return fmt.Sprintf("(%s) && ClusterId == %d && ProcId == 0", scope, root)
}

// progressOf is the batch's progress over every record, queue first.
func progressOf(recs []batchRecord, complete bool) batches.Progress {
	fields := make([]batches.Fields, len(recs))
	for i := range recs {
		fields[i] = recs[i].f
	}
	return batches.ProgressOf(fields, complete)
}

// dagInfo is the root DAGMan job's DAG_* attributes.
func dagInfo(ad *classad.ClassAd, source string) *BatchDag {
	d := &BatchDag{Attributes: map[string]any{}, Source: source}
	for _, name := range ad.GetAttributes() {
		if !strings.HasPrefix(strings.ToUpper(name), "DAG_") {
			continue
		}
		v := ad.EvaluateAttr(name)
		switch {
		case v.IsInteger():
			n, _ := v.IntValue()
			d.Attributes[name] = n
		case v.IsReal():
			x, _ := v.RealValue()
			d.Attributes[name] = x
		case v.IsString():
			str, _ := v.StringValue()
			d.Attributes[name] = str
		case v.IsBool():
			b, _ := v.BoolValue()
			d.Attributes[name] = b
		}
	}
	if st, ok := ad.EvaluateAttrInt("JobStatus"); ok {
		d.Status = &st
	}
	return d
}

// readBatchHistory reads the batch's history records entered at or after
// since, newest first, up to batchHistoryLimit, and reads them into
// records on every core. truncated says the bound stopped it.
func (s *Handler) readBatchHistory(ctx context.Context, r *http.Request, scope string, since int64) ([]batchRecord, bool, error) {
	dec := newBatchDecoder()
	n := 0
	truncated := false
	take := func() bool {
		if n >= batchHistoryLimit {
			truncated = true
			return false
		}
		n++
		return true
	}
	if s.mirrorAllowed(ctx, r) == nil {
		err := s.batchMirrorHistory(ctx, fmt.Sprintf("(%s) && EnteredHistoryTime >= %d", scope, since), func(row string) bool {
			if !take() {
				return false
			}
			dec.row(row)
			return true
		})
		if err == nil || n > 0 {
			recs := dec.finish()
			return recs, truncated, err
		}
		s.logger.Debug(logging.DestinationHTTP, "batch history: the mirror could not answer", "error", err)
	}
	results, err := s.getSchedd().QueryHistoryStream(ctx, fmt.Sprintf("(%s) && %s >= %d", scope, scheddEnteredHistory, since),
		&htcondor.HistoryQueryOptions{
			Source: htcondor.HistorySourceJobHistory, Limit: batchHistoryLimit + 1, ScanLimit: utilizationScanLimit(batchHistoryLimit),
			Projection: batchProjection, Backwards: true, StreamResults: true,
			Since: fmt.Sprintf("%s < %d", scheddEnteredHistory, since),
		},
		&htcondor.StreamOptions{BufferSize: s.streamBufferSize, WriteTimeout: s.streamWriteTimeout})
	if err != nil {
		dec.finish()
		return nil, false, err
	}
	var streamErr error
	open := true
	// Drained to the end, so the reader is never left blocked.
	for res := range results {
		switch {
		case res.Err != nil:
			streamErr = res.Err
		case open && res.Ad != nil:
			if open = take(); open {
				dec.ad(res.Ad)
			}
		}
	}
	recs := dec.finish()
	if streamErr != nil {
		return nil, false, streamErr
	}
	return recs, truncated, nil
}

// batchMirrorHistory streams the mirror's history rows matching
// constraint, newest first, if the mirror may answer.
func (s *Handler) batchMirrorHistory(ctx context.Context, constraint string, yield func(string) bool) error {
	info, err := s.dbMirror.Discover(ctx)
	if err != nil {
		return err
	}
	if d := dbmirror.HistoryDecision(info, &htcondor.HistoryQueryOptions{Backwards: true}); !d.Use {
		return errors.New(d.Note)
	}
	dbc, closer, _, err := s.dbMirror.Client(ctx)
	if err != nil {
		return err
	}
	defer closer()
	return dbc.QueryRawProjectStream(ctx, "history", constraint, batchProjection, batchHistoryLimit+1, yield)
}

// batchDecoder parses history rows into records on every core. Parsing
// is most of a read's cost -- tens of microseconds a record -- and the
// rows arrive faster than one core parses them.
type batchDecoder struct {
	work    chan []batchItem
	batch   []batchItem
	wg      sync.WaitGroup
	results [][]batchRecord
}

type batchItem struct {
	text string
	ad   *classad.ClassAd
}

const batchDecodeChunk = 256

func newBatchDecoder() *batchDecoder {
	workers := runtime.GOMAXPROCS(0)
	d := &batchDecoder{work: make(chan []batchItem, 2*workers), results: make([][]batchRecord, workers)}
	for w := range workers {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			var reader utilization.JobReader
			for items := range d.work {
				for _, it := range items {
					ad := it.ad
					if ad == nil {
						parsed, err := classad.ParseOld(it.text)
						if err != nil {
							continue
						}
						ad = parsed
					}
					d.results[w] = append(d.results[w], newBatchRecord(ad, false, &reader))
				}
			}
		}()
	}
	return d
}

func (d *batchDecoder) row(text string)        { d.add(batchItem{text: text}) }
func (d *batchDecoder) ad(ad *classad.ClassAd) { d.add(batchItem{ad: ad}) }

func (d *batchDecoder) add(it batchItem) {
	d.batch = append(d.batch, it)
	if len(d.batch) == batchDecodeChunk {
		d.work <- d.batch
		d.batch = nil
	}
}

// finish waits for the queued rows and returns their records. It must be
// called once, to stop the workers.
func (d *batchDecoder) finish() []batchRecord {
	if len(d.batch) > 0 {
		d.work <- d.batch
	}
	close(d.work)
	d.wg.Wait()
	return slices.Concat(d.results...)
}

// summarizeBatch is the summary and rows of a batch's records.
func summarizeBatch(ident batches.Identity, recs []batchRecord, dag *BatchDag) *batchSnapshot {
	a := newBatchSummary(ident, dag)
	rows := make([]BatchJobRow, 0, len(recs))
	for i := range recs {
		rec := &recs[i]
		rows = append(rows, rec.row())
		a.add(rec)
	}
	return &batchSnapshot{summary: a.finish(ident), rows: rows}
}

// batchSummary accumulates a BatchResponse over records.
type batchSummary struct {
	sum       BatchResponse
	clusters  map[int64]bool
	workflows map[string]*batchWorkflowAcc
	outcomes  map[[2]int64]*BatchOutcome
	runtimes  []float64
	peaks     []float64
	requests  []float64
	holds     *issues.Clusterer
}

type batchWorkflowAcc struct {
	BatchWorkflow
	order int
}

func newBatchSummary(ident batches.Identity, dag *BatchDag) *batchSummary {
	a := &batchSummary{
		sum: BatchResponse{
			Kind: ident.Kind, ID: ident.ID, Name: ident.Name, Owner: ident.Owner,
			Constraint: ident.Jobs, RemoveConstraint: ident.Remove,
			Live: map[batches.Status]int{}, Dag: dag,
			Finished:    BatchFinished{Limit: batchHistoryLimit, Outcomes: []BatchOutcome{}},
			HoldReasons: []BatchHoldReason{}, Workflows: []BatchWorkflow{}, Clusters: []int64{},
			FetchedAt: time.Now().Unix(),
		},
		clusters:  map[int64]bool{},
		workflows: map[string]*batchWorkflowAcc{},
		outcomes:  map[[2]int64]*BatchOutcome{},
		holds:     issues.NewClusterer(),
	}
	if ident.Kind == batches.KindDAG {
		a.sum.DagmanJobID = fmt.Sprintf("%d.0", ident.ID)
	}
	return a
}

func (a *batchSummary) add(rec *batchRecord) {
	a.clusters[rec.j.Cluster] = true
	a.sum.Submitted = minPositive(a.sum.Submitted, rec.j.QDate)
	a.sum.FirstStart = minPositive(a.sum.FirstStart, rec.j.FirstStart)
	a.addWorkflow(rec)
	a.addHold(rec)
	if rec.live {
		a.sum.Live[rec.status()]++
		a.sum.LiveJobs++
		return
	}
	a.sum.HasHistory = true
	if c := rec.j.Completion; c > 0 && (a.sum.LastCompletion == nil || c > *a.sum.LastCompletion) {
		a.sum.LastCompletion = &c
	}
	// A DAGMan job's run is the workflow's, not work of its own: its
	// hours are a DAG's whole span, and its exit status says whether
	// some node failed, which the nodes already say. Its record is in
	// the rows and in dag.
	if !rec.f.IsDagManJob() {
		a.addFinished(rec)
	}
}

// addWorkflow counts the job in its Utilization workflow. A DAGMan job
// is not one: it runs nothing of the user's.
func (a *batchSummary) addWorkflow(rec *batchRecord) {
	if rec.f.IsDagManJob() {
		return
	}
	key, name, exe := utilization.WorkflowOf(&rec.j)
	w := a.workflows[key]
	if w == nil {
		w = &batchWorkflowAcc{BatchWorkflow: BatchWorkflow{Key: key, Name: name, Executable: exe}, order: len(a.workflows)}
		a.workflows[key] = w
	}
	w.Jobs++
	if !rec.live && utilization.Finished(&rec.j) {
		w.FinishedJobs++
	}
}

// addHold files the job's hold reason: held now, or held on the way to
// finishing. Waiting for its inputs to upload is not a problem.
func (a *batchSummary) addHold(rec *batchRecord) {
	if rec.holdReason == "" {
		return
	}
	kind := "was_held"
	if rec.live {
		if rec.holdCode != nil && issues.HoldReasonIsRoutine(*rec.holdCode) {
			return
		}
		kind = "held"
	}
	a.holds.Add(issues.Record{Kind: kind, Message: rec.holdReason, Owner: rec.j.Owner,
		Cluster: rec.j.Cluster, Proc: rec.j.Proc, Code: val64(rec.holdCode), SubCode: rec.holdSub})
}

// addFinished counts a history record in the finished-job statistics.
func (a *batchSummary) addFinished(rec *batchRecord) {
	fin := &a.sum.Finished
	fin.Jobs++
	outcome := rec.outcome()
	if outcome == "" {
		return
	}
	a.addOutcome(rec, outcome)
	fin.WallHours += rec.j.Wall / 3600
	if c := rec.j.CommittedTime; c.OK() && rec.j.Wall > c.V() {
		fin.BadputHours += (rec.j.Wall - c.V()) / 3600
	}
	cpus := 1.0
	if rec.j.RequestCpus.OK() {
		cpus = rec.j.RequestCpus.V()
	}
	fin.CoreHours += rec.j.Wall * cpus / 3600
	if outcome == outcomeRemoved {
		return
	}
	if rt, ok := rec.runtime(); ok {
		a.runtimes = append(a.runtimes, rt)
	}
	if rec.j.MemoryUsage.OK() {
		a.peaks = append(a.peaks, rec.j.MemoryUsage.V())
		if rec.j.RequestMemory.OK() {
			a.requests = append(a.requests, rec.j.RequestMemory.V())
		}
	}
}

// addOutcome counts how the job ended: removed, a signal, or an exit
// code.
func (a *batchSummary) addOutcome(rec *batchRecord, outcome string) {
	fin := &a.sum.Finished
	o := BatchOutcome{Outcome: "exit"}
	var key [2]int64
	switch {
	case outcome == outcomeRemoved:
		fin.Removed++
		o.Outcome, key = outcomeRemoved, [2]int64{2, 0}
	case rec.j.ExitBySignal:
		fin.Failed++
		o.Outcome, key = "signal", [2]int64{1, -1}
		if rec.exitSignal != nil {
			o.Code, key[1] = rec.exitSignal, *rec.exitSignal
		}
	default:
		if outcome == outcomeFailed {
			fin.Failed++
		} else {
			fin.Succeeded++
		}
		key = [2]int64{0, math.MinInt64}
		if rec.j.ExitCode.OK() {
			c := int64(rec.j.ExitCode.V())
			o.Code, key[1] = &c, c
		}
	}
	if a.outcomes[key] == nil {
		a.outcomes[key] = &o
	}
	a.outcomes[key].Count++
}

// finish orders and rounds off what add gathered.
func (a *batchSummary) finish(ident batches.Identity) BatchResponse {
	sum := a.sum
	for c := range a.clusters {
		sum.Clusters = append(sum.Clusters, c)
	}
	slices.Sort(sum.Clusters)
	if ident.Kind == batches.KindNamed && len(sum.Clusters) > 0 {
		// The smallest cluster seen, queued or finished.
		sum.ID = min(sum.ID, sum.Clusters[0])
	}
	for _, o := range a.outcomes {
		sum.Finished.Outcomes = append(sum.Finished.Outcomes, *o)
	}
	slices.SortFunc(sum.Finished.Outcomes, func(x, y BatchOutcome) int {
		return cmp.Or(cmp.Compare(y.Count, x.Count), cmp.Compare(x.Outcome, y.Outcome), cmp.Compare(val64(x.Code), val64(y.Code)))
	})
	sum.Finished.Runtime = runtimeSummary(a.runtimes)
	sum.Finished.Memory = memorySummary(a.peaks, a.requests)
	wfs := make([]*batchWorkflowAcc, 0, len(a.workflows))
	for _, w := range a.workflows {
		wfs = append(wfs, w)
	}
	slices.SortFunc(wfs, func(x, y *batchWorkflowAcc) int {
		return cmp.Or(cmp.Compare(y.Jobs, x.Jobs), cmp.Compare(x.order, y.order))
	})
	for _, w := range wfs {
		sum.Workflows = append(sum.Workflows, w.BatchWorkflow)
	}
	sum.HoldReasons = holdReasons(a.holds)
	return sum
}

func runtimeSummary(runtimes []float64) *BatchRuntime {
	if len(runtimes) == 0 {
		return nil
	}
	slices.Sort(runtimes)
	total := 0.0
	for _, x := range runtimes {
		total += x
	}
	return &BatchRuntime{Count: len(runtimes), P10: quantile(runtimes, 0.10), P50: quantile(runtimes, 0.5),
		P90: quantile(runtimes, 0.9), Max: runtimes[len(runtimes)-1], Mean: total / float64(len(runtimes))}
}

func memorySummary(peaks, requests []float64) *BatchMemory {
	if len(peaks) == 0 {
		return nil
	}
	slices.Sort(peaks)
	slices.Sort(requests)
	m := &BatchMemory{Count: len(peaks), PeakP50: quantile(peaks, 0.5), PeakP95: quantile(peaks, 0.95), PeakMax: peaks[len(peaks)-1]}
	if len(requests) > 0 {
		m.RequestP50 = quantile(requests, 0.5)
	}
	return m
}

// holdReasons renders the holds as the Issues page groups them.
func holdReasons(c *issues.Clusterer) []BatchHoldReason {
	out := []BatchHoldReason{}
	for _, cl := range c.Clusters(issues.RenderOptions{Granularity: batchHoldGranularity, LabelCode: issues.HoldReasonLabel}) {
		h := BatchHoldReason{Kind: cl.Kind, Template: cl.Template, Count: cl.Count, Codes: cl.Codes, Examples: []BatchHoldExample{}}
		if h.Codes == nil {
			h.Codes = []issues.CodeCount{}
		}
		for _, e := range cl.Examples {
			if len(h.Examples) == batchExamples {
				break
			}
			h.Examples = append(h.Examples, BatchHoldExample{ID: fmt.Sprintf("%d.%d", e.Cluster, e.Proc), Message: e.Message})
		}
		out = append(out, h)
	}
	return out
}

func minPositive(cur *int64, v int64) *int64 {
	if v <= 0 || (cur != nil && *cur <= v) {
		return cur
	}
	return &v
}

func val64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// quantile of sorted xs, interpolated.
func quantile(xs []float64, q float64) float64 {
	pos := q * float64(len(xs)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	return xs[lo] + (xs[hi]-xs[lo])*(pos-float64(lo))
}

// batchPage is the jobs listing's query.
type batchPage struct {
	statuses map[string]bool
	sort     string
	desc     bool
	offset   int
	size     int
}

// batchSorts are the sort keys, and whether each runs descending by
// default.
var batchSorts = map[string]bool{
	"default": false, "id": false, "status": false, "exit": false,
	"submitted": true, "started": true, "finished": true, "runtime": true, "peak_memory": true,
}

func parseBatchPage(r *http.Request) (batchPage, error) {
	q := r.URL.Query()
	p := batchPage{sort: "default", size: batchPageDefault}
	if v := q.Get("status"); v != "" {
		p.statuses = map[string]bool{}
		for _, s := range strings.Split(v, ",") {
			s = strings.TrimSpace(s)
			switch batches.Status(s) {
			case batches.StatusRunning, batches.StatusIdle, batches.StatusUploading, batches.StatusTransferring,
				batches.StatusHeld, batches.StatusSuspended, batches.StatusCompleted, batches.StatusRemoved, batches.StatusUnknown:
			default:
				if s != "live" && s != "finished" {
					return p, fmt.Errorf("invalid status %q", s)
				}
			}
			p.statuses[s] = true
		}
	}
	if v := q.Get("sort"); v != "" {
		desc, ok := batchSorts[v]
		if !ok {
			return p, fmt.Errorf("invalid sort %q", v)
		}
		p.sort, p.desc = v, desc
	}
	switch q.Get("order") {
	case "":
	case "asc":
		p.desc = false
	case "desc":
		p.desc = true
	default:
		return p, fmt.Errorf("invalid order %q: asc or desc", q.Get("order"))
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return p, errors.New("invalid offset: must be a non-negative number")
		}
		p.offset = n
	}
	if v := q.Get("page_size"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return p, errors.New("invalid page_size: must be a positive number")
		}
		p.size = min(n, batchPageMax)
	}
	return p, nil
}

// apply is one page of the batch's rows.
func (p batchPage) apply(snap *batchSnapshot) BatchJobsResponse {
	rows := make([]BatchJobRow, 0, len(snap.rows))
	for _, row := range snap.rows {
		if p.statuses == nil || p.statuses[string(row.Status)] ||
			(p.statuses["live"] && row.Source == sourceQueue) || (p.statuses["finished"] && row.Source == sourceHistory) {
			rows = append(rows, row)
		}
	}
	slices.SortStableFunc(rows, p.compare)
	resp := BatchJobsResponse{
		ID: snap.summary.ID, Total: len(rows), Offset: p.offset, Jobs: []BatchJobRow{},
		LiveTruncated: snap.summary.LiveTruncated, HistoryTruncated: snap.summary.Finished.Truncated,
	}
	if p.offset < len(rows) {
		resp.Jobs = rows[p.offset:min(p.offset+p.size, len(rows))]
	}
	if next := p.offset + len(resp.Jobs); next < len(rows) {
		resp.NextOffset = &next
	}
	return resp
}

// statusRank orders statuses as the pages list them.
var statusRank = map[batches.Status]int{
	batches.StatusRunning: 0, batches.StatusIdle: 1, batches.StatusUploading: 2, batches.StatusTransferring: 3,
	batches.StatusHeld: 4, batches.StatusSuspended: 5, batches.StatusCompleted: 6, batches.StatusRemoved: 7,
	batches.StatusUnknown: 8,
}

// compare orders two rows by the page's key; a row without the key goes
// last either way, and ties fall to cluster and proc.
func (p batchPage) compare(a, b BatchJobRow) int {
	byID := cmp.Or(cmp.Compare(a.Cluster, b.Cluster), cmp.Compare(a.Proc, b.Proc))
	var c int
	switch p.sort {
	case "default":
		// The queue first, by id; then the finished, latest first.
		if a.Source != b.Source {
			if a.Source == sourceQueue {
				return -1
			}
			return 1
		}
		if a.Source == sourceQueue {
			return byID
		}
		return cmp.Or(lastIfMissing(a.Finished, b.Finished, true), byID)
	case "id":
		c = byID
	case "status":
		c = cmp.Compare(statusRank[a.Status], statusRank[b.Status])
	case "submitted":
		return cmp.Or(lastIfMissing(a.Submitted, b.Submitted, p.desc), byID)
	case "started":
		return cmp.Or(lastIfMissing(a.Started, b.Started, p.desc), byID)
	case "finished":
		return cmp.Or(lastIfMissing(a.Finished, b.Finished, p.desc), byID)
	case "runtime":
		return cmp.Or(lastIfMissing(a.RuntimeSeconds, b.RuntimeSeconds, p.desc), byID)
	case "peak_memory":
		return cmp.Or(lastIfMissing(a.PeakMemoryMiB, b.PeakMemoryMiB, p.desc), byID)
	case "exit":
		ea, eb := exitKey(a), exitKey(b)
		return cmp.Or(lastIfMissing(ea, eb, p.desc), byID)
	}
	if p.desc {
		c = -c
	}
	return cmp.Or(c, byID)
}

// exitKey sorts exit codes, then signals after them.
func exitKey(r BatchJobRow) *float64 {
	switch {
	case r.ExitCode != nil:
		v := float64(*r.ExitCode)
		return &v
	case r.ExitSignal != nil:
		v := 1e6 + float64(*r.ExitSignal)
		return &v
	}
	return nil
}

// lastIfMissing compares two optional values, ascending or descending,
// with a missing one after any present one.
func lastIfMissing[T cmp.Ordered](a, b *T, desc bool) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	}
	if desc {
		return cmp.Compare(*b, *a)
	}
	return cmp.Compare(*a, *b)
}
