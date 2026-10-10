package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/ratelimit"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/utilization"
)

// The Utilization page's endpoint: how well a person's finished jobs used
// what they reserved, and what to request next time.
//
// The analysis lives in webapi/utilization. This file decides whose jobs
// to read, reads them -- from the htcondordb mirror when it may, from the
// schedd's history otherwise -- and keeps the answer for a few minutes,
// because a page of advice about last week does not change between two
// clicks and the read behind it is the largest one this server makes.

// utilizationJobCap bounds one analysis. Most recent first, so a busy
// user's answer covers the latest of their work. An access point like
// ap40 enters ~90k records into history a day, so for a heavy user over
// thirty days this cap is real, and the response says when it was hit.
const utilizationJobCap = 50000

// utilizationScanLimit bounds the schedd's backwards walk of its history
// file when the mirror cannot answer. The walk normally stops at the
// window's start (HistoryQueryOptions.Since); this is the backstop for a
// file whose records are out of order.
const utilizationScanLimit = 3000000

// utilizationRefresh is how long an answer is reused.
const utilizationRefresh = 5 * time.Minute

// utilizationComputeTimeout bounds an analysis nobody may be waiting for
// any more. See sharedComputeContext.
const utilizationComputeTimeout = 3 * time.Minute

// utilizationDays are the windows offered. Fixed rather than free-form:
// each is a cache entry, and a slider would make every request its own.
var utilizationDays = map[int]bool{1: true, 7: true, 30: true}

// errMirrorRequiredUtilization is the failure when the operator requires
// the mirror and it could not answer.
var errMirrorRequiredUtilization = errors.New("this analysis must be served from the htcondordb mirror (HTTP_API_DBMIRROR_REQUIRED is set) and the mirror could not answer")

// handleUtilization handles GET /api/v1/utilization.
func (s *Handler) handleUtilization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	q := r.URL.Query()
	days := 7
	if v := q.Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || !utilizationDays[n] {
			s.writeError(w, http.StatusBadRequest, "Invalid days parameter: must be 1, 7 or 30")
			return
		}
		days = n
	}
	ownedByMe := true
	if v := q.Get("owned_by_me"); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid owned_by_me parameter: %v", err))
			return
		}
		ownedByMe = parsed
	}

	if s.multi != nil {
		s.handleMultiUtilization(w, r, days)
		return
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

	scope, showOwner, status, err := s.utilizationScope(ctx, r, ownedByMe)
	if err != nil {
		s.writeError(w, status, err.Error())
		return
	}

	// Whether the mirror may answer is part of the key: an answer read
	// out of the mirror must not be handed to a caller who may not read
	// it there. The scope constraint names whose jobs these are, so two
	// people never share an entry and two administrators asking for
	// everyone do.
	mirror := s.mirrorAllowed(ctx, r) == nil
	key := fmt.Sprintf("%s|%d|%t", scope, days, mirror)
	resp, err := s.utilizationResults().get(ctx, key, func(computeCtx context.Context) (*utilization.Response, error) {
		return s.computeUtilization(computeCtx, scope, days, showOwner, mirror)
	})
	if err != nil {
		s.writeUtilizationError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// utilizationScope is the constraint that confines the analysis to what
// this caller may see, and whether the result spans more than one owner.
//
// The same rule as every other listing: a caller that is not an
// administrator (seesAllJobs) is confined to its own jobs whatever
// owned_by_me says, and a project lead asking for everyone gets their own
// plus their projects'. The constraint is the whole of the enforcement --
// neither the schedd nor the mirror filters history by owner.
func (s *Handler) utilizationScope(ctx context.Context, r *http.Request, ownedByMe bool) (scope string, showOwner bool, status int, err error) {
	requestedEveryone := !ownedByMe
	ownedByMe = s.resolveOwnerScope(ctx, r, ownedByMe)
	var leadProjects []string
	if requestedEveryone && ownedByMe {
		leadProjects = s.projectLeadReadProjects(r)
	}
	if !ownedByMe {
		return "true", true, 0, nil
	}
	actor := htcondor.GetAuthenticatedUserFromContext(ctx)
	if actor == "" {
		return "", false, http.StatusUnauthorized,
			errors.New("authentication required: this analysis covers only your own jobs, and the caller's identity could not be established")
	}
	if len(leadProjects) > 0 {
		scope, err = scopeToOwnerOrProjects(ownerFromActor(actor), leadProjects, "true")
		return scope, true, http.StatusBadRequest, err
	}
	scope, err = scopeToOwner(ownerFromActor(actor), "true")
	return scope, false, http.StatusBadRequest, err
}

// computeUtilization reads the window's finished jobs and analyses them.
func (s *Handler) computeUtilization(ctx context.Context, scope string, days int, showOwner, mirror bool) (*utilization.Response, error) {
	now := time.Now().Unix()
	since := now - int64(days)*24*3600

	start := time.Now()
	jobs, truncated, source, err := s.utilizationJobs(ctx, scope, since, mirror)
	if err != nil {
		return nil, err
	}
	readTime := time.Since(start)
	resp := utilization.Analyze(jobs, utilization.Options{
		Since: since, Until: now, Days: days, Truncated: truncated, ShowOwner: showOwner,
		Machines: s.utilizationMachines(ctx),
	})
	s.logger.Info(logging.DestinationHTTP, "utilization analysed",
		"source", source, "jobs", len(jobs), "truncated", truncated, "days", days,
		"read_ms", readTime.Milliseconds(), "analyse_ms", (time.Since(start) - readTime).Milliseconds())
	return resp, nil
}

// scheddEnteredHistory is when a schedd history record entered history.
//
// The window is on the time a job LEFT the queue rather than on
// CompletionDate, because a removed job has a CompletionDate of 0 and
// removed jobs -- especially ones removed after being held for memory --
// are part of the answer. But a schedd does not necessarily write
// EnteredHistoryTime: HTCondor 25.8's history records have none, and a
// bare "EnteredHistoryTime >= since" matched nothing there. So the time
// falls back the way htcondordb derives the value it stamps on every
// record it mirrors (scheddsync's historyEventTime): EnteredCurrentStatus
// -- the transition to completed or removed -- then CompletionDate.
const scheddEnteredHistory = `ifThenElse(isUndefined(EnteredHistoryTime), ` +
	`ifThenElse(isUndefined(EnteredCurrentStatus) || EnteredCurrentStatus <= 0, CompletionDate, EnteredCurrentStatus), ` +
	`EnteredHistoryTime)`

// utilizationJobs reads up to utilizationJobCap of scope's jobs that
// entered history at or after since, most recent first, preferring the
// mirror.
//
// The two backends get different constraints for the same window. The
// mirror stamps EnteredHistoryTime on every record it archives (from the
// same fallback as scheddEnteredHistory), and its history archive is
// zone-mapped on that attribute -- but the pruner only reads top-level
// "attribute op literal" conjuncts, so the plain comparison skips whole
// segments outside the window while an ifThenElse would scan the entire
// archive. The schedd has no such index, and needs the fallback.
func (s *Handler) utilizationJobs(ctx context.Context, scope string, since int64, mirror bool) ([]utilization.Job, bool, string, error) {
	mirrorConstraint, scheddConstraint := utilizationWindow(scope, since)
	if mirror {
		jobs, truncated, err := s.utilizationFromMirror(ctx, mirrorConstraint, utilizationJobCap)
		if err == nil {
			return jobs, truncated, "htcondordb", nil
		}
		s.logger.Debug(logging.DestinationHTTP, "utilization: the mirror could not answer", "error", err)
	}
	if s.dbMirror.Required() {
		return nil, false, "", errMirrorRequiredUtilization
	}
	jobs, truncated, err := s.utilizationFromSchedd(ctx, scheddConstraint, since, utilizationJobCap)
	return jobs, truncated, "schedd", err
}

// utilizationWindow is the history constraint for scope's jobs since a
// time, for the mirror and for the schedd. See utilizationJobs.
func utilizationWindow(scope string, since int64) (mirror, schedd string) {
	return fmt.Sprintf("(%s) && EnteredHistoryTime >= %d", scope, since),
		fmt.Sprintf("(%s) && %s >= %d", scope, scheddEnteredHistory, since)
}

// utilizationFromMirror reads the jobs from the mirror's history archive,
// which returns matches newest first with the limit pushed down. One past
// the cap is asked for, so that hitting the cap and having exactly the
// cap are told apart.
func (s *Handler) utilizationFromMirror(ctx context.Context, constraint string, limit int) ([]utilization.Job, bool, error) {
	info, err := s.dbMirror.Discover(ctx)
	if err != nil {
		s.recordMirror("history", dbmirror.Decision{Reason: dbmirror.ReasonNoMirror, Note: err.Error()})
		return nil, false, err
	}
	// The same freshness rule as any other history read. A Since-free,
	// newest-first read is exactly what the archive serves.
	d := dbmirror.HistoryDecision(info, &htcondor.HistoryQueryOptions{Backwards: true})
	if !d.Use {
		s.recordMirror("history", d)
		return nil, false, errors.New(d.Note)
	}
	dbc, closer, _, err := s.dbMirror.Client(ctx)
	if err != nil {
		s.recordMirror("history", dbmirror.Decision{Reason: dbmirror.ReasonDialFailed, Note: err.Error()})
		return nil, false, err
	}
	defer closer()

	var jobs []utilization.Job
	truncated := false
	yield := func(row string) bool {
		if len(jobs) >= limit {
			truncated = true
			return false
		}
		ad, perr := classad.ParseOld(row)
		if perr != nil {
			return true
		}
		jobs = append(jobs, utilization.FromAd(ad, ""))
		return true
	}
	proj := utilization.Projection()
	// The reference-chasing projection, so that a request written as an
	// expression over some other attribute still evaluates. A mirror too
	// old for it gets the plain projection, where such a request drops
	// out of the numbers rather than being guessed at.
	err = dbc.QueryRawProjectRefsStream(ctx, "history", constraint, proj, limit+1, yield)
	if errors.Is(err, dbrpc.ErrProjectRefsUnsupported) {
		jobs, truncated = nil, false
		err = dbc.QueryRawProjectStream(ctx, "history", constraint, proj, limit+1, yield)
	}
	if err != nil {
		s.recordMirror("history", dbmirror.Decision{Reason: dbmirror.ReasonQueryFailed, Note: err.Error()})
		return nil, false, err
	}
	s.recordMirror("history", d)
	return jobs, truncated, nil
}

// utilizationFromSchedd reads the jobs from the schedd's history file,
// newest first. The backwards walk stops at the first record older than
// the window rather than reading the rest of the file to find nothing.
func (s *Handler) utilizationFromSchedd(ctx context.Context, constraint string, since int64, limit int) ([]utilization.Job, bool, error) {
	opts := &htcondor.HistoryQueryOptions{
		Source:        htcondor.HistorySourceJobHistory,
		Limit:         limit + 1,
		ScanLimit:     utilizationScanLimit,
		Projection:    utilization.Projection(),
		Backwards:     true,
		StreamResults: true,
		Since:         fmt.Sprintf("%s < %d", scheddEnteredHistory, since),
	}
	results, err := s.getSchedd().QueryHistoryStream(ctx, constraint, opts, &htcondor.StreamOptions{
		BufferSize:   s.streamBufferSize,
		WriteTimeout: s.streamWriteTimeout,
	})
	if err != nil {
		return nil, false, err
	}
	var jobs []utilization.Job
	truncated := false
	var streamErr error
	// Drained to the end even past the cap, so the reader is never left
	// blocked on a channel nobody reads; Limit keeps that tail to one.
	for res := range results {
		switch {
		case res.Err != nil:
			streamErr = res.Err
		case len(jobs) >= limit:
			truncated = true
		case res.Ad != nil:
			jobs = append(jobs, utilization.FromAd(res.Ad, ""))
		}
	}
	if streamErr != nil {
		return nil, false, streamErr
	}
	return jobs, truncated, nil
}

// handleMultiUtilization serves GET /api/v1/utilization in multi-AP mode:
// the caller's own finished jobs on every AP (or the one named by
// schedd), from the federation hub. Multi-AP reads are always the
// caller's own, so owned_by_me has nothing to widen.
func (s *Handler) handleMultiUtilization(w http.ResponseWriter, r *http.Request, days int) {
	ctx, user, ok := s.multiAPCaller(w, r)
	if !ok {
		return
	}
	schedd := r.URL.Query().Get("schedd")
	key := fmt.Sprintf("multi|%s|%d|%s", user, days, schedd)
	resp, err := s.utilizationResults().get(ctx, key, func(computeCtx context.Context) (*utilization.Response, error) {
		now := time.Now().Unix()
		since := now - int64(days)*24*3600
		jobs, truncated, err := s.multiUtilizationJobs(computeCtx, user, schedd, since, utilizationJobCap)
		if err != nil {
			return nil, err
		}
		return utilization.Analyze(jobs, utilization.Options{
			Since: since, Until: now, Days: days, Truncated: truncated,
		}), nil
	})
	if err != nil {
		var hubErr *multiap.Error
		if errors.As(err, &hubErr) {
			s.multiAPError(w, err)
			return
		}
		s.writeUtilizationError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// multiUtilizationJobs pages through the hub's history for one user.
func (s *Handler) multiUtilizationJobs(ctx context.Context, user, schedd string, since int64, limit int) ([]utilization.Job, bool, error) {
	var jobs []utilization.Job
	token := ""
	for {
		rows, res, err := s.multi.svc.ListHistory(ctx, multiap.ListRequest{
			User:       user,
			Constraint: fmt.Sprintf("EnteredHistoryTime >= %d", since),
			Projection: utilization.Projection(),
			Limit:      dbmirror.MaxProjectedLimit,
			PageToken:  token,
			Schedd:     schedd,
		})
		if err != nil {
			return nil, false, err
		}
		for _, row := range rows {
			if len(jobs) >= limit {
				return jobs, true, nil
			}
			jobs = append(jobs, utilization.FromAd(row.Ad, row.ID.Schedd))
		}
		if res == nil || !res.HasMore || res.NextPageToken == "" {
			return jobs, false, nil
		}
		if len(jobs) >= limit {
			return jobs, true, nil
		}
		token = res.NextPageToken
	}
}

// writeUtilizationError maps a failed analysis to a status.
func (s *Handler) writeUtilizationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		s.writeError(w, http.StatusGatewayTimeout, "The analysis did not finish in time; try again shortly")
	case errors.Is(err, errMirrorRequiredUtilization):
		s.writeError(w, http.StatusServiceUnavailable, err.Error())
	case ratelimit.IsRateLimitError(err):
		s.writeError(w, http.StatusTooManyRequests, err.Error())
	case isAuthenticationError(err):
		s.writeError(w, http.StatusUnauthorized, "Authentication failed")
	default:
		s.writeError(w, http.StatusBadGateway, fmt.Sprintf("Could not read job history: %v", err))
	}
}

// maxUtilizationCacheEntries bounds the cache: one entry per scope,
// window and access point.
const maxUtilizationCacheEntries = 256

// sharedCache single-flights and keeps one kind of result per key, the
// same shape as issueCache: concurrent identical requests cost one read,
// and the read runs on a context of its own so the request that
// triggered it can go away without taking the answer with it.
type sharedCache[T any] struct {
	mu    sync.Mutex
	byKey map[string]*sharedEntry[T]
	now   func() time.Time
	ttl   time.Duration
	// timeout bounds one computation.
	timeout time.Duration
}

type sharedEntry[T any] struct {
	// A channel rather than a sync.Mutex, so a waiter can give up when
	// its own caller goes away instead of blocking on a computation it no
	// longer needs.
	lock chan struct{}
	val  T
	has  bool
	at   time.Time
}

func newSharedCache[T any](ttl, timeout time.Duration) *sharedCache[T] {
	return &sharedCache[T]{
		byKey:   make(map[string]*sharedEntry[T]),
		now:     time.Now,
		ttl:     ttl,
		timeout: timeout,
	}
}

// utilizationCache holds analyses.
type utilizationCache = sharedCache[*utilization.Response]

func newUtilizationCache() *utilizationCache {
	return newSharedCache[*utilization.Response](utilizationRefresh, utilizationComputeTimeout)
}

// get returns the value for key, computing it if there is no fresh one.
//
// ctx bounds the WAIT, not the computation. The computation gets a
// context detached from ctx's cancellation (sharedComputeContext), so a
// first request that is cancelled part way -- a reload, a tab closed --
// still leaves a whole answer in the cache for the next one, rather than
// an error or, worse, half an answer. A failure is never cached.
func (c *sharedCache[T]) get(ctx context.Context, key string, compute func(context.Context) (T, error)) (T, error) {
	var zero T
	c.mu.Lock()
	entry := c.byKey[key]
	if entry == nil {
		c.makeRoom()
		entry = &sharedEntry[T]{lock: make(chan struct{}, 1)}
		c.byKey[key] = entry
	}
	c.mu.Unlock()

	select {
	case entry.lock <- struct{}{}:
		defer func() { <-entry.lock }()
	case <-ctx.Done():
		return zero, ctx.Err()
	}

	if entry.has && c.now().Sub(entry.at) < c.ttl {
		return entry.val, nil
	}
	computeCtx, cancel := sharedComputeContext(ctx, c.timeout)
	defer cancel()
	val, err := compute(computeCtx)
	if err != nil {
		// The last good answer beats an error page when the schedd or
		// the mirror hiccups; it is at most a refresh or two old.
		if entry.has {
			return entry.val, nil
		}
		return zero, err
	}
	entry.val, entry.has, entry.at = val, true, c.now()
	return val, nil
}

// makeRoom keeps the cache under maxUtilizationCacheEntries. Called with
// c.mu held, before adding an entry. Expired entries go first, then the
// oldest; one being computed or waited on is left alone.
func (c *sharedCache[T]) makeRoom() {
	if len(c.byKey) < maxUtilizationCacheEntries {
		return
	}
	now := c.now()
	busy := func(e *sharedEntry[T]) bool { return len(e.lock) > 0 }
	for k, e := range c.byKey {
		if !busy(e) && (!e.has || now.Sub(e.at) >= c.ttl) {
			delete(c.byKey, k)
		}
	}
	for len(c.byKey) >= maxUtilizationCacheEntries {
		var oldestKey string
		var oldest *sharedEntry[T]
		for k, e := range c.byKey {
			if !busy(e) && (oldest == nil || e.at.Before(oldest.at)) {
				oldestKey, oldest = k, e
			}
		}
		if oldest == nil {
			return
		}
		delete(c.byKey, oldestKey)
	}
}

func (s *Handler) utilizationResults() *utilizationCache {
	s.utilizationCacheOnce.Do(func() { s.utilizationCacheVal = newUtilizationCache() })
	return s.utilizationCacheVal
}

// poolShapeRefresh is how long the pool's machine shapes are reused.
// Machines come and go far more slowly than a page is reloaded.
const poolShapeRefresh = 10 * time.Minute

// poolShapeTimeout bounds one read of the pool.
const poolShapeTimeout = time.Minute

// poolShapeCache holds the pool's machine shapes.
type poolShapeCache = sharedCache[[]utilization.Machine]

func (s *Handler) poolShapes() *poolShapeCache {
	s.poolShapeCacheOnce.Do(func() {
		s.poolShapeCacheVal = newSharedCache[[]utilization.Machine](poolShapeRefresh, poolShapeTimeout)
	})
	return s.poolShapeCacheVal
}

// utilizationMachines is the pool's execute capacity for the throughput
// estimate, or nil when it cannot be had. Never an error: the estimate is
// an extra, and the rest of the analysis stands without it.
//
// One read serves everyone. The shapes of the pool's machines are not
// the caller's; a startd ad is READ-level on the collector, the same
// read /api/v1/collector/pool-summary makes for any signed-in user.
func (s *Handler) utilizationMachines(ctx context.Context) []utilization.Machine {
	if s.collector == nil {
		return nil
	}
	machines, err := s.poolShapes().get(ctx, "pool", s.readPoolShapes)
	if err != nil {
		s.logger.Info(logging.DestinationHTTP, "utilization: the pool's machines could not be read; no throughput estimate", "error", err)
		return nil
	}
	return machines
}

// readPoolShapes reads every slot that holds jobs from the collector.
// Dynamic slots are excluded in the query, as the pool summary does --
// they are carved from partitionable slots counted at full size -- and
// MachineFromAd drops anything else that adds no capacity.
func (s *Handler) readPoolShapes(ctx context.Context) ([]utilization.Machine, error) {
	results, err := s.collector.QueryAdsStream(ctx, "StartdAd", `SlotType =!= "Dynamic"`,
		utilization.MachineProjection(), 0, &htcondor.StreamOptions{})
	if err != nil {
		return nil, err
	}
	var machines []utilization.Machine
	var readErr error
	for res := range results {
		if res.Err != nil {
			readErr = res.Err
			continue
		}
		if m, ok := utilization.MachineFromAd(res.Ad); ok {
			machines = append(machines, m)
		}
	}
	if readErr != nil {
		return nil, readErr
	}
	if len(machines) == 0 {
		return nil, errors.New("the collector reported no execute slots")
	}
	return machines, nil
}
