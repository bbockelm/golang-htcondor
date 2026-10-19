package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

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

// utilizationDefaultLimit is how many jobs one analysis reads unless the
// caller asks for more. Most recent first, so a busy user's answer covers
// the latest of their work. An access point like ap40 enters ~90k
// records into history a day, so for a heavy user over thirty days this
// is a real bound, and the response says when it was hit.
const utilizationDefaultLimit = 50000

// utilizationDefaultMaxLimit is the most a caller may ask for when
// HTTP_API_UTILIZATION_MAX_JOBS does not say. A Job held for analysis is
// about 250 bytes (BenchmarkJobFootprint), so a million is a quarter of a
// gigabyte while the analysis runs; the cached result is the answer, not
// the jobs.
const utilizationDefaultMaxLimit = 1000000

// utilizationScanLimit is the schedd's backwards-walk budget for a limit:
// the walk normally stops at the window's start (HistoryQueryOptions.
// Since), and this is the backstop for a file whose records are out of
// order -- three records scanned for every one wanted, at least three
// million.
func utilizationScanLimit(limit int) int {
	return max(3000000, 3*limit)
}

// utilizationRefresh is how long an answer is reused.
const utilizationRefresh = 5 * time.Minute

// utilizationComputeTimeout bounds an analysis nobody may be waiting for
// any more (see sharedComputeContext): three minutes, and a minute more
// for each hundred thousand jobs the limit allows. Reading dominates --
// parsing an ad is 20-30 microseconds, and a schedd walks its history file
// far slower than the mirror answers -- while the analysis itself takes
// about a second per million (BenchmarkAnalyze).
func utilizationComputeTimeout(limit int) time.Duration {
	return 3*time.Minute + time.Duration(limit/100000)*time.Minute
}

// utilizationQuery is one request's parameters, as normalized for the
// cache key.
type utilizationQuery struct {
	days      int
	ownedByMe bool
	// filter is the caller's constraint, re-serialized by the parser, or
	// empty.
	filter string
	// owners narrows to these users, sorted; empty for no narrowing.
	owners []string
	limit  int
	// accessPoint is the schedd parameter: one AP, in multi-AP mode.
	accessPoint string
}

// parseUtilizationQuery reads and validates the parameters. An error is
// the caller's to fix and becomes a 400 with its text.
func (s *Handler) parseUtilizationQuery(r *http.Request) (utilizationQuery, error) {
	return s.parseUtilizationValues(r.URL.Query())
}

// parseUtilizationValues is parseUtilizationQuery over any set of values,
// for a POST body that carries the same parameters.
func (s *Handler) parseUtilizationValues(q url.Values) (utilizationQuery, error) {
	uq := utilizationQuery{days: 7, ownedByMe: true, limit: utilizationDefaultLimit, accessPoint: q.Get("schedd")}
	if v := q.Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || !utilizationDays[n] {
			return uq, errors.New("invalid days parameter: must be 1, 7 or 30")
		}
		uq.days = n
	}
	if v := strings.TrimSpace(q.Get("constraint")); v != "" {
		// Parsed here, before anything is read: an expression the
		// parser rejects is the caller's mistake, with the parser's
		// message to fix it by. The re-serialized form is what is
		// spliced into the query, so it cannot reach past the
		// parentheses around it (see andScope).
		safe, err := classadBalanced(v)
		if err != nil {
			return uq, fmt.Errorf("invalid constraint: %w", err)
		}
		uq.filter = safe
	}
	if v := q.Get("owners"); v != "" {
		seen := map[string]bool{}
		for _, o := range strings.Split(v, ",") {
			if o = strings.TrimSpace(o); o != "" && !seen[o] {
				seen[o] = true
				uq.owners = append(uq.owners, o)
			}
		}
		slices.Sort(uq.owners)
		// Naming users is asking about other people's jobs, so it
		// implies owned_by_me=false unless that is given. Whether the
		// caller may see them is still settled by the scope.
		if len(uq.owners) > 0 && q.Get("owned_by_me") == "" {
			uq.ownedByMe = false
		}
	}
	if v := q.Get("owned_by_me"); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return uq, fmt.Errorf("invalid owned_by_me parameter: %w", err)
		}
		uq.ownedByMe = parsed
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return uq, errors.New("invalid limit parameter: must be a positive number of jobs")
		}
		uq.limit = n
	}
	// Above the ceiling is clamped rather than refused: the page offers
	// "analyze more" and the response says what was applied.
	uq.limit = min(uq.limit, s.utilizationMaxLimit())
	return uq, nil
}

// utilizationMaxLimit is HTTP_API_UTILIZATION_MAX_JOBS, or its default.
func (s *Handler) utilizationMaxLimit() int {
	if s.utilizationMaxJobs > 0 {
		return s.utilizationMaxJobs
	}
	return utilizationDefaultMaxLimit
}

// narrow ANDs the caller's owner list and constraint onto a scope. It
// can only remove jobs from the scope, never add any: a non-administrator
// naming someone else's account gets the intersection of "mine" and
// "theirs", which is nothing. Owners are an OR of equalities rather than
// member(): the mirror's planner reads that form as one "Owner in {...}"
// probe it can answer from an index, and the schedd evaluates it as
// written.
func (uq utilizationQuery) narrow(scope string) string {
	out := "(" + scope + ")"
	if len(uq.owners) > 0 {
		parts := make([]string, len(uq.owners))
		for i, o := range uq.owners {
			parts[i] = "Owner == " + classadStringLit(o)
		}
		out += " && (" + strings.Join(parts, " || ") + ")"
	}
	if uq.filter != "" {
		out += " && (" + uq.filter + ")"
	}
	return out
}

// key is the cache key for the query in a scope.
func (uq utilizationQuery) key(scope string, mirror bool) string {
	return fmt.Sprintf("%s|%d|%t|%q|%q|%d|%s", scope, uq.days, mirror, uq.filter, strings.Join(uq.owners, ","), uq.limit, uq.accessPoint)
}

// utilizationDays are the windows offered. Fixed rather than free-form:
// each is a cache entry, and a slider would make every request its own.
var utilizationDays = map[int]bool{1: true, 7: true, 30: true}

// errMirrorRequiredUtilization is the failure when the operator requires
// the mirror and it could not answer.
var errMirrorRequiredUtilization = errors.New("this analysis must be served from the htcondordb mirror (HTTP_API_DBMIRROR_REQUIRED is set) and the mirror could not answer")

// handleUtilization handles GET /api/v1/utilization.
//
// The response carries a Server-Timing header with the phases of the
// computation that produced it (see utilizationTiming).
func (s *Handler) handleUtilization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	uq, err := s.parseUtilizationQuery(r)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	c, ok := s.utilizationCall(w, r, uq)
	if !ok {
		return
	}
	begin := time.Now()
	res, err := s.utilizationAnalysis(c, uq)
	if err != nil {
		s.writeUtilizationAnalysisError(w, err)
		return
	}
	w.Header().Set("Server-Timing", res.timing.serverTiming(begin))
	s.writeJSON(w, http.StatusOK, res.summary)
}

// utilizationCaller is who is asking, settled once per request: the
// scope their jobs are read in and the analysis cache key for it.
type utilizationCaller struct {
	ctx context.Context
	// scope is the owner-scope constraint (single-AP mode); user is the
	// caller's User (multi-AP mode).
	scope, user string
	mirror      bool
	showOwner   bool
	// key is the analysis cache key: the scope, the query and whether
	// the mirror may answer.
	key string
}

// utilizationCall authenticates and scopes a request, writing the error
// when it fails. Every utilization endpoint goes through it, so they
// cannot disagree on whose jobs a request sees.
func (s *Handler) utilizationCall(w http.ResponseWriter, r *http.Request, uq utilizationQuery) (*utilizationCaller, bool) {
	if s.multi != nil {
		// The hub confines every read to the caller's User; the owner
		// list and constraint narrow within that.
		ctx, user, ok := s.multiAPCaller(w, r)
		if !ok {
			return nil, false
		}
		// The hub the request is pinned to is in the key: an analysis of
		// one hub's rows is not served after reads move to another.
		return &utilizationCaller{ctx: ctx, user: user, key: uq.key("multi|"+s.multi.svc.HubOrigin(ctx)+"|"+user, false)}, true
	}
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return nil, false
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return nil, false
	}
	scope, showOwner, status, err := s.utilizationScope(ctx, r, uq.ownedByMe)
	if err != nil {
		s.writeError(w, status, err.Error())
		return nil, false
	}
	// Whether the mirror may answer is part of the key: an answer read
	// out of the mirror must not be handed to a caller who may not read
	// it there. The scope constraint names whose jobs these are, so two
	// people never share an entry and two administrators asking for
	// everyone do.
	mirror := s.mirrorAllowed(ctx, r) == nil
	return &utilizationCaller{ctx: ctx, scope: scope, mirror: mirror, showOwner: showOwner, key: uq.key(scope, mirror)}, true
}

// utilizationAnalysis is the caller's analysis, from the cache or
// computed.
func (s *Handler) utilizationAnalysis(c *utilizationCaller, uq utilizationQuery) (*utilizationResult, error) {
	return s.utilizationResults().getWithin(c.ctx, c.key, utilizationComputeTimeout(uq.limit),
		func(computeCtx context.Context) (*utilizationResult, error) {
			resp, timing, err := s.computeUtilization(computeCtx, c, uq)
			if err != nil {
				return nil, err
			}
			res, err := newUtilizationResult(resp, timing)
			if err != nil {
				return nil, err
			}
			s.logger.Debug(logging.DestinationHTTP, "utilization phases", res.timing.logArgs()...)
			s.observeUtilizationPhases(res.timing)
			return res, nil
		})
}

// writeUtilizationAnalysisError reports a failed analysis, with the
// federation hub's own status in multi-AP mode.
func (s *Handler) writeUtilizationAnalysisError(w http.ResponseWriter, err error) {
	var hubErr *multiap.Error
	if errors.As(err, &hubErr) {
		s.multiAPError(w, err)
		return
	}
	s.writeUtilizationError(w, err)
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
//
// The scope is narrowed by the caller's owners and constraint; the window
// is added per backend (see utilizationJobs). There is no pool to measure
// in multi-AP mode, so no throughput estimate either.
func (s *Handler) computeUtilization(ctx context.Context, c *utilizationCaller, uq utilizationQuery) (*utilization.Response, utilizationTiming, error) {
	now := time.Now().Unix()
	since := now - int64(uq.days)*24*3600

	var chunks [][]utilization.Job
	var truncated bool
	var err error
	var machines []utilization.Machine
	var t utilizationTiming
	if s.multi != nil {
		t.source = "hub"
		start := time.Now()
		var jobs []utilization.Job
		jobs, truncated, err = s.multiUtilizationJobs(ctx, c.user, uq.narrow("true"), uq.accessPoint, since, uq.limit)
		chunks, t.read, t.rows = [][]utilization.Job{jobs}, time.Since(start), len(jobs)
	} else {
		chunks, truncated, t, err = s.utilizationJobs(ctx, uq.narrow(c.scope), since, uq.limit, c.mirror)
		machines = s.utilizationMachines(ctx)
	}
	if err != nil {
		return nil, t, err
	}
	start := time.Now()
	resp := utilization.AnalyzeChunks(chunks, utilization.Options{
		Since: since, Until: now, Days: uq.days, Truncated: truncated, ShowOwner: c.showOwner,
		Limit: uq.limit, MaxLimit: s.utilizationMaxLimit(),
		Machines: machines,
	})
	t.analyze = time.Since(start)
	s.logger.Info(logging.DestinationHTTP, "utilization analysed",
		"source", t.source, "jobs", utilization.Count(chunks), "truncated", truncated, "days", uq.days,
		"read_ms", t.read.Milliseconds(), "decode_wait_ms", t.decodeWait.Milliseconds(),
		"analyse_ms", t.analyze.Milliseconds())
	return resp, t, nil
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

// utilizationJobs reads up to limit of scope's jobs that
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
func (s *Handler) utilizationJobs(ctx context.Context, scope string, since int64, limit int, mirror bool) ([][]utilization.Job, bool, utilizationTiming, error) {
	mirrorConstraint, scheddConstraint := utilizationWindow(scope, since)
	if mirror {
		chunks, truncated, t, err := s.utilizationFromMirror(ctx, mirrorConstraint, limit)
		if err == nil {
			t.source = "htcondordb"
			return chunks, truncated, t, nil
		}
		s.logger.Debug(logging.DestinationHTTP, "utilization: the mirror could not answer", "error", err)
	}
	if s.dbMirror.Required() {
		return nil, false, utilizationTiming{}, errMirrorRequiredUtilization
	}
	chunks, truncated, t, err := s.utilizationFromSchedd(ctx, scheddConstraint, since, limit)
	t.source = "schedd"
	return chunks, truncated, t, err
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
func (s *Handler) utilizationFromMirror(ctx context.Context, constraint string, limit int) ([][]utilization.Job, bool, utilizationTiming, error) {
	var t utilizationTiming
	info, err := s.dbMirror.Discover(ctx)
	if err != nil {
		s.recordMirror("history", dbmirror.Decision{Reason: dbmirror.ReasonNoMirror, Note: err.Error()})
		return nil, false, t, err
	}
	// The same freshness rule as any other history read. A Since-free,
	// newest-first read is exactly what the archive serves.
	d := dbmirror.HistoryDecision(info, &htcondor.HistoryQueryOptions{Backwards: true})
	if !d.Use {
		s.recordMirror("history", d)
		return nil, false, t, errors.New(d.Note)
	}
	dbc, closer, _, err := s.dbMirror.Client(ctx)
	if err != nil {
		s.recordMirror("history", dbmirror.Decision{Reason: dbmirror.ReasonDialFailed, Note: err.Error()})
		return nil, false, t, err
	}
	defer closer()

	// Rows are parsed and decoded on every core while the stream is
	// still arriving (see utilization.Decoder); this goroutine only
	// counts them and hands them over.
	read := func(stream func(yield func(string) bool) error) ([][]utilization.Job, bool, error) {
		dec := utilization.NewDecoder(0)
		rows, truncated := 0, false
		start := time.Now()
		err := stream(func(row string) bool {
			if rows >= limit {
				truncated = true
				return false
			}
			rows++
			dec.Row(row)
			return true
		})
		t.read, t.rows = time.Since(start), rows
		chunks, busy := dec.Finish()
		t.decode, t.decodeWait = busy, time.Since(start)-t.read
		return chunks, truncated, err
	}
	proj := utilization.Projection()
	// The reference-chasing projection, so that a request written as an
	// expression over some other attribute still evaluates. A mirror too
	// old for it gets the plain projection, where such a request drops
	// out of the numbers rather than being guessed at.
	chunks, truncated, err := read(func(yield func(string) bool) error {
		return dbc.QueryRawProjectRefsStream(ctx, "history", constraint, proj, limit+1, yield)
	})
	if errors.Is(err, dbrpc.ErrProjectRefsUnsupported) {
		chunks, truncated, err = read(func(yield func(string) bool) error {
			return dbc.QueryRawProjectStream(ctx, "history", constraint, proj, limit+1, yield)
		})
	}
	if err != nil {
		s.recordMirror("history", dbmirror.Decision{Reason: dbmirror.ReasonQueryFailed, Note: err.Error()})
		return nil, false, t, err
	}
	s.recordMirror("history", d)
	return chunks, truncated, t, nil
}

// utilizationFromSchedd reads the jobs from the schedd's history file,
// newest first. The backwards walk stops at the first record older than
// the window rather than reading the rest of the file to find nothing.
func (s *Handler) utilizationFromSchedd(ctx context.Context, constraint string, since int64, limit int) ([][]utilization.Job, bool, utilizationTiming, error) {
	var t utilizationTiming
	opts := &htcondor.HistoryQueryOptions{
		Source:        htcondor.HistorySourceJobHistory,
		Limit:         limit + 1,
		ScanLimit:     utilizationScanLimit(limit),
		Projection:    utilization.Projection(),
		Backwards:     true,
		StreamResults: true,
		Since:         fmt.Sprintf("%s < %d", scheddEnteredHistory, since),
	}
	start := time.Now()
	results, err := s.getSchedd().QueryHistoryStream(ctx, constraint, opts, &htcondor.StreamOptions{
		BufferSize:   s.streamBufferSize,
		WriteTimeout: s.streamWriteTimeout,
	})
	if err != nil {
		return nil, false, t, err
	}
	dec := utilization.NewDecoder(0)
	rows, truncated := 0, false
	var streamErr error
	// Drained to the end even past the cap, so the reader is never left
	// blocked on a channel nobody reads; Limit keeps that tail to one.
	for res := range results {
		switch {
		case res.Err != nil:
			streamErr = res.Err
		case rows >= limit:
			truncated = true
		case res.Ad != nil:
			rows++
			dec.Ad(res.Ad, "")
		}
	}
	t.read, t.rows = time.Since(start), rows
	chunks, busy := dec.Finish()
	t.decode, t.decodeWait = busy, time.Since(start)-t.read
	if streamErr != nil {
		return nil, false, t, streamErr
	}
	return chunks, truncated, t, nil
}

// multiUtilizationJobs pages through the hub's history for one user.
func (s *Handler) multiUtilizationJobs(ctx context.Context, user, selection, schedd string, since int64, limit int) ([]utilization.Job, bool, error) {
	var jobs []utilization.Job
	var reader utilization.JobReader
	token := ""
	for {
		rows, res, err := s.multi.svc.ListHistory(ctx, multiap.ListRequest{
			User:       user,
			Constraint: fmt.Sprintf("%s && EnteredHistoryTime >= %d", selection, since),
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
			jobs = append(jobs, reader.FromAd(row.Ad, row.ID.Schedd))
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
	// maxEntries bounds the cache; zero means maxUtilizationCacheEntries.
	maxEntries int
	// sizeOf and maxSize, when set, bound the cache by the total size of
	// its values as well (see store).
	sizeOf  func(T) int
	maxSize int
}

type sharedEntry[T any] struct {
	// A channel rather than a sync.Mutex, so a waiter can give up when
	// its own caller goes away instead of blocking on a computation it no
	// longer needs.
	lock chan struct{}
	val  T
	has  bool
	at   time.Time
	// size and used are read and written under the cache's mu, for
	// eviction by size: the value's sizeOf, and when it was last served.
	size int
	used time.Time
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
type utilizationCache = sharedCache[*utilizationResult]

// utilizationCacheBytes bounds the analysis cache by what its answers
// take: the compact list plus every workflow's compressed detail. A
// million-job analysis is about 5 MB of list and 45 MB of compressed
// detail (BenchmarkResponseSize), so this holds about ten of the largest
// and hundreds of ordinary ones. An answer larger than the whole bound is
// served without being kept.
const utilizationCacheBytes = 512 << 20

func newUtilizationCache() *utilizationCache {
	c := newSharedCache[*utilizationResult](utilizationRefresh, utilizationComputeTimeout(utilizationDefaultLimit))
	c.sizeOf = func(r *utilizationResult) int { return r.size }
	c.maxSize = utilizationCacheBytes
	return c
}

// get returns the value for key, computing it if there is no fresh one.
//
// ctx bounds the WAIT, not the computation. The computation gets a
// context detached from ctx's cancellation (sharedComputeContext), so a
// first request that is cancelled part way -- a reload, a tab closed --
// still leaves a whole answer in the cache for the next one, rather than
// an error or, worse, half an answer. A failure is never cached.
func (c *sharedCache[T]) get(ctx context.Context, key string, compute func(context.Context) (T, error)) (T, error) {
	return c.getWithin(ctx, key, c.timeout, compute)
}

// peek returns a fresh value for key if there is one, without computing
// or waiting: an entry being computed right now is reported absent.
func (c *sharedCache[T]) peek(key string) (T, bool) {
	var zero T
	c.mu.Lock()
	entry := c.byKey[key]
	c.mu.Unlock()
	if entry == nil {
		return zero, false
	}
	select {
	case entry.lock <- struct{}{}:
		defer func() { <-entry.lock }()
	default:
		return zero, false
	}
	if entry.has && c.now().Sub(entry.at) < c.ttl {
		return entry.val, true
	}
	return zero, false
}

// getWithin is get with a computation bound of its own, for work whose
// size the request decides.
func (c *sharedCache[T]) getWithin(ctx context.Context, key string, timeout time.Duration, compute func(context.Context) (T, error)) (T, error) {
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
		c.mu.Lock()
		entry.used = c.now()
		c.mu.Unlock()
		return entry.val, nil
	}
	computeCtx, cancel := sharedComputeContext(ctx, timeout)
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
	c.store(key, entry, val)
	return val, nil
}

// store keeps a computed value. Called with entry's lock held.
//
// With a size bound, a value larger than the whole bound is not kept at
// all -- the entry is dropped, so the next request computes it again --
// and keeping one evicts the least recently served others until the
// total fits. Entries being computed or waited on are left alone, so the
// total can briefly exceed the bound by their size.
func (c *sharedCache[T]) store(key string, entry *sharedEntry[T], val T) {
	now := c.now()
	if c.sizeOf == nil {
		entry.val, entry.has, entry.at = val, true, now
		return
	}
	size := c.sizeOf(val)
	c.mu.Lock()
	defer c.mu.Unlock()
	if size > c.maxSize {
		var zero T
		entry.val, entry.has, entry.size = zero, false, 0
		if c.byKey[key] == entry {
			delete(c.byKey, key)
		}
		return
	}
	entry.val, entry.has, entry.at, entry.size, entry.used = val, true, now, size, now
	total := 0
	for _, e := range c.byKey {
		total += e.size
	}
	for total > c.maxSize {
		var lruKey string
		var lru *sharedEntry[T]
		for k, e := range c.byKey {
			if e == entry || e.size == 0 || len(e.lock) > 0 {
				continue
			}
			if lru == nil || e.used.Before(lru.used) {
				lruKey, lru = k, e
			}
		}
		if lru == nil {
			return
		}
		total -= lru.size
		delete(c.byKey, lruKey)
	}
}

// makeRoom keeps the cache under maxUtilizationCacheEntries. Called with
// c.mu held, before adding an entry. Expired entries go first, then the
// oldest; one being computed or waited on is left alone.
func (c *sharedCache[T]) makeRoom() {
	limit := c.maxEntries
	if limit <= 0 {
		limit = maxUtilizationCacheEntries
	}
	if len(c.byKey) < limit {
		return
	}
	now := c.now()
	busy := func(e *sharedEntry[T]) bool { return len(e.lock) > 0 }
	for k, e := range c.byKey {
		if !busy(e) && (!e.has || now.Sub(e.at) >= c.ttl) {
			delete(c.byKey, k)
		}
	}
	for len(c.byKey) >= limit {
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
