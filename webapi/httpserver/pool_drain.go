package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/drainest"
	"github.com/bbockelm/golang-htcondor/webapi/runtimeest"
)

// GET /api/v1/pool/drain-estimates: for every execute node, when it
// would be empty if drained now. What the answer means lives in
// webapi/drainest; this file is where the slots and jobs come from.
//
// The answer covers every user's jobs, and any signed-in caller may
// read it, so neither read is the caller's: both run as this daemon, in
// one computation shared by everyone and cached for a minute. The
// request path never reaches the collector or the schedd itself -- it
// waits for the shared answer -- so there is no request whose own
// missing credential could fall back to the daemon's.
//
// Two reads per computation: the claimed slots from the collector (one
// per running job in the pool), and this access point's running jobs,
// for the runtime estimates. The jobs are read in one query rather than
// looked up by id: a schedd walks its whole queue for every query,
// whatever the constraint, so one "JobStatus == 2" walk is cheaper than
// any number of narrower ones.

const (
	// poolDrainTTL is how long one answer is served. The page refreshes
	// every 30 seconds; jobs' expected ends move slower than that.
	poolDrainTTL = time.Minute
	// poolDrainTimeout bounds one computation.
	poolDrainTimeout = 2 * time.Minute
	// poolDrainJobLimit caps the running-job read. Past it the jobs
	// left out simply have no estimate.
	poolDrainJobLimit = 200_000
)

// drainSlotSource reads slot ads from the collector.
type drainSlotSource interface {
	Slots(ctx context.Context, yield func(*classad.ClassAd)) error
}

// drainJobSource reads this access point's running jobs.
type drainJobSource interface {
	// RunningJobs yields up to limit running jobs with attrs projected,
	// and says whether there were more.
	RunningJobs(ctx context.Context, attrs []string, limit int, yield func(*classad.ClassAd)) (truncated bool, err error)
}

type collectorDrainSlots struct{ c *htcondor.Collector }

func (s collectorDrainSlots) Slots(ctx context.Context, yield func(*classad.ClassAd)) error {
	results, err := s.c.QueryAdsStream(ctx, "StartdAd", drainest.SlotConstraint, drainest.SlotProjection, 0, &htcondor.StreamOptions{})
	if err != nil {
		return err
	}
	var readErr error
	for res := range results {
		if res.Err != nil {
			readErr = res.Err
			continue
		}
		yield(res.Ad)
	}
	return readErr
}

// handlerDrainJobs reads the running jobs from the htcondordb mirror
// when there is one, and from the schedd otherwise -- the same order
// the job-watch evaluator's queue reads use.
type handlerDrainJobs struct{ h *Handler }

func (s handlerDrainJobs) RunningJobs(ctx context.Context, attrs []string, limit int, yield func(*classad.ClassAd)) (bool, error) {
	const constraint = "JobStatus == 2"
	seen := 0
	count := func(ad *classad.ClassAd) {
		seen++
		if seen <= limit {
			yield(ad)
		}
	}
	if s.h.dbMirror.Enabled() {
		err := watchSource{h: s.h}.streamMirror(ctx, "jobs", constraint, attrs, limit+1, count)
		if err == nil {
			return seen > limit, nil
		}
		s.h.logger.Debug(logging.DestinationHTTP,
			"pool drain estimates: mirror unavailable for the queue, using the schedd", "error", err)
	}
	// Restarting is harmless: the caller keys jobs by GlobalJobId.
	seen = 0
	ads, _, err := s.h.getSchedd().QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Limit:      limit + 1,
		Projection: attrs,
		FetchOpts:  htcondor.FetchNormal,
	})
	if err != nil {
		return false, fmt.Errorf("reading running jobs from the schedd: %w", err)
	}
	for _, ad := range ads {
		count(ad)
	}
	return seen > limit, nil
}

// poolDrain computes and caches the answer.
type poolDrain struct {
	slots drainSlotSource
	// jobs and est are nil when this access point does not estimate
	// runtimes; the answer then carries the retirement bounds alone.
	jobs drainJobSource
	est  *runtimeest.Estimator
	// accessPoint is the configured schedd name. When empty it is
	// learned from the running jobs' GlobalJobIds.
	accessPoint string
	// base is the context the computation runs under: the handler's
	// lifetime, never a request's.
	base   func() context.Context
	now    func() time.Time
	logger *logging.Logger
	cache  *sharedCache[*drainest.Response]

	mu        sync.Mutex
	lastErr   error
	lastErrAt time.Time
}

func newPoolDrain(slots drainSlotSource, jobs drainJobSource, est *runtimeest.Estimator, accessPoint string, logger *logging.Logger) *poolDrain {
	if est == nil {
		jobs = nil
	}
	return &poolDrain{
		slots:       slots,
		jobs:        jobs,
		est:         est,
		accessPoint: accessPoint,
		base:        context.Background,
		now:         time.Now,
		logger:      logger,
		cache:       newSharedCache[*drainest.Response](poolDrainTTL, poolDrainTimeout),
	}
}

// get returns the cached answer, computing it when it is older than the
// TTL. ctx bounds only the wait.
func (p *poolDrain) get(ctx context.Context) (*drainest.Response, error) {
	return p.cache.get(ctx, "pool", func(computeCtx context.Context) (*drainest.Response, error) {
		// Only the deadline is taken from computeCtx: its values are
		// whichever request happened to trigger the refresh.
		ctx := htcondor.WithDaemonCredential(p.base(), "pool drain estimates (shared by every caller)")
		if dl, ok := computeCtx.Deadline(); ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, dl)
			defer cancel()
		}
		resp, err := p.compute(ctx)
		p.mu.Lock()
		defer p.mu.Unlock()
		if err != nil {
			p.lastErr, p.lastErrAt = err, p.now()
			if p.logger != nil {
				p.logger.Warn(logging.DestinationHTTP, "Pool drain estimates could not be computed", "error", err)
			}
			return nil, err
		}
		p.lastErr = nil
		return resp, nil
	})
}

// lastFailure is the most recent computation's error, if it failed.
func (p *poolDrain) lastFailure() (time.Time, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastErrAt, p.lastErr
}

func (p *poolDrain) compute(ctx context.Context) (*drainest.Response, error) {
	now := p.now()
	var slots []drainest.Slot
	if err := p.slots.Slots(ctx, func(ad *classad.ClassAd) {
		slots = append(slots, drainest.SlotFromAd(ad))
	}); err != nil {
		return nil, fmt.Errorf("reading slots from the collector: %w", err)
	}

	in := drainest.Input{Now: now, Slots: slots, AccessPoint: p.accessPoint}
	var jobErr error
	if p.jobs != nil {
		jobs := make(map[string]*classad.ClassAd)
		learned := ""
		attrs := slices.Concat(runtimeest.QueryAttrs, []string{"GlobalJobId"})
		truncated, err := p.jobs.RunningJobs(ctx, attrs, poolDrainJobLimit, func(ad *classad.ClassAd) {
			gid, _ := ad.EvaluateAttrString("GlobalJobId")
			if gid == "" {
				return
			}
			jobs[gid] = ad
			if learned == "" {
				learned, _, _, _ = drainest.ParseGlobalJobID(gid)
			}
		})
		switch {
		case err != nil:
			jobErr = err
		default:
			if truncated && p.logger != nil {
				p.logger.Warn(logging.DestinationHTTP,
					"Pool drain estimates: the running-job read hit its cap; jobs past it have no estimate",
					"cap", poolDrainJobLimit)
			}
			if in.AccessPoint == "" {
				in.AccessPoint = learned
			}
			in.Estimate = func(gid string) (runtimeest.Result, bool) {
				ad, ok := jobs[gid]
				if !ok {
					return runtimeest.Result{}, false
				}
				return p.est.Estimate(runtimeest.QueryFromAd(ad, now)), true
			}
		}
	}
	resp := drainest.Compute(in)
	if jobErr != nil {
		// The retirement bounds stand without the estimates, so answer
		// with those rather than fail the whole page.
		resp.Error = "Running jobs could not be read, so there are no runtime estimates: " + jobErr.Error()
		if p.logger != nil {
			p.logger.Warn(logging.DestinationHTTP, "Pool drain estimates: running jobs could not be read", "error", jobErr)
		}
	}
	return resp, nil
}

// poolDrainService returns the shared computation, or nil when there is
// no pool to describe.
func (h *Handler) poolDrainService() *poolDrain {
	h.poolDrainOnce.Do(func() {
		if h.poolDrainVal != nil || h.collector == nil || h.multi != nil {
			return
		}
		var jobs drainJobSource = handlerDrainJobs{h: h}
		name := h.scheddName
		if s := h.getSchedd(); name == "" && s != nil {
			name = s.Name()
		}
		h.poolDrainVal = newPoolDrain(collectorDrainSlots{c: h.collector}, jobs, h.runtimeEst, name, h.logger)
		h.poolDrainVal.base = func() context.Context {
			if h.ctx != nil {
				return h.ctx
			}
			return context.Background()
		}
	})
	return h.poolDrainVal
}

// handlePoolDrainEstimates serves GET /api/v1/pool/drain-estimates.
//
// Without parameters it answers for every node, without per-job detail;
// ?machine=NAME answers for one node, with a row per running job.
func (h *Handler) handlePoolDrainEstimates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if _, needsRedirect, err := h.requireAuthentication(r); err != nil {
		if needsRedirect {
			h.redirectToLogin(w, r)
			return
		}
		h.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	if h.multi != nil {
		h.writeError(w, http.StatusNotImplemented, "Drain estimates are not available in multi-AP mode")
		return
	}
	pd := h.poolDrainService()
	if pd == nil {
		h.writeError(w, http.StatusNotImplemented, "Collector not configured")
		return
	}

	// The request's context bounds only how long this caller waits.
	resp, err := pd.get(r.Context())
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			h.writeError(w, http.StatusGatewayTimeout, "Drain estimates did not finish in time; try again shortly")
			return
		}
		h.writeError(w, http.StatusBadGateway, fmt.Sprintf("Drain estimates could not be computed: %v", err))
		return
	}

	var out *drainest.Response
	if m := strings.TrimSpace(r.URL.Query().Get("machine")); m != "" {
		out = resp.ForMachine(m)
	} else {
		out = resp.WithoutSlots()
	}
	now := pd.now()
	out.AgeSeconds = max(0, now.Sub(out.GeneratedAt).Truncate(time.Second).Seconds())
	if at, lastErr := pd.lastFailure(); lastErr != nil && at.After(out.GeneratedAt) {
		out.Stale = true
		out.Error = "The latest refresh failed; this answer is from the last one that worked: " + lastErr.Error()
	}
	h.writeJSON(w, http.StatusOK, out)
}
