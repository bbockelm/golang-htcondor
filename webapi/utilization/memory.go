package utilization

import (
	"math"
	"slices"
)

// Memory sizing.
//
// The question is which request_memory -- and, optionally, which
// retry_request_memory -- reserves the least memory over the same work.
// A request that covers the largest job wastes the difference on every
// other job for its whole run. A request that covers most jobs, with a
// retry at the larger size for the few that outgrow it, wastes less on
// the many and pays for the few twice: once for the attempt that was
// stopped, once for the rerun.
//
// Two properties of HTCondor's memory measurement shape the rules here.
// MemoryUsage is a high-water mark, so a finished job's value is its true
// peak (across every run), and the reserved-versus-peak comparison is a
// ceiling on how well the reservation was used rather than an average.
// And memory often spikes at the very END of a job -- output gets
// assembled, results get written -- so a running job's current figure
// understates where it will finish, and a job that is going to outgrow
// its request usually does so late. Hence: only finished jobs feed this
// (see memorySample), and a stopped attempt is costed at its full length.

// minMemoryJobs is the fewest finished jobs memory advice rests on. Below
// it a "95th percentile" is one or two jobs, and a retry that the
// history says one job in twenty needs may be needed by none or by five.
const minMemoryJobs = 20

// maxRetryFraction bounds how many jobs a recommended request may send
// to a retry. Past one in ten, the reruns are a large share of the
// workflow's wall clock and its latency, whatever the reservation sums
// say.
const maxRetryFraction = 0.10

// minRetrySaving is how much a retry must save over a single request
// that fits everything before it is worth recommending. A retry is a
// second thing to understand and a slower path for the jobs that take
// it; a few percent of memory does not pay for that.
const minRetrySaving = 0.15

// headroom is the margin added to an observed peak before it becomes a
// request: the next run of the same job will not use exactly the same
// memory.
const headroom = 1.1

// memoryJob is one finished job as the sizing sees it.
type memoryJob struct {
	// peak in MiB.
	peak float64
	// atLeast marks a peak that is only a lower bound: the job was
	// stopped for outgrowing its request, so its true peak is somewhere
	// ABOVE peak, which is that request. Any request at or below it would
	// have been outgrown again.
	atLeast bool
	// wallHours is the job's wall clock in hours.
	wallHours float64
	// request is the RequestMemory it started with, MiB.
	request float64
	// adaptive marks a formula request; inForce is its value for the
	// run that finished, which a job that outgrew the start was rerun at.
	adaptive bool
	inForce  float64
	// held marks a job with a memory hold recorded.
	held bool

	// ladder marks a job submitted with a memory retry ladder, and
	// climbed one that is known to have used it -- evicted for memory and
	// rerun at a larger request. startUnknown says its first rung is not
	// in its own record and planMemory must supply it.
	ladder       bool
	climbed      bool
	startUnknown bool
	// committedHours is CommittedTime, which is the wall clock of the run
	// that FINISHED. checkpointed is one reason it cannot be used to
	// split a rerun job's wall clock between the requests it held: a
	// checkpointing job commits work from the runs before the eviction
	// too (HTCondor only ever ADDS to CommittedTime; it is never reset
	// after submit). More than one rerun is the other: the uncommitted
	// time was then spent at two different requests.
	committedHours float64
	checkpointed   bool
	// reruns is how many times the job was stopped for outgrowing its
	// memory and started again at a LARGER request. A retry ladder does
	// that by climbing a rung and an adaptive formula by regrowing after
	// a hold; the record has the same shape either way, and the wall
	// clock sums every one of those runs.
	reruns int
}

// natural is the wall clock of ONE full run of the job.
//
// wallHours is every run summed, so for a job that was rerun it is
// already two runs' worth; costing a hypothetical retry against it would
// charge four runs for a job that takes two. The run that finished is the
// honest length, and CommittedTime is exactly that where it can be
// trusted; otherwise the runs are assumed equal, which is the assumption
// the stopping policy itself makes.
func (j memoryJob) natural() float64 {
	switch {
	case j.reruns == 0:
		return j.wallHours
	case j.splittable():
		return j.committedHours
	default:
		return j.wallHours / float64(j.reruns+1)
	}
}

// splittable reports whether the job's wall clock can be divided between
// the request it started at and the one it finished at.
func (j memoryJob) splittable() bool {
	return j.reruns == 1 && !j.checkpointed &&
		j.committedHours > 0 && j.committedHours < j.wallHours
}

// outgrows reports whether the job would exceed a request.
func (j memoryJob) outgrows(request float64) bool {
	return j.peak > request || (j.atLeast && j.peak >= request)
}

// memoryPlan is the result of sizing one workflow.
type memoryPlan struct {
	n int
	// single is the request that fits every job with headroom.
	single float64
	// recommended is the request to use; retry is the retry request to
	// pair with it, zero for none.
	recommended float64
	retry       float64
	// recommendedCost and currentCost are reserved MiB-hours over the
	// same jobs: what the recommendation would have reserved, and what
	// the jobs actually reserved.
	recommendedCost float64
	currentCost     float64
	// typical is the most common current request.
	typical float64
	// retryFraction is the share of jobs the recommendation would rerun.
	retryFraction float64
	// p95 and maxPeak describe the peaks, for the advice text.
	p95, maxPeak float64
	// adaptiveJobs had a formula request; outgrewStart of them peaked
	// above where it started. heldAbove and heldBelow are the jobs with a
	// memory hold recorded whose peak was above the start, and at or
	// under it.
	adaptiveJobs, outgrewStart int
	heldAbove, heldBelow       int
	// exceeded counts jobs stopped for outgrowing their request.
	exceeded int
	// ladderJobs were submitted with a memory retry ladder and climbed of
	// them used it. baseRung is the rung they all start at.
	ladderJobs, climbed int
	baseRung            float64
	// currentFloor is currentCost with every unsplittable climber costed
	// at its FIRST rung rather than its last: the lower bound of what the
	// workflow reserved, where currentCost is the upper. A saving is only
	// claimed against the floor, so a recommendation never undercuts a
	// number this could not pin down (see memoryAdvice).
	currentFloor float64
	curve        []MemoryCurvePoint
}

// expectedCost is the memory reserved, in MiB-hours, if every job asked
// for request and any job whose peak is above it reran at retry.
//
// The stopped attempt is charged its FULL wall clock (the failed fraction
// phi = 1), not half of it. Memory tends to spike at the end of a job, so
// a job that outgrows its request usually does so close to the end: by
// the time it is stopped it has run nearly as long as it ever would.
// Charging half -- the "on average it fails halfway" assumption -- would
// understate what a retry costs and recommend retries that do not pay.
func expectedCost(jobs []memoryJob, request, retry float64) (cost, retryFraction float64) {
	over := 0
	for _, j := range jobs {
		run := j.natural()
		cost += request * run
		if j.outgrows(request) {
			over++
			cost += retry * run
		}
	}
	if len(jobs) > 0 {
		retryFraction = float64(over) / float64(len(jobs))
	}
	return cost, retryFraction
}

// settleLadder fills in the first rung of a retry ladder, which no job
// that climbed it carries, and marks the jobs that climbed a single-rung
// ladder -- which sets no index, so until here they look like jobs that
// simply asked for more.
//
// The first rung is recoverable because the jobs that never climbed still
// hold it: every job of the workflow started there. The smallest request
// among them IS it. Where no such job exists -- a workflow where every
// job outgrew its first request -- there is nothing to recover it from,
// and the climbers keep the rung they ended on, which costs the sizing
// its precision rather than its correctness.
//
// It returns the rung, or zero when the workflow has no ladder.
func settleLadder(jobs []memoryJob) float64 {
	ladder := false
	base := math.Inf(1)
	for _, j := range jobs {
		if j.ladder {
			ladder = true
		}
		if !j.climbed && !j.startUnknown && j.request > 0 && j.request < base {
			base = j.request
		}
	}
	if !ladder || math.IsInf(base, 1) {
		for i := range jobs {
			if jobs[i].startUnknown {
				jobs[i].request = jobs[i].inForce
				jobs[i].startUnknown = false
			}
		}
		return 0
	}
	for i := range jobs {
		j := &jobs[i]
		if j.startUnknown {
			j.request, j.startUnknown = base, false
		}
		// The single-rung form leaves no index, so a job sitting above
		// the first rung in a ladder workflow is one that climbed it.
		if !j.climbed && j.ladder && j.inForce > base {
			j.climbed, j.request, j.reruns = true, base, 1
		}
		if j.climbed && j.peak <= j.request {
			// It was evicted for outgrowing this rung, so its true peak
			// is above it however the high-water mark came out.
			j.peak, j.atLeast = j.request, true
		}
	}
	return base
}

// maxRetryFraction is how many jobs this workflow's recommendation may
// send to a retry.
//
// The constant is a bound on PROPOSING a retry: past one in ten the
// reruns are a large share of a workflow's wall clock, and that is a lot
// to ask of someone who is not doing it yet. It is the wrong bound for a
// workflow that already reruns at a higher rate and has decided the
// trade is worth it -- there, applying it rules out the configuration in
// force and leaves only a flat request, which is how advice came to tell
// people to undo a working ladder, and to tell a workflow whose formula
// starts too high to raise it. So the floor is what they are already
// running at.
func (p *memoryPlan) maxRetryFraction() float64 {
	if p.n == 0 {
		return maxRetryFraction
	}
	// Both mechanisms count. A retry ladder reruns a job that climbs a
	// rung; an adaptive formula reruns one that outgrows its start. A
	// workflow where most jobs carry one of them is already running at
	// that rate, whichever it is.
	rerun := 0
	if p.ladderJobs*2 > p.n {
		rerun = p.climbed
	}
	if p.adaptiveJobs*2 > p.n {
		rerun = max(rerun, p.outgrewStart)
	}
	return max(maxRetryFraction, float64(rerun)/float64(p.n))
}

// planMemory sizes a workflow's memory from its finished jobs. It returns
// nil when there are too few to size from.
func planMemory(jobs []memoryJob) *memoryPlan {
	if len(jobs) < minMemoryJobs {
		return nil
	}
	peaks := make([]float64, len(jobs))
	requests := make([]float64, len(jobs))
	plan := &memoryPlan{n: len(jobs)}
	plan.baseRung = settleLadder(jobs)
	for i, j := range jobs {
		peaks[i] = j.peak
		requests[i] = j.request
		switch {
		case j.reruns == 0:
			plan.currentCost += j.request * j.wallHours
			plan.currentFloor += j.request * j.wallHours
		case j.splittable():
			// Exactly what the job reserved: the starting request for
			// the run that was stopped, the grown one for the run that
			// finished.
			cost := j.request*(j.wallHours-j.committedHours) + j.inForce*j.committedHours
			plan.currentCost += cost
			plan.currentFloor += cost
		default:
			// The split is not in the record. Charge the whole wall clock
			// at the grown request for the upper bound and at the
			// starting one for the lower, and let the advice refuse to
			// claim the difference.
			plan.currentCost += j.inForce * j.wallHours
			plan.currentFloor += j.request * j.wallHours
		}
		if j.ladder {
			plan.ladderJobs++
		}
		if j.climbed {
			plan.climbed++
		}
		// An adaptive request is a retry by another name: a job that
		// outgrows the start is held and rerun at the grown request.
		// That rerun is already in the switch above, which charges the
		// two runs the way it charges a ladder's -- the record does not
		// distinguish the mechanisms and neither does the cost.
		if j.adaptive {
			plan.adaptiveJobs++
			if j.outgrows(j.request) {
				plan.outgrewStart++
			}
		}
		switch {
		case j.held && j.outgrows(j.request):
			plan.heldAbove++
		case j.held:
			plan.heldBelow++
		}
		if j.atLeast {
			plan.exceeded++
		}
	}
	slices.Sort(peaks)
	plan.maxPeak = peaks[len(peaks)-1]
	plan.p95 = percentile(peaks, 95)
	plan.typical = summarizeRequest(requests).Typical
	plan.single = niceMiB(plan.maxPeak * headroom)

	// The candidates: every request on a dense grid from about the
	// smallest peaks up to the request that fits everything -- or up to
	// what the jobs ask for now, if that is more, so the curve also shows
	// what the over-request costs -- plus the current request itself.
	// Dense, because the curve is how a person sees the trade-off: a
	// handful of points plots as a straight line and hides the knee where
	// the retries stop paying for themselves.
	candidates := requestGrid(percentile(peaks, 5), max(plan.single, plan.typical))
	if !slices.Contains(candidates, plan.typical) && plan.typical > 0 {
		candidates = append(candidates, plan.typical)
		slices.Sort(candidates)
	}

	singleCost, _ := expectedCost(jobs, plan.single, 0)
	best := -1
	var bestCost, bestFrac float64
	for i, r := range candidates {
		// Below the request that fits everything, a request is always
		// paired with a retry at that request: even where no job in the
		// history outgrew it, the next one may, and the retry is what
		// keeps that from being a hold.
		retry := 0.0
		if r < plan.single {
			retry = plan.single
		}
		cost, frac := expectedCost(jobs, r, retry)
		point := MemoryCurvePoint{
			RequestMiB:       r,
			ReservedMiBHours: round(cost, 3),
			RetryFraction:    round(frac, 4),
			IsCurrent:        r == plan.typical,
		}
		if retry > 0 {
			point.RetryMiB = ptr(retry, 0)
		}
		plan.curve = append(plan.curve, point)
		if frac > plan.maxRetryFraction() {
			continue
		}
		// An equal reservation goes to the one with fewer reruns, then to
		// the smaller request (candidates ascend, so the first such wins).
		if best < 0 || cost < bestCost || (cost == bestCost && frac < bestFrac) {
			best, bestCost, bestFrac = i, cost, frac
		}
	}

	plan.recommended, plan.recommendedCost = plan.single, singleCost
	if best >= 0 {
		r := candidates[best]
		// A retry has to earn its keep; otherwise one request that fits
		// everything is simpler and nearly as cheap.
		if r >= plan.single || bestCost <= (1-minRetrySaving)*singleCost {
			plan.recommended, plan.recommendedCost = r, bestCost
		}
	}
	if plan.recommended < plan.single {
		plan.retry = plan.single
		_, plan.retryFraction = expectedCost(jobs, plan.recommended, plan.retry)
	}
	plan.mark(plan.recommended)
	return plan
}

// keepCurrent makes the jobs' current request the recommendation, for
// when the advice is to leave it alone. The curve then marks the request
// the advice names rather than a cheaper one the advice declined to push.
//
// It is only used when every job fit the current request, so no retry
// goes with it, and the curve's point for it drops the retry it would
// otherwise be paired with.
func (p *memoryPlan) keepCurrent() {
	p.recommended, p.retry = p.typical, 0
	p.recommendedCost, p.retryFraction = p.currentCost, 0
	for i := range p.curve {
		if p.curve[i].RequestMiB == p.typical {
			p.curve[i].RetryMiB = nil
		}
	}
	p.mark(p.typical)
}

// mark flags the curve point at request as the recommendation.
func (p *memoryPlan) mark(request float64) {
	for i := range p.curve {
		p.curve[i].IsRecommended = p.curve[i].RequestMiB == request
	}
}

// maxCurvePoints bounds the memory curve.
const maxCurvePoints = 40

// curveSamples is how many log-spaced requests a range too wide for
// every round value is sampled at.
const curveSamples = 32

// requestGrid is the requests memory is costed at: every round request
// (see niceMiB) from the one just above lo through hi, or, when that is
// more than maxCurvePoints, round requests at roughly log-spaced steps --
// even ratios, so the curve is as detailed at 1 GB as at 20. hi is always
// included.
func requestGrid(lo, hi float64) []float64 {
	hi = niceMiB(hi)
	lo = min(niceMiB(lo), hi)
	var grid []float64
	for r := lo; r <= hi; r = niceMiB(r + 1) {
		grid = append(grid, r)
		if len(grid) > maxCurvePoints {
			break
		}
	}
	if len(grid) <= maxCurvePoints {
		return grid
	}
	grid = grid[:0]
	for k := range curveSamples {
		r := hi
		if k < curveSamples-1 {
			r = min(niceMiB(lo*math.Pow(hi/lo, float64(k)/float64(curveSamples-1))), hi)
		}
		if len(grid) == 0 || grid[len(grid)-1] != r {
			grid = append(grid, r)
		}
	}
	return grid
}
