package utilization

import (
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

// candidatePercentiles are the observed peaks a request is tried at.
var candidatePercentiles = []float64{50, 60, 70, 75, 80, 85, 90, 95, 99}

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
	// request is the RequestMemory it ran with, MiB.
	request float64
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
		cost += request * j.wallHours
		if j.outgrows(request) {
			over++
			cost += retry * j.wallHours
		}
	}
	if len(jobs) > 0 {
		retryFraction = float64(over) / float64(len(jobs))
	}
	return cost, retryFraction
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
	for i, j := range jobs {
		peaks[i] = j.peak
		requests[i] = j.request
		plan.currentCost += j.request * j.wallHours
	}
	slices.Sort(peaks)
	plan.maxPeak = peaks[len(peaks)-1]
	plan.p95 = percentile(peaks, 95)
	plan.typical = summarizeRequest(requests).Typical
	plan.single = niceMiB(plan.maxPeak * headroom)

	// The candidates: a request just above each of several observed
	// peaks, the one that fits everything, and what the jobs ask for now
	// so the curve can show where they stand.
	seen := map[float64]bool{}
	var candidates []float64
	add := func(r float64) {
		if r > 0 && !seen[r] {
			seen[r] = true
			candidates = append(candidates, r)
		}
	}
	for _, p := range candidatePercentiles {
		add(niceMiB(percentile(peaks, p) * headroom))
	}
	add(plan.single)
	add(plan.typical)
	slices.Sort(candidates)

	singleCost, _ := expectedCost(jobs, plan.single, 0)
	best := -1
	var bestCost, bestFrac float64
	for i, r := range candidates {
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
		if frac > 0 {
			point.RetryMiB = ptr(retry, 0)
		}
		plan.curve = append(plan.curve, point)
		if frac > maxRetryFraction {
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
	for i := range plan.curve {
		plan.curve[i].IsRecommended = plan.curve[i].RequestMiB == plan.recommended
	}
	return plan
}
