package reservation

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Stamping puts RuntimeP90Bucket on the idle queue, which is what lets
// a held machine admit anything at all. Without it the sieve refuses
// every job, and a drain costs the whole machine rather than nothing.
//
// It writes the CLUSTER ad, not each proc. A proc inherits an attribute
// from its cluster ad, including for matchmaking: verified against a
// real pool in TestClusterAdStampGovernsEveryProc, where one
// SetAttribute on a cluster let all three of its procs onto a held
// machine. On the access point this was measured against, the idle
// queue holds a median of 43,567 jobs in 371 distinct clusters, so that
// is about 120 times fewer writes -- the difference between a pass that
// is free and one nobody would run.
//
// The value written for a cluster is the LARGEST of its idle procs'
// estimates. A cluster whose procs really do differ is then described
// by its longest, which costs some admissions and never admits a job
// that will not fit. The other way round would put jobs on machines
// that need the core back.

// JobView is one idle job, reduced to what stamping decides from.
type JobView struct {
	Cluster int
	// Owner is the identity the write is made as, taken from the job
	// ad. A cluster whose owner is unknown is not stamped: the write
	// is made as the job's owner editing their own job, so there is
	// nobody to make it as.
	Owner string
	// Want is the estimate for this job, already bucketed; zero when
	// the estimator could not say.
	Want int64
}

// ClusterView is a cluster's current stamp, as the schedd reports it.
type ClusterView struct {
	Cluster int
	// Have is the bucket currently on the cluster ad; zero for none.
	Have int64
}

// Stamp is one cluster ad to write.
type Stamp struct {
	Cluster int
	// Owner is who to make the write as.
	Owner  string
	Bucket int64
	// Jobs is how many idle procs this write covers, for logging: it is
	// the whole point of writing the cluster rather than the procs.
	Jobs int
	// New is true when the cluster carried no stamp at all. Those come
	// first: the sieve refuses an unstamped job outright, where a stale
	// stamp still admits one.
	New bool
}

// PlanStamps decides which cluster ads to write.
//
// Unstamped clusters first, then the ones covering the most idle jobs,
// so a budget spent early does the most good. Ties break on cluster id
// so two passes over the same queue plan the same thing.
//
// budget caps the writes. A queue far larger than the budget is stamped
// over several passes rather than in one: the sieve treats a missing
// stamp as a refusal and a stale one as valid, so falling behind costs
// admissions and never correctness.
func PlanStamps(jobs []JobView, clusters []ClusterView, budget int) []Stamp {
	have := make(map[int]int64, len(clusters))
	for _, c := range clusters {
		have[c.Cluster] = c.Have
	}

	want := map[int]int64{}
	count := map[int]int{}
	owner := map[int]string{}
	var order []int
	for _, j := range jobs {
		if j.Owner == "" {
			// Nobody to write as. Counted as unstampable by Pass
			// rather than written as whoever this process happens to
			// be: a stamp is an edit to somebody's job.
			continue
		}
		if j.Want <= 0 {
			// No estimate. Writing zero would be worse than writing
			// nothing: the sieve reads a non-positive bucket as a
			// refusal either way, and a cluster stamped zero looks
			// stamped to the next pass.
			continue
		}
		if _, seen := want[j.Cluster]; !seen {
			order = append(order, j.Cluster)
			owner[j.Cluster] = j.Owner
		}
		if j.Want > want[j.Cluster] {
			want[j.Cluster] = j.Want
		}
		count[j.Cluster]++
	}

	var out []Stamp
	for _, cluster := range order {
		w := want[cluster]
		h, stamped := have[cluster]
		if stamped && h == w {
			continue
		}
		out = append(out, Stamp{
			Cluster: cluster,
			Owner:   owner[cluster],
			Bucket:  w,
			Jobs:    count[cluster],
			New:     !stamped || h <= 0,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].New != out[j].New {
			return out[i].New
		}
		if out[i].Jobs != out[j].Jobs {
			return out[i].Jobs > out[j].Jobs
		}
		return out[i].Cluster < out[j].Cluster
	})
	if budget > 0 && len(out) > budget {
		out = out[:budget]
	}
	return out
}

// IdleQueue reads what has to be stamped.
type IdleQueue interface {
	// IdleJobs is every idle job's estimate, already bucketed.
	IdleJobs(ctx context.Context) ([]JobView, error)
	// Clusters is the stamp currently on each of those jobs' cluster
	// ads. Read separately from the procs because a proc reports the
	// value it inherits, which would make an unstamped cluster whose
	// submitter set their own look already written and never converge.
	Clusters(ctx context.Context) ([]ClusterView, error)
}

// StampWriter writes cluster-ad attributes.
type StampWriter interface {
	// Write sets RuntimeP90Bucket on each cluster ad, as that cluster's
	// owner, in one transaction per owner where the implementation can.
	//
	// It returns how many of the stamps were written. Writing as each
	// owner separately means a pass can partly succeed: one user whose
	// jobs the schedd will not let this process edit costs that user
	// their stamps and nobody else theirs, and the count says so.
	Write(ctx context.Context, stamps []Stamp) (int, error)
}

// ByOwner groups a plan into the writes each owner makes to their own
// clusters, with the owners in a fixed order so two passes over the
// same plan do the same thing in the same sequence.
func ByOwner(stamps []Stamp) ([]string, map[string][]Stamp) {
	out := map[string][]Stamp{}
	var owners []string
	for _, s := range stamps {
		if _, seen := out[s.Owner]; !seen {
			owners = append(owners, s.Owner)
		}
		out[s.Owner] = append(out[s.Owner], s)
	}
	sort.Strings(owners)
	return owners, out
}

// Stamper keeps the idle queue stamped.
type Stamper struct {
	Queue  IdleQueue
	Writer StampWriter
	// Budget is the most cluster ads one pass writes. Zero means
	// DefaultStampBudget.
	Budget int
	// Horizon is the furthest ahead any reservation looks -- the
	// longest lead among them. Estimates are capped one grain beyond
	// it, because the sieve cannot tell two values apart once both are
	// past the bell, and every distinct value costs autocluster
	// splitting across the whole pool. Zero means no cap.
	Horizon func() time.Duration
	// Engaged gates the pass. Nil means every pass runs. A pass that is
	// gated off reads nothing and writes nothing: stamping exists to
	// make held machines usable, so with nothing held and nothing about
	// to be, it is a write to every user's cluster ad for no reason.
	Engaged Gate

	last StampResult
}

// DefaultStampBudget is how many cluster ads a pass writes.
//
// Generous, because a write is per cluster: the access point this was
// measured on would have stamped its whole idle queue in one pass at
// the median (371 clusters) and in two at the worst moment observed
// (2,676). It is a limit on a pathological queue, not a pacing
// mechanism.
const DefaultStampBudget = 2000

// StampResult is what one pass did.
type StampResult struct {
	At time.Time
	// Idle is how many idle jobs were considered, Clusters how many
	// distinct clusters they belong to. The ratio is why this writes
	// cluster ads.
	Idle     int
	Clusters int
	// Written is how many cluster ads were written, Covered how many
	// idle jobs those writes stamped.
	Written int
	Covered int
	// Deferred is how many clusters wanted a write and did not get one
	// this pass. Persistently non-zero means the budget is too small
	// for the queue.
	Deferred int
	// Unestimated is how many idle jobs the estimator could not answer
	// for. They stay refused by the sieve, so this is the share of the
	// queue a reservation cannot use.
	Unestimated int
	// Unowned is how many idle jobs carried no owner to write as. A
	// stamp is an edit to somebody's job, made as them, so these are
	// left alone.
	Unowned int
	// Quiescent is true when the pass did nothing because nothing is
	// reserved. The queue was not read and nothing was written.
	Quiescent bool
	Err       error
}

func (s *Stamper) budget() int {
	if s.Budget > 0 {
		return s.Budget
	}
	return DefaultStampBudget
}

// Pass stamps what it can and reports what it did.
func (s *Stamper) Pass(ctx context.Context) (StampResult, error) {
	res := StampResult{At: time.Now()}

	if s.Engaged != nil {
		on, err := s.Engaged(ctx)
		if err != nil {
			res.Err = fmt.Errorf("deciding whether anything is reserved: %w", err)
			s.record(res)
			return res, res.Err
		}
		if !on {
			res.Quiescent = true
			s.record(res)
			return res, nil
		}
	}

	jobs, err := s.Queue.IdleJobs(ctx)
	if err != nil {
		res.Err = fmt.Errorf("reading the idle queue: %w", err)
		s.record(res)
		return res, res.Err
	}
	clusters, err := s.Queue.Clusters(ctx)
	if err != nil {
		res.Err = fmt.Errorf("reading cluster stamps: %w", err)
		s.record(res)
		return res, res.Err
	}

	res.Idle = len(jobs)
	seen := map[int]bool{}
	for _, j := range jobs {
		seen[j.Cluster] = true
		if j.Owner == "" {
			res.Unowned++
		}
		if j.Want <= 0 {
			res.Unestimated++
		}
	}
	res.Clusters = len(seen)

	budget := s.budget()
	all := PlanStamps(jobs, clusters, 0)
	plan := all
	if len(plan) > budget {
		plan, res.Deferred = all[:budget], len(all)-budget
	}
	for _, st := range plan {
		res.Covered += st.Jobs
	}
	res.Written = len(plan)

	if len(plan) > 0 {
		written, err := s.Writer.Write(ctx, plan)
		if written < 0 || written > len(plan) {
			written = 0
		}
		if written < len(plan) {
			// Only the stamps that landed are claimed, and Covered is
			// recomputed from them rather than scaled: the plan is
			// ordered by how many jobs each write covers, so a share
			// of the writes is not a share of the jobs.
			res.Written, res.Covered = written, 0
			for _, st := range plan[:written] {
				res.Covered += st.Jobs
			}
		}
		if err != nil {
			res.Err = fmt.Errorf("writing %d cluster ads: %w", len(plan), err)
			s.record(res)
			return res, res.Err
		}
	}
	s.record(res)
	return res, nil
}

func (s *Stamper) record(res StampResult) { s.last = res }

// Last is what the most recent pass did, for the admin page.
func (s *Stamper) Last() StampResult { return s.last }

// Run stamps every interval until ctx is cancelled.
func (s *Stamper) Run(ctx context.Context, every time.Duration, report func(StampResult, error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		res, err := s.Pass(ctx)
		if report != nil {
			report(res, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
