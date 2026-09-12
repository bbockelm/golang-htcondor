package httpserver

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// The dashboard used to walk the whole queue on every load, for every
// viewer, to produce a handful of counts. That is the most expensive
// question the access point is asked and the least valuable answer it
// gives -- a number with no cause attached.
//
// Two things change here. The walk now yields everything a glance needs
// from the pass it was already paying for: what is held and WHY, and
// what has changed recently. And the result is cached, so the schedd is
// walked at most once per refreshInterval no matter how many people are
// looking -- where before each open of the page was another full scan.
//
// "Recently completed" is approximated rather than absent. A finished
// job is destroyed from the queue by the schedd's reaper, but there is a
// window between the terminal write and the destroy where it sits in
// JobStatus == 4 -- so a queue walk catches the few that finished in the
// last moments. That is a real answer, just a short-sighted one, and the
// history archive supplies the rest when it is reachable.
//
// The two are reported as one list with a flag saying whether the
// archive contributed, because the difference matters: queue-only means
// "the last few seconds", not "all that finished".

// dashboardRefresh is the floor between schedd walks. Every viewer
// shares one snapshot, so this bounds the cost at one queue scan per
// interval for the whole deployment rather than per page load.
const dashboardRefresh = 3 * time.Minute

// recentPerList is how many entries each recent-activity list keeps.
// Enough to see the shape of a burst, few enough to read at a glance.
const recentPerList = 10

// topHoldReasons bounds the hold breakdown; the tail is summed into one
// "other" row rather than dropped, so the numbers still add up.
const topHoldReasons = 6

// RecentJob is one entry in a recent-activity list.
type RecentJob struct {
	ClusterID int64  `json:"cluster_id"`
	ProcID    int64  `json:"proc_id"`
	Owner     string `json:"owner,omitempty"`
	// At is when the event this list is about happened, unix seconds.
	At int64 `json:"at"`
	// Detail is the one fact worth showing beside it: a hold reason, the
	// executable, the host it started on.
	Detail string `json:"detail,omitempty"`
	// Archived says this row came from the history archive rather than
	// the live queue, which decides where a click on it should go. The
	// queue destroys a finished job within seconds, so most completions
	// shown here no longer have a job page -- linking them all to one
	// sent people to "not found".
	Archived bool `json:"archived,omitempty"`
}

// HoldReasonCount is one row of the hold breakdown.
type HoldReasonCount struct {
	Code  int64  `json:"code"`
	Label string `json:"label"`
	Count int    `json:"count"`
	// Example is one hold reason string with this code, because the code
	// says the category and the message says which file or which host.
	Example string `json:"example,omitempty"`
}

// DashboardActivity is the "how is this access point doing" half of the
// dashboard: why jobs are held, and what has changed lately.
type DashboardActivity struct {
	HoldReasons []HoldReasonCount `json:"hold_reasons,omitempty"`

	RecentlySubmitted []RecentJob `json:"recently_submitted,omitempty"`
	RecentlyStarted   []RecentJob `json:"recently_started,omitempty"`
	RecentlyHeld      []RecentJob `json:"recently_held,omitempty"`
	RecentlyCompleted []RecentJob `json:"recently_completed,omitempty"`

	// CompletedAvailable is false when nothing could answer "what
	// finished recently". Reported rather than left as an empty list,
	// which would read as "nothing finished".
	CompletedAvailable bool `json:"completed_available"`
	// CompletedPartial says the list came from the queue alone -- the
	// handful still in JobStatus == 4 before the reaper destroys them.
	// That is minutes of history at best, and a viewer told otherwise
	// would read a short list as a quiet access point.
	CompletedPartial bool `json:"completed_partial"`

	// HoldWindowSeconds is the span the hold breakdown covers. Reported
	// rather than assumed: the rows answer "why did jobs BECOME held
	// recently", which is a different question from the HELD tile beside
	// them, and a reader who takes it for the latter will conclude the
	// backlog vanished.
	HoldWindowSeconds int64 `json:"hold_window_seconds,omitempty"`

	// Source is what answered, and ComputedAt when. A cached snapshot is
	// minutes old by design; saying so is the difference between a stale
	// number and a wrong one.
	Source     string `json:"source"`
	ComputedAt int64  `json:"computed_at"`
}

// dashboardSnapshot is one computed view, shared by every viewer with
// the same scope.
type dashboardSnapshot struct {
	Counts   map[string]int
	Total    int
	Activity DashboardActivity
	// Goodput is nil where nothing could answer it. It needs a history
	// archive, so the schedd path never fills it in: the queue does not
	// keep finished jobs long enough to have a rate.
	Goodput *GoodputSummary
}

// dashboardCache holds the most recent snapshot per scope key, and
// serializes the recomputation so a burst of page loads produces one
// queue walk rather than one each.
type dashboardCache struct {
	mu    sync.Mutex
	byKey map[string]*cachedDashboard
	now   func() time.Time
}

type cachedDashboard struct {
	mu       sync.Mutex // held across a recompute, so viewers queue rather than pile on
	snapshot *dashboardSnapshot
	at       time.Time
}

func newDashboardCache() *dashboardCache {
	return &dashboardCache{byKey: make(map[string]*cachedDashboard), now: time.Now}
}

// get returns a snapshot no older than dashboardRefresh, computing one
// if needed.
//
// The per-key lock is held across the computation on purpose: ten people
// opening the dashboard at once should cost one queue walk, not ten.
// The tenth waits for the first rather than starting its own.
func (c *dashboardCache) get(key string, compute func() (*dashboardSnapshot, error)) (*dashboardSnapshot, error) {
	c.mu.Lock()
	entry := c.byKey[key]
	if entry == nil {
		entry = &cachedDashboard{}
		c.byKey[key] = entry
	}
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.snapshot != nil && c.now().Sub(entry.at) < dashboardRefresh {
		return entry.snapshot, nil
	}
	snap, err := compute()
	if err != nil {
		// A failed refresh falls back to the last good answer rather
		// than blanking the page: a dashboard that goes empty when the
		// schedd hiccups is worse than one that says it is three minutes
		// old.
		if entry.snapshot != nil {
			return entry.snapshot, nil
		}
		return nil, err
	}
	entry.snapshot, entry.at = snap, c.now()
	return snap, nil
}

// activityCollector accumulates the recent-activity lists during a queue
// walk, keeping only the newest few of each so the pass stays O(1) in
// memory rather than O(queue).
type activityCollector struct {
	submitted, started, held, completed recentTop
	holds                               map[int64]*HoldReasonCount
	// since bounds the hold breakdown. The recent lists bound
	// themselves by keeping only the newest few; the breakdown is a
	// count, so it needs the window stated.
	since int64
}

func newActivityCollector(since int64) *activityCollector {
	return &activityCollector{
		since:     since,
		submitted: recentTop{limit: recentPerList},
		started:   recentTop{limit: recentPerList},
		held:      recentTop{limit: recentPerList},
		completed: recentTop{limit: recentPerList},
		holds:     make(map[int64]*HoldReasonCount, 8),
	}
}

// observe folds one job ad into the activity view.
func (a *activityCollector) observe(ad *classad.ClassAd) {
	id := RecentJob{}
	id.ClusterID, _ = ad.EvaluateAttrInt("ClusterId")
	id.ProcID, _ = ad.EvaluateAttrInt("ProcId")
	id.Owner, _ = ad.EvaluateAttrString("Owner")

	status, _ := ad.EvaluateAttrInt("JobStatus")

	if qdate, ok := ad.EvaluateAttrInt("QDate"); ok && qdate > 0 {
		e := id
		e.At = qdate
		e.Detail, _ = ad.EvaluateAttrString("Cmd")
		a.submitted.add(e)
	}
	if start, ok := jobStart(ad); ok {
		e := id
		e.At = start
		e.Detail, _ = ad.EvaluateAttrString("RemoteHost")
		a.started.add(e)
	}
	if status == jobStatusCompleted {
		// Caught in the window before the reaper destroys it. Rare per
		// walk, but on a busy access point there is usually something
		// here, and it is the freshest possible answer -- fresher than
		// the archive, which only learns once the schedd has written
		// history and the syncer has read it.
		e := id
		e.At = completionTime(ad)
		if code, ok := ad.EvaluateAttrInt("ExitCode"); ok {
			e.Detail = fmt.Sprintf("exit %d", code)
		}
		a.completed.add(e)
	}
	if status == jobStatusHeld {
		code, _ := ad.EvaluateAttrInt("HoldReasonCode")
		reason, _ := ad.EvaluateAttrString("HoldReason")
		heldAt, _ := ad.EvaluateAttrInt("EnteredCurrentStatus")

		// Recent holds only, matching the mirror path and the lists
		// below. A job held last Tuesday is still held, and counting it
		// here would make a long-standing backlog drown out what is
		// going wrong right now -- which is the question this panel is
		// for. The HELD tile is where the standing total lives.
		if heldAt < a.since {
			return
		}

		row := a.holds[code]
		if row == nil {
			row = &HoldReasonCount{Code: code, Label: holdReasonLabel(code)}
			a.holds[code] = row
		}
		row.Count++
		if row.Example == "" {
			row.Example = reason
		}

		e := id
		e.At = heldAt
		e.Detail = reason
		a.held.add(e)
	}
}

const (
	jobStatusCompleted = 4
	jobStatusHeld      = 5
)

// completionTime reads whichever stamp says when a job finished.
func completionTime(ad *classad.ClassAd) int64 {
	for _, attr := range []string{"CompletionDate", "EnteredCurrentStatus"} {
		if v, ok := ad.EvaluateAttrInt(attr); ok && v > 0 {
			return v
		}
	}
	return 0
}

// jobStart reads whichever start stamp the ad carries.
func jobStart(ad *classad.ClassAd) (int64, bool) {
	for _, attr := range []string{"JobCurrentStartDate", "JobStartDate"} {
		if v, ok := ad.EvaluateAttrInt(attr); ok && v > 0 {
			return v, true
		}
	}
	return 0, false
}

// result renders the collected activity, newest first.
func (a *activityCollector) result(now time.Time) DashboardActivity {
	completed := a.completed.sorted()
	act := DashboardActivity{
		RecentlySubmitted: a.submitted.sorted(),
		RecentlyStarted:   a.started.sorted(),
		RecentlyHeld:      a.held.sorted(),
		RecentlyCompleted: completed,
		// The queue can only show what has not been reaped yet, so this
		// is available-but-partial until the archive is merged in.
		CompletedAvailable: len(completed) > 0,
		CompletedPartial:   true,
		// The queue is what this collector walks; a caller that merges
		// the archive in says so itself.
		Source:            "schedd",
		ComputedAt:        now.Unix(),
		HoldWindowSeconds: now.Unix() - a.since,
	}

	rows := make([]HoldReasonCount, 0, len(a.holds))
	for _, r := range a.holds {
		rows = append(rows, *r)
	}
	act.HoldReasons = topHoldReasonRows(rows)
	return act
}

// topHoldReasonRows orders the breakdown by weight and folds the tail
// into one row.
//
// Shared by both sources on purpose: the rows sit beside the HELD tile,
// so they have to add up to it, and a rule that drifted between the
// mirror and the schedd would make the panel disagree with itself
// depending on which answered.
func topHoldReasonRows(rows []HoldReasonCount) []HoldReasonCount {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Code < rows[j].Code
	})
	if len(rows) <= topHoldReasons {
		return rows
	}
	other := HoldReasonCount{Code: -1, Label: "other reasons"}
	for _, r := range rows[topHoldReasons:] {
		other.Count += r.Count
	}
	return append(rows[:topHoldReasons:topHoldReasons], other)
}

// newestFirst sorts an activity list and trims it to limit.
func newestFirst(jobs []RecentJob, limit int) []RecentJob {
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].At > jobs[j].At })
	if len(jobs) > limit {
		jobs = jobs[:limit]
	}
	return jobs
}

// recentTop keeps the newest `limit` entries seen, by At.
type recentTop struct {
	limit int
	items []RecentJob
}

func (r *recentTop) add(e RecentJob) {
	if e.At <= 0 {
		return
	}
	if len(r.items) < r.limit {
		r.items = append(r.items, e)
		return
	}
	// Replace the oldest, if this beats it. A linear scan over ten
	// entries is cheaper than maintaining a heap for a list this size.
	oldest := 0
	for i := 1; i < len(r.items); i++ {
		if r.items[i].At < r.items[oldest].At {
			oldest = i
		}
	}
	if e.At > r.items[oldest].At {
		r.items[oldest] = e
	}
}

func (r *recentTop) sorted() []RecentJob {
	out := append([]RecentJob(nil), r.items...)
	sort.Slice(out, func(i, j int) bool { return out[i].At > out[j].At })
	return out
}

// dashboards returns the handler's dashboard cache, building it on first
// use so a Handler constructed directly in a test still has one.
func (s *Handler) dashboards() *dashboardCache {
	s.dashboardCacheOnce.Do(func() { s.dashboardCacheVal = newDashboardCache() })
	return s.dashboardCacheVal
}

// dashboardCacheKey names the snapshot a viewer may be served.
//
// The owner is in the key because most viewers see only their own jobs,
// and a snapshot holds their counts, their hold messages and their job
// ids. Leaving the owner out would not merely waste a query -- it would
// serve one user's dashboard to another, and nothing downstream would
// notice. The pool-wide admin view is the same answer for everybody, so
// it shares a single key.
func dashboardCacheKey(owner string, ownedByMe bool) string {
	if !ownedByMe {
		return "all"
	}
	return "mine:" + owner
}

// mergeArchivedCompletions folds history rows into the completed list.
//
// The queue can only show jobs the reaper has not destroyed yet -- the
// last seconds, not the last hour. The archive holds the rest, and the
// two together are what a viewer means by "recently completed". Rows are
// deduplicated by job id because the window overlaps: a job can be in
// both, the archive's copy being the one with the outcome attributes.
//
// A failure here leaves the queue's answer in place rather than emptying
// the list: partial and labelled beats absent.
func (act *DashboardActivity) mergeArchivedCompletions(archived []RecentJob) {
	if len(archived) == 0 {
		return
	}
	seen := make(map[[2]int64]struct{}, len(archived)+len(act.RecentlyCompleted))
	merged := make([]RecentJob, 0, len(archived)+len(act.RecentlyCompleted))
	// Archive first, so its row wins the deduplication: it is the
	// durable record and carries the exit status, where the queue's copy
	// may have been caught mid-flight. Winning the tie also decides
	// where the row links: a job in both places is still in the queue,
	// so it keeps a job page -- see the Archived reset below.
	for i := range archived {
		archived[i].Archived = true
	}
	inQueue := make(map[[2]int64]struct{}, len(act.RecentlyCompleted))
	for _, e := range act.RecentlyCompleted {
		inQueue[[2]int64{e.ClusterID, e.ProcID}] = struct{}{}
	}
	for _, e := range append(archived, act.RecentlyCompleted...) {
		k := [2]int64{e.ClusterID, e.ProcID}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		if _, live := inQueue[k]; live {
			// Present in both: the queue has not reaped it yet, so the
			// job page still resolves and is the better destination.
			e.Archived = false
		}
		merged = append(merged, e)
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].At > merged[j].At })
	if len(merged) > recentPerList {
		merged = merged[:recentPerList]
	}
	act.RecentlyCompleted = merged
	act.CompletedAvailable = true
	// The archive answered, so this is no longer just the last few
	// seconds the queue happened to be holding.
	act.CompletedPartial = false
}
