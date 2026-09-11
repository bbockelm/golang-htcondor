package httpserver

import (
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
// "Recently completed" is deliberately absent from this path. A finished
// job is destroyed from the queue by the schedd, so a queue walk cannot
// see one however recent; it lives in the history archive. Reporting an
// empty list would read as "nothing finished", which is the opposite of
// the truth on a busy access point.

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

	// CompletedAvailable is false when nothing can answer "what finished
	// recently": a finished job has left the queue, so only the history
	// archive knows. Reported rather than left as an empty list, which
	// would read as "nothing finished".
	CompletedAvailable bool `json:"completed_available"`

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

// get returns a snapshot no older than maxAge, computing one if needed.
//
// The per-key lock is held across the computation on purpose: ten people
// opening the dashboard at once should cost one queue walk, not ten.
// The tenth waits for the first rather than starting its own.
func (c *dashboardCache) get(key string, maxAge time.Duration, compute func() (*dashboardSnapshot, error)) (*dashboardSnapshot, error) {
	c.mu.Lock()
	entry := c.byKey[key]
	if entry == nil {
		entry = &cachedDashboard{}
		c.byKey[key] = entry
	}
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.snapshot != nil && c.now().Sub(entry.at) < maxAge {
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
	submitted, started, held recentTop
	holds                    map[int64]*HoldReasonCount
}

func newActivityCollector() *activityCollector {
	return &activityCollector{
		submitted: recentTop{limit: recentPerList},
		started:   recentTop{limit: recentPerList},
		held:      recentTop{limit: recentPerList},
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
	if status == jobStatusHeld {
		code, _ := ad.EvaluateAttrInt("HoldReasonCode")
		reason, _ := ad.EvaluateAttrString("HoldReason")

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
		e.At, _ = ad.EvaluateAttrInt("EnteredCurrentStatus")
		e.Detail = reason
		a.held.add(e)
	}
}

const jobStatusHeld = 5

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
func (a *activityCollector) result(source string, now time.Time) DashboardActivity {
	act := DashboardActivity{
		RecentlySubmitted: a.submitted.sorted(),
		RecentlyStarted:   a.started.sorted(),
		RecentlyHeld:      a.held.sorted(),
		Source:            source,
		ComputedAt:        now.Unix(),
	}

	rows := make([]HoldReasonCount, 0, len(a.holds))
	for _, r := range a.holds {
		rows = append(rows, *r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Code < rows[j].Code
	})
	if len(rows) > topHoldReasons {
		// Sum the tail rather than dropping it, so the rows still add up
		// to the HELD tile beside them.
		other := HoldReasonCount{Code: -1, Label: "other reasons"}
		for _, r := range rows[topHoldReasons:] {
			other.Count += r.Count
		}
		rows = append(rows[:topHoldReasons:topHoldReasons], other)
	}
	act.HoldReasons = rows
	return act
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
