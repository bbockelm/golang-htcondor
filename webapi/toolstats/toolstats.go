// Package toolstats counts MCP tool calls: which tool, for whom, from
// which client harness, with what outcome and how long it took.
//
// It owns the numbers rather than handing them to a prometheus
// CounterVec, for one reason: they have to survive a restart. A
// client_golang counter cannot be set to a value, only incremented from
// zero, and a histogram cannot be given a pre-existing distribution at
// all. Holding the state here means startup can seed it from SQLite
// exactly -- counts, duration sum and every bucket -- and /metrics is
// then rendered from it through prometheus.MustNewConstMetric and
// MustNewConstHistogram (see collector.go).
//
// The split between what SQLite keeps and what /metrics shows is
// deliberate:
//
//   - SQLite keeps every series VERBATIM: the real user name, the real
//     client string. It is a table an operator queries directly, and it
//     is the durable record.
//   - /metrics projects that onto a BOUNDED label space. A Prometheus
//     label value is a time series, and a server that minted one per
//     distinct user string would hand any caller the ability to grow
//     the scrape without limit. Past MaxLabelValues distinct values for
//     a label, further ones render as "other" -- still counted, still
//     exact in SQLite, just summed under one label.
//
// Nothing here is in the request path's critical section for longer
// than a map lookup and a few adds under a mutex.
package toolstats

import (
	"sort"
	"sync"
	"time"
)

// Outcome values. Bounded on purpose: this is a Prometheus label, and
// the set of things that can happen to a tool call is small and known.
const (
	// OutcomeOK is a tool that ran and returned a result.
	OutcomeOK = "ok"
	// OutcomeError is a tool that ran and failed. It covers both a tool
	// returning an error and the request being rejected after dispatch
	// began; what it does NOT cover is a malformed request that never
	// named a tool, which is not attributable to one.
	OutcomeError = "error"
	// OutcomeUnknownTool is a call that named a tool this server does
	// not have. Its own outcome rather than an error, because it says
	// the caller's catalogue is wrong -- a stale client, or an agent
	// inventing a name -- which is a different problem from a tool
	// that ran and failed.
	OutcomeUnknownTool = "unknown_tool"
	// OutcomeRefused is a tool call rejected before the tool ran --
	// today, one disabled by configuration. Separated from "error"
	// because it says something about the deployment rather than about
	// the call: a dashboard that lumps them together reports a policy
	// decision as a malfunction.
	OutcomeRefused = "refused"
)

// UnknownUser and UnknownClient are the recorded values when a call
// carries no identity. They are spelled out rather than left empty so a
// query result never has a blank cell whose meaning is ambiguous
// between "nobody" and "not recorded".
const (
	UnknownUser   = "unknown"
	UnknownClient = "unknown"
)

// OtherLabel is what a label value collapses to once a label has more
// distinct values than MaxLabelValues allows.
const OtherLabel = "other"

// DefaultMaxLabelValues bounds the distinct values any single label can
// contribute to /metrics. It is a safety valve, not a policy: it sits
// far above the number of users or client harnesses a real access point
// has, so under normal operation nothing is ever collapsed. It exists
// so that a caller inventing identities cannot grow the scrape without
// limit.
const DefaultMaxLabelValues = 1000

// DurationBuckets are the histogram boundaries, in seconds.
//
// Not prometheus.DefBuckets, which stops at 10s. MCP tool calls here
// legitimately run for minutes -- watch_jobs blocks until a job changes
// state, interactive_session_exec runs a command on an execute node --
// and a histogram whose last bucket is 10s reports every one of those
// identically as +Inf, which is exactly the case an operator is trying
// to see.
var DurationBuckets = []float64{
	0.005, 0.025, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300,
}

// Key identifies one counted series. Every field is recorded verbatim;
// the bounding to a label space happens at render time.
type Key struct {
	Tool    string
	User    string
	Client  string
	Outcome string
}

// Entry is one series' accumulated numbers.
type Entry struct {
	// Calls is the number of calls counted.
	Calls uint64
	// DurationSum is their total duration in seconds, the numerator of
	// an average and the _sum of the Prometheus histogram.
	DurationSum float64
	// Buckets holds the per-bucket counts, NOT cumulative, index-aligned
	// with DurationBuckets. A call longer than the last boundary is in
	// none of them and shows up only in Calls, which is what makes
	// Calls the histogram's _count.
	Buckets []uint64
	// LastCall is when this series was last seen. Kept for the operator
	// querying SQLite ("who used this last month?"), and rendered as a
	// gauge so an unused tool is visible as such.
	LastCall time.Time
}

// clone returns a deep copy, so a snapshot handed to a caller cannot be
// mutated by concurrent recording.
func (e *Entry) clone() Entry {
	out := *e
	out.Buckets = append([]uint64(nil), e.Buckets...)
	return out
}

// Store accumulates tool-call statistics in memory.
//
// The zero value is not usable; call New.
type Store struct {
	mu sync.Mutex
	m  map[Key]*Entry

	// maxLabelValues bounds each label's distinct values at render time.
	maxLabelValues int

	// now is time.Now, replaced in tests. A stat with a timestamp in it
	// is otherwise untestable without sleeping.
	now func() time.Time

	// dirty tracks whether anything has been recorded since the last
	// successful flush, so a periodic flush on an idle server does no
	// SQLite writes at all.
	dirty bool
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		m:              map[Key]*Entry{},
		maxLabelValues: DefaultMaxLabelValues,
		now:            time.Now,
	}
}

// SetMaxLabelValues overrides the per-label distinct-value ceiling. A
// value of zero or less restores the default rather than disabling the
// bound: an unbounded label space is not something a configuration
// mistake should be able to switch on.
func (s *Store) SetMaxLabelValues(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n <= 0 {
		n = DefaultMaxLabelValues
	}
	s.maxLabelValues = n
}

// Record counts one tool call.
//
// Empty user or client are recorded as UnknownUser / UnknownClient:
// a call with no identity is a fact worth counting, and dropping it
// would make the totals disagree with the server's own logs.
func (s *Store) Record(tool, user, client, outcome string, d time.Duration) {
	if tool == "" {
		// Nothing to attribute this to. A tools/call whose params did
		// not parse never named a tool, and inventing a bucket for it
		// would put protocol errors in the same table as tool results.
		return
	}
	if user == "" {
		user = UnknownUser
	}
	if client == "" {
		client = UnknownClient
	}
	if outcome == "" {
		outcome = OutcomeError
	}
	key := Key{Tool: tool, User: user, Client: client, Outcome: outcome}

	// A negative duration means a clock that went backwards mid-call.
	// Clamp rather than discard: the call happened, and a negative
	// addend would corrupt the histogram's _sum for every later reader.
	secs := d.Seconds()
	if secs < 0 {
		secs = 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.m[key]
	if e == nil {
		e = &Entry{Buckets: make([]uint64, len(DurationBuckets))}
		s.m[key] = e
	}
	e.Calls++
	e.DurationSum += secs
	e.LastCall = s.now()
	for i, b := range DurationBuckets {
		if secs <= b {
			e.Buckets[i]++
			break
		}
	}
	s.dirty = true
}

// Snapshot returns a copy of every series, for flushing or for a test.
// Sorted by key so output is deterministic.
func (s *Store) Snapshot() map[Key]Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

func (s *Store) snapshotLocked() map[Key]Entry {
	out := make(map[Key]Entry, len(s.m))
	for k, e := range s.m {
		out[k] = e.clone()
	}
	return out
}

// SnapshotForFlush returns the series together with the dirty flag, and
// clears the flag. The caller flushes only when dirty is true, and on
// failure calls MarkDirty so the next tick tries again.
func (s *Store) SnapshotForFlush() (map[Key]Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dirty := s.dirty
	s.dirty = false
	return s.snapshotLocked(), dirty
}

// MarkDirty re-arms the flush, after one failed.
func (s *Store) MarkDirty() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty = true
}

// Load installs persisted series, replacing anything already held.
//
// It is startup's job: the counters resume from where the last run left
// them, so /metrics shows lifetime totals rather than restarting at
// zero. Entries are taken as given -- a bucket slice of the wrong
// length is resized rather than rejected, because the alternative is
// discarding a deployment's entire history the day the bucket
// boundaries are retuned.
func (s *Store) Load(entries map[Key]Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = make(map[Key]*Entry, len(entries))
	for k, e := range entries {
		c := e.clone()
		switch {
		case len(c.Buckets) < len(DurationBuckets):
			c.Buckets = append(c.Buckets, make([]uint64, len(DurationBuckets)-len(c.Buckets))...)
		case len(c.Buckets) > len(DurationBuckets):
			c.Buckets = c.Buckets[:len(DurationBuckets)]
		}
		s.m[k] = &c
	}
	// Loaded state is already in SQLite; flushing it straight back is
	// pure write amplification on every restart of an idle server.
	s.dirty = false
}

// labelSpace decides, for one label, which values keep their own name
// and which collapse to OtherLabel.
//
// Ordering is by call volume, descending, then by name: when the
// ceiling does bite, the series an operator most wants to see are the
// ones that keep their identity. Name breaks ties so the choice is
// deterministic and a scrape does not reshuffle labels between ticks.
func labelSpace(totals map[string]uint64, limit int) map[string]string {
	keep := make(map[string]string, len(totals))
	if len(totals) <= limit {
		for v := range totals {
			keep[v] = v
		}
		return keep
	}
	type vt struct {
		name  string
		calls uint64
	}
	all := make([]vt, 0, len(totals))
	for n, c := range totals {
		all = append(all, vt{n, c})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].calls != all[j].calls {
			return all[i].calls > all[j].calls
		}
		return all[i].name < all[j].name
	})
	for i, v := range all {
		if i < limit {
			keep[v.name] = v.name
		} else {
			keep[v.name] = OtherLabel
		}
	}
	return keep
}
