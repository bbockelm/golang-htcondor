package toolstats

import (
	"math"
	"sort"
	"time"
)

// Filter narrows a Summary to the series matching every non-empty field.
// Matching is exact: these are values the caller picked from the
// summary's own Options, not search terms.
type Filter struct {
	Tool   string `json:"tool,omitempty"`
	User   string `json:"user,omitempty"`
	Client string `json:"client,omitempty"`
}

func (f Filter) matches(k Key) bool {
	return (f.Tool == "" || f.Tool == k.Tool) &&
		(f.User == "" || f.User == k.User) &&
		(f.Client == "" || f.Client == k.Client)
}

// UsageRow is the aggregate of every series sharing one tool, user or
// client -- or, for Summary.Totals, of every series in the summary.
type UsageRow struct {
	// Name is the tool, user or client the row aggregates. Empty on
	// the totals row.
	Name string `json:"name,omitempty"`

	Calls       uint64 `json:"calls"`
	OK          uint64 `json:"ok"`
	Error       uint64 `json:"error"`
	Refused     uint64 `json:"refused"`
	UnknownTool uint64 `json:"unknown_tool"`

	// Users and Clients are distinct identities behind the row. The
	// placeholders for "no identity" (UnknownUser/UnknownClient) and
	// for the overflow bucket (OtherLabel) are not counted: each stands
	// for an unknown number of real ones, so counting it as one would
	// be a guess presented as a fact. This matches the tool_users gauge.
	Users   int `json:"users"`
	Clients int `json:"clients"`

	// AvgSeconds is the mean call duration.
	AvgSeconds float64 `json:"avg_seconds"`

	// P95Seconds approximates the 95th-percentile duration as the upper
	// boundary of the histogram bucket it falls in. Nil when it falls
	// past the last boundary, in which case P95OverSeconds is that
	// boundary ("longer than this"), or when no call carries a
	// distribution at all, in which case both are nil.
	P95Seconds     *float64 `json:"p95_seconds"`
	P95OverSeconds *float64 `json:"p95_over_seconds,omitempty"`

	// LastCall is the most recent call in the row; nil if none
	// recorded one.
	LastCall *time.Time `json:"last_call"`
}

// Options lists every tool, user and client in the store, unfiltered and
// sorted, so a caller can offer them as filter choices while a filter
// is in force.
type Options struct {
	Tools   []string `json:"tools"`
	Users   []string `json:"users"`
	Clients []string `json:"clients"`
}

// Summary is a snapshot aggregated for display.
type Summary struct {
	Filter   Filter     `json:"filter"`
	Totals   UsageRow   `json:"totals"`
	ByTool   []UsageRow `json:"by_tool"`
	ByUser   []UsageRow `json:"by_user"`
	ByClient []UsageRow `json:"by_client"`
	Options  Options    `json:"options"`
}

// accumulator builds one UsageRow.
type accumulator struct {
	row      UsageRow
	sum      float64
	buckets  []uint64
	bucketed uint64 // calls in series that carry a distribution
	users    map[string]struct{}
	clients  map[string]struct{}
	last     time.Time
}

func newAccumulator(name string) *accumulator {
	return &accumulator{
		row:     UsageRow{Name: name},
		buckets: make([]uint64, len(DurationBuckets)),
		users:   map[string]struct{}{},
		clients: map[string]struct{}{},
	}
}

func (a *accumulator) add(k Key, e *Entry) {
	a.row.Calls += e.Calls
	switch k.Outcome {
	case OutcomeOK:
		a.row.OK += e.Calls
	case OutcomeError:
		a.row.Error += e.Calls
	case OutcomeRefused:
		a.row.Refused += e.Calls
	case OutcomeUnknownTool:
		a.row.UnknownTool += e.Calls
	}
	a.sum += e.DurationSum

	// A series whose bucket array was lost (an unreadable cell on load)
	// still has a count but no distribution. Leaving it out of the
	// percentile keeps its calls from all reading as "past the last
	// boundary", which is what an empty array would otherwise say.
	if len(e.Buckets) > 0 {
		a.bucketed += e.Calls
		for i := range a.buckets {
			if i < len(e.Buckets) {
				a.buckets[i] += e.Buckets[i]
			}
		}
	}

	if k.User != UnknownUser && k.User != OtherLabel {
		a.users[k.User] = struct{}{}
	}
	if k.Client != UnknownClient && k.Client != OtherLabel {
		a.clients[k.Client] = struct{}{}
	}
	if e.LastCall.After(a.last) {
		a.last = e.LastCall
	}
}

func (a *accumulator) finish() UsageRow {
	r := a.row
	r.Users = len(a.users)
	r.Clients = len(a.clients)
	if r.Calls > 0 {
		r.AvgSeconds = a.sum / float64(r.Calls)
	}
	r.P95Seconds, r.P95OverSeconds = percentile(a.buckets, a.bucketed, 0.95)
	if !a.last.IsZero() {
		t := a.last
		r.LastCall = &t
	}
	return r
}

// percentile returns the upper boundary of the bucket holding quantile q
// of total calls, given per-bucket (non-cumulative) counts aligned with
// DurationBuckets. Calls beyond the last boundary are in no bucket; if
// the quantile lands among them, the result is (nil, last boundary).
func percentile(buckets []uint64, total uint64, q float64) (at, over *float64) {
	if total == 0 {
		return nil, nil
	}
	rank := uint64(math.Ceil(q * float64(total)))
	var cum uint64
	for i, n := range buckets {
		cum += n
		if cum >= rank {
			v := DurationBuckets[i]
			return &v, nil
		}
	}
	v := DurationBuckets[len(DurationBuckets)-1]
	return nil, &v
}

// Summarize aggregates a snapshot by tool, by user and by client, plus
// overall totals, over the series matching f. Rows are ordered busiest
// first, ties by name. Options always reflect the whole snapshot.
func Summarize(snap map[Key]Entry, f Filter) Summary {
	totals := newAccumulator("")
	byTool := map[string]*accumulator{}
	byUser := map[string]*accumulator{}
	byClient := map[string]*accumulator{}
	tools, users, clients := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}

	add := func(m map[string]*accumulator, name string, k Key, e *Entry) {
		a := m[name]
		if a == nil {
			a = newAccumulator(name)
			m[name] = a
		}
		a.add(k, e)
	}

	for k, e := range snap {
		tools[k.Tool] = struct{}{}
		users[k.User] = struct{}{}
		clients[k.Client] = struct{}{}
		if !f.matches(k) {
			continue
		}
		totals.add(k, &e)
		add(byTool, k.Tool, k, &e)
		add(byUser, k.User, k, &e)
		add(byClient, k.Client, k, &e)
	}

	return Summary{
		Filter:   f,
		Totals:   totals.finish(),
		ByTool:   rows(byTool),
		ByUser:   rows(byUser),
		ByClient: rows(byClient),
		Options: Options{
			Tools:   sortedKeys(tools),
			Users:   sortedKeys(users),
			Clients: sortedKeys(clients),
		},
	}
}

func rows(m map[string]*accumulator) []UsageRow {
	out := make([]UsageRow, 0, len(m))
	for _, a := range m {
		out = append(out, a.finish())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Calls != out[j].Calls {
			return out[i].Calls > out[j].Calls
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
