package usagestats

import (
	"math"
	"sort"
	"time"
)

// Filter narrows a Summary to the series matching every non-empty field.
// Matching is exact: these are values the caller picked from the
// summary's own Options, not search terms.
type Filter struct {
	// Name is the tool or endpoint to narrow to. Spelled generically
	// rather than per kind so one filter type serves both; the spec's
	// Noun is what the UI labels it with.
	Name   string `json:"name,omitempty"`
	User   string `json:"user,omitempty"`
	Client string `json:"client,omitempty"`
}

func (f Filter) matches(k Key) bool {
	return (f.Name == "" || f.Name == k.Name) &&
		(f.User == "" || f.User == k.User) &&
		(f.Client == "" || f.Client == k.Client)
}

// UsageRow is the aggregate of every series sharing one tool,
// endpoint, user or client -- or, for Summary.Totals, of every series
// in the summary.
type UsageRow struct {
	// Name is the tool, endpoint, user or client the row aggregates.
	// Empty on the totals row. It is the VALUE a filter matches on,
	// so it is always the string the store recorded.
	Name string `json:"name,omitempty"`

	// Label is what to show instead of Name, when the recorded value
	// is an identifier a reader should not have to decode -- today,
	// an OAuth2 client id resolved to the client's name.
	//
	// Separate from Name rather than replacing it because the two have
	// different jobs: Name goes back to the server as a filter and has
	// to stay exactly what was recorded, while Label is for the
	// reader and may change when an admin renames something.
	Label string `json:"label,omitempty"`

	Calls uint64 `json:"calls"`

	// Outcomes counts the calls per outcome. A map rather than a field
	// per outcome because the vocabulary belongs to the spec: MCP has
	// four outcomes and REST six, and a struct that named them all
	// would give each kind columns the other can never fill.
	//
	// Every outcome in the spec is present, zero included, so a
	// renderer can read the row without checking for absent keys and a
	// column never silently disappears on a quiet day.
	Outcomes map[string]uint64 `json:"outcomes"`

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

// Options lists every name, user and client in the store, unfiltered
// and sorted, so a caller can offer them as filter choices while a
// filter is in force.
type Options struct {
	Names   []string `json:"names"`
	Users   []string `json:"users"`
	Clients []string `json:"clients"`
}

// Summary is a snapshot aggregated for display.
type Summary struct {
	// Kind and Noun say which vocabulary this summary is in, so the
	// renderer does not have to know which endpoint it asked.
	Kind string `json:"kind"`
	Noun string `json:"noun"`
	// Title is Noun capitalised, for a column heading.
	Title string `json:"title"`
	// Outcomes is the spec's vocabulary in display order: the columns,
	// left to right.
	Outcomes []string `json:"outcomes"`

	// ClientLabels maps a recorded client string to its display label,
	// for the entries in Options.Clients that have one.
	ClientLabels map[string]string `json:"client_labels,omitempty"`

	Filter   Filter     `json:"filter"`
	Totals   UsageRow   `json:"totals"`
	ByName   []UsageRow `json:"by_name"`
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

func newAccumulator(name string, outcomes []string) *accumulator {
	// Seeded with every outcome at zero: a column the spec defines
	// should read 0, not vanish, on a day nothing hit it.
	counts := make(map[string]uint64, len(outcomes))
	for _, o := range outcomes {
		counts[o] = 0
	}
	return &accumulator{
		row:     UsageRow{Name: name, Outcomes: counts},
		buckets: make([]uint64, len(DurationBuckets)),
		users:   map[string]struct{}{},
		clients: map[string]struct{}{},
	}
}

func (a *accumulator) add(k Key, e *Entry) {
	a.row.Calls += e.Calls
	// A row persisted under an outcome the spec has since dropped
	// still counts toward Calls; it just has no column of its own.
	// Adding a key for it would put a column on the page that the
	// vocabulary no longer admits.
	if _, ok := a.row.Outcomes[k.Outcome]; ok {
		a.row.Outcomes[k.Outcome] += e.Calls
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

// Summarize aggregates a snapshot by name, by user and by client, plus
// overall totals, over the series matching f. Rows are ordered busiest
// first, ties by name. Options always reflect the whole snapshot.
func Summarize(spec Spec, snap map[Key]Entry, f Filter) Summary {
	totals := newAccumulator("", spec.Outcomes)
	byName := map[string]*accumulator{}
	byUser := map[string]*accumulator{}
	byClient := map[string]*accumulator{}
	names, users, clients := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}

	add := func(m map[string]*accumulator, name string, k Key, e *Entry) {
		a := m[name]
		if a == nil {
			a = newAccumulator(name, spec.Outcomes)
			m[name] = a
		}
		a.add(k, e)
	}

	for k, e := range snap {
		names[k.Name] = struct{}{}
		users[k.User] = struct{}{}
		clients[k.Client] = struct{}{}
		if !f.matches(k) {
			continue
		}
		totals.add(k, &e)
		add(byName, k.Name, k, &e)
		add(byUser, k.User, k, &e)
		add(byClient, k.Client, k, &e)
	}

	return Summary{
		Kind:     spec.Kind,
		Noun:     spec.Noun,
		Title:    spec.Title,
		Outcomes: spec.Outcomes,
		Filter:   f,
		Totals:   totals.finish(),
		ByName:   rows(byName),
		ByUser:   rows(byUser),
		ByClient: rows(byClient),
		Options: Options{
			Names:   sortedKeys(names),
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
