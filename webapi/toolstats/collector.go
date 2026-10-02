package toolstats

import (
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
)

// Namespace and subsystem match the server's existing metrics, so these
// names sit alongside htcondor_api_http_* rather than inventing a
// second naming scheme on the same endpoint.
const (
	namespace = "htcondor_api"
	subsystem = "mcp"
)

// Collector renders a Store as Prometheus metrics.
//
// It is an UNCHECKED collector in client_golang's sense -- Describe
// sends nothing -- because the set of series is whatever has been
// called since startup and changes between scrapes. That is the same
// path metricsdAdapter in the httpserver package already uses.
//
// Everything is built per-scrape with MustNewConstMetric and
// MustNewConstHistogram from the Store's own numbers, which is what
// lets a restarted server resume its counters: a client_golang Counter
// can only count up from zero, a ConstMetric can be any value.
type Collector struct {
	store *Store

	// omitUser replaces every rendered user label with a single
	// placeholder.
	//
	// It exists because /metrics can be served unauthenticated
	// (HTTP_API_METRICS_PUBLIC) and is otherwise reachable with an API
	// key the codebase deliberately treats as low-value -- the stated
	// risk of leaking one is "scrape /metrics". Putting real usernames
	// there turns that key into a roster of who uses the access point
	// and what for, which is a bigger thing to lose than it was. A site
	// that does not want to make that trade can turn the label off and
	// keep every other number.
	//
	// The durable table is unaffected: it still records the real name
	// for the admin view and for SQL, both of which are already gated
	// on more than a metrics key.
	omitUser bool

	callsDesc    *prometheus.Desc
	durationDesc *prometheus.Desc
	lastCallDesc *prometheus.Desc
	usersDesc    *prometheus.Desc
}

// NewCollector returns a Collector over store.
func NewCollector(store *Store) *Collector { return NewCollectorWithOptions(store, false) }

// NewCollectorWithOptions builds a collector that can omit the user
// label. See Collector.omitUser.
func NewCollectorWithOptions(store *Store, omitUser bool) *Collector {
	return &Collector{
		store:    store,
		omitUser: omitUser,
		callsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "tool_calls_total"),
			"MCP tool calls, by tool, user, client harness and outcome (ok/error/refused). "+
				"Resumed from the persisted totals at startup, so this counts the lifetime of the "+
				"deployment rather than of the process.",
			[]string{"tool", "user", "client", "outcome"}, nil,
		),
		durationDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "tool_duration_seconds"),
			"MCP tool call duration. Labelled by tool, client and outcome but NOT by user: "+
				"how long a tool takes is a property of the tool and the pool, not of who asked, "+
				"and a histogram carries fourteen series per label combination.",
			[]string{"tool", "client", "outcome"}, nil,
		),
		lastCallDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "tool_last_call_timestamp_seconds"),
			"Unix timestamp of the most recent call to each tool. Only tools that have been "+
				"called appear here, so this answers \"how long since this was used\" and not "+
				"\"is this tool used at all\" -- a tool nobody has ever called has no series.",
			[]string{"tool"}, nil,
		),
		usersDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "tool_users"),
			"Distinct users that have called each tool, over the whole retained history. "+
				"Counted over the verbatim user names, so it stays accurate even where the user "+
				"label has collapsed to \"other\" or been turned off.",
			[]string{"tool"}, nil,
		),
	}
}

// Describe sends no descriptors: see the type comment.
func (c *Collector) Describe(_ chan<- *prometheus.Desc) {}

// Collect renders the store.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	snap := c.store.Snapshot()
	c.store.mu.Lock()
	limit := c.store.maxLabelValues
	c.store.mu.Unlock()

	// Decide the label space from call volume, so that if the ceiling
	// ever bites it is the quiet series that collapse.
	userTotals := map[string]uint64{}
	clientTotals := map[string]uint64{}
	toolTotals := map[string]uint64{}
	for k, e := range snap {
		userTotals[k.User] += e.Calls
		clientTotals[k.Client] += e.Calls
		toolTotals[k.Tool] += e.Calls
	}
	userLabel := labelSpace(userTotals, limit)
	if c.omitUser {
		// One value for everyone: the series still exist and still sum
		// correctly, they just no longer say who.
		userLabel = nil
	}
	clientLabel := labelSpace(clientTotals, limit)
	// The tool name is bounded too, which looks odd for a value drawn
	// from a fixed catalogue of ~46 -- until a client calls a tool that
	// does not exist. Those are counted (OutcomeUnknownTool), the name
	// is whatever the caller sent, and an agent inventing names would
	// otherwise mint a label value per hallucination. Ordering by call
	// volume means the real tools are never the ones collapsed.
	toolLabel := labelSpace(toolTotals, limit)

	// Aggregate onto the label space. Two different verbatim users can
	// land on the same label -- both collapsed to "other" -- and their
	// counts have to be summed, not emitted twice: a duplicate label
	// set is a collection error that drops the whole scrape.
	type callKey struct{ tool, user, client, outcome string }
	type histKey struct{ tool, client, outcome string }

	calls := map[callKey]uint64{}
	hists := map[histKey]*Entry{}
	lastCall := map[string]float64{}
	users := map[string]map[string]struct{}{}

	for k, e := range snap {
		renderedUser := OmittedLabel
		if userLabel != nil {
			renderedUser = userLabel[k.User]
		}
		ck := callKey{toolLabel[k.Tool], renderedUser, clientLabel[k.Client], k.Outcome}
		calls[ck] += e.Calls

		hk := histKey{toolLabel[k.Tool], clientLabel[k.Client], k.Outcome}
		h := hists[hk]
		if h == nil {
			h = &Entry{Buckets: make([]uint64, len(DurationBuckets))}
			hists[hk] = h
		}
		h.Calls += e.Calls
		h.DurationSum += e.DurationSum
		for i := range h.Buckets {
			if i < len(e.Buckets) {
				h.Buckets[i] += e.Buckets[i]
			}
		}

		if !e.LastCall.IsZero() {
			tl, ts := toolLabel[k.Tool], float64(e.LastCall.Unix())
			if ts > lastCall[tl] {
				lastCall[tl] = ts
			}
		}

		// Counted over the VERBATIM name, which is the whole point of
		// this gauge: it stays right when the label has collapsed.
		tl := toolLabel[k.Tool]
		if users[tl] == nil {
			users[tl] = map[string]struct{}{}
		}
		if k.User != UnknownUser {
			users[tl][k.User] = struct{}{}
		}
	}

	for k, n := range calls {
		ch <- prometheus.MustNewConstMetric(c.callsDesc, prometheus.CounterValue,
			float64(n), safeLabel(k.tool), safeLabel(k.user), safeLabel(k.client), k.outcome)
	}

	for k, e := range hists {
		cum := make(map[float64]uint64, len(DurationBuckets))
		var running uint64
		for i, b := range DurationBuckets {
			running += e.Buckets[i]
			cum[b] = running
		}
		ch <- prometheus.MustNewConstHistogram(c.durationDesc,
			e.Calls, e.DurationSum, cum, safeLabel(k.tool), safeLabel(k.client), k.outcome)
	}

	for tool, ts := range lastCall {
		ch <- prometheus.MustNewConstMetric(c.lastCallDesc, prometheus.GaugeValue, ts, safeLabel(tool))
	}

	for tool, set := range users {
		ch <- prometheus.MustNewConstMetric(c.usersDesc, prometheus.GaugeValue,
			float64(len(set)), safeLabel(tool))
	}
}

// InvalidLabel replaces a label value that is not valid UTF-8.
const InvalidLabel = "invalid-utf8"

// safeLabel keeps an unrepresentable value from taking the whole
// endpoint down.
//
// MustNewConstMetric PANICS on a label value that is not valid UTF-8.
// client_golang recovers it, so the process survives -- but Collect
// dies partway through its map iteration, and only the metrics already
// pushed onto the channel survive. The scrape returns 200 with a
// silently truncated body, and because the iteration order varies, a
// different subset vanishes each time: series flap in and out, which
// Prometheus reads as repeated counter resets.
//
// The `user` label is the exposed one. It is not sanitised the way
// `client` is -- it comes from the authenticated identity, which is
// normally valid UTF-8 but need not be: a passwd/GECOS-derived name is
// bytes, and the value round-trips through SQLite, so one bad row makes
// the damage permanent across restarts until somebody deletes it by
// hand.
func safeLabel(v string) string {
	if utf8.ValidString(v) {
		return v
	}
	return InvalidLabel
}

// OmittedLabel is the user label's value when the label is turned off.
// A fixed string rather than an empty one, so a reader can tell
// "suppressed" from "nobody".
const OmittedLabel = "omitted"
