package usagestats

import (
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
)

// namespace matches the server's existing metrics, so these names sit
// alongside htcondor_api_http_* rather than inventing a second naming
// scheme on the same endpoint. The subsystem and the middle word come
// from the Store's Spec: htcondor_api_mcp_tool_* and
// htcondor_api_rest_endpoint_*.
const namespace = "htcondor_api"

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
	spec := store.Spec()
	// The metric name's middle word is the spec's noun, so MCP's
	// counters keep the htcondor_api_mcp_tool_* names dashboards
	// already reference and REST's land on names of their own.
	name := func(suffix string) string {
		return prometheus.BuildFQName(namespace, spec.Subsystem, spec.Noun+"_"+suffix)
	}
	return &Collector{
		store:    store,
		omitUser: omitUser,
		callsDesc: prometheus.NewDesc(
			name("calls_total"), spec.CallsHelp,
			[]string{spec.Noun, "user", "client", "outcome"}, nil,
		),
		durationDesc: prometheus.NewDesc(
			name("duration_seconds"), spec.DurationHelp,
			[]string{spec.Noun, "client", "outcome"}, nil,
		),
		lastCallDesc: prometheus.NewDesc(
			name("last_call_timestamp_seconds"), spec.LastCallHelp,
			[]string{spec.Noun}, nil,
		),
		usersDesc: prometheus.NewDesc(
			name("users"), spec.UsersHelp,
			[]string{spec.Noun}, nil,
		),
	}
}

// Describe sends no descriptors: see the type comment.
func (c *Collector) Describe(_ chan<- *prometheus.Desc) {}

// Collect renders the store.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	spec := c.store.Spec()
	snap := c.store.Snapshot()
	c.store.mu.Lock()
	limit := c.store.maxLabelValues
	c.store.mu.Unlock()

	// Decide the label space from call volume, so that if the ceiling
	// ever bites it is the quiet series that collapse.
	userTotals := map[string]uint64{}
	clientTotals := map[string]uint64{}
	nameTotals := map[string]uint64{}
	for k, e := range snap {
		userTotals[k.User] += e.Calls
		clientTotals[k.Client] += e.Calls
		nameTotals[k.Name] += e.Calls
	}
	userLabel := labelSpace(userTotals, limit)
	if c.omitUser {
		// One value for everyone: the series still exist and still sum
		// correctly, they just no longer say who.
		userLabel = nil
	}
	clientLabel := labelSpace(clientTotals, limit)
	// The name is bounded too, which looks odd for a value drawn from
	// a fixed catalogue -- ~46 tools, or a closed route table -- until
	// a client calls a tool that does not exist. Those are counted
	// (OutcomeUnknownTool), the name is whatever the caller sent, and
	// an agent inventing names would otherwise mint a label value per
	// hallucination. Ordering by call volume means the real ones are
	// never the ones collapsed.
	nameLabel := labelSpace(nameTotals, limit)

	// Aggregate onto the label space. Two different verbatim users can
	// land on the same label -- both collapsed to "other" -- and their
	// counts have to be summed, not emitted twice: a duplicate label
	// set is a collection error that drops the whole scrape.
	type callKey struct{ name, user, client, outcome string }
	type histKey struct{ name, client, outcome string }

	calls := map[callKey]uint64{}
	hists := map[histKey]*Entry{}
	lastCall := map[string]float64{}
	users := map[string]map[string]struct{}{}

	for k, e := range snap {
		renderedUser := OmittedLabel
		if userLabel != nil {
			renderedUser = userLabel[k.User]
		}
		ck := callKey{nameLabel[k.Name], renderedUser, clientLabel[k.Client], k.Outcome}
		calls[ck] += e.Calls

		hk := histKey{nameLabel[k.Name], clientLabel[k.Client], k.Outcome}
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
			tl, ts := nameLabel[k.Name], float64(e.LastCall.Unix())
			if ts > lastCall[tl] {
				lastCall[tl] = ts
			}
		}

		// Counted over the VERBATIM user name, which is the whole
		// point of this gauge: it stays right when the label has
		// collapsed.
		tl := nameLabel[k.Name]
		if users[tl] == nil {
			users[tl] = map[string]struct{}{}
		}
		if k.User != UnknownUser {
			users[tl][k.User] = struct{}{}
		}
	}

	for k, n := range calls {
		ch <- prometheus.MustNewConstMetric(c.callsDesc, prometheus.CounterValue,
			float64(n), safeLabel(k.name), safeLabel(k.user), safeLabel(k.client), k.outcome)
	}

	// A kind whose latency another metric already publishes does not
	// get a second histogram here; it still has the durations, in the
	// store and in the table, which is what the admin page reads.
	if spec.ExportDurations {
		for k, e := range hists {
			cum := make(map[float64]uint64, len(DurationBuckets))
			var running uint64
			for i, b := range DurationBuckets {
				running += e.Buckets[i]
				cum[b] = running
			}
			ch <- prometheus.MustNewConstHistogram(c.durationDesc,
				e.Calls, e.DurationSum, cum, safeLabel(k.name), safeLabel(k.client), k.outcome)
		}
	}

	for name, ts := range lastCall {
		ch <- prometheus.MustNewConstMetric(c.lastCallDesc, prometheus.GaugeValue, ts, safeLabel(name))
	}

	for name, set := range users {
		ch <- prometheus.MustNewConstMetric(c.usersDesc, prometheus.GaugeValue,
			float64(len(set)), safeLabel(name))
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
