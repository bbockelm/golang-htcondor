package httpserver

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/metricsd"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	dto "github.com/prometheus/client_model/go"
)

// metricsNamespace is the leading "<ns>_" string applied to every
// metric name we register here. Stable across releases — once a
// dashboard or alert references a metric name, renaming breaks it.
const metricsNamespace = "htcondor_api"

// httpMetrics holds the HTTP request observability metrics we record
// via the recordingMiddleware wrapper. Kept in a single struct so the
// init order is obvious (NewHandler() builds one and stashes it on the
// Handler) and tests can construct one in isolation.
type httpMetrics struct {
	registry *prometheus.Registry

	requestsTotal     *prometheus.CounterVec
	requestDuration   *prometheus.HistogramVec
	requestsInFlight  prometheus.Gauge
	scheddQueryTotal  *prometheus.CounterVec
	scheddQueryDur    prometheus.Histogram
	authFailuresTotal *prometheus.CounterVec
	mirror            *mirrorMetrics
}

// newHTTPMetrics constructs a fresh metrics state. Each Handler owns
// its own registry — we deliberately do NOT use prometheus.DefaultRegisterer
// because:
//   - Tests can spin up many Handlers in one process without
//     duplicate-registration panics.
//   - The Go runtime / process collectors are still available; we
//     register them explicitly below.
func newHTTPMetrics() *httpMetrics {
	m := &httpMetrics{
		registry: prometheus.NewRegistry(),

		requestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: "http",
				Name:      "requests_total",
				Help:      "HTTP requests handled, labeled by method, route template, and status class (2xx/3xx/4xx/5xx).",
			},
			[]string{"method", "route", "status_class"},
		),

		requestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: metricsNamespace,
				Subsystem: "http",
				Name:      "request_duration_seconds",
				Help:      "HTTP request duration. Buckets cover the typical schedd/collector RPC range.",
				// Tuned for HTCondor RPC-bound API calls: most are
				// 5-100ms, sandbox downloads / large queue scans
				// can spike to seconds. Default Prometheus buckets
				// (5ms..10s) are fine here.
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "route"},
		),

		requestsInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: "http",
			Name:      "requests_in_flight",
			Help:      "Number of HTTP requests currently being handled.",
		}),

		scheddQueryTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: "schedd",
				Name:      "queries_total",
				Help:      "Schedd queries dispatched from this API server, labeled by outcome (ok/error/rate_limited).",
			},
			[]string{"outcome"},
		),

		scheddQueryDur: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: "schedd",
			Name:      "query_duration_seconds",
			Help:      "Wall-clock latency of schedd query RPCs.",
			Buckets:   prometheus.DefBuckets,
		}),

		mirror: newMirrorMetrics(),

		authFailuresTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: "auth",
				Name:      "failures_total",
				Help:      "Authentication failures by reason (no_session, bad_token, group_denied, etc.).",
			},
			[]string{"reason"},
		),
	}

	m.registry.MustRegister(
		m.requestsTotal,
		m.requestDuration,
		m.requestsInFlight,
		m.scheddQueryTotal,
		m.scheddQueryDur,
		m.authFailuresTotal,
		m.mirror.decisions,
		// The standard Go runtime + process collectors give us GC,
		// goroutines, FD count, RSS — table stakes for any Go service.
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// recordingMiddleware wraps an http.Handler with the request counter,
// duration histogram, and in-flight gauge. The status-code label is
// bucketed to {1xx,2xx,3xx,4xx,5xx} so the cardinality stays bounded
// even if some downstream returns a wide range of codes. Route is
// derived from the URL path via classifyRoute — see that function for
// the canonical templates.
func (m *httpMetrics) middleware(next http.Handler) http.Handler {
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip recursive instrumentation for the metrics endpoint
		// itself; otherwise Prometheus scrapes start showing up in
		// the very metrics they're scraping.
		if r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		route := classifyRoute(r.URL.Path)
		method := normalizeMethod(r.Method)

		m.requestsInFlight.Inc()
		defer m.requestsInFlight.Dec()

		// statusRecorder lets us read the status code after the
		// handler returns. We default to 200 because handlers that
		// never call WriteHeader() are implicitly OK by Go's
		// http.ResponseWriter contract.
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		dur := time.Since(start).Seconds()
		statusClass := strconv.Itoa(rec.status/100) + "xx"

		m.requestsTotal.WithLabelValues(method, route, statusClass).Inc()
		m.requestDuration.WithLabelValues(method, route).Observe(dur)
	})
}

// statusRecorder wraps an http.ResponseWriter just enough to remember
// the status code the handler wrote. Falls back to 200 when no
// WriteHeader was called (the http stdlib's implicit behavior).
//
// Hijack/Flush/Push interfaces: Go's method-set rules do NOT promote
// these methods through an embedded http.ResponseWriter interface
// (the embedded interface only contributes its own three methods —
// Header / Write / WriteHeader — to the wrapper's static method set,
// regardless of what concrete type the embedded interface holds at
// runtime). An earlier version of this struct embedded
// http.ResponseWriter and assumed the interfaces would "pass through"
// — they don't. The result was every WebSocket upgrade through this
// middleware getting a 500: gorilla/websocket's Upgrade does
// `w.(http.Hijacker)` and the assertion fails.
//
// We forward Hijack explicitly. Unwrap is also exposed so any caller
// going through http.NewResponseController (Go 1.20+) reaches the
// underlying writer for Flush/Push/etc.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap returns the wrapped writer for callers using
// http.NewResponseController (Go 1.20+). This covers Flush/Push/etc.
// without each one needing an explicit forwarding method here.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Hijack forwards to the underlying ResponseWriter when it implements
// http.Hijacker. Required for the SSH-to-job and JupyterLab WebSocket
// handlers — gorilla/websocket asserts Hijacker on the response writer
// before upgrading the connection. Without this method on the
// recorder, the assertion fails and the upgrade returns 500
// "Internal Server Error" (the http.Error default body).
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("statusRecorder: underlying ResponseWriter (%T) does not implement http.Hijacker", s.ResponseWriter)
	}
	return hj.Hijack()
}

// Compile-time assertion that *statusRecorder implements http.Hijacker.
// This is the second time we've shipped a response-writer wrapper that
// embedded http.ResponseWriter without forwarding Hijack, broken every
// WebSocket upgrade through it, and only noticed when the SSH-to-job
// or Jupyter terminal returned a baffling 500. The line below makes
// any future "let's just embed the interface" refactor fail to
// compile rather than silently regress.
var _ http.Hijacker = (*statusRecorder)(nil)

// classifyRoute maps an incoming URL path to a low-cardinality template
// suitable as a Prometheus label. Without this, every job ID, batch
// ID, jupyter instance, etc. would create a new label series and
// blow up the time-series count in scrapers.
//
// Patterns are checked in order. New routes added to routes.go
// SHOULD be added here too — failing to do so puts them under a
// generic "/api/v1/<unmatched>" bucket which is still bounded but
// less informative.
func classifyRoute(path string) string {
	if path == "" {
		return "/"
	}
	for _, p := range routePatterns {
		if p.match(path) {
			return p.template
		}
	}
	if strings.HasPrefix(path, "/api/v1/") {
		return "/api/v1/<other>"
	}
	if strings.HasPrefix(path, "/mcp/") {
		return "/mcp/<other>"
	}
	return "/<other>"
}

// routePattern matches an exact path or a regex; `template` is the
// stable label string we surface to Prometheus.
type routePattern struct {
	exact    string
	re       *regexp.Regexp
	template string
}

func (p routePattern) match(path string) bool {
	if p.exact != "" {
		return p.exact == path
	}
	return p.re.MatchString(path)
}

// routePatterns lists the routes we want labeled distinctly. Static
// paths first (cheap exact match), then regexes for routes with IDs.
// Order matters: more-specific patterns must come before more-general
// ones (e.g. /jobs/{id}/log before /jobs/{id}).
var routePatterns = []routePattern{
	// Auth / session
	{exact: "/api/v1/whoami", template: "/api/v1/whoami"},
	{exact: "/api/v1/auth/me", template: "/api/v1/auth/me"},
	{exact: "/api/v1/auth/logout", template: "/api/v1/auth/logout"},
	{exact: "/login", template: "/login"},
	{exact: "/logout", template: "/logout"},

	// Dashboard / version / health
	{exact: "/api/v1/dashboard", template: "/api/v1/dashboard"},
	{exact: "/api/v1/version", template: "/api/v1/version"},
	{exact: "/healthz", template: "/healthz"},
	{exact: "/readyz", template: "/readyz"},
	{exact: "/metrics", template: "/metrics"},
	{exact: "/openapi.json", template: "/openapi.json"},
	{exact: "/docs", template: "/docs"},

	// Job collection
	{exact: "/api/v1/jobs", template: "/api/v1/jobs"},
	{exact: "/api/v1/jobs/archive", template: "/api/v1/jobs/archive"},
	{exact: "/api/v1/jobs/epochs", template: "/api/v1/jobs/epochs"},
	{exact: "/api/v1/jobs/transfers", template: "/api/v1/jobs/transfers"},
	{exact: "/api/v1/jobs/hold", template: "/api/v1/jobs/hold"},
	{exact: "/api/v1/jobs/release", template: "/api/v1/jobs/release"},

	// Job item — order is critical: longest-prefix wins.
	{re: regexp.MustCompile(`^/api/v1/jobs/[^/]+/files/.+$`), template: "/api/v1/jobs/{id}/files/{name}"},
	{re: regexp.MustCompile(`^/api/v1/jobs/[^/]+/input/multipart$`), template: "/api/v1/jobs/{id}/input/multipart"},
	{re: regexp.MustCompile(`^/api/v1/jobs/[^/]+/output/share$`), template: "/api/v1/jobs/{id}/output/share"},
	{re: regexp.MustCompile(`^/api/v1/jobs/[^/]+/(input|output|stdout|stderr|log|hold|release|ssh)$`), template: "/api/v1/jobs/{id}/{action}"},
	{re: regexp.MustCompile(`^/api/v1/jobs/[^/]+$`), template: "/api/v1/jobs/{id}"},

	// Templates
	{exact: "/api/v1/templates", template: "/api/v1/templates"},
	{re: regexp.MustCompile(`^/api/v1/templates/[^/]+$`), template: "/api/v1/templates/{id}"},

	// Credentials
	{exact: "/api/v1/creds/user", template: "/api/v1/creds/user"},
	{exact: "/api/v1/creds/service", template: "/api/v1/creds/service"},
	{re: regexp.MustCompile(`^/api/v1/creds/service/[^/]+$`), template: "/api/v1/creds/service/{name}"},

	// Jupyter — match more specific paths first.
	{re: regexp.MustCompile(`^/api/v1/jupyter/instances/[^/]+/proxy/.*$`), template: "/api/v1/jupyter/instances/{id}/proxy/*"},
	{re: regexp.MustCompile(`^/api/v1/jupyter/instances/[^/]+/(events|tunnel|stop)$`), template: "/api/v1/jupyter/instances/{id}/{action}"},
	{re: regexp.MustCompile(`^/api/v1/jupyter/instances/[^/]+$`), template: "/api/v1/jupyter/instances/{id}"},
	{exact: "/api/v1/jupyter/instances", template: "/api/v1/jupyter/instances"},

	// Interactive terminals
	{exact: "/api/v1/interactive/terminal", template: "/api/v1/interactive/terminal"},

	// Collector + ping + share + admin (collapse admin under one
	// label since the paths under /admin/ are operator-only and
	// scaling per-route adds little).
	{re: regexp.MustCompile(`^/api/v1/collector/.*$`), template: "/api/v1/collector/*"},
	{exact: "/api/v1/ping", template: "/api/v1/ping"},
	{exact: "/api/v1/schedd/ping", template: "/api/v1/schedd/ping"},
	{exact: "/api/v1/share/output", template: "/api/v1/share/output"},
	{re: regexp.MustCompile(`^/api/v1/admin/.*$`), template: "/api/v1/admin/*"},

	// MCP / IDP — bucket aggressively; these aren't user-facing flows.
	{re: regexp.MustCompile(`^/mcp/oauth2/.*$`), template: "/mcp/oauth2/*"},
	{exact: "/mcp/message", template: "/mcp/message"},
	{re: regexp.MustCompile(`^/idp/.*$`), template: "/idp/*"},
	{re: regexp.MustCompile(`^/.well-known/.*$`), template: "/.well-known/*"},
}

// normalizeMethod folds rare HTTP methods into "OTHER" so unexpected
// inputs (verb fuzzing, weird clients) can't blow up the cardinality.
func normalizeMethod(m string) string {
	switch m {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodHead, http.MethodOptions:
		return m
	default:
		return "OTHER"
	}
}

// metricsdAdapter exposes metrics from the in-house metricsd.Registry
// (PoolCollector, ProcessCollector, etc.) through the prometheus
// client_golang interface so a single /metrics endpoint serves both
// the new HTTP request metrics AND the existing pool/process ones.
//
// metricsd metrics carry their own help text, label set, and type.
// We translate per-collect rather than describing up-front because
// the metricsd registry is dynamic (collectors can return different
// label combos on different ticks).
type metricsdAdapter struct {
	registry *metricsd.Registry
}

func newMetricsdAdapter(reg *metricsd.Registry) *metricsdAdapter {
	return &metricsdAdapter{registry: reg}
}

// Describe is a no-op; we use the unchecked-collector path so
// prometheus client_golang accepts metrics that change shape between
// collects. Cost: a small startup safety check is bypassed. The
// channel parameter is unused but required by the prometheus.Collector
// interface.
func (a *metricsdAdapter) Describe(_ chan<- *prometheus.Desc) {}

func (a *metricsdAdapter) Collect(ch chan<- prometheus.Metric) {
	// metricsd's Collect doesn't accept a context-with-deadline; the
	// registry runs its own caching + per-collector timeouts. A bare
	// background context is fine here.
	metrics, err := a.registry.Collect(context.Background())
	if err != nil {
		return
	}
	for _, m := range metrics {
		var vt prometheus.ValueType
		switch m.Type {
		case metricsd.MetricTypeCounter:
			vt = prometheus.CounterValue
		case metricsd.MetricTypeGauge:
			vt = prometheus.GaugeValue
		default:
			// Histograms from metricsd are uncommon; skip rather
			// than misreport them as gauges.
			continue
		}

		labelKeys := make([]string, 0, len(m.Labels))
		labelVals := make([]string, 0, len(m.Labels))
		for k, v := range m.Labels {
			labelKeys = append(labelKeys, k)
			labelVals = append(labelVals, v)
		}
		desc := prometheus.NewDesc(m.Name, m.Help, labelKeys, nil)
		pm, err := prometheus.NewConstMetric(desc, vt, m.Value, labelVals...)
		if err != nil {
			continue
		}
		ch <- pm
	}
}

// --- htcondordb mirror routing -------------------------------------
//
// The question these answer is the one every operator of the mirror
// integration asks first: is it actually working? Before this, the only
// evidence was the "source" field on individual responses, which tells
// you about one request and nothing about the deployment.
//
// mirrorDecisions is the primary signal. The ratio of decision="served"
// to everything else is how much load actually moved off the access
// point, and the reason label says what to fix when it is not moving:
// "stale"/"not_caught_up" means the syncer is behind, "no_mirror" means
// discovery is failing, "unsupported_query" means callers are asking
// for something the mirror cannot serve and no amount of tuning will
// change that.
//
// The gauges describe the mirror itself, refreshed on scrape from the
// last discovery. They are what an alert rule watches, since staleness
// crossing the routing tolerance is exactly when serving silently moves
// back to the schedd.

// mirrorMetrics is the mirror-routing half of httpMetrics, kept
// separate so a Handler with routing disabled still exports the series
// (as zeros) rather than making dashboards handle missing metrics.
type mirrorMetrics struct {
	decisions *prometheus.CounterVec
}

func newMirrorMetrics() *mirrorMetrics {
	return &mirrorMetrics{
		decisions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: metricsNamespace,
				Subsystem: "dbmirror",
				Name:      "decisions_total",
				Help: "Routing decisions for reads that may be served from the htcondordb mirror, " +
					"by table (jobs/history), whether the mirror served it, and why.",
			},
			[]string{"table", "decision", "reason"},
		),
	}
}

// recordMirrorDecision counts one routing decision.
func (m *httpMetrics) recordMirrorDecision(table string, d dbmirror.Decision) {
	if m == nil || m.mirror == nil {
		return
	}
	decision := "declined"
	if d.Use {
		decision = "served"
	}
	m.mirror.decisions.WithLabelValues(table, decision, string(d.Reason)).Inc()
}

// mirrorCollector exports the mirror's state at scrape time rather than
// on a timer: the values come from the Locator's cached discovery, so a
// scrape costs nothing and can never block on the collector.
//
// Implemented as a custom collector because these are properties of an
// external system observed at a point in time, not events this process
// accumulates — a Gauge that some background goroutine has to remember
// to refresh would go stale silently, which is precisely the failure
// this metric exists to detect.
type mirrorCollector struct {
	locator *dbmirror.Locator

	up           *prometheus.Desc
	required     *prometheus.Desc
	caughtUp     *prometheus.Desc
	jobsStale    *prometheus.Desc
	historyStale *prometheus.Desc
	historyGap   *prometheus.Desc
	adAge        *prometheus.Desc
}

func newMirrorCollector(l *dbmirror.Locator) *mirrorCollector {
	n := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(metricsNamespace+"_dbmirror_"+name, help, nil, nil)
	}
	return &mirrorCollector{
		locator:      l,
		up:           n("up", "1 if an htcondordb mirror was discovered and is usable, 0 otherwise."),
		required:     n("required", "1 if reads must be served from the mirror (no schedd fallback), 0 otherwise."),
		caughtUp:     n("job_queue_caught_up", "1 if the mirror had drained the schedd's job_queue.log at its last poll."),
		jobsStale:    n("job_queue_staleness_seconds", "How far the mirror's job queue was behind the schedd when it last advertised. Live job reads route to the mirror only below the routing tolerance."),
		historyStale: n("history_staleness_seconds", "How far the mirror's history was behind when it last advertised."),
		adAge:        n("ad_age_seconds", "Age of the mirror advertisement these figures come from. The mirror measures its own lag when it advertises and keeps syncing between advertisements, so this is the age of the information, not of the mirror's data."),
		historyGap:   n("history_gap", "1 if the mirror reported a history durability gap, which stops all history routing."),
	}
}

func (c *mirrorCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.up
	ch <- c.required
	ch <- c.caughtUp
	ch <- c.jobsStale
	ch <- c.historyStale
	ch <- c.historyGap
	ch <- c.adAge
}

func (c *mirrorCollector) Collect(ch chan<- prometheus.Metric) {
	h := c.locator.Health()
	g := func(d *prometheus.Desc, v float64) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v)
	}
	g(c.required, b2f(h.Required))
	if !h.Enabled || h.Info == nil {
		// Routing off, or discovery has never succeeded. Report up=0 and
		// stop: emitting zero staleness here would read as "perfectly
		// fresh" on a dashboard, which is the opposite of the truth.
		g(c.up, 0)
		return
	}
	g(c.up, 1)
	g(c.caughtUp, b2f(h.Info.JobQueueCaughtUp))
	g(c.jobsStale, float64(dbmirror.JobQueueStaleness(h.Info)))
	g(c.historyStale, float64(dbmirror.HistoryStaleness(h.Info)))
	g(c.historyGap, b2f(h.Info.HistoryGap))
	if !h.InfoAt.IsZero() {
		// Without this, every other gauge here is a number with no
		// indication of how old it is, and a mirror that stopped
		// advertising looks indistinguishable from a healthy one until
		// the collector expires its ad.
		g(c.adAge, time.Since(h.InfoAt).Seconds())
	}
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// mirrorRoutingCount is one (table, decision, reason) tally read back
// out of the metrics registry.
type mirrorRoutingCount struct {
	Table    string `json:"table"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	Count    int64  `json:"count"`
}

// mirrorRoutingCounts reads the routing-decision counter, so the admin
// UI can answer "is this host actually using the mirror?" without the
// operator standing up Prometheus.
//
// It collects the ONE CounterVec directly rather than calling
// registry.Gather(). Gather runs every collector registered on the
// shared registry, and that set includes the metricsdAdapter -- whose
// Collect queries the pool for every machine, slot and job with no
// deadline. Using it to read a handful of in-process counters turned an
// admin page view into a full pool scrape: seconds of latency, hundreds
// of megabytes of ClassAds, and on a large pool an OOM kill that leaves
// no Go panic behind because SIGKILL is not catchable. The Info page
// polls, so it did that repeatedly.
//
// A CounterVec is itself a prometheus.Collector, so collecting it alone
// touches nothing else. Collect writes into the channel and blocks, so
// it runs in a goroutine while we range.
//
// Counts are cumulative since process start. That is the honest shape --
// a rate needs two samples and this endpoint only ever has one -- so the
// UI presents them as totals, not as current behavior.
func (m *httpMetrics) mirrorRoutingCounts() []mirrorRoutingCount {
	if m == nil || m.mirror == nil || m.mirror.decisions == nil {
		return nil
	}

	ch := make(chan prometheus.Metric, 64)
	go func() {
		defer close(ch)
		m.mirror.decisions.Collect(ch)
	}()

	var out []mirrorRoutingCount
	for metric := range ch {
		var pb dto.Metric
		if err := metric.Write(&pb); err != nil {
			// One unreadable series should not drop the rest; the
			// panel is a summary, not an audit.
			continue
		}
		row := mirrorRoutingCount{Count: int64(pb.GetCounter().GetValue())}
		for _, label := range pb.GetLabel() {
			switch label.GetName() {
			case "table":
				row.Table = label.GetValue()
			case "decision":
				row.Decision = label.GetValue()
			case "reason":
				row.Reason = label.GetValue()
			}
		}
		out = append(out, row)
	}
	// Stable order so the panel does not reshuffle between refreshes;
	// Gather's own order is by label hash.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Table != out[j].Table {
			return out[i].Table < out[j].Table
		}
		if out[i].Decision != out[j].Decision {
			return out[i].Decision < out[j].Decision
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}
