package httpserver

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/metricsd"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
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
// We deliberately don't try to wrap Hijack/Flush/Push: the SSH and
// Jupyter websocket handlers need to upgrade the connection and rely
// on the underlying ResponseWriter implementing http.Hijacker. By
// embedding instead of forwarding, those interfaces survive — at the
// cost of not recording bytes-written. That's fine for now; we don't
// have a metric for response size.
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

// Hijack passes through to the underlying ResponseWriter so the SSH /
// Jupyter websocket upgrade still works through the metrics wrapper.
// We mark the request as "200" since by the time a Hijacker is called
// the upgrade has already succeeded (101 Switching Protocols would be
// more accurate but the histograms then misrepresent live websocket
// duration anyway).
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

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
// collects. Cost: a small startup safety check is bypassed.
func (a *metricsdAdapter) Describe(ch chan<- *prometheus.Desc) {}

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
