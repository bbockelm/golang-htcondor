package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

func newDBMirrorStatusServer(t *testing.T) (*Server, func(user string, groups []string) *http.Request) {
	t.Helper()
	server, err := NewServer(Config{
		ListenAddr:   "127.0.0.1:0",
		ScheddName:   "test",
		ScheddAddr:   "127.0.0.1:9618",
		SessionTTL:   time.Hour,
		OAuth2DBPath: t.TempDir() + "/t.db",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	server.webuiAdminGroup = "condor-admins"

	return server, func(user string, groups []string) *http.Request {
		sid, _, err := server.sessionStore.Create(user, groups)
		if err != nil {
			t.Fatalf("session create: %v", err)
		}
		r := httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/dbmirror/status", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec
		return r
	}
}

// The endpoint names an internal daemon's address and describes how the
// deployment is wired; neither belongs to a general user.
func TestDBMirrorStatusRequiresAdmin(t *testing.T) {
	server, req := newDBMirrorStatusServer(t)

	rec := httptest.NewRecorder()
	server.handleDBMirrorStatus(rec, req("alice", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin: status = %d, want 403", rec.Code)
	}

	rec = httptest.NewRecorder()
	server.handleDBMirrorStatus(rec,
		httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/dbmirror/status", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: status = %d, want 401", rec.Code)
	}
}

// With no collector configured, routing cannot run. The endpoint must
// say so plainly rather than reporting an absent mirror as a failure --
// "disabled" and "broken" are different answers for the operator.
func TestDBMirrorStatusReportsDisabled(t *testing.T) {
	server, req := newDBMirrorStatusServer(t)

	rec := httptest.NewRecorder()
	server.handleDBMirrorStatus(rec, req("root", []string{"condor-admins"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp dbMirrorStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Enabled {
		t.Error("routing must report disabled with no collector configured")
	}
	if resp.Health != nil {
		t.Errorf("health should be absent when routing is off, got %+v", resp.Health)
	}
}

// The counts are the part that answers "is the mirror actually serving
// my queries", so they have to reflect real decisions rather than always
// reading zero.
func TestDBMirrorStatusCountsRoutingDecisions(t *testing.T) {
	server, req := newDBMirrorStatusServer(t)

	server.recordMirror("jobs", dbmirror.Decision{Use: true, Reason: dbmirror.ReasonServed})
	server.recordMirror("jobs", dbmirror.Decision{Use: true, Reason: dbmirror.ReasonServed})
	server.recordMirror("history", dbmirror.Decision{Reason: dbmirror.ReasonStale})

	rec := httptest.NewRecorder()
	server.handleDBMirrorStatus(rec, req("root", []string{"condor-admins"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp dbMirrorStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ServedTotal != 2 {
		t.Errorf("served_total = %d, want 2", resp.ServedTotal)
	}
	if resp.DeclinedTotal != 1 {
		t.Errorf("declined_total = %d, want 1", resp.DeclinedTotal)
	}

	var sawServedJobs, sawStaleHistory bool
	for _, row := range resp.Routing {
		if row.Table == "jobs" && row.Decision == "served" && row.Count == 2 {
			sawServedJobs = true
		}
		if row.Table == "history" && row.Decision == "declined" &&
			row.Reason == string(dbmirror.ReasonStale) && row.Count == 1 {
			sawStaleHistory = true
		}
	}
	if !sawServedJobs {
		t.Errorf("missing the served jobs tally: %+v", resp.Routing)
	}
	if !sawStaleHistory {
		t.Errorf("missing the declined history tally with its reason: %+v", resp.Routing)
	}
}

// Rows must come back in a stable order or the panel reshuffles on every
// refresh; Gather's own order is by label hash.
func TestDBMirrorRoutingCountsAreOrdered(t *testing.T) {
	server, _ := newDBMirrorStatusServer(t)

	server.recordMirror("jobs", dbmirror.Decision{Reason: dbmirror.ReasonStale})
	server.recordMirror("history", dbmirror.Decision{Use: true, Reason: dbmirror.ReasonServed})
	server.recordMirror("jobs", dbmirror.Decision{Use: true, Reason: dbmirror.ReasonServed})
	server.recordMirror("history", dbmirror.Decision{Reason: dbmirror.ReasonNoMirror})

	first := server.httpMetricsState.mirrorRoutingCounts()
	if len(first) != 4 {
		t.Fatalf("got %d rows, want 4: %+v", len(first), first)
	}
	for i := 1; i < len(first); i++ {
		a, b := first[i-1], first[i]
		if a.Table > b.Table ||
			(a.Table == b.Table && a.Decision > b.Decision) ||
			(a.Table == b.Table && a.Decision == b.Decision && a.Reason > b.Reason) {
			t.Fatalf("rows are not ordered at %d: %+v", i, first)
		}
	}
	for i, row := range server.httpMetricsState.mirrorRoutingCounts() {
		if row != first[i] {
			t.Errorf("row %d changed between reads: %+v vs %+v", i, row, first[i])
		}
	}
}

// A Locator with a collector and config reports enabled even before
// discovery has found anything: "configured but nothing advertising" is
// a different answer from "not configured", and the operator needs to
// tell them apart.
func TestDBMirrorStatusEnabledWithoutDiscovery(t *testing.T) {
	server, req := newDBMirrorStatusServer(t)
	server.dbMirror = dbmirror.NewLocator(
		htcondor.NewCollector("collector.invalid:9618"), config.NewEmpty())

	rec := httptest.NewRecorder()
	server.handleDBMirrorStatus(rec, req("root", []string{"condor-admins"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp dbMirrorStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Enabled {
		t.Fatal("routing must report enabled when a collector and config are present")
	}
	if resp.Health == nil {
		t.Fatal("health must be reported once routing is enabled")
	}
	// Nothing discovered yet, so reads are falling back to the schedd.
	if resp.Health.Status != "down" {
		t.Errorf("status = %q, want down before discovery succeeds", resp.Health.Status)
	}
	// The endpoint probes rather than reporting whatever a previous read
	// happened to leave behind. Without that, an idle daemon reports
	// "not reachable" for a mirror it never tried to reach, and the
	// operator gets no error to work from and no idea when -- or
	// whether -- anything was checked. Both of these are empty when the
	// probe did not run.
	if resp.Health.LastAttempt == "" {
		t.Error("the status endpoint must run discovery, recording when it last tried")
	}
	if resp.Health.LastError == "" {
		t.Error("an unreachable collector must surface its error, not a bare 'down'")
	}
	if resp.Health.Discovered {
		t.Error("nothing is advertising, so discovered must be false")
	}
}

// expensiveCollector stands in for the metricsdAdapter: a collector on
// the shared registry whose Collect is costly. The real one queries the
// pool for every machine, slot and job, with no deadline.
type expensiveCollector struct {
	collected atomic.Int64
	desc      *prometheus.Desc
}

func newExpensiveCollector() *expensiveCollector {
	return &expensiveCollector{
		desc: prometheus.NewDesc("test_expensive_metric", "stands in for a pool scrape", nil, nil),
	}
}

func (c *expensiveCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *expensiveCollector) Collect(ch chan<- prometheus.Metric) {
	c.collected.Add(1)
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, 1)
}

// Reading the routing counters must not run the other collectors on the
// shared registry.
//
// This is a regression test for a real outage, not a hypothetical: the
// first version called registry.Gather(), which runs EVERY registered
// collector -- including the metricsdAdapter, whose Collect scrapes the
// whole pool with no deadline. Loading the admin Info page therefore
// triggered a full pool scrape, and on a large pool the container was
// OOM-killed. SIGKILL is not catchable, so nothing was logged and the
// process just vanished; the page showed a bare "Could not load mirror
// status" and the pod restarted. The page polls, so it recurred.
func TestMirrorRoutingCountsDoesNotScrapeTheRegistry(t *testing.T) {
	m := newHTTPMetrics()
	expensive := newExpensiveCollector()
	m.registry.MustRegister(expensive)

	m.recordMirrorDecision("jobs", dbmirror.Decision{Use: true, Reason: dbmirror.ReasonServed})
	m.recordMirrorDecision("history", dbmirror.Decision{Reason: dbmirror.ReasonStale})

	counts := m.mirrorRoutingCounts()

	if n := expensive.collected.Load(); n != 0 {
		t.Errorf("reading the routing counters ran %d other collector(s); "+
			"on a real deployment that is a full pool scrape per page view", n)
	}

	// And it still has to return the counts, or the cheap version is
	// cheap for the wrong reason.
	if len(counts) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(counts), counts)
	}
	var served, declined int64
	for _, row := range counts {
		if row.Decision == "served" {
			served += row.Count
			continue
		}
		declined += row.Count
	}
	if served != 1 || declined != 1 {
		t.Errorf("served=%d declined=%d, want 1 and 1 (%+v)", served, declined, counts)
	}

	// Sanity check on the fixture: the collector IS reachable through
	// the registry, so the assertion above is about our access path and
	// not about a collector that could never have run.
	if _, err := m.registry.Gather(); err != nil {
		t.Fatalf("Gather: %v", err)
	}
	if n := expensive.collected.Load(); n == 0 {
		t.Error("fixture is inert: Gather did not run the expensive collector either")
	}
}
