package httpserver

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// TestMirrorHealthOmittedWhenRoutingIsOff: a deployment that does not
// use htcondordb must see no new field in /readyz, and nothing that
// could be read as a degraded state.
func TestMirrorHealthOmittedWhenRoutingIsOff(t *testing.T) {
	if h := mirrorHealth(dbmirror.NewLocator(nil, nil), time.Now()); h != nil {
		t.Errorf("expected no dbmirror block when routing is off, got %+v", h)
	}
	var nilLoc *dbmirror.Locator
	if h := mirrorHealth(nilLoc, time.Now()); h != nil {
		t.Errorf("nil locator should produce no block, got %+v", h)
	}
}

// TestMirrorHealthBeforeDiscovery: routing is configured but nothing has
// been found yet. "down" with the pinned targeting echoed back is what
// makes a typo in HTTP_API_DBMIRROR_NAME diagnosable — the operator sees
// the name they configured next to the fact that nothing matched it.
func TestMirrorHealthBeforeDiscovery(t *testing.T) {
	l := dbmirror.NewLocatorWithOptions(
		htcondor.NewCollector("collector.invalid"), config.NewEmpty(),
		dbmirror.Options{Name: "db-typo", Address: "<10.0.0.5:9619>", Required: true})

	h := mirrorHealth(l, time.Now())
	if h == nil {
		t.Fatal("expected a dbmirror block when routing is configured")
	}
	if h.Status != "down" {
		t.Errorf("status = %q, want down before any successful discovery", h.Status)
	}
	if !h.Required {
		t.Error("required should be reported")
	}
	if h.PinnedName != "db-typo" || h.PinnedAddress != "<10.0.0.5:9619>" {
		t.Errorf("configured targeting not echoed: %+v", h)
	}
	if h.Name != "" || h.Address != "" {
		t.Errorf("nothing was discovered, so no mirror identity should be reported: %+v", h)
	}
	// The tolerances say what "stale" means for this daemon; an operator
	// comparing staleness against the wrong number reaches the wrong
	// conclusion.
	if h.JobsToleranceSecs != dbmirror.JobsToleranceSecs || h.HistoryToleranceSecs != dbmirror.HistoryToleranceSecs {
		t.Errorf("tolerances not reported: %+v", h)
	}
}

// TestMirrorCollectorReportsDownWithoutZeroStaleness is the trap this
// collector exists to avoid: emitting 0 seconds of staleness for a
// mirror that was never found reads as "perfectly fresh" on a dashboard,
// which is the exact opposite of the truth.
func TestMirrorCollectorReportsDownWithoutZeroStaleness(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(newMirrorCollector(dbmirror.NewLocator(nil, nil)))

	got, err := testutil.CollectAndLint(reg)
	if err != nil {
		t.Fatalf("lint: %v", err)
	}
	for _, p := range got {
		t.Errorf("lint problem: %s: %s", p.Metric, p.Text)
	}

	var buf strings.Builder
	if err := testutil.CollectAndCompare(reg, strings.NewReader(`
# HELP htcondor_api_dbmirror_required 1 if reads must be served from the mirror (no schedd fallback), 0 otherwise.
# TYPE htcondor_api_dbmirror_required gauge
htcondor_api_dbmirror_required 0
# HELP htcondor_api_dbmirror_up 1 if an htcondordb mirror was discovered and is usable, 0 otherwise.
# TYPE htcondor_api_dbmirror_up gauge
htcondor_api_dbmirror_up 0
`), "htcondor_api_dbmirror_up", "htcondor_api_dbmirror_required"); err != nil {
		t.Errorf("unexpected metrics: %v %s", err, buf.String())
	}

	// The staleness gauges must be absent entirely rather than zero.
	if n := testutil.CollectAndCount(reg, "htcondor_api_dbmirror_job_queue_staleness_seconds"); n != 0 {
		t.Errorf("staleness reported for a mirror that was never discovered (%d series)", n)
	}
	if n := testutil.CollectAndCount(reg, "htcondor_api_dbmirror_history_staleness_seconds"); n != 0 {
		t.Errorf("history staleness reported for a mirror that was never discovered (%d series)", n)
	}
}
