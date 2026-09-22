package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// The probe names an internal daemon's address and can be pressed
// repeatedly; neither belongs to a general user.
func TestDBMirrorTestRequiresAdmin(t *testing.T) {
	server, req := newDBMirrorServer(t, http.MethodPost, "/api/v1/dbmirror/test")

	rec := httptest.NewRecorder()
	server.handleDBMirrorTest(rec, req("alice", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin: status = %d, want 403", rec.Code)
	}

	rec = httptest.NewRecorder()
	server.handleDBMirrorTest(rec,
		httptest.NewRequestWithContext(context.Background(), "GET", "/api/v1/dbmirror/test", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: status = %d, want 405 (this runs a read, so it is a POST)", rec.Code)
	}
}

// TestDBMirrorTestReportsTheFailingStage is the whole point of the
// probe. The status card already says the mirror is not working; which
// step fails -- discovery against the collector, the authenticated
// connection, or the query itself -- is what an operator cannot get
// anywhere else, and they are different problems with different fixes.
func TestDBMirrorTestReportsTheFailingStage(t *testing.T) {
	server, req := newDBMirrorServer(t, http.MethodPost, "/api/v1/dbmirror/test")
	server.dbMirror = dbmirror.NewLocator(
		htcondor.NewCollector("collector.invalid:9618"), config.NewEmpty())

	rec := httptest.NewRecorder()
	server.handleDBMirrorTest(rec, req("root", []string{"condor-admins"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var got dbMirrorTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.OK {
		t.Error("nothing is advertising to collector.invalid; the probe should not report success")
	}
	if len(got.Stages) == 0 {
		t.Fatal("a failure with no stages is no more useful than the card already was")
	}
	last := got.Stages[len(got.Stages)-1]
	if last.Name != "discover" {
		t.Errorf("the first stage to fail should be discovery, got %q", last.Name)
	}
	if last.Error == "" {
		t.Error("the failing stage must carry the error, not just a false flag")
	}
	// Stages after the failure are not invented.
	for _, st := range got.Stages[:len(got.Stages)-1] {
		if !st.OK {
			t.Errorf("stage %q is reported failed before the one that stopped the probe", st.Name)
		}
	}
}

// TestDBMirrorTestSaysWhenRoutingIsOff: "not configured" and "broken"
// are different answers, and pressing the button on a pool with no
// mirror should get the first.
func TestDBMirrorTestSaysWhenRoutingIsOff(t *testing.T) {
	server, req := newDBMirrorServer(t, http.MethodPost, "/api/v1/dbmirror/test")

	rec := httptest.NewRecorder()
	server.handleDBMirrorTest(rec, req("root", []string{"condor-admins"}))
	var got dbMirrorTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.OK || len(got.Stages) != 1 || got.Stages[0].Name != "configured" {
		t.Fatalf("expected a single 'configured' stage: %+v", got)
	}
	if !strings.Contains(got.Stages[0].Error, "not configured") {
		t.Errorf("the reason should say routing is off, not that something broke: %q", got.Stages[0].Error)
	}
}

// TestDBMirrorTestQueryMatchesNothing: the probe is meant to be pressed
// repeatedly while chasing a misconfiguration, so it must not move rows.
func TestDBMirrorTestQueryMatchesNothing(t *testing.T) {
	if dbMirrorTestConstraint != "false" {
		t.Errorf("the probe constraint is %q; it should match nothing so the button is free to press",
			dbMirrorTestConstraint)
	}
}

// The probe walks the connection; the gate decides whether a read uses
// the mirror. They are different answers, and the panel showed only the
// first -- so a mirror whose ad carried no sync attributes reported
// three green stages while every live job read declined it and went to
// the schedd. This is what that mirror looks like now.
func TestRoutingReportsWhenReadsWouldDeclineAReachableMirror(t *testing.T) {
	// Reachable and identified, but nothing says the job queue has ever
	// synced -- the shape a projected collector read produced.
	got := routingFor(&dbmirror.Info{
		Name:    "htcondordb@ap2001",
		Address: "<10.0.0.1:9618>",
	})
	if len(got) == 0 {
		t.Fatal("no routing decisions reported for a discovered mirror")
	}

	byKind := map[string]dbMirrorRouting{}
	for _, r := range got {
		byKind[r.Kind] = r
	}
	jobs, ok := byKind["jobs"]
	if !ok {
		t.Fatalf("no decision for live job reads: %+v", got)
	}
	if jobs.Use {
		t.Error("live job reads reported as served from a mirror that has never synced the queue")
	}
	if jobs.Reason == "" {
		t.Error("a decline with no reason is what the stages already said")
	}
	// The other read kinds are judged too: history and epoch have their
	// own gates and can disagree with jobs.
	for _, kind := range []string{"history", "epoch"} {
		if _, ok := byKind[kind]; !ok {
			t.Errorf("no decision for %s reads", kind)
		}
	}
}

// A mirror that is genuinely current must not be reported as declining,
// or the panel cries wolf and operators learn to ignore it.
func TestRoutingReportsAHealthyMirrorAsServed(t *testing.T) {
	now := time.Now().Unix()
	got := routingFor(&dbmirror.Info{
		Name:    "htcondordb@ap2001",
		Address: "<10.0.0.1:9618>",
		// Caught up, synced a moment ago, no gap.
		JobQueueCaughtUp:     true,
		JobQueueLastSyncTime: now,
		JobQueueSecondsSync:  1,
		HistoryLastSyncTime:  now,
		SecondsSinceSync:     1,
	})
	for _, r := range got {
		if r.Kind == "jobs" && !r.Use {
			t.Errorf("a caught-up mirror was reported as declining live job reads: %s %s", r.Reason, r.Note)
		}
	}
}

// Nothing to judge before discovery succeeds, and the probe reports the
// stages in that case rather than an empty verdict.
func TestRoutingIsAbsentWithoutAnAd(t *testing.T) {
	if got := routingFor(nil); got != nil {
		t.Errorf("routing reported for a mirror that was never discovered: %+v", got)
	}
}

// The probe must actually attach the verdict, not merely be able to
// compute it. The connection stage still fails here -- there is no
// mirror to dial -- and that is the point: routing is judged off the ad,
// so it is reported even when the probe cannot get further, and a
// reachable-but-declining mirror is exactly the case that used to show
// three green stages and nothing else.
func TestProbeAttachesTheRoutingVerdict(t *testing.T) {
	server, _ := newDBMirrorServer(t, http.MethodPost, "/api/v1/dbmirror/test")
	server.dbMirror = dbmirror.NewLocator(
		htcondor.NewCollector("collector.invalid:9618"), config.NewEmpty())

	// A mirror that is advertising and identified, but whose ad says
	// nothing about the job queue ever having synced.
	got := server.probeDBMirrorWith(context.Background(),
		func(context.Context) (*dbmirror.Info, error) {
			return &dbmirror.Info{Name: "htcondordb@ap2001", Address: "<10.0.0.1:9618>"}, nil
		})

	if len(got.Routing) == 0 {
		t.Fatal("the probe discovered a mirror and reported no routing verdict")
	}
	var sawJobs bool
	for _, r := range got.Routing {
		if r.Kind != "jobs" {
			continue
		}
		sawJobs = true
		if r.Use {
			t.Error("live job reads reported as served from a mirror that has never synced")
		}
	}
	if !sawJobs {
		t.Errorf("no verdict for live job reads: %+v", got.Routing)
	}
}

// Nothing was discovered, so there is no ad to judge and no verdict to
// report -- an empty one would read as "declined".
func TestProbeReportsNoRoutingWhenDiscoveryFails(t *testing.T) {
	server, _ := newDBMirrorServer(t, http.MethodPost, "/api/v1/dbmirror/test")
	server.dbMirror = dbmirror.NewLocator(
		htcondor.NewCollector("collector.invalid:9618"), config.NewEmpty())

	got := server.probeDBMirrorWith(context.Background(),
		func(context.Context) (*dbmirror.Info, error) {
			return nil, errNoMirrorForTest
		})

	if len(got.Routing) != 0 {
		t.Errorf("routing reported for a mirror that was never found: %+v", got.Routing)
	}
}

var errNoMirrorForTest = errors.New("no htcondordb is advertising")
