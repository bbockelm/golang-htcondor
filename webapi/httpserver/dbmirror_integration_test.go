//go:build integration

package httpserver

import (
	"context"
	"strings"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// Everything else about mirror routing is tested against a collector
// that does not exist, which exercises the decline paths and nothing
// else. No test has ever completed discover -> dial -> query against a
// real htcondordb, and the seam nothing crossed is where the bugs were:
// a "served" tally counted before anything was dialed, a dial failure
// with no error recorded anywhere, discovery guessing between mirrors,
// and a freshness gate reading an attribute that meant something else.
// Each was invisible to unit tests because each lives in the round trip.
//
// This runs the real thing. The daemon helpers, and how the binary is
// found, are in htcondordb_harness_integration_test.go.

// TestMirrorRoundTrip is the test the unit suite structurally cannot be:
// a real collector, a real database, and a real authenticated read.
func TestMirrorRoundTrip(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	// Look for the daemon before paying for a pool: a developer without
	// htcondordb should skip in milliseconds, not after a harness boot.
	bin := htcondordbBinary(t)
	// A collector is all the pool this needs: discovery is what the
	// mirror path turns on, and a schedd would only slow the test down.
	harness := htcondor.SetupCondorHarnessWithConfig(t, "DAEMON_LIST = MASTER, COLLECTOR\n")
	startMirror(t, harness, bin, t.TempDir())

	cfg := config.NewEmpty()
	cfg.Set("SEC_DEFAULT_AUTHENTICATION_METHODS", "FS")
	cfg.Set("SEC_CLIENT_AUTHENTICATION_METHODS", "FS")
	cfg.Set("UID_DOMAIN", harness.GetTrustDomain())
	cfg.Set("TRUST_DOMAIN", harness.GetTrustDomain())

	locator := dbmirror.NewLocator(htcondor.NewCollector(harness.GetCollectorAddr()), cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Discovery. The ad reaches the collector on the update interval, so
	// this is the slow step, not the connection.
	var info *dbmirror.Info
	waitFor(t, "the collector to carry the htcondordb ad", 45*time.Second, func() bool {
		var err error
		info, err = locator.Discover(ctx)
		return err == nil && info != nil
	})
	if info.Address == "" {
		t.Fatalf("discovered a mirror with no address: %+v", info)
	}
	t.Logf("discovered %q at %s", info.Name, info.Address)

	// Connect. This is the step that was failing in production with
	// nothing recorded anywhere but a metric label.
	dbc, closer, _, err := locator.Client(ctx)
	if err != nil {
		t.Fatalf("connecting to the discovered mirror: %v", err)
	}
	defer closer()

	// A fresh database has no jobs table -- schedd-sync creates it on its
	// first pass -- and this test deliberately runs no schedd, because
	// what is under test is the round trip rather than the sync. Create
	// it, which also exercises a mutating call over the same session.
	if err := dbc.CreateTable(ctx, "jobs"); err != nil && !strings.Contains(err.Error(), "exists") {
		t.Fatalf("creating the jobs table on the mirror: %v", err)
	}

	// And a real query, over the authenticated session.
	rows, err := dbc.QueryRawProject(ctx, "jobs", "false", []string{"ClusterId"}, 1)
	if err != nil {
		t.Fatalf("querying the mirror's jobs table: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("a constraint matching nothing returned %d rows", len(rows))
	}

	// The health view must agree with what just happened. It reported a
	// mirror as healthy off the ad alone before dial failures were
	// recorded, which is how one that never answered looked fine.
	health := mirrorHealth(locator, time.Now())
	if health == nil {
		t.Fatal("no health reported for a locator that just answered a query")
	}
	if health.DialError != "" {
		t.Errorf("a successful connection left a dial error behind: %q", health.DialError)
	}
	if !health.Discovered {
		t.Error("health says nothing was discovered, immediately after a successful read")
	}
	if health.Status == "down" {
		t.Errorf("status is %q after a successful round trip", health.Status)
	}
}

// TestMirrorProbeReportsEachStage drives the admin page's test button
// against a real database, so the stages it reports are the stages that
// actually happen rather than the ones I assumed.
func TestMirrorProbeReportsEachStage(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	bin := htcondordbBinary(t)
	harness := htcondor.SetupCondorHarnessWithConfig(t, "DAEMON_LIST = MASTER, COLLECTOR\n")
	startMirror(t, harness, bin, t.TempDir())

	cfg := config.NewEmpty()
	cfg.Set("SEC_DEFAULT_AUTHENTICATION_METHODS", "FS")
	cfg.Set("SEC_CLIENT_AUTHENTICATION_METHODS", "FS")
	cfg.Set("UID_DOMAIN", harness.GetTrustDomain())
	cfg.Set("TRUST_DOMAIN", harness.GetTrustDomain())

	h := &Handler{
		dbMirror: dbmirror.NewLocator(htcondor.NewCollector(harness.GetCollectorAddr()), cfg),
		logger:   testLogger(t),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The probe queries the jobs table, so it has to exist -- see
	// TestMirrorRoundTrip.
	waitFor(t, "the mirror to accept a connection", 45*time.Second, func() bool {
		dbc, closer, _, err := h.dbMirror.Client(ctx)
		if err != nil {
			return false
		}
		defer closer()
		cerr := dbc.CreateTable(ctx, "jobs")
		return cerr == nil || strings.Contains(cerr.Error(), "exists")
	})

	got := h.probeDBMirror(ctx)

	want := []string{"discover", "connect", "query"}
	if len(got.Stages) != len(want) {
		t.Fatalf("probe reported %d stages, want %v: %+v", len(got.Stages), want, got.Stages)
	}
	for i, name := range want {
		if got.Stages[i].Name != name {
			t.Errorf("stage %d is %q, want %q", i, got.Stages[i].Name, name)
		}
		if !got.Stages[i].OK {
			t.Errorf("stage %q failed against a working mirror: %s", name, got.Stages[i].Error)
		}
	}
}
