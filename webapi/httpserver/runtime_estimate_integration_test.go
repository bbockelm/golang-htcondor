//go:build integration

package httpserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/db"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/runtimeest"
)

// TestRuntimeEstimatesFromRealMirror reads finished jobs from a real
// htcondordb's history ARCHIVE -- the table kind schedd-sync creates,
// which some operations reach and others do not -- through the same
// source the refresher uses in production, and answers an estimate.
//
// Only the freshness gate is replaced: a bare htcondordb with no
// schedd-sync never advertises a history sync, so the production gate
// would (rightly) refuse it. The read itself -- constraint, projection,
// archive, parsing -- is the real one.
func TestRuntimeEstimatesFromRealMirror(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	bin := htcondordbBinary(t)
	harness := htcondor.SetupCondorHarnessWithConfig(t, "DAEMON_LIST = MASTER, COLLECTOR\n")
	startMirror(t, harness, bin, t.TempDir())

	cfg := config.NewEmpty()
	cfg.Set("SEC_DEFAULT_AUTHENTICATION_METHODS", "FS")
	cfg.Set("SEC_CLIENT_AUTHENTICATION_METHODS", "FS")
	cfg.Set("UID_DOMAIN", harness.GetTrustDomain())
	cfg.Set("TRUST_DOMAIN", harness.GetTrustDomain())
	locator := dbmirror.NewLocator(htcondor.NewCollector(harness.GetCollectorAddr()), cfg)

	waitFor(t, "the mirror to accept a connection", 45*time.Second, func() bool {
		dbc, closer, _, err := locator.Client(ctx)
		if err != nil {
			return false
		}
		defer closer()
		cerr := dbc.CreateArchiveTable(ctx, "history", db.ArchiveConfig{
			ZoneAttrs: []string{"CompletionDate", "EnteredHistoryTime"},
		})
		return cerr == nil || strings.Contains(cerr.Error(), "exists")
	})

	n := time.Now().Unix()
	dbc, closer, _, err := locator.Client(ctx)
	if err != nil {
		t.Fatalf("connecting to seed: %v", err)
	}
	var rows []string
	for i := range 4 {
		rows = append(rows, historyRecordText("rtuser", 500+i, 120, n-600+int64(i)))
	}
	rows = append(rows,
		// Removed: filtered on the server by JobStatus.
		strings.Replace(historyRecordText("rtuser", 600, 99999, n-300), "JobStatus = 4", "JobStatus = 3", 1),
		// Older than the backfill window.
		historyRecordText("rtuser", 601, 99999, n-30*24*3600),
	)
	for _, ad := range rows {
		if err := dbc.ArchiveAppend(ctx, "history", ad); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	closer()

	src := mirrorRuntimeHistory{
		locator: locator,
		gate: func(*dbmirror.Info) dbmirror.Decision {
			return dbmirror.Decision{Use: true, Reason: dbmirror.ReasonServed}
		},
	}
	r := newRuntimeRefresher(runtimeest.New(runtimeest.Config{}), src, time.Minute, 7*24*time.Hour, testLogger(t))
	if err := r.Refresh(ctx); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := r.est.Stats().JobsIngested; got != 4 {
		t.Fatalf("ingested %d jobs, want the 4 clean completions in the window", got)
	}
	res := r.est.Estimate(runtimeest.Query{Features: runtimeest.Features{Owner: "rtuser", Cmd: "/home/rtuser/sim"}})
	if !res.Available || res.EstimateSeconds != 120 || res.Basis.Level != "exact" {
		t.Errorf("estimate = %+v", res)
	}
	if want := time.Unix(n-597, 0).UTC().Format(time.RFC3339); res.Model.TrainedThrough != want {
		t.Errorf("trained through %q, want %q", res.Model.TrainedThrough, want)
	}

	// A second refresh reads from the watermark and re-ingests nothing.
	if err := r.Refresh(ctx); err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if got := r.est.Stats().JobsIngested; got != 4 {
		t.Errorf("after a second refresh: %d jobs, want still 4", got)
	}
}
