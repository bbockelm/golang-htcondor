//go:build integration

package httpserver

import (
	"context"
	"fmt"
	"testing"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
)

// The mirror-backed half of the per-job watch, end to end.
//
// The unit tests drive jobwatch.Feed by handing it events directly, which
// says nothing about whether a change committed to a real htcondordb ever
// becomes one of those events. Everything between -- the watch opcode, the
// server's stream, the ad text on the wire, the key the delete carries --
// only exists in the round trip, and that is the half of the feature that
// had no coverage.
//
// No schedd and no schedd-sync here: writes go to the jobs table over the
// same RPC the sync uses, because what is under test is the feed, not how
// rows come to be.

// mirrorFeed starts a real htcondordb, points a Feed at it through the
// production dialer, and returns the client for writing rows.
func mirrorFeed(t *testing.T, ctx context.Context) (*Handler, *jobwatch.Feed, func(context.Context, func(*txWriter))) {
	t.Helper()

	bin := htcondordbBinary(t)
	harness := htcondor.SetupCondorHarnessWithConfig(t, "DAEMON_LIST = MASTER, COLLECTOR\n")
	startMirror(t, harness, bin, t.TempDir())

	cfg := config.NewEmpty()
	cfg.Set("SEC_DEFAULT_AUTHENTICATION_METHODS", "FS")
	cfg.Set("SEC_CLIENT_AUTHENTICATION_METHODS", "FS")
	cfg.Set("UID_DOMAIN", harness.GetTrustDomain())
	cfg.Set("TRUST_DOMAIN", harness.GetTrustDomain())

	locator := dbmirror.NewLocator(htcondor.NewCollector(harness.GetCollectorAddr()), cfg)
	waitFor(t, "the collector to carry the htcondordb ad", 45*time.Second, func() bool {
		info, err := locator.Discover(ctx)
		return err == nil && info != nil && info.Address != ""
	})

	h := &Handler{dbMirror: locator, logger: testLogger(t)}

	// The sync creates this on its first pass; there is no sync here.
	dbc, closer, _, err := locator.Client(ctx)
	if err != nil {
		t.Fatalf("connecting to the mirror: %v", err)
	}
	if err := dbc.CreateTable(ctx, "jobs"); err != nil {
		t.Fatalf("creating the jobs table: %v", err)
	}
	closer()

	feed := jobwatch.NewFeed(func(msg string, args ...any) { t.Logf(msg+" %v", args...) })
	go func() { _ = feed.Run(ctx, h.watchJobsTable) }()
	waitFor(t, "the feed to connect", 30*time.Second, feed.Warm)

	// write runs one transaction against the jobs table.
	write := func(ctx context.Context, fn func(*txWriter)) {
		t.Helper()
		dbc, closer, _, err := locator.Client(ctx)
		if err != nil {
			t.Fatalf("connecting to write: %v", err)
		}
		defer closer()
		tx, err := dbc.BeginTable(ctx, "jobs")
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		w := &txWriter{t: t, ctx: ctx, tx: tx}
		fn(w)
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	return h, feed, write
}

func TestMirrorFeedDeliversAJobsChanges(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	_, feed, write := mirrorFeed(t, ctx)

	ch, unsub := feed.Subscribe(42, 0)
	defer unsub()

	// A different job first: the stream carries the whole table, and the
	// filtering is the reason a per-job subscriber is cheap to have.
	write(ctx, func(w *txWriter) {
		w.newJob("41.0", 41, 0, 1)
	})
	select {
	case c := <-ch:
		t.Fatalf("another job's change reached this subscriber: %+v", c)
	case <-time.After(3 * time.Second):
	}

	write(ctx, func(w *txWriter) {
		w.newJob("42.0", 42, 0, 1)
	})
	got := recvChange(t, ch, 30*time.Second)
	if got.Ad == nil {
		t.Fatalf("expected an ad for 42.0, got %+v", got)
	}
	if v, _ := got.Ad.EvaluateAttrInt("JobStatus"); v != 1 {
		t.Errorf("JobStatus = %d, want 1", v)
	}

	// An attribute edit is what the session pages are waiting on.
	write(ctx, func(w *txWriter) {
		w.set("42.0", "JobStatus", "2")
	})
	got = recvChange(t, ch, 30*time.Second)
	if v, _ := got.Ad.EvaluateAttrInt("JobStatus"); v != 2 {
		t.Errorf("after the edit JobStatus = %d, want 2", v)
	}
}

func TestMirrorFeedReportsAJobLeavingTheQueue(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	_, feed, write := mirrorFeed(t, ctx)

	ch, unsub := feed.Subscribe(43, 0)
	defer unsub()

	write(ctx, func(w *txWriter) { w.newJob("43.0", 43, 0, 1) })
	if got := recvChange(t, ch, 30*time.Second); got.Ad == nil {
		t.Fatalf("expected the initial ad, got %+v", got)
	}

	// The delete carries only the storage key. Attributing it to a
	// subscriber depends on the feed still holding the last upsert, which
	// is the part a unit test cannot show is true of a real stream: it
	// depends on the key the server actually sends matching the one the
	// upsert arrived under.
	write(ctx, func(w *txWriter) { w.destroy("43.0") })
	got := recvChange(t, ch, 30*time.Second)
	if !got.Gone {
		t.Fatalf("expected Gone after the row was destroyed, got %+v", got)
	}
}

func recvChange(t *testing.T, ch <-chan jobwatch.KeyChange, limit time.Duration) jobwatch.KeyChange {
	t.Helper()
	for deadline := time.Now().Add(limit); time.Now().Before(deadline); {
		select {
		case c, open := <-ch:
			if !open {
				t.Fatal("the subscription closed")
			}
			// A stale marker is not the change under test; the feed
			// reconnects on its own and the next change follows.
			if c.Stale {
				continue
			}
			return c
		case <-time.After(time.Second):
		}
	}
	t.Fatalf("no change within %s", limit)
	return jobwatch.KeyChange{}
}

// txWriter is the little bit of sugar that keeps the tests readable.
type txWriter struct {
	t   *testing.T
	ctx context.Context
	tx  interface {
		NewClassAd(context.Context, string, string) error
		SetAttribute(context.Context, string, string, string) error
		DestroyClassAd(context.Context, string) error
	}
}

func (w *txWriter) newJob(key string, cluster, proc, status int) {
	w.t.Helper()
	ad := fmt.Sprintf("ClusterId = %d\nProcId = %d\nJobStatus = %d\nOwner = \"tester\"\n",
		cluster, proc, status)
	if err := w.tx.NewClassAd(w.ctx, key, ad); err != nil {
		w.t.Fatalf("NewClassAd(%s): %v", key, err)
	}
}

func (w *txWriter) set(key, name, expr string) {
	w.t.Helper()
	if err := w.tx.SetAttribute(w.ctx, key, name, expr); err != nil {
		w.t.Fatalf("SetAttribute(%s.%s): %v", key, name, err)
	}
}

func (w *txWriter) destroy(key string) {
	w.t.Helper()
	if err := w.tx.DestroyClassAd(w.ctx, key); err != nil {
		w.t.Fatalf("DestroyClassAd(%s): %v", key, err)
	}
}

// TestMirrorRawWatchDelivers is a diagnostic: it reads the dialer's own
// channel rather than going through the Feed, so a failure says which
// side is at fault.
func TestMirrorRawWatchDelivers(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (forks a real htcondordb)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
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
	waitFor(t, "the collector to carry the htcondordb ad", 45*time.Second, func() bool {
		info, err := locator.Discover(ctx)
		return err == nil && info != nil && info.Address != ""
	})

	dbc, closer, _, err := locator.Client(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer closer()
	if err := dbc.CreateTable(ctx, "jobs"); err != nil {
		t.Logf("CreateTable: %v", err)
	}

	head, err := dbc.WatchHead(ctx, "jobs")
	if err != nil {
		t.Fatalf("WatchHead: %v", err)
	}
	t.Logf("head cursor: %d bytes", len(head))

	raw, stop, err := dbc.WatchTable(ctx, "jobs", head)
	if err != nil {
		t.Fatalf("WatchTable: %v", err)
	}
	defer stop()

	// Write on a second connection, the way the feed and the sync are
	// separate processes in production.
	go func() {
		time.Sleep(2 * time.Second)
		wc, wcloser, _, werr := locator.Client(ctx)
		if werr != nil {
			t.Errorf("write connect: %v", werr)
			return
		}
		defer wcloser()
		tx, terr := wc.BeginTable(ctx, "jobs")
		if terr != nil {
			t.Errorf("begin: %v", terr)
			return
		}
		if aerr := tx.NewClassAd(ctx, "77.0", "ClusterId = 77\nProcId = 0\nJobStatus = 1\n"); aerr != nil {
			t.Errorf("NewClassAd: %v", aerr)
			return
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			t.Errorf("commit: %v", cerr)
		}
		t.Log("wrote 77.0")
	}()

	// Collect for a while: the first event is the end-of-catch-up marker
	// (kind 3, Synced), not the write. Returning on the first event says
	// only that the stream opened.
	deadline := time.After(30 * time.Second)
	var sawUpsert bool
	for !sawUpsert {
		select {
		case ev, ok := <-raw:
			if !ok {
				t.Fatal("the raw watch channel closed")
			}
			t.Logf("RAW EVENT kind=%d key=%q adText=%q", ev.Kind, ev.Key, ev.AdText)
			if ev.Kind == 0 && ev.Key == "77.0" {
				sawUpsert = true
			}
		case <-deadline:
			t.Fatal("no upsert for 77.0 within 30s")
		}
	}
}
