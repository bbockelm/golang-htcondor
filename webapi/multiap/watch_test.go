package multiap

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

// Job watches over the hub: the real evaluator, the real WatchSource, a
// real (in-process) hub. The central rule -- a tracked job's absence
// from the queue is evidence it finished only for an AP whose source is
// fresh and whose jobs stream is connected without error -- is driven
// through every state federation_sources can report.

const (
	ap1 = "ap1.example.org"
	ap2 = "ap2.example.org"
)

// sourceAd is a federation_sources row for schedd in the given state,
// with its jobs stream connected and a measured staleness unless the
// test overrides those lines.
func sourceAd(schedd, state string, lines ...string) string {
	ad := fmt.Sprintf("ScheddName = %q\nState = %q\nJobsConnected = true\nStalenessSeconds = 2\nLastSeen = %d\n"+
		"JobsRows = 1\nHistoryConnected = true\nSyncStatusConnected = true",
		schedd, state, time.Now().Unix())
	for _, l := range lines {
		ad += "\n" + l
	}
	return ad
}

// watchRig is alice's "done" watch over 1.0, which exists on both APs;
// bob has 4.0 on ap1, an id alice does not have.
type watchRig struct {
	t     *testing.T
	hub   *testDB
	reg   *multiaptest.Registry
	svc   *Service
	store *jobwatch.Store
	eval  *jobwatch.Evaluator
}

func newWatchRig(t *testing.T, mode jobwatch.Mode, constraint string) *watchRig {
	t.Helper()
	hub := hubDB(t)
	hub.PutJob(ap1, "alice@d", 1, 0, "")
	hub.PutJob(ap2, "alice@d", 1, 0, "")
	hub.PutJob(ap1, "bob@d", 4, 0, "")
	hub.PutSourceAd(ap1, sourceAd(ap1, StateFresh))
	hub.PutSourceAd(ap2, sourceAd(ap2, StateFresh))
	reg := newFakeRegistry(ap1, ap2)
	svc := newService(t, hub, reg)

	sqldb, err := appdb.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := appdb.Migrate(context.Background(), sqldb); err != nil {
		t.Fatal(err)
	}
	store := jobwatch.NewStore(sqldb)
	r := &watchRig{t: t, hub: hub, reg: reg, svc: svc, store: store,
		eval: jobwatch.NewEvaluator(store, WatchSource{Service: svc}, nil)}
	w, err := jobwatch.New("alice", "", constraint, jobwatch.EventDone, "", mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Register(context.Background(), w, 0); err != nil {
		t.Fatal(err)
	}
	return r
}

// advanceHub moves the hub's clock past the evaluator's last sighting:
// what the rule needs to see before an absence counts is a
// federation_sources read newer than the job's last sighting by the
// bound on how stale it may be.
func (r *watchRig) advanceHub(by time.Duration) {
	r.t.Helper()
	r.advanceHubFrom(time.Now(), by)
}

// advanceHubFrom sets the hub's clock to from+by.
func (r *watchRig) advanceHubFrom(from time.Time, by time.Duration) {
	r.t.Helper()
	at := from.Add(by)
	r.svc.Hub.now = func() time.Time { return at }
	if err := r.svc.Hub.Refresh(context.Background()); err != nil {
		r.t.Fatal(err)
	}
}

func (r *watchRig) pass() jobwatch.Stats {
	r.t.Helper()
	st, err := r.eval.Pass(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	return st
}

func (r *watchRig) watch() *jobwatch.Watch {
	r.t.Helper()
	all, err := r.store.ForOwner(context.Background(), "alice", nil)
	if err != nil || len(all) != 1 {
		r.t.Fatalf("ForOwner: %d, %v", len(all), err)
	}
	return all[0]
}

// TestWatchAbsenceRuleMatrix: ap2's 1.0 leaves the hub's queue. Only a
// fresh, connected, error-free, trusted ap2 -- on a hub snapshot this
// server can still vouch for -- makes that absence a completion.
// Everything else waits; ap1's 1.0 is never touched.
func TestWatchAbsenceRuleMatrix(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(r *watchRig)
		fires bool
	}{
		{"fresh and connected", func(*watchRig) {}, true},
		{"stale", func(r *watchRig) { r.hub.PutSourceAd(ap2, sourceAd(ap2, StateStale)) }, false},
		{"absent", func(r *watchRig) { r.hub.PutSourceAd(ap2, sourceAd(ap2, StateAbsent)) }, false},
		{"untrusted on the hub", func(r *watchRig) { r.hub.PutSourceAd(ap2, sourceAd(ap2, StateUntrusted)) }, false},
		{"retiring", func(r *watchRig) { r.hub.PutSourceAd(ap2, sourceAd(ap2, StateRetiring)) }, false},
		{"jobs stream disconnected", func(r *watchRig) {
			r.hub.PutSourceAd(ap2, strings.Replace(sourceAd(ap2, StateFresh), "JobsConnected = true", "JobsConnected = false", 1))
		}, false},
		{"jobs stream erroring", func(r *watchRig) {
			r.hub.PutSourceAd(ap2, sourceAd(ap2, StateFresh, `JobsLastError = "connection reset by peer"`))
		}, false},
		{"spoke restarted, replay in progress", func(r *watchRig) {
			// cedarsync keeps the session's error until a session reaches
			// Synced; the hub's Reset sweep runs only at Synced.
			r.hub.PutSourceAd(ap2, sourceAd(ap2, StateStale, fmt.Sprintf("LastReset = %d", time.Now().Unix()),
				`JobsLastError = "EOF"`))
		}, false},
		{"no measured staleness", func(r *watchRig) {
			r.hub.PutSourceAd(ap2, strings.Replace(sourceAd(ap2, StateFresh), "StalenessSeconds = 2\n", "", 1))
		}, false},
		{"untrusted by the trust probe", func(r *watchRig) {
			r.reg.Update(ap2, func(m *apregistry.Member) {
				m.Trust = apregistry.Trust{State: apregistry.TrustUntrusted, Reason: "refused the token"}
			})
		}, false},
		{"jobs catch-up published and done", func(r *watchRig) {
			r.hub.PutSourceAd(ap2, sourceAd(ap2, StateFresh, "JobsSynced = true", "JobsSyncedAt = 100"))
		}, true},
		{"jobs catch-up published and not done", func(r *watchRig) {
			// A from-scratch replay: connected, no error, fresh heartbeat,
			// rows still arriving.
			r.hub.PutSourceAd(ap2, sourceAd(ap2, StateFresh, "JobsSynced = false", "JobsSyncedAt = 100"))
		}, false},
		{"no catch-up published, reset just now", func(r *watchRig) {
			r.hub.PutSourceAd(ap2, sourceAd(ap2, StateFresh,
				fmt.Sprintf("LastReset = %d", time.Now().Add(3*time.Hour-time.Minute).Unix())))
		}, false},
		{"no catch-up published, reset long ago", func(r *watchRig) {
			r.hub.PutSourceAd(ap2, sourceAd(ap2, StateFresh,
				fmt.Sprintf("LastReset = %d", time.Now().Add(-time.Hour).Unix())))
		}, true},
		{"not in the AP set", func(r *watchRig) {
			r.reg.Remove(ap2)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newWatchRig(t, jobwatch.ModeAny, "ClusterId == 1")
			r.pass()
			if got := r.watch().Tracked; len(got) != 2 {
				t.Fatalf("tracked %+v, want alice's 1.0 on both APs and not bob's", got)
			}
			r.hub.DeleteJob(ap2, 1, 0)
			tc.setup(r)
			r.advanceHub(3 * time.Hour) // past the test hub's one-hour interval
			st := r.pass()
			if fired := st.Fired == 1; fired != tc.fires {
				t.Fatalf("fired=%v, want %v", fired, tc.fires)
			}
			if tc.fires {
				w := r.watch()
				if len(w.Matched) != 1 || w.Matched[0].Schedd != ap2 {
					t.Fatalf("matched %+v, want 1.0@%s alone", w.Matched, ap2)
				}
			}
		})
	}
}

// TestWatchWaitsOnAnUnreachableHub: with no hub the pass fails rather
// than reading an empty queue.
func TestWatchWaitsOnAnUnreachableHub(t *testing.T) {
	r := newWatchRig(t, jobwatch.ModeAny, "ClusterId == 1")
	r.pass()
	r.hub.DeleteJob(ap2, 1, 0)
	r.advanceHub(3 * time.Hour)
	r.svc.Hub.Active().dial = func(context.Context) (*dbrpc.Client, func(), error) {
		return nil, nil, errors.New("connection refused")
	}
	if st := r.pass(); st.Fired != 0 || st.Errors != 1 {
		t.Fatalf("stats %+v: an unreachable hub must be a failed pass, not an empty queue", st)
	}
}

// TestWatchCatchUpMustHoldAcrossTheRead: an AP is vouched for only if
// the federation_sources read after the jobs read still says JobsSynced
// with the JobsSyncedAt the read before it did.
func TestWatchCatchUpMustHoldAcrossTheRead(t *testing.T) {
	r := newWatchRig(t, jobwatch.ModeAny, "ClusterId == 1")
	parse := func(text string) map[string]Source {
		ad, err := classad.ParseOld(text)
		if err != nil {
			t.Fatal(err)
		}
		src, _ := ParseSource(ad)
		return map[string]Source{ap2: src}
	}
	at := time.Now()
	synced := parse(sourceAd(ap2, StateFresh, "JobsSynced = true", "JobsSyncedAt = 100"))
	for name, after := range map[string]map[string]Source{
		"a replay began":    parse(sourceAd(ap2, StateFresh, "JobsSynced = false", "JobsSyncedAt = 100")),
		"a replay finished": parse(sourceAd(ap2, StateFresh, "JobsSynced = true", "JobsSyncedAt = 200")),
		"the row went":      {},
	} {
		if _, ok := r.svc.coverage(jobwatch.NewCoverage(), synced, after, at).AsOf(ap2); ok {
			t.Errorf("%s during the read, yet ap2 was vouched for", name)
		}
	}
	// Not caught up before the read is not vouched for, whatever the
	// read after it says.
	catching := parse(sourceAd(ap2, StateFresh, "JobsSynced = false", "JobsSyncedAt = 100"))
	if _, ok := r.svc.coverage(jobwatch.NewCoverage(), catching, synced, at).AsOf(ap2); ok {
		t.Error("ap2 was vouched for on a read made while its jobs were still catching up")
	}
	if _, ok := r.svc.coverage(jobwatch.NewCoverage(), synced, synced, at).AsOf(ap2); !ok {
		t.Error("an unchanged catch-up across the read was not vouched for")
	}
}

// TestWatchAbsenceWaitsForTheHorizon: a job gone from a fresh AP counts
// as finished only once a federation_sources read is newer than its last
// sighting by the reported staleness, the row's refresh lag and one hub
// state interval -- not a moment before. Each term is large enough here
// that dropping any one fires early.
func TestWatchAbsenceWaitsForTheHorizon(t *testing.T) {
	r := newWatchRig(t, jobwatch.ModeAny, "ClusterId == 1")
	r.hub.PutSourceAd(ap2, strings.Replace(sourceAd(ap2, StateFresh), "StalenessSeconds = 2", "StalenessSeconds = 30", 1))
	r.pass()
	sighted := time.Now() // just after the read that last saw it
	r.hub.DeleteJob(ap2, 1, 0)
	horizon := 30*time.Second + sourceRowRefresh + DefaultHubStateInterval
	r.advanceHubFrom(sighted, horizon-2*time.Second)
	if st := r.pass(); st.Fired != 0 {
		t.Fatal("fired before the horizon")
	}
	r.advanceHubFrom(sighted, horizon+2*time.Second)
	if st := r.pass(); st.Fired != 1 {
		t.Fatal("did not fire past the horizon")
	}
}

// TestWatchQueueReadReportsTruncation: a queue read past its limit says
// so, and the evaluator then treats no absence as evidence.
func TestWatchQueueReadReportsTruncation(t *testing.T) {
	r := newWatchRig(t, jobwatch.ModeAny, "ClusterId == 1")
	var got int
	truncated, _, err := WatchSource{Service: r.svc}.QueueCovered(context.Background(), "alice",
		[]string{"ClusterId"}, 1, func(*classad.ClassAd) { got++ })
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || got != 1 {
		t.Fatalf("truncated=%v with %d rows yielded: alice has two jobs and the limit is one", truncated, got)
	}
}

// TestWatchHistoryFiresOnAStaleAP: a history record on the hub is
// terminal evidence of its own; the AP's freshness does not matter.
func TestWatchHistoryFiresOnAStaleAP(t *testing.T) {
	r := newWatchRig(t, jobwatch.ModeAny, "ClusterId == 1")
	r.pass()
	r.hub.DeleteJob(ap2, 1, 0)
	r.hub.PutSourceAd(ap2, sourceAd(ap2, StateStale))
	r.hub.PutHistory(ap2, "alice@d", 1, 0, time.Now().Unix())
	r.advanceHub(time.Second)
	if st := r.pass(); st.Fired != 1 {
		t.Fatal("a history record on a stale AP did not fire the watch")
	}
	w := r.watch()
	if len(w.Matched) != 1 || w.Matched[0].Schedd != ap2 || w.Matched[0].Attrs["JobStatus"] != "4" {
		t.Fatalf("matched %+v, want 1.0@%s from its history record", w.Matched, ap2)
	}
}

// TestWatchIsOwnerScoped: the source reads one owner's jobs by User,
// whatever the watch's constraint says. bob's 4.0 on ap1, an id alice
// does not have, is never tracked though the constraint names him.
func TestWatchIsOwnerScoped(t *testing.T) {
	r := newWatchRig(t, jobwatch.ModeAll, `ClusterId == 1 || Owner == "bob" || User == "bob@d"`)
	r.hub.PutJob(ap1, "bob@d", 5, 0, "")
	r.pass()
	for _, id := range r.watch().Tracked {
		if id.Cluster != 1 || id.Proc != 0 {
			t.Errorf("tracked %+v: another user's job", id)
		}
	}
	if n := len(r.watch().Tracked); n != 2 {
		t.Errorf("tracked %d jobs, want alice's two", n)
	}
	// alice's 1.0 leaves ap1; her 1.0 on ap2 is still queued, so the
	// "all" watch waits.
	r.hub.DeleteJob(ap1, 1, 0)
	r.advanceHub(3 * time.Hour)
	if st := r.pass(); st.Fired != 0 {
		t.Fatal(`an "all" watch fired with alice's 1.0@ap2 still queued`)
	}
}

// TestWatchSourceRefusesAnotherDomain: a watch owner is a local name;
// an identity in another domain never reaches the hub.
func TestWatchSourceRefusesAnotherDomain(t *testing.T) {
	r := newWatchRig(t, jobwatch.ModeAny, "ClusterId == 1")
	_, _, err := WatchSource{Service: r.svc}.QueueCovered(context.Background(), "alice@elsewhere",
		[]string{"ClusterId"}, 10, func(*classad.ClassAd) {})
	if err == nil {
		t.Fatal("a watch read for alice@elsewhere was served")
	}
}

// TestWatchCoverageBound: the time an AP is vouched for up to allows
// for the staleness the hub reported, the row's own lag and one hub
// state interval.
func TestWatchCoverageBound(t *testing.T) {
	r := newWatchRig(t, jobwatch.ModeAny, "ClusterId == 1")
	r.hub.PutSourceAd(ap2, sourceAd(ap2, StateFresh, "StalenessSeconds = 30"))
	r.advanceHub(0)
	at := r.svc.Hub.Status().LastSuccess
	asOf, ok := r.svc.WatchCoverage(context.Background()).AsOf(ap2)
	if !ok {
		t.Fatal("a fresh, connected ap2 is not vouched for")
	}
	if want := at.Add(-30*time.Second - sourceRowRefresh - DefaultHubStateInterval); !asOf.Equal(want) {
		t.Errorf("ap2 vouched for up to %v, want %v", asOf, want)
	}
}

// TestFeedHooks: the hub feed names a row's owner by User in UID_DOMAIN
// only.
func TestFeedHooks(t *testing.T) {
	r := newWatchRig(t, jobwatch.ModeAny, "ClusterId == 1")
	row := func(schedd, user string) *classad.ClassAd {
		ad := classad.New()
		ad.InsertAttrString(AttrScheddName, schedd)
		ad.InsertAttrString(AttrUser, user)
		return ad
	}
	if got := r.svc.OwnerOfRow(row(ap1, "alice@d")); got != "alice" {
		t.Errorf("owner of alice@d = %q", got)
	}
	if got := r.svc.OwnerOfRow(row(ap1, "alice@elsewhere")); got != "" {
		t.Errorf("owner of alice@elsewhere = %q, want none", got)
	}
}

// TestHubFederatesFromSourceRows: the hub federates epoch_history when
// its source rows carry EpochHistoryConnected.
func TestHubFederatesFromSourceRows(t *testing.T) {
	r := newWatchRig(t, jobwatch.ModeAny, "ClusterId == 1")
	if r.svc.Hub.Active().Federates(TableEpochHistory) {
		t.Fatal("federates epoch_history with no row listing it")
	}
	if !r.svc.Hub.Active().Federates(TableHistory) {
		t.Fatal("does not federate history, which every row lists")
	}
	r.hub.PutSourceAd(ap1, sourceAd(ap1, StateFresh, "EpochHistoryConnected = false"))
	r.advanceHub(0)
	if !r.svc.Hub.Active().Federates(TableEpochHistory) {
		t.Fatal("does not federate epoch_history, which ap1's row lists")
	}
}

// followHub runs a feed over the in-process hub's jobs table, as the
// server does (Service.OpenJobsWatch), until the test ends.
func followHub(t *testing.T, r *watchRig) *jobwatch.Feed {
	t.Helper()
	feed := jobwatch.NewFeed(nil)
	feed.OwnerOf = r.svc.OwnerOfRow
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = feed.RunResumableFrom(ctx, r.svc.OpenJobsWatch)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !feed.Warm() {
		if time.Now().After(deadline) {
			t.Fatal("the feed never followed the hub")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return feed
}

// TestWatchFeedTerminalRecordsNeedEvidence: a job leaving the hub's
// queue is offered to the evaluator as finished only if its last ad
// said it completed or was removed, and only on an AP in the set. A held
// job's row leaving (an AP retired or reconciled) is not.
func TestWatchFeedTerminalRecordsNeedEvidence(t *testing.T) {
	r := newWatchRig(t, jobwatch.ModeAny, "ClusterId > 5")
	feed := followHub(t, r)
	r.hub.PutJob(ap2, "alice@d", 6, 0, "JobStatus = 4")
	r.hub.PutJob(ap2, "alice@d", 8, 0, "JobStatus = 5")
	r.hub.PutJob("ap9.example.org", "alice@d", 7, 0, "JobStatus = 4")
	for _, k := range []struct {
		schedd string
		c      int
	}{{ap2, 6}, {ap2, 8}, {"ap9.example.org", 7}} {
		r.hub.DeleteJob(k.schedd, k.c, 0)
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(feed.Terminal("alice", time.Now().Add(-time.Hour))) != 3 {
		if time.Now().After(deadline) {
			t.Fatal("the deletes never reached the feed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := map[int64]bool{}
	err := WatchSource{Service: r.svc, Feed: feed}.History(context.Background(), "alice",
		[]string{"ClusterId", "ProcId", "JobStatus"}, time.Now().Add(-time.Hour), 100, func(ad *classad.ClassAd) {
			c, _ := ad.EvaluateAttrInt("ClusterId")
			got[c] = true
		})
	if err != nil {
		t.Fatal(err)
	}
	if !got[6] || got[8] || got[7] {
		t.Fatalf("terminal records %v: want 6.0 (completed on a member), not 8.0 (held) or 7.0 (not a member)", got)
	}
}
