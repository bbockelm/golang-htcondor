package multiap

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
)

type bulkRecorder struct {
	mu        sync.Mutex
	contacted map[string]int
	fail      map[string]error
	counts    map[string]BulkCounts
}

func (b *bulkRecorder) act(_ context.Context, m apregistry.Member) (BulkOutcome, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.contacted == nil {
		b.contacted = map[string]int{}
	}
	b.contacted[m.Name]++
	if err := b.fail[m.Name]; err != nil {
		return BulkOutcome{}, err
	}
	return BulkOutcome{Counts: b.counts[m.Name]}, nil
}

// bulkService: alice has an idle job on ap1 (fresh) and on stale; ap2
// (fresh) holds only bob's job; lagging is fresh by state but 300s
// behind; absent and untrusted cannot be acted on at all.
func bulkService(t *testing.T) *Service {
	t.Helper()
	hub := hubDB(t)
	hub.PutJob("ap1", "alice@d", 1, 0, "")
	hub.PutJob("ap2", "bob@d", 1, 0, "")
	hub.PutJob("stale", "alice@d", 1, 0, "")
	hub.PutSource("ap1", StateFresh, 2)
	hub.PutSource("ap2", StateFresh, 2)
	hub.PutSource("empty", StateFresh, 2)
	hub.PutSource("stale", StateStale, 400)
	hub.PutSource("lagging", StateFresh, 300)
	hub.PutSource("unmeasured", StateFresh, -1)
	reg := newFakeRegistry("ap1", "ap2", "empty", "stale", "lagging", "unmeasured", "absent", "untrusted").
		WithSchedds(func(n string) string { return "<10.0.0.1:9618?name=" + n + ">" })
	reg.Update("absent", func(m *apregistry.Member) { m.Present = false })
	reg.Update("untrusted", func(m *apregistry.Member) {
		m.Trust = apregistry.Trust{State: apregistry.TrustUntrusted, Reason: "refused"}
	})
	return newService(t, hub, reg)
}

func statusOf(rep *BulkReport, ap string) BulkAPResult {
	for _, a := range rep.APs {
		if a.Schedd == ap {
			return a
		}
	}
	return BulkAPResult{}
}

func TestFanOutSkipsOnlyProvablyEmptyAPs(t *testing.T) {
	s := bulkService(t)
	rec := &bulkRecorder{counts: map[string]BulkCounts{"ap1": {Total: 1, Success: 1}}}
	rep, err := s.FanOut(context.Background(), BulkRequest{
		User: "alice@d", Owner: "alice", Constraint: "JobStatus == 1", FreshWithin: 60 * time.Second,
	}, rec.act)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"ap1":        BulkActed,       // fresh, and the hub has alice's job
		"ap2":        BulkSkipped,     // fresh, and only bob's job there
		"empty":      BulkSkipped,     // fresh, nothing at all
		"stale":      BulkNoMatch,     // stale: contacted, whatever the hub says
		"lagging":    BulkNoMatch,     // fresh by state, but beyond the tolerance
		"unmeasured": BulkNoMatch,     // no measured lag is never fresh enough
		"absent":     BulkUnreachable, // not contacted
		"untrusted":  BulkUntrusted,   // not contacted
	}
	for ap, st := range want {
		got := statusOf(rep, ap)
		if got.Status != st {
			t.Errorf("%s: %+v, want %s", ap, got, st)
		}
		contacted := rec.contacted[ap] > 0
		shouldContact := st == BulkActed || st == BulkNoMatch || st == BulkFailed
		if contacted != shouldContact {
			t.Errorf("%s contacted=%v, want %v", ap, contacted, shouldContact)
		}
	}
	if rep.Complete {
		t.Error("a report with an unreachable and an untrusted AP claims to be complete")
	}
	if rep.Totals.Total != 1 || rep.Totals.Success != 1 {
		t.Errorf("totals = %+v", rep.Totals)
	}
	if len(rep.APs) != len(want) {
		t.Errorf("report has %d APs, want every member", len(rep.APs))
	}
	if !strings.Contains(statusOf(rep, "untrusted").Reason, "does not trust") {
		t.Errorf("untrusted reason = %q", statusOf(rep, "untrusted").Reason)
	}
}

// With skipping disabled, or the hub down, every usable AP is contacted.
func TestFanOutContactsEverythingWithoutProof(t *testing.T) {
	s := bulkService(t)
	rec := &bulkRecorder{}
	if _, err := s.FanOut(context.Background(), BulkRequest{User: "alice@d", Owner: "alice", Constraint: "true"}, rec.act); err != nil {
		t.Fatal(err)
	}
	for _, ap := range []string{"ap1", "ap2", "empty", "stale", "lagging", "unmeasured"} {
		if rec.contacted[ap] != 1 {
			t.Errorf("FreshWithin=0: %s contacted %d times", ap, rec.contacted[ap])
		}
	}

	// The hub's snapshot says fresh, but the hub stops answering queries:
	// nothing is proven, so nothing is skipped.
	s.Hub.Active().dial = func(context.Context) (*dbrpc.Client, func(), error) { return nil, nil, errors.New("hub down") }
	rec = &bulkRecorder{}
	if _, err := s.FanOut(context.Background(), BulkRequest{User: "alice@d", Owner: "alice", Constraint: "true",
		FreshWithin: time.Minute}, rec.act); err != nil {
		t.Fatal(err)
	}
	if rec.contacted["empty"] != 1 || rec.contacted["ap2"] != 1 {
		t.Errorf("with the hub unreadable, fresh APs were skipped: %v", rec.contacted)
	}
}

// The hub check looks where the action will: confined to the caller,
// unless the caller acts on every user's jobs on that AP.
func TestFanOutHubCheckFollowsScope(t *testing.T) {
	s := bulkService(t)
	rec := &bulkRecorder{}
	req := BulkRequest{User: "alice@d", Owner: "alice", Constraint: `Owner == "bob" || true`, FreshWithin: time.Minute}
	rep, err := s.FanOut(context.Background(), req, rec.act)
	if err != nil {
		t.Fatal(err)
	}
	if statusOf(rep, "ap2").Status != BulkSkipped {
		t.Errorf("a crafted constraint widened alice's hub check to bob's job: %+v", statusOf(rep, "ap2"))
	}
	req.AllUsers = func(ap string) bool { return ap == "ap2" }
	rec = &bulkRecorder{}
	rep, err = s.FanOut(context.Background(), req, rec.act)
	if err != nil {
		t.Fatal(err)
	}
	if rec.contacted["ap2"] != 1 {
		t.Errorf("a superuser on ap2 did not reach bob's job there: %+v", statusOf(rep, "ap2"))
	}
	if _, err := s.FanOut(context.Background(), BulkRequest{User: "alice@d", Owner: "alice", Constraint: "true) || (true"}, rec.act); StatusOf(err) != 400 {
		t.Errorf("an unbalanced constraint = %v, want 400", err)
	}
}

// A failing AP is reported, and the rest still run.
func TestFanOutReportsFailures(t *testing.T) {
	s := bulkService(t)
	rec := &bulkRecorder{fail: map[string]error{"stale": errors.New("connection refused")},
		counts: map[string]BulkCounts{"ap1": {Total: 2, Success: 2}}}
	rep, err := s.FanOut(context.Background(), BulkRequest{User: "alice@d", Owner: "alice", Constraint: "true"}, rec.act)
	if err != nil {
		t.Fatal(err)
	}
	if got := statusOf(rep, "stale"); got.Status != BulkFailed || !strings.Contains(got.Error, "connection refused") {
		t.Errorf("stale = %+v", got)
	}
	if statusOf(rep, "ap1").Status != BulkActed || rep.Totals.Success != 2 {
		t.Errorf("ap1 = %+v, totals %+v", statusOf(rep, "ap1"), rep.Totals)
	}
	if ok, failed := rep.Contacted(); ok != 5 || failed != 1 {
		t.Errorf("Contacted = %d ok, %d failed", ok, failed)
	}
}

// A change this server made on an AP more recently than the hub's copy
// is known to reflect voids the hub's "nothing matches": a bulk release
// right after a bulk hold must reach the jobs the hub still shows idle.
func TestFanOutDoesNotTrustTheHubAboutItsOwnWrites(t *testing.T) {
	s := bulkService(t)
	now := time.Now()
	s.Now = func() time.Time { return now }
	req := BulkRequest{User: "alice@d", Owner: "alice", Constraint: "JobStatus == 5", FreshWithin: time.Minute}

	rec := &bulkRecorder{}
	rep, err := s.FanOut(context.Background(), req, rec.act)
	if err != nil {
		t.Fatal(err)
	}
	if statusOf(rep, "ap1").Status != BulkSkipped {
		t.Fatalf("before any write ap1 = %+v, want skipped", statusOf(rep, "ap1"))
	}
	s.NoteWrite("AP1")
	rec = &bulkRecorder{}
	if rep, err = s.FanOut(context.Background(), req, rec.act); err != nil {
		t.Fatal(err)
	}
	if rec.contacted["ap1"] != 1 || statusOf(rep, "empty").Status != BulkSkipped {
		t.Errorf("after a write to ap1: contacted %v, empty=%s", rec.contacted, statusOf(rep, "empty").Status)
	}
	// Well after the write -- past the tolerance plus the hub's row
	// refresh -- the hub's word counts again.
	now = now.Add(3 * time.Minute)
	rec = &bulkRecorder{}
	if rep, err = s.FanOut(context.Background(), req, rec.act); err != nil {
		t.Fatal(err)
	}
	if rec.contacted["ap1"] != 0 {
		t.Errorf("a write older than the hub's lag still voids the skip: %+v", statusOf(rep, "ap1"))
	}
}

// reviewService is one fresh AP, ap1, with rows put by the test.
func reviewService(t *testing.T, putRows func(h *testDB)) *Service {
	t.Helper()
	hub := hubDB(t)
	hub.PutSource("ap1", StateFresh, 2)
	putRows(hub)
	reg := newFakeRegistry("ap1").WithSchedds(func(n string) string { return "<10.0.0.1:9618?name=" + n + ">" })
	return newService(t, hub, reg)
}

func fanOutAP1(t *testing.T, s *Service, constraint string) BulkAPResult {
	t.Helper()
	rep, err := s.FanOut(context.Background(), BulkRequest{User: "alice@d", Owner: "alice", Constraint: constraint,
		FreshWithin: time.Minute}, (&bulkRecorder{}).act)
	if err != nil {
		t.Fatal(err)
	}
	return statusOf(rep, "ap1")
}

func putRaw(t *testing.T, h *testDB, key, ad string) {
	t.Helper()
	ctx := context.Background()
	cl, closer, _ := h.Dial(ctx)
	defer closer()
	tx, err := cl.BeginTable(ctx, TableJobs)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.NewClassAd(ctx, key, ad); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// Only a definite false rules a hub row out. A row the spoke never
// chained (no Owner, User or JobStatus), or a constraint using a
// function the hub's evaluator lacks, may match on the schedd.
func TestFanOutUndefinedIsNotNoMatch(t *testing.T) {
	s := reviewService(t, func(h *testDB) {
		putRaw(t, h, "opaque-x", "ScheddName = \"ap1\"\nProcId = 0\nKey = \"1.0\"")
	})
	if r := fanOutAP1(t, s, "JobStatus == 1"); r.Status == BulkSkipped {
		t.Errorf("an unchained row was counted out: %+v", r)
	}
	s = reviewService(t, func(h *testDB) { h.PutJob("ap1", "alice@d", 1, 0, "QDate = 1000") })
	for _, c := range []string{`debug(JobStatus) == 1`, `absTime(QDate) > absTime(0)`} {
		if r := fanOutAP1(t, s, c); r.Status == BulkSkipped {
			t.Errorf("%s: skipped though the schedd may match: %+v", c, r)
		}
	}
	// A definite false is still a skip.
	if r := fanOutAP1(t, s, "JobStatus == 7"); r.Status != BulkSkipped {
		t.Errorf("JobStatus == 7 on an idle job: %+v, want skipped", r)
	}
}

// A hub that does not answer proves nothing, quickly.
func TestFanOutHungHubIsNotProof(t *testing.T) {
	s := reviewService(t, func(*testDB) {})
	s.Hub.Active().dial = func(ctx context.Context) (*dbrpc.Client, func(), error) { <-ctx.Done(); return nil, nil, ctx.Err() }
	rec := &bulkRecorder{}
	start := time.Now()
	rep, err := s.FanOut(context.Background(), BulkRequest{User: "alice@d", Owner: "alice", Constraint: "true",
		FreshWithin: time.Minute}, rec.act)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > hubCheckTimeout+3*time.Second {
		t.Errorf("a hung hub held the fan-out %v", d)
	}
	if rec.contacted["ap1"] != 1 || statusOf(rep, "ap1").Status == BulkSkipped {
		t.Errorf("a hung hub's silence skipped ap1: %+v", statusOf(rep, "ap1"))
	}
}

// The jobs stream must be connected and error-free for the hub's word to
// count; freshness is measured on another stream.
func TestFanOutNeedsAConnectedJobsStream(t *testing.T) {
	for _, row := range []string{
		"ScheddName = \"ap1\"\nState = \"fresh\"\nStalenessSeconds = 1\nJobsConnected = false",
		"ScheddName = \"ap1\"\nState = \"fresh\"\nStalenessSeconds = 1\nJobsConnected = true\nJobsLastError = \"reset\"",
		"ScheddName = \"ap1\"\nState = \"fresh\"\nStalenessSeconds = 1",
	} {
		hub := hubDB(t)
		hub.PutSourceAd("ap1", row)
		reg := newFakeRegistry("ap1").WithSchedds(func(string) string { return "<10.0.0.1:9618>" })
		s := newService(t, hub, reg)
		if r := fanOutAP1(t, s, "true"); r.Status == BulkSkipped {
			t.Errorf("row %q: skipped", row)
		}
	}
}

// Before the first collector poll there is nothing to fan out to, which
// is not "nothing matched".
func TestFanOutEmptyRegistry(t *testing.T) {
	s := newService(t, hubDB(t), newFakeRegistry())
	_, err := s.FanOut(context.Background(), BulkRequest{User: "alice@d", Owner: "alice", Constraint: "true"}, (&bulkRecorder{}).act)
	if StatusOf(err) != 503 {
		t.Errorf("empty registry: %v, want 503", err)
	}
}

// A leg that failed may still have been applied: it is noted as a write.
func TestFanOutNotesFailedLegs(t *testing.T) {
	s := reviewService(t, func(h *testDB) { h.PutJob("ap1", "alice@d", 1, 0, "") })
	rec := &bulkRecorder{fail: map[string]error{"ap1": context.DeadlineExceeded}}
	if _, err := s.FanOut(context.Background(), BulkRequest{User: "alice@d", Owner: "alice", Constraint: "true"}, rec.act); err != nil {
		t.Fatal(err)
	}
	if !s.wroteSince("ap1", time.Minute) {
		t.Error("a failed leg left no own-write record")
	}
}

// The caller's cancellation does not stop a fan-out half way.
func TestFanOutOutlivesTheCaller(t *testing.T) {
	s := reviewService(t, func(h *testDB) { h.PutJob("ap1", "alice@d", 1, 0, "") })
	ctx, cancel := context.WithCancel(context.Background())
	sawCancel := false
	rep, err := s.FanOut(ctx, BulkRequest{User: "alice@d", Owner: "alice", Constraint: "true"},
		func(legCtx context.Context, _ apregistry.Member) (BulkOutcome, error) {
			cancel()
			time.Sleep(10 * time.Millisecond)
			sawCancel = legCtx.Err() != nil
			return BulkOutcome{Counts: BulkCounts{Total: 1, Success: 1}}, nil
		})
	if err != nil || sawCancel || statusOf(rep, "ap1").Status != BulkActed {
		t.Errorf("caller cancelled mid-fan-out: leg saw cancel=%v, %+v, %v", sawCancel, statusOf(rep, "ap1"), err)
	}
}

// A vetted member list is the set acted on, not the registry's later one.
func TestFanOutUsesTheVettedMembers(t *testing.T) {
	s := bulkService(t)
	only, _ := s.Registry.Get("ap1")
	rec := &bulkRecorder{}
	rep, err := s.FanOut(context.Background(), BulkRequest{User: "alice@d", Owner: "alice", Constraint: "true",
		Members: []apregistry.Member{only}}, rec.act)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.APs) != 1 || len(rec.contacted) != 1 || rec.contacted["ap1"] != 1 {
		t.Errorf("fanned out over %v (%d APs), want ap1 only", rec.contacted, len(rep.APs))
	}
}

// The own-write window does not trust the measured lag, which the hub
// may report up to a minute late: a write 30 s ago against a hub that
// says it is 2 s behind still voids the skip.
func TestFanOutOwnWriteWindowIgnoresTheMeasuredLag(t *testing.T) {
	s := reviewService(t, func(h *testDB) { h.PutJob("ap1", "alice@d", 1, 0, "") })
	base := time.Now()
	now := base
	s.Now = func() time.Time { return now }
	s.NoteWrite("ap1")
	now = base.Add(30 * time.Second)
	if r := fanOutAP1(t, s, "JobStatus == 5"); r.Status == BulkSkipped {
		t.Errorf("skipped 30 s after this server's own write: %+v", r)
	}
}
