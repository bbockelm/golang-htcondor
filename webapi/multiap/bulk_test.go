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
	s.Hub.dial = func(context.Context) (*dbrpc.Client, func(), error) { return nil, nil, errors.New("hub down") }
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
	// Once the hub's copy is newer than the write, its word counts again.
	now = now.Add(time.Minute)
	rec = &bulkRecorder{}
	if rep, err = s.FanOut(context.Background(), req, rec.act); err != nil {
		t.Fatal(err)
	}
	if rec.contacted["ap1"] != 0 {
		t.Errorf("a write older than the hub's lag still voids the skip: %+v", statusOf(rep, "ap1"))
	}
}
