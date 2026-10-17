package multiap

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
)

// TestSettleWindowAfterSwitch: alice saw 5.0 on hub A; reads move to
// hub B, which does not hold it yet. For the settle window B's fresh APs
// are reported settling, a by-id read of 5.0 that misses on B is asked
// of the AP and found, and a bulk action does not skip ap1 on B's word.
// After the window B is trusted as any fresh hub: ap1 is fresh, a miss
// is a 404, and the bulk skip applies.
func TestSettleWindowAfterSwitch(t *testing.T) {
	a, b := hubDB(t), hubDB(t)
	a.PutJob(ap1, "alice@d", 5, 0, "")
	for _, db := range []*testDB{a, b} {
		db.PutSource(ap1, StateFresh, 2)
		db.PutSource(ap2, StateFresh, 2)
	}
	p := newHubPair(t, a, b, HubPolicy{Settle: 90 * time.Second})
	p.refresh()
	s := pairService(p)
	s.Registry = newFakeRegistry(ap1, ap2).WithSchedds(func(n string) string { return "<10.0.0.1:9618?name=" + n + ">" })
	job, err := classad.ParseOld("ClusterId = 5\nProcId = 0\nUser = \"alice@d\"\nJobStatus = 1")
	if err != nil {
		t.Fatal(err)
	}
	schedd := &fakeSchedd{ads: []*classad.ClassAd{job}}
	s.Schedd = func(apregistry.Member) ScheddQuerier { return schedd }
	id, err := s.Codec.Parse("5.0@" + ap1)
	if err != nil {
		t.Fatal(err)
	}
	bulk := func() BulkAPResult {
		rec := &bulkRecorder{}
		rep, err := s.FanOut(context.Background(), BulkRequest{User: "alice@d", Owner: "alice", Constraint: "ClusterId == 99",
			FreshWithin: 60 * time.Second}, rec.act)
		if err != nil {
			t.Fatal(err)
		}
		return statusOf(rep, ap1)
	}

	p.moveTo(t, hubB)
	if src := s.Sources(context.Background()); src.Fresh != 0 || src.StateOf(ap1) != StateSettling || src.StateOf(ap2) != StateSettling {
		t.Fatalf("sources just after the switch: %+v, want both APs settling", src)
	}
	res, err := s.GetJob(context.Background(), "alice@d", id, nil)
	if err != nil {
		t.Fatalf("GET 5.0 during the settle window: %v (a miss on the new hub must be asked of the AP)", err)
	}
	if res.Source != SourceSchedd || res.Degraded == nil || res.Degraded.State != StateSettling {
		t.Fatalf("GET 5.0 during the settle window: source %q degraded %+v, want the schedd's answer marked settling", res.Source, res.Degraded)
	}
	if got := bulk(); got.Status == BulkSkipped {
		t.Fatalf("bulk skipped ap1 on the word of a hub still settling: %+v", got)
	}

	p.clock.advance(2 * time.Minute)
	p.refresh()
	if src := s.Sources(context.Background()); src.Fresh != 2 {
		t.Fatalf("sources after the settle window: %+v, want both APs fresh", src)
	}
	if _, err := s.GetJob(context.Background(), "alice@d", id, nil); StatusOf(err) != http.StatusNotFound {
		t.Fatalf("GET 5.0 after the settle window: %v, want the fresh hub's 404", err)
	}
	if got := bulk(); got.Status != BulkSkipped {
		t.Fatalf("bulk after the settle window: %+v, want ap1 skipped as provably empty", got)
	}
}
