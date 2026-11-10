package multiap

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/dbrpc"
)

// metricsSource is a federation_sources row for schedd, fresh, with its
// job_metrics stream connected -- or, missing, the AP keeping none.
func metricsSource(schedd string, missing bool) string {
	if missing {
		return sourceAd(schedd, StateFresh, "JobMetricsMissing = true", "JobMetricsConnected = false")
	}
	return sourceAd(schedd, StateFresh, "JobMetricsConnected = true")
}

func countSamples(t *testing.T, res *MetricsResult) int {
	t.Helper()
	n := 0
	for _, r := range res.Rows {
		v, err := strconv.Atoi(r.Values[0])
		if err != nil {
			t.Fatalf("count %q: %v", r.Values[0], err)
		}
		n += v
	}
	return n
}

var countAll = []dbrpc.AggSpec{{Func: dbrpc.AggCount, Arg: "*"}}

// TestMetricsReadStaysOnItsPinnedHub: a samples read pinned to hub A
// before reads move to hub B -- which federates no job_metrics and does
// not hold the job -- resolves the job, aggregates and reports its
// sources all on A. An unpinned read after the switch is B's answer.
func TestMetricsReadStaysOnItsPinnedHub(t *testing.T) {
	a, b := hubDB(t), hubDB(t)
	a.EnableJobMetrics()
	a.PutJob(ap1, "alice@d", 7, 0, "")
	now := time.Now().Unix()
	for i := 0; i < 3; i++ {
		a.PutMetric(ap1, "alice@d", 7, 0, 1, now-int64(60*i), "CpusUsage = 1.0")
	}
	a.PutSourceAd(ap1, metricsSource(ap1, false))
	a.PutSourceAd(ap2, metricsSource(ap2, false))
	freshSources(b)
	p := newHubPair(t, a, b, HubPolicy{})
	p.refresh()
	s := pairService(p)
	bare, err := s.Codec.Parse("7.0")
	if err != nil {
		t.Fatal(err)
	}
	pinned := s.PinHub(context.Background())
	p.moveTo(t, hubB)

	res, err := s.AggregateMetrics(pinned, MetricsRequest{User: "alice@d", Job: &bare, Aggs: countAll})
	if err != nil {
		t.Fatalf("a samples read pinned to %s, after the switch: %v", hubA, err)
	}
	if n := countSamples(t, res); n != 3 || res.Sources.Hub != hubA || res.Job == nil || res.Job.Schedd != ap1 {
		t.Fatalf("pinned read: %d samples, sources from %q, job %+v; want hub A's 3 for 7.0@%s", n, res.Sources.Hub, res.Job, ap1)
	}
	if src, off := s.MetricsOff(pinned); off {
		t.Fatalf("MetricsOff on a request pinned to %s, which federates job_metrics: off, %+v", hubA, src)
	}
	if _, err := s.AggregateMetrics(context.Background(), MetricsRequest{User: "alice@d", Aggs: countAll}); !errors.Is(err, ErrMetricsNotFederated) {
		t.Fatalf("an unpinned read after the switch: %v, want hub B's ErrMetricsNotFederated", err)
	}
}

// TestMetricsNotKeptWhileSettling: right after a switch the new hub's
// APs are settling; one the new hub reports keeps no job_metrics is
// listed in not_kept too -- it has no samples on any hub -- and stays
// settling, so the switch is still reported. After the window it is
// not_kept alone, and counts as fresh.
func TestMetricsNotKeptWhileSettling(t *testing.T) {
	a, b := hubDB(t), hubDB(t)
	for _, db := range []*testDB{a, b} {
		db.EnableJobMetrics()
		db.PutSourceAd(ap1, metricsSource(ap1, false))
	}
	a.PutSourceAd(ap2, metricsSource(ap2, false))
	b.PutSourceAd(ap2, metricsSource(ap2, true))
	p := newHubPair(t, a, b, HubPolicy{Settle: 90 * time.Second})
	p.refresh()
	s := pairService(p)
	p.moveTo(t, hubB)
	notKept := func(src Sources) bool {
		for _, n := range src.NotKept {
			if n.Schedd == ap2 && n.Table == TableJobMetrics && n.Reason != "" {
				return true
			}
		}
		return false
	}
	res, err := s.AggregateMetrics(context.Background(), MetricsRequest{User: "alice@d", Aggs: countAll})
	if err != nil {
		t.Fatal(err)
	}
	if src := res.Sources; !notKept(src) || src.StateOf(ap2) != StateSettling || src.StateOf(ap1) != StateSettling || src.Fresh != 0 {
		t.Fatalf("during the settle window: %+v; want both APs settling and ap2 also not_kept", src)
	}
	p.clock.advance(2 * time.Minute)
	p.refresh()
	res, err = s.AggregateMetrics(context.Background(), MetricsRequest{User: "alice@d", Aggs: countAll})
	if err != nil {
		t.Fatal(err)
	}
	if src := res.Sources; !notKept(src) || src.StateOf(ap2) != StateFresh || src.Fresh != 2 {
		t.Fatalf("after the settle window: %+v; want ap2 not_kept and fresh", src)
	}
}

// TestMetricsReadFailuresFailOver: a samples aggregate whose connection
// drops under it counts toward FailAfter like any other data read.
func TestMetricsReadFailuresFailOver(t *testing.T) {
	a, b := hubDB(t), hubDB(t)
	for _, db := range []*testDB{a, b} {
		db.EnableJobMetrics()
		db.PutSourceAd(ap1, metricsSource(ap1, false))
		db.PutSourceAd(ap2, metricsSource(ap2, false))
	}
	p := newHubPair(t, a, b, HubPolicy{FailAfter: 2})
	p.hub.Active().dial = func(ctx context.Context) (*dbrpc.Client, func(), error) {
		cl, closer, err := a.Dial(ctx)
		if err == nil && ctx.Value(dataReadKey{}) != nil {
			closer() // the connection drops under the aggregate
			return cl, func() {}, nil
		}
		return cl, closer, err
	}
	p.refresh()
	s := pairService(p)
	ctx := context.WithValue(context.Background(), dataReadKey{}, true)
	for i := 0; i < 2; i++ {
		if _, err := s.AggregateMetrics(ctx, MetricsRequest{User: "alice@d", Aggs: countAll}); err == nil {
			t.Fatalf("aggregate %d on hub A succeeded", i)
		}
	}
	p.refresh()
	if p.active() != hubB {
		t.Fatalf("active %q after two failed aggregates, want %s", p.active(), hubB)
	}
}
