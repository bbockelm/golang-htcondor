package jobwatch

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// expressionJobAd is a finished job whose memory request is an
// expression over another expression, the shape a real job ad has:
// MemoryUsage is defined in terms of ResidentSetSize, and RequestMemory
// is commonly defined in terms of MemoryUsage. Evaluating a reference to
// a non-literal attribute records it in the ad's cyclic-reference map, so
// reading RequestMemory writes to the ad.
func expressionJobAd(cluster int64, owner string) string {
	return fmt.Sprintf(`ClusterId = %d
ProcId = 0
Owner = %q
JobStatus = 4
ExitCode = 1
ExitBySignal = false
ResidentSetSize = 500000
MemoryUsage = ((ResidentSetSize + 1023) / 1024)
RequestMemory = ifThenElse(MemoryUsage =!= undefined, MemoryUsage, 2048)
`, cluster, owner)
}

// endJob records a terminal ad for cluster on the feed.
func endJob(f *Feed, cluster int64, owner string) {
	key := fmt.Sprintf("%d.0", cluster)
	f.Apply(WatchEvent{Kind: WatchUpsert, Key: key, AdText: expressionJobAd(cluster, owner)})
	f.Apply(WatchEvent{Kind: WatchDelete, Key: key})
}

// TestTerminalAdsAreNotSharedBetweenConsumers: several consumers of
// Terminal -- the periodic sweep, a nudged check, an MCP caller waiting
// on a watch, a watch share -- can evaluate the same owner at once.
// Each must get ads it can evaluate without coordinating with the
// others. A constraint naming an expression-valued attribute writes to
// the ad it evaluates, so two consumers sharing one ad is a concurrent
// map write, which kills the process rather than failing the request.
func TestTerminalAdsAreNotSharedBetweenConsumers(t *testing.T) {
	f := warmFeed(t)
	for c := int64(1); c <= 8; c++ {
		endJob(f, c, "alice")
	}
	since := time.Now().Add(-time.Hour)

	const consumers = 8
	const rounds = 50
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The feed keeps applying changes while the consumers read: other
	// owners' jobs, and more of this owner's jobs ending.
	var feeder sync.WaitGroup
	feeder.Add(1)
	go func() {
		defer feeder.Done()
		for i := int64(0); ctx.Err() == nil; i++ {
			endJob(f, 1000+i%64, "bob")
			endJob(f, 100+i%16, "alice")
		}
	}()

	var wg sync.WaitGroup
	errs := make(chan string, consumers)
	for range consumers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, err := New("alice", "l", "RequestMemory > 100 && ClusterId == 3", EventFailed, "", ModeAny)
			if err != nil {
				errs <- err.Error()
				return
			}
			// A feed record resolves a job the watch tracks.
			w.Tracked = []JobID{{Cluster: 3}}
			for range rounds {
				ads := f.Terminal("alice", since)
				fold := w.Fold(time.Time{}, false)
				for _, ad := range ads {
					fold.Finished(ad)
					if v, ok := ad.EvaluateAttrInt("RequestMemory"); !ok || v != 489 {
						errs <- fmt.Sprintf("RequestMemory = %d, %v; want 489", v, ok)
						return
					}
				}
				if out := fold.Done(); !out.Fires || out.Satisfied != 1 {
					errs <- fmt.Sprintf("watch over cluster 3 did not fire once: %+v", out)
					return
				}
			}
		}()
	}
	wg.Wait()
	cancel()
	feeder.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// feedSource is the evaluator's Source with history coming from the
// feed's terminal records, as the daemon's own source does when the
// archive has nothing for a job yet.
type feedSource struct{ f *Feed }

func (feedSource) Queue(context.Context, string, []string, int, func(*classad.ClassAd)) (bool, error) {
	return false, nil
}

func (s feedSource) History(_ context.Context, owner string, _ []string, since time.Time, _ int,
	yield func(*classad.ClassAd)) error {
	s.f.EachTerminal(owner, since, yield)
	return nil
}

// TestConcurrentChecksOfOneOwnerAreSafe drives the same race through the
// evaluator: overlapping CheckOwner calls for one owner, as the sweep,
// the Nudger and Await make them, with a watch whose constraint names an
// expression-valued attribute.
func TestConcurrentChecksOfOneOwnerAreSafe(t *testing.T) {
	s := testStore(t)
	f := warmFeed(t)
	for c := int64(1); c <= 8; c++ {
		endJob(f, c, "alice")
	}
	// Watching for success on jobs that all failed: the watch never
	// fires, so it stays live and every check evaluates it.
	w, err := New("alice", "l", "RequestMemory > 100", EventSucceeded, "", ModeAny)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(context.Background(), w, 0); err != nil {
		t.Fatal(err)
	}
	e := NewEvaluator(s, feedSource{f: f}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var feeder sync.WaitGroup
	feeder.Add(1)
	go func() {
		defer feeder.Done()
		for i := int64(0); ctx.Err() == nil; i++ {
			endJob(f, 100+i%16, "alice")
		}
	}()

	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				// Storage contention between the checks is not what
				// this is about; the evaluation is.
				_, _ = e.CheckOwner(context.Background(), "alice")
			}
		}()
	}
	wg.Wait()
	cancel()
	feeder.Wait()
}

// TestTerminalReturnsTheCallersOwnAds: an ad from Terminal belongs to
// the caller, so changing it changes nothing the feed or a later caller
// sees.
func TestTerminalReturnsTheCallersOwnAds(t *testing.T) {
	f := warmFeed(t)
	endJob(f, 7, "alice")
	since := time.Now().Add(-time.Hour)

	first := f.Terminal("alice", since)
	if len(first) != 1 {
		t.Fatalf("want one terminal ad, got %d", len(first))
	}
	first[0].InsertAttr("ExitCode", 0)
	first[0].InsertAttrString("Owner", "mallory")

	again := f.Terminal("alice", since)
	if len(again) != 1 {
		t.Fatalf("a caller's edit changed what the feed holds: got %d ads for alice", len(again))
	}
	if code, _ := again[0].EvaluateAttrInt("ExitCode"); code != 1 {
		t.Errorf("ExitCode = %d after a caller edited its copy, want 1", code)
	}
	if v, ok := again[0].EvaluateAttrInt("RequestMemory"); !ok || v != 489 {
		t.Errorf("RequestMemory = %d, %v; want 489", v, ok)
	}
}

// TestTerminalNeedsAnOwner: an empty owner is what an unidentified
// caller has, and it must not select the jobs whose Owner is missing.
func TestTerminalNeedsAnOwner(t *testing.T) {
	f := warmFeed(t)
	f.Apply(WatchEvent{Kind: WatchUpsert, Key: "5.0", AdText: "ClusterId = 5\nProcId = 0\nJobStatus = 4\n"})
	f.Apply(WatchEvent{Kind: WatchDelete, Key: "5.0"})
	if got := f.Terminal("", time.Time{}); len(got) != 0 {
		t.Errorf("an empty owner selected %d ownerless jobs", len(got))
	}
}

// BenchmarkEachTerminal is the per-evaluation cost of the copies: one
// owner with 1,000 ended jobs of about 160 attributes each.
func BenchmarkEachTerminal(b *testing.B) {
	f := NewFeed(nil)
	f.setWarm(true)
	f.MaxEnded = 0
	var pad strings.Builder
	for i := range 150 {
		fmt.Fprintf(&pad, "Attribute%d = \"value number %d\"\n", i, i)
	}
	for c := int64(1); c <= 1000; c++ {
		key := fmt.Sprintf("%d.0", c)
		f.Apply(WatchEvent{Kind: WatchUpsert, Key: key, AdText: expressionJobAd(c, "alice") + pad.String()})
		f.Apply(WatchEvent{Kind: WatchDelete, Key: key})
	}
	b.ReportAllocs()
	for b.Loop() {
		n := 0
		f.EachTerminal("alice", time.Time{}, func(*classad.ClassAd) { n++ })
		if n != 1000 {
			b.Fatalf("yielded %d, want 1000", n)
		}
	}
}
