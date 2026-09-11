package spool

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

func adsForProcs(t *testing.T, cluster, n int) []*classad.ClassAd {
	t.Helper()
	out := make([]*classad.ClassAd, n)
	for i := 0; i < n; i++ {
		ad, err := classad.Parse(fmt.Sprintf("[ClusterId = %d; ProcId = %d]", cluster, i))
		if err != nil {
			t.Fatal(err)
		}
		out[i] = ad
	}
	return out
}

// More procs than the concurrency limit, so the fan-out has to run in
// waves. Not observable through a real schedd: "all 25 spooled" looks
// the same whether 10 or 25 were in flight, so a fan-out that ignored
// its bound would pass an integration test.
func TestFanOutRunsInWavesAndRespectsItsBound(t *testing.T) {
	const procs, concurrency = 25, 10
	ads := adsForProcs(t, 7, procs)

	var mu sync.Mutex
	inFlight, maxInFlight, attempted := 0, 0, 0

	res := FanOut(context.Background(), ads, Bytes("tar"),
		Limits{Concurrency: concurrency},
		func(_ context.Context, _ []*classad.ClassAd, _ io.Reader) error {
			mu.Lock()
			inFlight++
			attempted++
			if inFlight > maxInFlight {
				maxInFlight = inFlight
			}
			mu.Unlock()

			// Hold the slot long enough that a bound violation shows as
			// overlap rather than being hidden by fast returns.
			time.Sleep(20 * time.Millisecond)

			mu.Lock()
			inFlight--
			mu.Unlock()
			return nil
		})

	if attempted != procs {
		t.Errorf("attempted %d procs, want %d", attempted, procs)
	}
	if len(res.Spooled) != procs {
		t.Errorf("reported %d spooled, want %d", len(res.Spooled), procs)
	}
	if maxInFlight > concurrency {
		t.Errorf("had %d uploads in flight, bound is %d", maxInFlight, concurrency)
	}
	// And it must use the concurrency it has: a serial implementation
	// passes every check above.
	if maxInFlight < 2 {
		t.Errorf("never more than %d in flight; the fan-out is serial", maxInFlight)
	}
}

func TestFanOutReportsPerProcFailures(t *testing.T) {
	ads := adsForProcs(t, 7, 5)
	res := FanOut(context.Background(), ads, Bytes("tar"), Limits{Concurrency: 3},
		func(_ context.Context, ads []*classad.ClassAd, _ io.Reader) error {
			if p, _ := ads[0].EvaluateAttrInt("ProcId"); p == 2 {
				return fmt.Errorf("boom")
			}
			return nil
		})

	if len(res.Spooled) != 4 {
		t.Errorf("spooled %d, want 4: %v", len(res.Spooled), res.Spooled)
	}
	if got, ok := res.Failed["7.2"]; !ok || !strings.Contains(got, "boom") {
		t.Errorf("expected 7.2 failed with its reason, got %+v", res.Failed)
	}
	if res.Remaining() != 1 {
		t.Errorf("Remaining() = %d, want 1", res.Remaining())
	}
}

// Each proc must get the whole tar. A shared reader leaves the first
// proc with it and every later one with nothing -- and the schedd accepts
// a short tar without complaint, so those procs leave the hold and then
// fail at run time on a missing file.
func TestFanOutGivesEveryProcTheWholeTar(t *testing.T) {
	ads := adsForProcs(t, 7, 6)
	payload := "the whole tar"

	var mu sync.Mutex
	sizes := map[string]int{}

	FanOut(context.Background(), ads, Bytes(payload), Limits{Concurrency: 4},
		func(_ context.Context, ads []*classad.ClassAd, r io.Reader) error {
			b, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			mu.Lock()
			sizes[ProcID(ads[0])] = len(b)
			mu.Unlock()
			return nil
		})

	if len(sizes) != 6 {
		t.Fatalf("saw %d procs, want 6", len(sizes))
	}
	for id, n := range sizes {
		if n != len(payload) {
			t.Errorf("proc %s received %d bytes, want %d", id, n, len(payload))
		}
	}
}

// PlanStreaming is what decides how many procs a streamed upload serves
// and how large that upload may be. It had no test at all.

func planAds(n int) []*classad.ClassAd {
	ads := make([]*classad.ClassAd, 0, n)
	for i := 0; i < n; i++ {
		ad := classad.New()
		_ = ad.Set("ClusterId", 9)
		_ = ad.Set("ProcId", i)
		ads = append(ads, ad)
	}
	return ads
}

func TestPlanStreamingDividesTheVolumeAcrossProcs(t *testing.T) {
	attempt, res, maxTar, err := PlanStreaming(planAds(10),
		Limits{MaxProcs: 1000, MaxVolume: 1000, Concurrency: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(attempt) != 10 {
		t.Errorf("attempting %d procs, want 10", len(attempt))
	}
	if maxTar != 100 {
		t.Errorf("maxTar = %d, want 100 (1000 bytes across 10 procs)", maxTar)
	}
	if res.Capped {
		t.Error("nothing was capped")
	}
}

func TestPlanStreamingCapsProcsAndReportsTheRemainder(t *testing.T) {
	attempt, res, _, err := PlanStreaming(planAds(25),
		Limits{MaxProcs: 10, MaxVolume: 1 << 30, Concurrency: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(attempt) != 10 {
		t.Errorf("attempting %d procs, want 10", len(attempt))
	}
	if res.NotAttempted != 15 {
		t.Errorf("NotAttempted = %d, want 15", res.NotAttempted)
	}
	if !res.Capped {
		t.Error("Capped is false after capping")
	}
}

// The ceiling has to be a number Growing can apply. A negative sentinel
// would make `written > limit` true on the first byte, so an unlimited
// call would refuse every upload.
func TestPlanStreamingWithNoVolumeLimitAcceptsBytes(t *testing.T) {
	_, _, maxTar, err := PlanStreaming(planAds(3),
		Limits{MaxProcs: 1000, MaxVolume: 0, Concurrency: 10})
	if err != nil {
		t.Fatal(err)
	}
	if maxTar <= 0 {
		t.Fatalf("maxTar = %d; Growing would refuse the first byte", maxTar)
	}

	g, err := NewGrowing(t.TempDir(), maxTar)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if err := g.Fill(bytes.NewReader(bytes.Repeat([]byte("x"), 4096))); err != nil {
		t.Errorf("an unlimited upload was refused: %v", err)
	}
}

// More procs than MaxVolume has bytes for: there is no upload that
// serves them, so the call is refused rather than serving a truncated
// one.
func TestPlanStreamingRefusesWhenNothingIsAffordable(t *testing.T) {
	_, _, _, err := PlanStreaming(planAds(10),
		Limits{MaxProcs: 1000, MaxVolume: 5, Concurrency: 10})
	if err == nil {
		t.Fatal("expected a refusal when the volume limit leaves under a byte per proc")
	}
}

func TestPlanStreamingWithNoProcs(t *testing.T) {
	attempt, _, _, err := PlanStreaming(nil, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(attempt) != 0 {
		t.Errorf("attempting %d procs from an empty list", len(attempt))
	}
}
