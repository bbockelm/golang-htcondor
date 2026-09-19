package matchanalyzer

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// sliceOnlyProvider can only hand over the whole slice, like a provider
// that has no streaming query.
type sliceOnlyProvider struct{ ads []*classad.ClassAd }

func (p *sliceOnlyProvider) Slots(context.Context, []string) ([]*classad.ClassAd, error) {
	return p.ads, nil
}

// streamingProvider serves the same ads one at a time.
type streamingProvider struct {
	ads      []*classad.ClassAd
	streamed bool
}

func (p *streamingProvider) Slots(context.Context, []string) ([]*classad.ClassAd, error) {
	return p.ads, nil
}

func (p *streamingProvider) StreamSlots(_ context.Context, _ []string, fn func(*classad.ClassAd) bool) error {
	p.streamed = true
	for _, ad := range p.ads {
		if !fn(ad) {
			return nil
		}
	}
	return nil
}

func poolAds(t *testing.T, n int) []*classad.ClassAd {
	t.Helper()
	ads := make([]*classad.ClassAd, 0, n)
	for i := 0; i < n; i++ {
		ads = append(ads, makeSlotAd(t, fmt.Sprintf(
			`[ Name = "slot%d"; Machine = "h%d"; Arch = "X86_64"; OpSys = "LINUX"; Cpus = %d; Memory = %d; Disk = 1048576 ]`,
			i, i, 1<<(i%4), 1024*(1+i%8))))
	}
	return ads
}

// Streaming must not change a single number in the result. This is the
// test that lets the slice path be retired with confidence: the same pool
// through both routes has to produce identical output, including the
// narrowing-predicate pick and the resource suggestions, which were the
// two things that previously needed the whole slot slice.
func TestStreamingAndSliceAgree(t *testing.T) {
	ads := poolAds(t, 400)
	job := makeJobAd(t, `(TARGET.Cpus >= MY.RequestCpus) && (TARGET.Memory >= MY.RequestMemory) && (TARGET.Arch == "X86_64")`)
	if err := job.Set("RequestCpus", 6); err != nil {
		t.Fatal(err)
	}
	if err := job.Set("RequestMemory", 6000); err != nil {
		t.Fatal(err)
	}

	sliceRes, err := New(&sliceOnlyProvider{ads: ads}).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("slice path: %v", err)
	}
	streamProv := &streamingProvider{ads: ads}
	streamRes, err := New(streamProv).Analyze(context.Background(), job)
	if err != nil {
		t.Fatalf("stream path: %v", err)
	}

	if !streamProv.streamed {
		t.Fatal("the streaming provider was never used; the analyzer took the slice path")
	}
	if sliceRes.TotalSlots != len(ads) || streamRes.TotalSlots != len(ads) {
		t.Fatalf("TotalSlots: slice=%d stream=%d, want %d",
			sliceRes.TotalSlots, streamRes.TotalSlots, len(ads))
	}
	if !reflect.DeepEqual(sliceRes, streamRes) {
		t.Errorf("streaming changed the analysis:\n  slice  = %+v\n  stream = %+v", sliceRes, streamRes)
	}
}

// countingProvider streams generated ads without ever holding them, so
// the only thing that can grow the heap is the analyzer itself.
type countingProvider struct {
	n    int
	make func(i int) *classad.ClassAd
}

func (p *countingProvider) Slots(context.Context, []string) ([]*classad.ClassAd, error) {
	return nil, fmt.Errorf("this provider only streams")
}

func (p *countingProvider) StreamSlots(_ context.Context, _ []string, fn func(*classad.ClassAd) bool) error {
	for i := 0; i < p.n; i++ {
		if !fn(p.make(i)) {
			return nil
		}
	}
	return nil
}

// The whole point of the rework. Analyzing a large pool must not cost
// memory proportional to the pool: previously the slot slice alone was
// ~7.7 KiB per ad, so 100k slots meant ~730 MiB resident and the OOM
// killer. Nothing retained per slot means the pass costs what one ad
// costs.
func TestStreamingDoesNotGrowWithPoolSize(t *testing.T) {
	job := makeJobAd(t, `(TARGET.Cpus >= MY.RequestCpus) && (TARGET.Arch == "X86_64")`)
	if err := job.Set("RequestCpus", 6); err != nil {
		t.Fatal(err)
	}

	measure := func(n int) uint64 {
		prov := &countingProvider{n: n, make: func(i int) *classad.ClassAd {
			ad, err := classad.Parse(fmt.Sprintf(
				`[ Name = "slot%d"; Machine = "h%d"; Arch = "X86_64"; Cpus = %d; Memory = %d ]`,
				i, i, 1<<(i%4), 1024*(1+i%8)))
			if err != nil {
				t.Fatal(err)
			}
			return ad
		}}

		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		res, err := New(prov).Analyze(context.Background(), job)
		if err != nil {
			t.Fatalf("Analyze: %v", err)
		}
		if res.TotalSlots != n {
			t.Fatalf("TotalSlots = %d, want %d", res.TotalSlots, n)
		}

		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(res)
		if after.HeapAlloc < before.HeapAlloc {
			return 0
		}
		return after.HeapAlloc - before.HeapAlloc
	}

	small := measure(1000)
	large := measure(50000)
	t.Logf("retained after analysis: %d slots -> %d bytes, %d slots -> %d bytes", 1000, small, 50000, large)

	// The old shape retained ~7.7 KiB per slot, so 50k slots would be
	// ~370 MiB. Allow generous headroom for the distribution collectors
	// (bounded by distinct values, not slots) and still catch any
	// per-slot retention.
	const ceiling = 32 << 20
	if large > ceiling {
		t.Errorf("analysing 50k slots retained %d bytes (> %d); something is held per slot", large, ceiling)
	}
}
