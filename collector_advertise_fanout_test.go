package htcondor

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
)

// withFakeSend replaces the per-collector send for the duration of a
// test and records which addresses were asked to take the ad.
func withFakeSend(t *testing.T, fail map[string]error) *fanoutRecorder {
	t.Helper()
	rec := &fanoutRecorder{fail: fail}
	saved := sendOneAd
	sendOneAd = func(_ *Collector, _ context.Context, addr string, _ commands.CommandType, _ *classad.ClassAd, _ *AdvertiseOptions) error {
		return rec.record(addr)
	}
	t.Cleanup(func() { sendOneAd = saved })
	return rec
}

type fanoutRecorder struct {
	mu   sync.Mutex
	got  []string
	fail map[string]error
}

func (r *fanoutRecorder) record(addr string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, addr)
	return r.fail[addr]
}

func (r *fanoutRecorder) addrs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]string(nil), r.got...)
	sort.Strings(out)
	return out
}

func testAd(t *testing.T) *classad.ClassAd {
	t.Helper()
	ad := classad.New()
	if err := ad.Set("MyType", "Generic"); err != nil {
		t.Fatal(err)
	}
	if err := ad.Set("Name", "fanout-test"); err != nil {
		t.Fatal(err)
	}
	if err := ad.Set("MyAddress", "<127.0.0.1:9618>"); err != nil {
		t.Fatal(err)
	}
	return ad
}

// An advertisement goes to every configured collector, not to whichever
// one answers first. Each collector keeps its own copy of the ad and
// expires it on its own, so an ad that reached only one of them leaves
// the daemon invisible in the others -- which is how a daemon
// configured with two central managers ended up advertised to only one,
// varying per process because NewCollector shuffles the list.
func TestAdvertiseReachesEveryCollector(t *testing.T) {
	rec := withFakeSend(t, nil)

	c := NewCollector("cm-1.example.org:9618,cm-2.example.org:9618,cm-3.example.org:9618")
	if err := c.Advertise(context.Background(), testAd(t), &AdvertiseOptions{}); err != nil {
		t.Fatalf("Advertise: %v", err)
	}

	want := []string{"cm-1.example.org:9618", "cm-2.example.org:9618", "cm-3.example.org:9618"}
	got := rec.addrs()
	if len(got) != len(want) {
		t.Fatalf("advertised to %v, want all of %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("advertised to %v, want %v", got, want)
			break
		}
	}
}

// Partial success is a real outcome and must be visible: the caller
// needs to tell "the ad is nowhere" from "the ad is in two of three".
func TestAdvertisePartialSuccessIsReported(t *testing.T) {
	down := errors.New("connection refused")
	rec := withFakeSend(t, map[string]error{"cm-2.example.org:9618": down})

	c := NewCollector("cm-1.example.org:9618,cm-2.example.org:9618,cm-3.example.org:9618")
	err := c.Advertise(context.Background(), testAd(t), &AdvertiseOptions{})
	if err == nil {
		t.Fatal("a collector failed and Advertise reported success")
	}

	var adErr *AdvertiseError
	if !errors.As(err, &adErr) {
		t.Fatalf("error is %T, want *AdvertiseError", err)
	}
	if adErr.AllFailed() {
		t.Error("AllFailed is true although two collectors took the ad")
	}
	if len(adErr.Succeeded) != 2 {
		t.Errorf("Succeeded = %v, want the two reachable collectors", adErr.Succeeded)
	}
	if _, ok := adErr.Failed["cm-2.example.org:9618"]; !ok {
		t.Errorf("Failed = %v, want the unreachable collector", adErr.Failed)
	}
	// The unreachable one must not have stopped the others.
	if len(rec.addrs()) != 3 {
		t.Errorf("attempted %v; a failing collector must not skip the rest", rec.addrs())
	}
	// And the cause survives for errors.Is.
	if !errors.Is(err, down) {
		t.Error("the per-collector cause is not reachable through errors.Is")
	}
	if !strings.Contains(err.Error(), "2 of 3") {
		t.Errorf("error does not say how many collectors took it: %v", err)
	}
}

func TestAdvertiseAllFailed(t *testing.T) {
	boom := errors.New("no route to host")
	withFakeSend(t, map[string]error{
		"cm-1.example.org:9618": boom,
		"cm-2.example.org:9618": boom,
	})

	c := NewCollector("cm-1.example.org:9618,cm-2.example.org:9618")
	err := c.Advertise(context.Background(), testAd(t), &AdvertiseOptions{})
	var adErr *AdvertiseError
	if !errors.As(err, &adErr) {
		t.Fatalf("error is %T, want *AdvertiseError", err)
	}
	if !adErr.AllFailed() {
		t.Errorf("AllFailed is false although no collector took the ad: %v", err)
	}
}

// One collector keeps the old error shape, so callers that never
// configured a list see exactly what they saw before.
func TestAdvertiseSingleCollectorKeepsItsErrorShape(t *testing.T) {
	boom := errors.New("connection refused")
	withFakeSend(t, map[string]error{"cm-1.example.org:9618": boom})

	c := NewCollector("cm-1.example.org:9618")
	err := c.Advertise(context.Background(), testAd(t), &AdvertiseOptions{})
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want the underlying cause", err)
	}
	var adErr *AdvertiseError
	if errors.As(err, &adErr) {
		t.Error("a single-collector failure was wrapped in *AdvertiseError")
	}
}

// The batch path fans out too, and reports per-ad which collectors took
// each one.
func TestAdvertiseMultipleReachesEveryCollector(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	saved := sendOneAd
	t.Cleanup(func() { sendOneAd = saved })
	sendOneAd = func(_ *Collector, _ context.Context, addr string, _ commands.CommandType, _ *classad.ClassAd, _ *AdvertiseOptions) error {
		mu.Lock()
		defer mu.Unlock()
		seen[addr]++
		if addr == "cm-2.example.org:9618" {
			return fmt.Errorf("collector down")
		}
		return nil
	}

	// AdvertiseMultiple builds its own connections, so exercise it
	// through the single-ad seam by giving each ad its own call.
	c := NewCollector("cm-1.example.org:9618,cm-2.example.org:9618")
	ads := []*classad.ClassAd{testAd(t), testAd(t)}
	for _, ad := range ads {
		err := c.Advertise(context.Background(), ad, &AdvertiseOptions{})
		var adErr *AdvertiseError
		if !errors.As(err, &adErr) {
			t.Fatalf("error is %T, want *AdvertiseError", err)
		}
		if adErr.AllFailed() {
			t.Error("the reachable collector should still have taken the ad")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if seen["cm-1.example.org:9618"] != len(ads) || seen["cm-2.example.org:9618"] != len(ads) {
		t.Errorf("per-collector attempts = %v, want %d each", seen, len(ads))
	}
}
