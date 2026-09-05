package daemon

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/config"
)

// TestAdvertiseTriggerForcesEarlyUpdate verifies that a send on cfg.Trigger produces an advertise
// promptly, well before the (long) interval would -- so a caller can push a state change to the
// collector without waiting a full cycle. Augment runs on every publish attempt (before the actual
// collector send), so counting Augment calls counts publishes even against an unreachable collector.
func TestAdvertiseTriggerForcesEarlyUpdate(t *testing.T) {
	cfg := config.NewEmpty()
	cfg.Set("FULL_HOSTNAME", "ap40.chtc.wisc.edu")
	cfg.Set("COLLECTOR_HOST", "127.0.0.1:1") // unreachable; the send fails+warns but Augment still runs
	d := testDaemon(t, cfg)

	var count atomic.Int64
	trigger := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())

	// Join the Advertise goroutine on cleanup (even on t.Fatal): it opens connection fds to the
	// (unreachable) collector, and leaving it running past this test would churn fds into a later,
	// fd-sensitive test (TestResolveInheritedListener adopts a socket by fd number).
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.Advertise(ctx, AdvertiseConfig{
			MyType:   "HTCondorDB",
			Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
			Interval: 60 * time.Second, // long: only a trigger yields a prompt second publish
			Augment:  func(*classad.ClassAd) { count.Add(1) },
			Trigger:  trigger,
		})
	}()
	t.Cleanup(func() { cancel(); <-done })

	waitFor := func(want int64, within time.Duration) bool {
		deadline := time.Now().Add(within)
		for time.Now().Before(deadline) {
			if count.Load() >= want {
				return true
			}
			time.Sleep(5 * time.Millisecond)
		}
		return false
	}

	if !waitFor(1, 10*time.Second) {
		t.Fatal("no initial advertise")
	}
	trigger <- struct{}{}
	if !waitFor(2, 10*time.Second) {
		t.Fatal("Trigger did not force an early advertise (still waiting on the 60s interval)")
	}
}
