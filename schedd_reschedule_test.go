package htcondor

import (
	"testing"
	"time"
)

// TestRescheduleClaimSlot covers the rate-limiter primitive without
// touching the network. The wire side is exercised by
// schedd_reschedule_integration_test.go (build tag: integration).
func TestRescheduleClaimSlot(t *testing.T) {
	t.Cleanup(ResetRescheduleLimiter)
	ResetRescheduleLimiter()

	const addr = "test://schedd"
	const interval = 5 * time.Second
	base := time.Unix(1_700_000_000, 0)

	// First claim wins.
	if !rescheduleClaimSlot(addr, interval, base) {
		t.Fatalf("first claim should succeed")
	}
	// Same instant, second claim is denied.
	if rescheduleClaimSlot(addr, interval, base) {
		t.Errorf("immediate re-claim should be denied")
	}
	// Just before the interval — still denied.
	if rescheduleClaimSlot(addr, interval, base.Add(interval-time.Millisecond)) {
		t.Errorf("claim 1ms before interval should be denied")
	}
	// Exactly at the interval — allowed.
	if !rescheduleClaimSlot(addr, interval, base.Add(interval)) {
		t.Errorf("claim at exactly interval should succeed")
	}
	// Right after a successful claim — denied again.
	if rescheduleClaimSlot(addr, interval, base.Add(interval+time.Millisecond)) {
		t.Errorf("claim just after a fresh success should be denied")
	}
}

// TestRescheduleClaimSlot_PerAddress verifies the limiter is keyed
// by address. A claim against addr A must not block addr B.
func TestRescheduleClaimSlot_PerAddress(t *testing.T) {
	t.Cleanup(ResetRescheduleLimiter)
	ResetRescheduleLimiter()

	now := time.Now()
	if !rescheduleClaimSlot("A", 5*time.Second, now) {
		t.Fatalf("first claim on A failed")
	}
	if !rescheduleClaimSlot("B", 5*time.Second, now) {
		t.Errorf("simultaneous claim on B should succeed; A and B are independent")
	}
}

// TestRescheduleClaimSlot_ZeroInterval: zero interval means the
// limiter is effectively off — every call should succeed.
func TestRescheduleClaimSlot_ZeroInterval(t *testing.T) {
	t.Cleanup(ResetRescheduleLimiter)
	ResetRescheduleLimiter()

	now := time.Now()
	for i := 0; i < 5; i++ {
		if !rescheduleClaimSlot("X", 0, now.Add(time.Duration(i)*time.Millisecond)) {
			t.Errorf("call %d with interval=0 should succeed", i)
		}
	}
}

// TestRescheduleClaimSlot_Concurrent races N goroutines on the same
// address with `now = base`. Exactly one should win; the rest should
// be denied (none of them are at least `interval` apart from each
// other).
func TestRescheduleClaimSlot_Concurrent(t *testing.T) {
	t.Cleanup(ResetRescheduleLimiter)
	ResetRescheduleLimiter()

	const n = 64
	const addr = "concurrent"
	const interval = time.Second
	now := time.Now()

	results := make(chan bool, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			<-start
			results <- rescheduleClaimSlot(addr, interval, now)
		}()
	}
	close(start)

	wins := 0
	for i := 0; i < n; i++ {
		if <-results {
			wins++
		}
	}
	if wins != 1 {
		t.Errorf("expected exactly 1 winner out of %d concurrent calls, got %d",
			n, wins)
	}
}
