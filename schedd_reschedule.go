package htcondor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
)

// DefaultRescheduleInterval is the minimum wall-clock gap between
// successful Reschedule calls to the same schedd address.
//
// Five seconds matches the typical NEGOTIATOR_INTERVAL operators
// configure for low-latency pools and stays well clear of the rate
// at which a busy submitter loop might fire-and-forget reschedule
// requests — sending one after every Submit in a tight loop should
// not amount to DoS pressure on the schedd.
const DefaultRescheduleInterval = 5 * time.Second

// rescheduleLimiter is a process-wide last-send tracker keyed by
// schedd address. It's intentionally not bounded: in practice a
// process talks to at most a handful of schedds, so unbounded growth
// is not a real concern. If a use case ever materializes that
// rotates through tens of thousands of addresses, swap to an LRU.
var rescheduleLimiter sync.Map // map[string]time.Time

// Reschedule asks the schedd to push a fresh submitter ad to the
// collector and kick off a negotiation cycle. This is the wire-level
// equivalent of `condor_reschedule <schedd>`.
//
// Why call this: after Schedd.Submit, the schedd doesn't immediately
// advertise a SubmitterAd; it waits SCHEDD_INTERVAL (default 300s)
// before its next collector update. The negotiator can't match the
// new job until a SubmitterAd arrives, so without Reschedule a fresh
// pool may take minutes to start the first job. condor_submit fires
// a reschedule itself; library callers must do the same.
//
// Rate limiting: this client deliberately throttles successful
// reschedule requests to one every DefaultRescheduleInterval per
// schedd address (process-wide). The schedd treats reschedules as
// advisory anyway — it coalesces close-together requests — so
// dropping the duplicate on the client side is purely a courtesy.
// To bypass the limiter use RescheduleWithOptions with
// MinInterval = 0.
//
// Errors: returns a non-nil error only when the connect/auth itself
// fails. A rate-limited skip returns nil; callers should treat
// Reschedule as advisory regardless. The context's deadline applies
// to the connect/auth attempt.
func (s *Schedd) Reschedule(ctx context.Context) error {
	return s.RescheduleWithOptions(ctx, nil)
}

// RescheduleOptions tunes Reschedule's behavior for a single call.
type RescheduleOptions struct {
	// MinInterval is the minimum gap between successful reschedule
	// requests to this schedd. Zero disables the limiter for this
	// call. Negative is treated as zero. If unset (zero value),
	// DefaultRescheduleInterval applies.
	MinInterval time.Duration

	// Force, when true, sends the reschedule even if the limiter
	// would otherwise skip it. Equivalent to MinInterval = 0 but
	// reads better at call sites that want the limiter to *protect
	// the schedd from us* most of the time and *not* protect it
	// during, say, an end-to-end test setup.
	Force bool
}

// RescheduleWithOptions is the configurable form of Reschedule. See
// the Reschedule doc for behavior; opts controls the rate limiter.
func (s *Schedd) RescheduleWithOptions(ctx context.Context, opts *RescheduleOptions) error {
	interval := DefaultRescheduleInterval
	force := false
	if opts != nil {
		if opts.MinInterval > 0 {
			interval = opts.MinInterval
		} else if opts.MinInterval < 0 {
			interval = 0
		}
		force = opts.Force
	}
	if !force && interval > 0 {
		if !rescheduleClaimSlot(s.address, interval, time.Now()) {
			// Limiter declined — this is a no-op success.
			return nil
		}
	}

	secConfig, err := GetSecurityConfigOrDefault(ctx, nil,
		int(commands.RESCHEDULE), "CLIENT", s.address)
	if err != nil {
		return fmt.Errorf("reschedule: build security config: %w", err)
	}

	htcondorClient, err := client.ConnectAndAuthenticate(ctx, s.address, secConfig)
	if err != nil {
		return wrapScheddConnectError(s.address, err)
	}
	return htcondorClient.Close()
}

// rescheduleClaimSlot returns true if `now` is at least `interval`
// after the last claim recorded for `addr`, and atomically records
// `now` as the new last claim. Returns false otherwise without
// modifying state.
//
// Concurrency: two goroutines racing on the same address will both
// observe the same prior value; LoadOrStore picks one winner and
// the loser's CompareAndSwap fails. We retry once to recover the
// case where the prior winner stored a newer timestamp that is
// itself still close enough to deny us.
func rescheduleClaimSlot(addr string, interval time.Duration, now time.Time) bool {
	for i := 0; i < 2; i++ {
		prev, loaded := rescheduleLimiter.LoadOrStore(addr, now)
		if !loaded {
			// First time we've seen this address — slot is ours.
			return true
		}
		prevTime, ok := prev.(time.Time)
		if !ok {
			// Defensive: shouldn't happen, but if the map ever
			// gets corrupted, repopulate.
			rescheduleLimiter.Store(addr, now)
			return true
		}
		if now.Sub(prevTime) < interval {
			return false
		}
		if rescheduleLimiter.CompareAndSwap(addr, prevTime, now) {
			return true
		}
		// Another goroutine raced ahead of us; reload and retry.
	}
	return false
}

// ResetRescheduleLimiter clears the per-process reschedule rate
// limiter state. Intended for tests; production callers shouldn't
// need it.
func ResetRescheduleLimiter() {
	rescheduleLimiter.Range(func(k, _ any) bool {
		rescheduleLimiter.Delete(k)
		return true
	})
}
