package reservation

import (
	"context"
	"time"
)

// Nothing here should touch the pool or the job queue while no
// reservation needs it. Every loop in this package reads the pool on an
// interval, the prober writes to a machine ad, and the stamper writes to
// other people's cluster ads. On an access point that has the feature
// switched on but nothing booked, all of that is cost with no purpose --
// and any failure in it is a warning about work that did not need doing,
// which is worse than no warning at all.
//
// Engaged is the single predicate the loops gate on. It is answered from
// the reservation store, which is local, so asking it every tick costs
// nothing and a reservation created while quiescent is noticed on the
// next one.

// SettleAfter is how long a reservation stays engaged past the end of
// its window.
//
// Releasing the machines it held is a tick like any other, so the period
// the controller is awake for has to outlast the reservation it undoes.
// Several ticks' worth, because a tick that cannot reach an execute
// point has to be able to try again.
const SettleAfter = 15 * time.Minute

// StampWarmup is how far ahead of a reservation stamping starts.
//
// A held machine admits only jobs carrying a bucket that fits before the
// bell, so the queue has to be stamped by the time the first machine is
// held -- which is the start of the planning lead, not the bell. Several
// passes' worth of margin, so a queue that needs more than one pass is
// still ready in time.
const StampWarmup = 20 * time.Minute

// Engaged reports whether any of specs needs the subsystem to act at now.
//
// A standing reservation is always engaged: it holds seats whether or not
// a class is in session. Every other spec is engaged from the start of
// its planning lead until settle past the end of its window.
func Engaged(specs []*Spec, now time.Time, forgive, settle time.Duration) bool {
	for _, s := range specs {
		if s == nil || !s.Enabled {
			continue
		}
		if s.Standing > 0 {
			return true
		}
		if _, _, ok := s.activeWindow(now, forgive); ok {
			return true
		}
		// A window that closed moments ago still has machines held for
		// it, and the tick that releases them has yet to run.
		if settle > 0 {
			if _, _, ok := s.activeWindow(now.Add(-settle), forgive); ok {
				return true
			}
		}
	}
	return false
}

// Gate answers whether a loop should do its work this time round.
type Gate func(ctx context.Context) (bool, error)

// SpecGate is a Gate reading the reservations from specs.
//
// ahead moves the question forward in time, which is how a loop wakes
// before the reservation it is preparing for: the stamper has to have
// the queue stamped by the time the controller holds the first machine.
func SpecGate(specs Specs, forgive, settle, ahead time.Duration, now func() time.Time) Gate {
	return func(ctx context.Context) (bool, error) {
		list, err := specs.List(ctx)
		if err != nil {
			return false, err
		}
		at := time.Now()
		if now != nil {
			at = now()
		}
		return Engaged(list, at.Add(ahead), forgive, settle), nil
	}
}
