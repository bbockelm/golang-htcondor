package reservation

import (
	"context"
	"testing"
	"time"
)

// When the always-on reservations are held as persistent claims, this
// controller must leave them alone: both acting on one reservation
// would count its seats twice and steer the same machines against each
// other.

type listSpecs []*Spec

func (l listSpecs) List(context.Context) ([]*Spec, error) { return l, nil }

// countingSource records whether the pool was read at all.
type countingSource struct {
	reads int
	view  View
}

func (c *countingSource) Read(context.Context, time.Time) (View, error) {
	c.reads++
	return c.view, nil
}

func TestControllerLeavesAlwaysOnToTheClaims(t *testing.T) {
	spec := claimSpec("cs301-lab", 2)
	src := &countingSource{}
	c := &Controller{
		Policy:             Policy{Forgive: 30 * time.Minute},
		Config:             DefaultPlanConfig(),
		Source:             src,
		Specs:              listSpecs{spec},
		Actuator:           &fakeActuator{},
		ClaimsHoldAlwaysOn: true,
	}
	// The first tick reads once to confirm the pool really is holding
	// nothing -- a reservation handed over while it still held machines
	// leaves them held, and that read is what releases them. The second
	// is the one that should find nothing to do at all.
	first, err := c.Tick(context.Background())
	if err != nil {
		t.Fatalf("first tick: %v", err)
	}
	if len(first.Plan.Hold) != 0 || len(first.Plan.Evict) != 0 {
		t.Errorf("the controller acted on a reservation the claims hold: %+v", first.Plan)
	}

	second, err := c.Tick(context.Background())
	if err != nil {
		t.Fatalf("second tick: %v", err)
	}
	if !second.Quiescent {
		t.Errorf("the controller kept working for a reservation it does not act on: %+v", second.Plan)
	}
	if src.reads != 1 {
		t.Errorf("the pool was read %d times, want the one confirming read", src.reads)
	}
}

// With the switch off it is the controller's reservation again, so it
// reads the pool and plans for it. Paired with the test above: without
// this, a controller that had simply stopped working would pass.
func TestControllerStillHoldsAlwaysOnWithoutTheSwitch(t *testing.T) {
	spec := claimSpec("cs301-lab", 2)
	src := &countingSource{}
	c := &Controller{
		Policy:   Policy{Forgive: 30 * time.Minute},
		Config:   DefaultPlanConfig(),
		Source:   src,
		Specs:    listSpecs{spec},
		Actuator: &fakeActuator{},
	}
	for i := 0; i < 2; i++ {
		res, err := c.Tick(context.Background())
		if err != nil {
			t.Fatalf("tick %d: %v", i+1, err)
		}
		if res.Quiescent {
			t.Fatalf("tick %d went quiet for a reservation nothing else is holding", i+1)
		}
	}
	if src.reads != 2 {
		t.Errorf("the pool was read %d times, want once per tick", src.reads)
	}
}
