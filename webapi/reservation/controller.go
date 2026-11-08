package reservation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Pool is the controller's view of the execute points.
type Pool interface {
	// Machines is the current census.
	Machines(ctx context.Context) ([]Machine, error)
	// Held is the deadline currently pushed to each machine, read back
	// from the pool rather than remembered. A controller restarted
	// mid-drain has to pick up where the pool actually is, and a
	// deadline left behind by a dead one has to be visible so it can be
	// cleared.
	Held(ctx context.Context) (map[string]time.Time, error)
}

// Jobs reports what each project is already running. A project's own
// running jobs are seats it already holds.
type Jobs interface {
	RunningByProject(ctx context.Context) (map[string]int, error)
}

// Actuator applies a plan. It is an interface because the only
// implementation talks to startds over CEDAR, which is not something a
// test should need.
//
// Hold pushes absolute times rather than a flag: the machine attributes
// they become cannot be deleted and have no expiry, so a time in the
// past stops constraining anything on its own and a controller that
// dies leaves the pool recoverable.
type Actuator interface {
	Hold(ctx context.Context, h HoldRequest) error
	Release(ctx context.Context, machine string) error
	Evict(ctx context.Context, e EvictRequest) error
}

// HoldRequest is one machine to put under a reservation.
type HoldRequest struct {
	Machine string
	// Deadline is the bell: nothing may start here that will not have
	// finished by then.
	Deadline time.Time
	// Until is when the reservation ends and the machine is the pool's
	// again.
	Until time.Time
	// Project is the ProjectName whose jobs the machine is held for.
	Project string
}

// EvictRequest is one running job to preempt.
//
// Slot is the slot ad's Name, which is how the startd that owns it
// names the claim. Machine is carried for the error message and to
// find the execute point; the startd does the rest by name.
type EvictRequest struct {
	Machine string
	Slot    string
}

// Specs supplies the reservations to act on.
type Specs interface {
	List(ctx context.Context) ([]*Spec, error)
}

// Controller runs one tick of the reservation policy against a pool.
//
// It is deliberately a single pass with no memory between ticks: every
// decision is taken from what the pool reports now. A controller that
// remembered what it had tagged would disagree with the pool after a
// restart, a missed push or a second controller, and the disagreement
// would be invisible.
type Controller struct {
	Policy   Policy
	Config   PlanConfig
	Pool     Pool
	Jobs     Jobs
	Specs    Specs
	Actuator Actuator
	// Now is overridable for tests; nil means time.Now.
	Now func() time.Time
}

// TickResult reports what one tick did, for logging and for the admin
// page. Errors applying individual machines are collected rather than
// aborting the tick: one unreachable startd should not stop the others
// being held.
type TickResult struct {
	Plan     Plan
	Held     int
	Released int
	Evicted  int
	Errs     []error
}

// Err is the joined error of everything that failed to apply.
func (r TickResult) Err() error { return errors.Join(r.Errs...) }

func (c *Controller) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Tick reads the pool, decides, and applies.
func (c *Controller) Tick(ctx context.Context) (TickResult, error) {
	var res TickResult

	specs, err := c.Specs.List(ctx)
	if err != nil {
		return res, fmt.Errorf("listing reservations: %w", err)
	}
	machines, err := c.Pool.Machines(ctx)
	if err != nil {
		return res, fmt.Errorf("reading the pool: %w", err)
	}
	held, err := c.Pool.Held(ctx)
	if err != nil {
		return res, fmt.Errorf("reading what is already held: %w", err)
	}
	running, err := c.Jobs.RunningByProject(ctx)
	if err != nil {
		return res, fmt.Errorf("counting running jobs: %w", err)
	}

	// Only projects that actually hold a reservation are protected from
	// eviction. Every project-tagged job would be far too many.
	policy := c.Policy
	policy.Reserved = map[string]bool{}
	need := map[string]Resources{}
	for _, spec := range specs {
		if spec == nil || !spec.Enabled {
			continue
		}
		policy.Reserved[spec.Project] = true
		shape, err := spec.SeatResources()
		if err != nil {
			// Left out of need, which Plan reports as a shortfall for
			// that reservation rather than silently planning nothing.
			res.Errs = append(res.Errs, fmt.Errorf("reservation %s: %w", spec.ID, err))
			continue
		}
		need[spec.ID] = shape
	}

	tick := Tick{
		Now: c.now(), Machines: machines, Specs: specs,
		Running: running, Tagged: held, Need: need,
	}
	res.Plan = policy.Plan(tick, c.Config)
	res.Errs = append(res.Errs, c.apply(ctx, res.Plan, specs, machines, &res)...)
	return res, nil
}

// apply pushes a plan. Releases go first so a machine moving from one
// reservation to another is never briefly held for neither, and evictions
// go last so nothing is preempted for a seat that was not secured.
func (c *Controller) apply(ctx context.Context, plan Plan, specs []*Spec, machines []Machine, res *TickResult) []error {
	project := map[string]string{}
	for _, s := range specs {
		if s != nil {
			project[s.ID] = s.Project
		}
	}
	var mu sync.Mutex
	var errs []error
	fail := func(err error) {
		mu.Lock()
		errs = append(errs, err)
		mu.Unlock()
	}

	for _, name := range plan.Untag {
		if err := c.Actuator.Release(ctx, name); err != nil {
			fail(fmt.Errorf("releasing %s: %w", name, err))
			continue
		}
		res.Released++
	}
	for _, h := range plan.Hold {
		// The project of the reservation whose bell is soonest, which is
		// the one whose deadline and window end are being pushed.
		var p string
		if len(h.For) > 0 {
			p = project[h.For[0]]
		}
		if err := c.Actuator.Hold(ctx, HoldRequest{
			Machine: h.Machine, Deadline: h.Deadline, Until: h.Until, Project: p,
		}); err != nil {
			fail(fmt.Errorf("holding %s: %w", h.Machine, err))
			continue
		}
		res.Held++
	}
	for _, e := range plan.Evict {
		slot := slotName(machines, e)
		if slot == "" {
			// A census built without slot names cannot evict. Say so
			// rather than guessing at which d-slot of the machine the
			// index meant: vacating the wrong one preempts somebody
			// who was not in the way and leaves the one that was.
			fail(fmt.Errorf("evicting %s d-slot %d: the census carries no slot name", e.Machine, e.Dslot))
			continue
		}
		if err := c.Actuator.Evict(ctx, EvictRequest{Machine: e.Machine, Slot: slot}); err != nil {
			fail(fmt.Errorf("evicting %s: %w", slot, err))
			continue
		}
		res.Evicted++
	}
	sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
	return errs
}

// slotName resolves an eviction's (machine, d-slot index) against the
// census the plan was made from. Empty when the census does not name
// that slot.
func slotName(machines []Machine, e Eviction) string {
	for _, m := range machines {
		if m.Name != e.Machine {
			continue
		}
		if e.Dslot < 0 || e.Dslot >= len(m.Dslots) {
			return ""
		}
		return m.Dslots[e.Dslot].Slot
	}
	return ""
}

// Run ticks until ctx is cancelled. A tick that fails to read the pool is
// logged by the caller and retried next interval; the pool is left exactly
// as it was, which is safe because every deadline already pushed expires
// on its own.
func (c *Controller) Run(ctx context.Context, every time.Duration, report func(TickResult, error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		res, err := c.Tick(ctx)
		if report != nil {
			report(res, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
