package reservation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Source reads everything one tick needs in a single pass, so the parts
// agree with each other and cost one collector query between them. See
// ReadPool, which is the implementation the access point uses.
type Source interface {
	// Read returns the pool as of now, which is when a deadline is
	// judged to still hold.
	Read(ctx context.Context, now time.Time) (View, error)
}

// Pool is the controller's view of the execute points.
//
// Deprecated: set Controller.Source instead. Machines and Held are two
// collector queries over the same ads at two different moments; Source
// reads them once, together, and cannot disagree with itself.
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
//
// Deprecated: set Controller.Source instead. The only implementation
// re-ran the census to count dynamic slots, which View.Running now
// derives from the census the tick already has.
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
	Policy Policy
	Config PlanConfig
	// Source is the one-pass read. When it is set, Pool and Jobs are
	// not consulted.
	Source Source
	// Pool is the superseded two-query read.
	//
	// Deprecated: set Source.
	Pool Pool
	// Jobs is the superseded running-job count.
	//
	// Deprecated: set Source.
	Jobs     Jobs
	Specs    Specs
	Actuator Actuator
	// Now is overridable for tests; nil means time.Now.
	Now func() time.Time

	// ClaimsHoldAlwaysOn says the always-on reservations are held as the
	// schedd's own persistent claims, so this controller should leave
	// them alone.
	//
	// Without it the two would both act on the same reservation: the
	// claims would hold machines through HTCondor while this pushed
	// deadlines at the same machines, and every seat would be counted
	// twice. See the reservation package's claims.go.
	ClaimsHoldAlwaysOn bool

	// clean is the one thing a tick remembers: that the last one found
	// nothing reserved and nothing held, so there is nothing for the
	// next one to read the pool about. It is not memory of what was
	// tagged -- that is still read back from the pool every tick -- it
	// is memory that there was nothing to tag. A reservation appearing
	// in the store clears it on the next tick, because the store is
	// listed before the gate.
	clean bool
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
	// Quiescent is true when the tick did nothing because nothing is
	// reserved and nothing is held. The pool was not read.
	Quiescent bool
}

// Err is the joined error of everything that failed to apply.
func (r TickResult) Err() error { return errors.Join(r.Errs...) }

func (c *Controller) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// mine drops the reservations somebody else is holding.
//
// Filtered here rather than inside Plan so the planning stays a pure
// function of what it is given, and so the quiescence gate above sees
// the same list the plan does -- a controller that had handed its only
// reservation over to the claims should go quiet, not keep reading the
// pool for a reservation it no longer acts on.
func (c *Controller) mine(specs []*Spec) []*Spec {
	if !c.ClaimsHoldAlwaysOn {
		return specs
	}
	out := specs[:0:0]
	for _, s := range specs {
		if s != nil && s.alwaysOn() {
			continue
		}
		out = append(out, s)
	}
	return out
}

// Tick reads the pool, decides, and applies.
func (c *Controller) Tick(ctx context.Context) (TickResult, error) {
	var res TickResult

	specs, err := c.Specs.List(ctx)
	if err != nil {
		return res, fmt.Errorf("listing reservations: %w", err)
	}
	specs = c.mine(specs)

	// With nothing reserved and a pool already confirmed clean, the read
	// below would return the same nothing. Listing the store is local;
	// reading the pool is not, and a reservation holds capacity by
	// evicting other people's jobs, so a subsystem nobody is using
	// should be invisible from outside this process.
	engaged := Engaged(specs, c.now(), c.Policy.Forgive, SettleAfter)
	if !engaged && c.clean {
		res.Quiescent = true
		return res, nil
	}

	view, err := c.read(ctx)
	if err != nil {
		return res, err
	}
	machines, held, running := view.Machines, view.Held, view.Running

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

	// Quiet down only once the pool says so. A reservation deleted or
	// disabled while it held machines leaves them held, and this tick's
	// plan is what releases them; held is what the pool reported before
	// that, so the next tick reads once more and confirms the release
	// landed before anything stops.
	c.clean = !engaged && len(held) == 0 && len(res.Errs) == 0
	return res, nil
}

// read takes the pool, preferring the single-pass Source and falling
// back to the deprecated Pool/Jobs pair.
//
// The fallback is kept because Pool and Jobs are exported and something
// outside this repo may still set them. It is the old behaviour exactly,
// three reads and all: a caller that has not moved to Source should get
// what it had, not a quiet half-migration.
func (c *Controller) read(ctx context.Context) (View, error) {
	if c.Source != nil {
		view, err := c.Source.Read(ctx, c.now())
		if err != nil {
			return View{}, fmt.Errorf("reading the pool: %w", err)
		}
		return view, nil
	}
	machines, err := c.Pool.Machines(ctx)
	if err != nil {
		return View{}, fmt.Errorf("reading the pool: %w", err)
	}
	held, err := c.Pool.Held(ctx)
	if err != nil {
		return View{}, fmt.Errorf("reading what is already held: %w", err)
	}
	running, err := c.Jobs.RunningByProject(ctx)
	if err != nil {
		return View{}, fmt.Errorf("counting running jobs: %w", err)
	}
	return View{Machines: machines, Held: held, Running: running}, nil
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
