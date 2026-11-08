package reservation

import (
	"testing"
	"time"
)

func planSpec(t *testing.T, id, project, cron string) *Spec {
	t.Helper()
	s := seatSpec(gpuSeat)
	s.ID, s.Project = id, project
	s.Seats, s.Standing = 4, 0
	s.Duration, s.Lead, s.Hold = time.Hour, 6*time.Hour, 15*time.Minute
	s.Schedule = mustSchedule(t, cron, time.UTC)
	return s
}

// planNow is a Monday 08:00 UTC; a "0 14 * * 1" class is six hours out,
// which is exactly the planning lead.
var planNow = time.Date(2026, 3, 2, 8, 0, 0, 0, time.UTC)

func planPolicy() Policy {
	return Policy{Forgive: 30 * time.Minute, Reserved: map[string]bool{"cs301-f26": true}}
}

func busyMachines(n int, age time.Duration, left time.Duration) []Machine {
	out := make([]Machine, 0, n)
	for i := range n {
		out = append(out, Machine{
			Name:   string(rune('a'+i)) + "-ep",
			Dslots: []Dslot{{Started: planNow.Add(-age), Res: one, Remaining: left}},
		})
	}
	return out
}

func planTick(t *testing.T, spec *Spec, machines []Machine, tagged map[string]time.Time) Tick {
	t.Helper()
	return Tick{
		Now: planNow, Machines: machines, Specs: []*Spec{spec},
		Running: map[string]int{}, Tagged: tagged,
		Need: map[string]Resources{spec.ID: one},
	}
}

func TestPlanHoldsMoreThanItNeeds(t *testing.T) {
	spec := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1") // bell 6h out
	tick := planTick(t, spec, busyMachines(20, time.Hour, 2*time.Hour), nil)
	plan := planPolicy().Plan(tick, DefaultPlanConfig())

	// No core is guaranteed six hours out -- guarantees only accrue in the
	// last Forgive -- so the hold is the full Want for four seats.
	if want := Want(4, 0); len(plan.Hold) != want {
		t.Errorf("held %d machines, want %d", len(plan.Hold), want)
	}
	if len(plan.Hold) <= spec.Seats {
		t.Errorf("held %d machines for %d seats: a hold must exceed the seats it covers", len(plan.Hold), spec.Seats)
	}
	for _, h := range plan.Hold {
		if !h.Deadline.Equal(planNow.Add(6 * time.Hour)) {
			t.Errorf("%s held until %v, want the bell", h.Machine, h.Deadline)
		}
		if len(h.For) != 1 || h.For[0] != "cs301" {
			t.Errorf("%s held for %v", h.Machine, h.For)
		}
	}
	if len(plan.Evict) != 0 {
		t.Errorf("evicted %d slots while still planning", len(plan.Evict))
	}
}

// TestPlanPrefersMachinesAboutToFreeUp: a tag only governs the next
// admission, so it is worth spending on a machine that will turn over
// before the bell. One that will not never makes an admission decision.
func TestPlanPrefersMachinesAboutToFreeUp(t *testing.T) {
	spec := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1")
	spec.Seats = 1
	hold := Want(1, 0) // 4 machines held for one seat
	// Eight equally cheap machines, differing only in when they free up.
	// The four soonest should be chosen and the four latest left alone.
	lefts := []time.Duration{
		20 * time.Hour, 10 * time.Minute, 15 * time.Hour, 5 * time.Minute,
		30 * time.Minute, 18 * time.Hour, 2 * time.Minute, 25 * time.Hour,
	}
	var machines []Machine
	for i, left := range lefts {
		machines = append(machines, Machine{
			Name:   string(rune('a' + i)),
			Dslots: []Dslot{{Started: planNow.Add(-time.Hour), Res: one, Remaining: left}},
		})
	}
	plan := planPolicy().Plan(planTick(t, spec, machines, nil), DefaultPlanConfig())
	if len(plan.Hold) != hold {
		t.Fatalf("held %d machines, want %d (so the choice is not vacuous)", len(plan.Hold), hold)
	}
	held := map[string]bool{}
	for _, h := range plan.Hold {
		held[h.Machine] = true
	}
	// g=2min, d=5min, b=10min, e=30min are the four soonest.
	for _, name := range []string{"g", "d", "b", "e"} {
		if !held[name] {
			t.Errorf("machine %s frees up soon but was not held; held %v", name, held)
		}
	}
	for _, name := range []string{"a", "c", "f", "h"} {
		if held[name] {
			t.Errorf("machine %s will not free up before the bell but was held", name)
		}
	}
}

// TestPlanStopsHoldingInsideForgive: within the forgiveness window a tag
// changes nothing, because anything started from there is cheap to evict
// at the bell anyway.
func TestPlanStopsHoldingInsideForgive(t *testing.T) {
	spec := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1")
	tick := planTick(t, spec, busyMachines(20, time.Hour, 2*time.Hour), nil)
	tick.Now = planNow.Add(6*time.Hour - 20*time.Minute) // 20 min to the bell
	plan := planPolicy().Plan(tick, DefaultPlanConfig())
	if len(plan.Hold) != 0 {
		t.Errorf("held %d machines inside the forgiveness window", len(plan.Hold))
	}
}

// TestPlanEvictsOnlyAtTheBell.
func TestPlanEvictsOnlyAtTheBell(t *testing.T) {
	spec := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1")
	tick := planTick(t, spec, busyMachines(10, 3*time.Hour, 20*time.Hour), nil)
	tick.Now = planNow.Add(6 * time.Hour) // the bell
	plan := planPolicy().Plan(tick, DefaultPlanConfig())
	if len(plan.Evict) != spec.Seats {
		t.Fatalf("evicted %d slots at the bell, want %d", len(plan.Evict), spec.Seats)
	}
	if len(plan.Hold) != 0 {
		t.Errorf("still holding machines at the bell: %v", plan.Hold)
	}
	for _, e := range plan.Evict {
		if e.Reservation != "cs301" {
			t.Errorf("eviction attributed to %q", e.Reservation)
		}
	}
}

// TestPlanCountsRunningJobsAsSeats: a reservation that already has what it
// asked for holds nothing. It exists to make room, not to idle capacity.
func TestPlanCountsRunningJobsAsSeats(t *testing.T) {
	spec := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1")
	tick := planTick(t, spec, busyMachines(20, time.Hour, 2*time.Hour), nil)
	tick.Running = map[string]int{"cs301-f26": spec.Seats}
	plan := planPolicy().Plan(tick, DefaultPlanConfig())
	if len(plan.Hold) != 0 || len(plan.Evict) != 0 {
		t.Errorf("a fully seated reservation planned hold=%d evict=%d", len(plan.Hold), len(plan.Evict))
	}
}

// TestPlanUntagsOnlyOnARealSurplus: untagging is not reversible on the
// drain's timescale, so it waits for a surplus worth acting on.
func TestPlanUntagsOnlyOnARealSurplus(t *testing.T) {
	spec := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1")
	spec.Enabled = false // nothing is wanted at all
	tagged := map[string]time.Time{}
	for i := range 10 {
		tagged[string(rune('a'+i))+"-ep"] = planNow.Add(6 * time.Hour)
	}
	cfg := DefaultPlanConfig()
	plan := planPolicy().Plan(planTick(t, spec, busyMachines(10, time.Hour, 2*time.Hour), tagged), cfg)
	if len(plan.Untag) != len(tagged) {
		t.Errorf("a disabled reservation released %d of %d machines", len(plan.Untag), len(tagged))
	}
}

// TestPlanReportsAShortfallRatherThanPretending.
func TestPlanReportsAShortfallRatherThanPretending(t *testing.T) {
	spec := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1")
	spec.Seats = 20
	// Two machines, each with one slot: nowhere near twenty seats.
	plan := planPolicy().Plan(planTick(t, spec, busyMachines(2, time.Hour, 2*time.Hour), nil), DefaultPlanConfig())
	if plan.Short["cs301"] == 0 {
		t.Errorf("a pool too small to seat the class reported no shortfall: %+v", plan)
	}
}

// TestPlanWithoutASeatShapeIsShort: no shape, no plan -- and it says so
// rather than quietly holding nothing.
func TestPlanWithoutASeatShapeIsShort(t *testing.T) {
	spec := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1")
	tick := planTick(t, spec, busyMachines(20, time.Hour, 2*time.Hour), nil)
	tick.Need = nil
	plan := planPolicy().Plan(tick, DefaultPlanConfig())
	if plan.Short["cs301"] != spec.Seats {
		t.Errorf("short = %d, want the whole ask (%d)", plan.Short["cs301"], spec.Seats)
	}
	if len(plan.Hold) != 0 {
		t.Errorf("held %d machines with no seat shape", len(plan.Hold))
	}
}

// TestPlanSoonerBellWinsTheMachines is the multi-reservation interaction:
// the same core cannot be promised twice, and the reservation that needs
// it first gets it.
func TestPlanSoonerBellWinsTheMachines(t *testing.T) {
	soon := planSpec(t, "soon", "cs301-f26", "0 14 * * 1")    // 6h out
	later := planSpec(t, "later", "bio500-f26", "0 18 * * 1") // 10h out
	later.Lead = 12 * time.Hour                               // so it is also planning
	machines := busyMachines(6, time.Hour, 2*time.Hour)
	tick := Tick{
		Now: planNow, Machines: machines, Specs: []*Spec{later, soon},
		Running: map[string]int{}, Tagged: nil,
		Need: map[string]Resources{"soon": one, "later": one},
	}
	pol := Policy{Forgive: 30 * time.Minute, Reserved: map[string]bool{"cs301-f26": true, "bio500-f26": true}}
	plan := pol.Plan(tick, DefaultPlanConfig())

	bell := planNow.Add(6 * time.Hour)
	for _, h := range plan.Hold {
		if h.For[0] != "soon" {
			continue
		}
		if !h.Deadline.Equal(bell) {
			t.Errorf("%s held until %v, want the sooner bell %v", h.Machine, h.Deadline, bell)
		}
	}
	// With only six machines the later reservation cannot also be covered.
	if plan.Short["later"] == 0 {
		t.Errorf("the later reservation reported no shortfall on a pool the sooner one took: %+v", plan.Short)
	}
}
