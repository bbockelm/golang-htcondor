package reservation

import (
	"strings"
	"testing"
	"time"
)

// alwaysSpec is a reservation that holds capacity continuously: no cron
// expression, no recurrence, and none of the three durations that
// describe a window.
func alwaysSpec(t *testing.T) *Spec {
	t.Helper()
	s := seatSpec(gpuSeat)
	s.Kind, s.Schedule = KindAlways, nil
	s.Duration, s.Lead, s.Hold = 0, 0, 0
	return s
}

// TestAlwaysOnNeedsNoScheduleOrWindow: the same spec is rejected as a
// cron reservation and accepted as an always-on one, so the acceptance
// is the kind doing the work rather than the validation being lax.
func TestAlwaysOnNeedsNoScheduleOrWindow(t *testing.T) {
	s := alwaysSpec(t)
	s.Kind = KindCron
	err := s.Validate()
	if err == nil {
		t.Fatal("a cron reservation with no schedule was accepted")
	}
	for _, want := range []string{"Schedule is required", "Duration must be positive", "Lead must be positive"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	s.Kind = KindAlways
	if err := s.Validate(); err != nil {
		t.Errorf("an always-on reservation was rejected: %v", err)
	}
}

// TestAlwaysOnCountsNoOccurrences: there are none to count, and taking
// the number as a hint would stop the reservation on a date nobody
// chose.
func TestAlwaysOnCountsNoOccurrences(t *testing.T) {
	s := alwaysSpec(t)
	s.Starts = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	s.Occurrences = 15
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "no occurrences to count") {
		t.Errorf("an always-on reservation with a count gave %v", err)
	}
	// An end date is how an always-on reservation is bounded, so that
	// must still be accepted.
	s.Occurrences = 0
	s.Ends = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	if err := s.Validate(); err != nil {
		t.Errorf("an always-on reservation with an end date was rejected: %v", err)
	}
}

// TestAlwaysOnHasNoWindows: it holds capacity continuously, so there is
// nothing to list. The cron form of the same reservation lists plenty,
// which is what makes the empty answer meaningful.
func TestAlwaysOnHasNoWindows(t *testing.T) {
	from := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	timed := testSpec(t, "0 14 * * *")
	if got := timed.Windows(from, 7*24*time.Hour, recurForgive); len(got) != 7 {
		t.Fatalf("the timed reservation gave %d windows over a week, want 7", len(got))
	}
	if got := alwaysSpec(t).Windows(from, 7*24*time.Hour, recurForgive); len(got) != 0 {
		t.Errorf("an always-on reservation listed %d windows: %v", len(got), stamps(got))
	}
}

// TestAlwaysOnIsEngagedWhileEnabled: there is no moment at which the
// subsystem could correctly ignore it, because there is no window for it
// to be between.
func TestAlwaysOnIsEngagedWhileEnabled(t *testing.T) {
	s := alwaysSpec(t)
	// No headroom, so nothing but the kind itself can engage it. A
	// reservation with standing capacity engages the subsystem whatever
	// its kind, which would hide the case this test is about.
	s.Standing = 0
	// A Sunday at 03:00: nowhere near any timetable.
	now := time.Date(2026, 3, 15, 3, 0, 0, 0, time.UTC)
	if !Engaged([]*Spec{s}, now, recurForgive, SettleAfter) {
		t.Fatal("an always-on reservation was not engaged")
	}
	// The same reservation with a cron timing and no headroom is not
	// engaged at that hour, which is what makes the answer above the
	// kind doing the work.
	timed := testSpec(t, "0 14 * * 1")
	timed.Standing = 0
	if Engaged([]*Spec{timed}, now, recurForgive, SettleAfter) {
		t.Fatal("a timed reservation was engaged on a Sunday at 03:00")
	}

	s.Enabled = false
	if Engaged([]*Spec{s}, now, recurForgive, SettleAfter) {
		t.Error("a disabled always-on reservation was engaged")
	}
	s.Enabled = true

	s.Starts = now.Add(24 * time.Hour)
	if Engaged([]*Spec{s}, now, recurForgive, SettleAfter) {
		t.Error("an always-on reservation was engaged before it started")
	}
	s.Starts = time.Time{}

	s.Ends = now.Add(-time.Hour)
	if Engaged([]*Spec{s}, now, recurForgive, SettleAfter) {
		t.Error("an always-on reservation was engaged past its end date")
	}
}

// freeMachines is a pool of machines with exactly one seat's worth of
// unused capacity each, so a count of holds is a count of seats.
func freeMachines(n int) []Machine {
	out := make([]Machine, 0, n)
	for i := range n {
		out = append(out, Machine{Name: string(rune('a'+i)) + "-ep", Free: one})
	}
	return out
}

// offSpec is a reservation whose next window is far enough away that the
// planning lead has not begun: Friday's window seen from Monday morning.
func offSpec(t *testing.T, standing int) *Spec {
	t.Helper()
	s := planSpec(t, "cs301", "cs301-f26", "0 14 * * 5")
	s.Seats, s.Standing = 20, standing
	return s
}

// TestStandingOutOfWindowIsAskedForExactly: two spare instances means
// two. The over-provisioning that precedes a window pays for machines
// that may not come good by the time it opens; headroom has no such
// moment, and asking for the over-provisioned count would hold three
// times what was asked out of the pool for as long as the reservation
// lasts.
func TestStandingOutOfWindowIsAskedForExactly(t *testing.T) {
	spec := offSpec(t, 2)
	tick := planTick(t, spec, freeMachines(20), nil)
	plan := planPolicy().Plan(tick, DefaultPlanConfig())

	if len(plan.Hold) != 2 {
		t.Fatalf("standing 2 held %d machines, want 2: %+v", len(plan.Hold), plan.Hold)
	}
	// Named so a regression reads as what it is rather than as an
	// arbitrary count being wrong.
	if over := Want(2, 0); over == 2 {
		t.Fatalf("Want(2, 0) is %d, so this test cannot tell the two apart", over)
	} else if len(plan.Hold) == over {
		t.Errorf("standing capacity was routed through the over-provisioning: held %d", over)
	}
	for _, h := range plan.Hold {
		if !h.Deadline.Equal(planNow) {
			t.Errorf("%s is held to %v, want now (%v): headroom is wanted already", h.Machine, h.Deadline, planNow)
		}
		if want := planNow.Add(StandingLease); !h.Until.Equal(want) {
			t.Errorf("%s is held until %v, want a lease to %v", h.Machine, h.Until, want)
		}
	}
}

// TestStandingCountsNoRunningJobsAgainstItself is the headroom rule as
// the plan sees it: a project already using five instances still gets
// its two spare.
func TestStandingCountsNoRunningJobsAgainstItself(t *testing.T) {
	spec := offSpec(t, 2)
	tick := planTick(t, spec, freeMachines(20), nil)
	tick.Running = map[string]int{"cs301-f26": 5}
	plan := planPolicy().Plan(tick, DefaultPlanConfig())
	if len(plan.Hold) != 2 {
		t.Errorf("with five running, standing 2 held %d machines, want 2", len(plan.Hold))
	}

	// At the cap there is no room for headroom: holding more would
	// promise capacity the project may not occupy.
	tick.Running = map[string]int{"cs301-f26": spec.Seats}
	if plan := planPolicy().Plan(tick, DefaultPlanConfig()); len(plan.Hold) != 0 {
		t.Errorf("at the cap, standing held %d machines", len(plan.Hold))
	}
}

// TestStandingHoldsNothingWhenNoneIsAsked: the headroom branch must not
// start holding machines for every reservation that happens to be
// between windows.
func TestStandingHoldsNothingWhenNoneIsAsked(t *testing.T) {
	spec := offSpec(t, 0)
	plan := planPolicy().Plan(planTick(t, spec, freeMachines(20), nil), DefaultPlanConfig())
	if len(plan.Hold) != 0 {
		t.Errorf("a reservation with no standing capacity held %d machines", len(plan.Hold))
	}
}

// TestStandingPreemptsNothing: throwing away running work to create an
// idle instance spends something real for something nobody is waiting
// on. The headroom appears as the jobs on the held machine finish.
func TestStandingPreemptsNothing(t *testing.T) {
	spec := offSpec(t, 2)
	// Every machine is busy with a job young enough that evicting it
	// would be free under the policy -- so an eviction is available and
	// is declined, rather than being impossible.
	tick := planTick(t, spec, busyMachines(20, time.Minute, 2*time.Hour), nil)
	plan := planPolicy().Plan(tick, DefaultPlanConfig())
	if len(plan.Hold) == 0 {
		t.Fatal("standing capacity held nothing at all on a busy pool")
	}
	if len(plan.Evict) != 0 {
		t.Errorf("standing capacity preempted %d jobs: %+v", len(plan.Evict), plan.Evict)
	}
}

// TestStandingYieldsToAWindowAboutToOpen: a window is a commitment at a
// time and headroom is not, so when the pool cannot serve both, the
// window wins. Headroom's deadline is now, which would otherwise sort it
// ahead of everything.
func TestStandingYieldsToAWindowAboutToOpen(t *testing.T) {
	soon := planSpec(t, "soon", "cs301-f26", "0 14 * * 1") // opens in six hours
	soon.Seats, soon.Standing = 2, 0
	idle := planSpec(t, "idle", "bio500-f26", "0 14 * * 5") // Friday: no window near
	idle.Seats, idle.Standing = 2, 2

	// Exactly enough for the window's over-provisioned ask and nothing
	// over, so the two reservations are genuinely in competition.
	machines := freeMachines(Want(2, 0))
	tick := Tick{
		Now: planNow, Machines: machines, Specs: []*Spec{idle, soon},
		Running: map[string]int{}, Tagged: map[string]time.Time{},
		Need: map[string]Resources{soon.ID: one, idle.ID: one},
	}
	plan := planPolicy().Plan(tick, DefaultPlanConfig())

	for _, h := range plan.Hold {
		for _, id := range h.For {
			if id == "idle" {
				t.Errorf("%s was held for standing capacity while a window was about to open", h.Machine)
			}
		}
	}
	if plan.Short["idle"] != 2 {
		t.Errorf("the standing ask reported short %d, want 2: the pool really was spoken for", plan.Short["idle"])
	}
}

// TestAlwaysOnPlansExactStandingHeadroom: an always-on reservation is
// the standing rule with no window ever opening. It must therefore never
// reach the planning phase, where the ask is over-provisioned.
func TestAlwaysOnPlansExactStandingHeadroom(t *testing.T) {
	spec := alwaysSpec(t)
	spec.ID, spec.Project = "cs301", "cs301-f26"
	spec.Seats, spec.Standing = 20, 3

	tick := planTick(t, spec, freeMachines(20), nil)
	plan := planPolicy().Plan(tick, DefaultPlanConfig())
	if len(plan.Hold) != 3 {
		t.Fatalf("an always-on reservation with standing 3 held %d machines, want 3", len(plan.Hold))
	}
	if over := Want(3, 0); len(plan.Hold) == over {
		t.Errorf("an always-on reservation was over-provisioned to %d machines", over)
	}
	if _, _, ok := spec.activeWindow(planNow, 30*time.Minute); ok {
		t.Error("an always-on reservation reported an active window")
	}
}

// TestStandingStopsWhenTheReservationIsOver: the last window produces
// nothing, but headroom has no window to run out, so without the bound
// it would go on holding part of the pool for a reservation nobody is
// using any more.
func TestStandingStopsWhenTheReservationIsOver(t *testing.T) {
	spec := offSpec(t, 2)
	spec.Starts = planNow.Add(-30 * 24 * time.Hour)
	spec.Ends = planNow.Add(24 * time.Hour)
	if plan := planPolicy().Plan(planTick(t, spec, freeMachines(20), nil), DefaultPlanConfig()); len(plan.Hold) != 2 {
		t.Fatalf("inside its dates, standing held %d machines, want 2", len(plan.Hold))
	}

	spec.Ends = planNow.Add(-time.Hour)
	if plan := planPolicy().Plan(planTick(t, spec, freeMachines(20), nil), DefaultPlanConfig()); len(plan.Hold) != 0 {
		t.Errorf("past its end date, standing still held machines")
	}

	spec.Ends = time.Time{}
	spec.Starts = planNow.Add(24 * time.Hour)
	if plan := planPolicy().Plan(planTick(t, spec, freeMachines(20), nil), DefaultPlanConfig()); len(plan.Hold) != 0 {
		t.Errorf("before its start date, standing already held machines")
	}
}
