package reservation

import (
	"sort"
	"time"
)

// Tick is everything the controller knows at one moment.
type Tick struct {
	Now      time.Time
	Machines []Machine
	Specs    []*Spec
	// Running counts each project's jobs that are currently executing.
	// A project's own running jobs are seats it already holds.
	Running map[string]int
	// Tagged is the deadline currently pushed to each machine, as read
	// back from the pool rather than remembered. The controller can be
	// restarted mid-drain and must pick up where the pool actually is.
	Tagged map[string]time.Time
	// Need is each reservation's seat shape, keyed by reservation ID,
	// rendered from its submit file by the caller. A reservation with no
	// entry cannot be planned for and is reported short: without a shape
	// there is no way to say which machines could host it.
	Need map[string]Resources
}

// Hold is a machine the controller wants held, and until when.
//
// The deadline is absolute rather than a flag because the attribute it
// becomes cannot be deleted and has no expiry: a controller that dies
// leaves it behind, and an absolute deadline in the past stops
// constraining anything on its own.
type Hold struct {
	Machine  string
	Deadline time.Time
	// For names the reservations this machine is held for, soonest bell
	// first. Only the earliest deadline reaches the pool; the rest are
	// here so an operator can see why a machine is held.
	For []string
}

// Eviction is one d-slot to preempt so a reservation can seat a job.
type Eviction struct {
	Machine     string
	Dslot       int
	Reservation string
	// Waste is what the eviction costs under the policy; zero is free.
	Waste time.Duration
}

// Plan is what to do this tick.
type Plan struct {
	Hold  []Hold
	Untag []string
	Evict []Eviction
	// Short is how many seats each reservation cannot get from the pool
	// at all, keyed by reservation ID. A non-empty entry is an operator
	// problem -- too small a pool, or too little lead -- not something
	// the controller can fix by tagging harder.
	Short map[string]int
}

// PlanConfig is the controller's tuning. None of it describes the pool;
// the pool is measured, not assumed.
type PlanConfig struct {
	// HBuffer is how many machines of surplus to tolerate before
	// untagging, so the count does not chatter.
	HBuffer int
	// SwapGain is how much better a candidate must look before a tag
	// moves to it. A tag only changes anything if the machine turns over
	// before the bell, so tags are worth moving toward machines about to
	// free up -- but the estimate moves as jobs run, and swapping on
	// noise is churn.
	SwapGain float64
}

// DefaultPlanConfig is the tuning the measurements were taken with.
func DefaultPlanConfig() PlanConfig { return PlanConfig{HBuffer: 3, SwapGain: 0.75} }

// activeWindow is the window a spec is currently acting for, if any: the
// one in progress, else the next one once its planning lead has started.
func (s *Spec) activeWindow(now time.Time, forgive time.Duration) (Window, Phase, bool) {
	// Look back far enough to catch a window already in progress, and
	// forward past the lead to catch the next one.
	for _, w := range s.Windows(now.Add(-s.Duration-forgive), s.Duration+s.Lead+forgive, forgive) {
		if phase := s.PhaseAt(w, now); phase != PhaseOff {
			return w, phase, true
		}
	}
	return Window{}, PhaseOff, false
}

// Plan decides this tick: which machines to hold, which to release, and
// what to preempt.
func (p Policy) Plan(t Tick, cfg PlanConfig) Plan {
	out := Plan{Short: map[string]int{}}

	// What each reservation wants, and by when.
	type active struct {
		spec   *Spec
		window Window
		phase  Phase
		want   int
		need   Resources
	}
	var acts []active
	for _, spec := range t.Specs {
		if spec == nil || !spec.Enabled {
			continue
		}
		window, phase, ok := spec.activeWindow(t.Now, p.Forgive)
		if !ok {
			// Outside every window the standing seats still apply, but
			// there is no bell to drain towards, so nothing is held.
			continue
		}
		want := spec.Target(phase, t.Running[spec.Project])
		if want <= 0 {
			continue
		}
		need, ok := t.Need[spec.ID]
		if !ok {
			// A reservation whose submit file no longer renders has no
			// shape to plan against. Say so by reporting the whole ask
			// as short rather than silently holding nothing.
			out.Short[spec.ID] = want
			continue
		}
		acts = append(acts, active{spec, window, phase, want, need})
	}
	if len(acts) == 0 {
		out.Untag = taggedMachines(t.Tagged)
		return out
	}

	// Divide the pool in bell order so no core is promised twice.
	demands := make([]Demand, 0, len(acts))
	byID := map[string]active{}
	for _, a := range acts {
		// While planning, ask for the over-provisioned count rather than
		// the seats themselves: holding exactly as many machines as
		// seats leaves no room for the ones that do not come good. No
		// core is guaranteed outside the forgiveness window, so
		// Want(target, 0) is exact here.
		seats := a.want
		if a.phase == PhasePlanning {
			seats = Want(a.want, 0)
		}
		demands = append(demands, Demand{ID: a.spec.ID, Need: a.need, Seats: seats, Bell: a.window.Bell()})
		byID[a.spec.ID] = a
	}
	allocs := p.Assign(t.Machines, demands, t.Now)

	wantHold := map[string]time.Time{}
	holdFor := map[string][]string{}
	for _, alloc := range allocs {
		a := byID[alloc.ID]
		if alloc.Short > 0 {
			out.Short[alloc.ID] = alloc.Short
		}
		// Past the bell the seats are taken, not drained towards.
		if a.phase != PhasePlanning {
			out.Evict = append(out.Evict, evictionsFor(alloc, a.spec.ID)...)
			continue
		}
		// Inside the forgiveness window a tag changes nothing: anything
		// started from here is cheap to evict at the bell anyway.
		if a.window.Bell().Sub(t.Now) <= p.Forgive {
			continue
		}
		hold := machinesToHold(alloc)
		for _, name := range hold {
			if cur, ok := wantHold[name]; !ok || a.window.Bell().Before(cur) {
				wantHold[name] = a.window.Bell()
			}
			holdFor[name] = append(holdFor[name], alloc.ID)
		}
	}

	for name, deadline := range wantHold {
		out.Hold = append(out.Hold, Hold{Machine: name, Deadline: deadline, For: holdFor[name]})
	}
	sort.Slice(out.Hold, func(i, j int) bool { return out.Hold[i].Machine < out.Hold[j].Machine })

	// Release what is tagged and no longer wanted, once the surplus is
	// worth acting on. Untagging is not reversible on the drain's
	// timescale -- the machine takes a long job and is gone until the
	// bell -- so it waits for a real surplus where tagging does not.
	var stale []string
	for name := range t.Tagged {
		if _, still := wantHold[name]; !still {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	if len(stale) > cfg.HBuffer {
		out.Untag = stale[:len(stale)-cfg.HBuffer]
	}
	sort.Slice(out.Evict, func(i, j int) bool {
		if out.Evict[i].Machine != out.Evict[j].Machine {
			return out.Evict[i].Machine < out.Evict[j].Machine
		}
		return out.Evict[i].Dslot < out.Evict[j].Dslot
	})
	return out
}

// machinesToHold is the distinct machines behind a reservation's allocated
// seats. Assign has already chosen them cheapest-first and, among equals,
// soonest to free up, and has already been asked for the over-provisioned
// count, so there is nothing left to rank here.
func machinesToHold(alloc Allocation) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(alloc.Seats))
	for _, s := range alloc.Seats {
		if seen[s.Machine] {
			continue
		}
		seen[s.Machine] = true
		out = append(out, s.Machine)
	}
	return out
}

func evictionsFor(alloc Allocation, id string) []Eviction {
	var out []Eviction
	for _, s := range alloc.Seats {
		for _, i := range s.Evict {
			out = append(out, Eviction{Machine: s.Machine, Dslot: i, Reservation: id, Waste: s.Waste})
		}
	}
	return out
}

func taggedMachines(tagged map[string]time.Time) []string {
	if len(tagged) == 0 {
		return nil
	}
	out := make([]string, 0, len(tagged))
	for name := range tagged {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
