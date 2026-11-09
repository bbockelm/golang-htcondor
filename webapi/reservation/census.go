// Package reservation decides which machines can seat a reservation's jobs
// and how many of them to hold back ahead of time.
//
// A reservation asks for Seats cores at a moment ("the bell") and keeps them
// for a while. Freeing a core means evicting whatever is on it, and the
// policy this package implements is that evicting a job that has run less
// than Forgive is free, while evicting an older one is not. Everything here
// is arithmetic over that rule; nothing in this package talks to the pool.
//
// The two quantities that matter are worked out per machine:
//
//   - AgeAtClass, how long a running job will have been going at the bell.
//     For a job that keeps running this is invariant -- the clock advances
//     and the bell approaches by the same amount -- so a ranking built on
//     it never flaps.
//
//   - Guaranteed, whether a core is certain to be cheap at the bell. Both
//     ways of qualifying imply the bell is less than Forgive away, so the
//     state is absorbing: neither the job continuing nor the core turning
//     over can undo it. Guaranteed is therefore empty until the last
//     Forgive before the bell, which is why a reservation has to hold
//     cores back rather than wait for them.
package reservation

import (
	"math"
	"sort"
	"time"
)

// Resources is what a seat needs, or what a machine has spare.
type Resources struct {
	Cpus     int
	Gpus     int
	MemoryMB int64
	DiskMB   int64
}

// fits reports whether r covers need.
func (r Resources) fits(need Resources) bool {
	return r.Cpus >= need.Cpus && r.Gpus >= need.Gpus &&
		r.MemoryMB >= need.MemoryMB && r.DiskMB >= need.DiskMB
}

// add returns r plus o.
func (r Resources) add(o Resources) Resources {
	return Resources{r.Cpus + o.Cpus, r.Gpus + o.Gpus, r.MemoryMB + o.MemoryMB, r.DiskMB + o.DiskMB}
}

// seats is how many copies of need r covers, which is the limiting
// resource rather than any one of them. A machine with a spare GPU but no
// spare memory seats nobody.
func (r Resources) seats(need Resources) int {
	n := math.MaxInt
	lim := func(have, want int64) {
		if want <= 0 {
			return
		}
		if k := int(have / want); k < n {
			n = k
		}
	}
	lim(int64(r.Cpus), int64(need.Cpus))
	lim(int64(r.Gpus), int64(need.Gpus))
	lim(r.MemoryMB, need.MemoryMB)
	lim(r.DiskMB, need.DiskMB)
	if n == math.MaxInt || n < 0 {
		return 0
	}
	return n
}

// Dslot is one running job as the census sees it.
type Dslot struct {
	// Slot is the slot ad's Name ("slot1_3@host"), which is how a
	// d-slot is named to the startd that owns it. Empty in a census
	// built without it, which makes the slot unevictable rather than
	// evicting the wrong one.
	Slot string
	// Started is when this execution began. Zero means the slot is idle.
	Started time.Time
	// Res is what the job holds.
	Res Resources
	// Project is non-empty when the job is already a reservation's seat,
	// which makes the slot unavailable to any other reservation.
	Project string
	// Remaining is the estimator's bound on how much longer the job will
	// run, conditioned on it having survived this long. Zero when unknown.
	// Only used for ranking, never for a guarantee.
	Remaining time.Duration
}

// Machine is one execute point: its unclaimed capacity and what is running.
type Machine struct {
	Name string
	// Free is capacity not currently carved into a d-slot.
	Free   Resources
	Dslots []Dslot
}

// Policy is the operator's cost rule.
type Policy struct {
	// Forgive is the age below which evicting a job costs nothing.
	Forgive time.Duration
	// Reserved names the projects that hold seats of their own. A job
	// running under one of them is somebody's seat and is never evicted
	// to make another.
	//
	// Only these projects are protected. A slot ad carries RemoteProject
	// for any job whose submitter named a project, and treating every
	// one of those as untouchable would make most of a busy pool look
	// unevictable while reserving nothing.
	Reserved map[string]bool
}

// reservedSeat reports whether d is a seat some reservation already holds.
func (p Policy) reservedSeat(d Dslot) bool {
	return d.Project != "" && p.Reserved[d.Project]
}

// AgeAtClass is how long d will have been running at the bell. For an idle
// slot it is how long whatever it picks up could run by then, which bounds
// the same quantity.
func AgeAtClass(d Dslot, bell time.Time, now time.Time) time.Duration {
	if d.Started.IsZero() {
		return bell.Sub(now)
	}
	return bell.Sub(d.Started)
}

// ProjectedWaste is the compute discarded by evicting d at the bell, with
// the forgiveness rule applied. It assumes the job is still there, so it is
// an upper bound: a slot that turns over does better.
func (p Policy) ProjectedWaste(d Dslot, bell, now time.Time) time.Duration {
	age := AgeAtClass(d, bell, now)
	if age <= p.Forgive {
		return 0
	}
	return age
}

// Guaranteed reports whether d is certain to be cheap to evict at the bell.
//
// It is the same test as ProjectedWaste being zero, and it holds for the
// rest of the wait: the condition implies the bell is within Forgive, so if
// the job keeps running its age stays under the line, and if it ends the
// core can only pick up something younger.
func (p Policy) Guaranteed(d Dslot, bell, now time.Time) bool {
	return p.ProjectedWaste(d, bell, now) == 0
}

// Seat is one place a reservation could take on a machine.
type Seat struct {
	Machine string
	// Evict names the d-slots that must go to free the seat; empty when the
	// machine has the capacity spare.
	Evict []int
	// Waste is what evicting them costs under the policy.
	Waste time.Duration
	// Guaranteed is true when every eviction is free at the bell.
	Guaranteed bool
	// TimeLeft is how soon the machine is predicted to free a slot. A
	// tag only governs the next admission, so of two equally cheap
	// seats the one on a machine about to turn over is worth more: a
	// machine that never frees up never makes an admission decision and
	// its tag does nothing.
	TimeLeft time.Duration
}

// SeatsOn enumerates the seats m could offer for need at the bell, cheapest
// first. A d-slot already serving a reservation (see Policy.Reserved) is
// never evicted to make room for another.
//
// Seats are built greedily from the cheapest evictions, which is the same
// order the bell uses, so the census and the eviction agree.
func (p Policy) SeatsOn(m Machine, need Resources, bell, now time.Time) []Seat {
	type cand struct {
		idx   int
		waste time.Duration
		res   Resources
	}
	var cands []cand
	for i, d := range m.Dslots {
		if p.reservedSeat(d) {
			continue // already some reservation's seat
		}
		cands = append(cands, cand{i, p.ProjectedWaste(d, bell, now), d.Res})
	}
	// Cheapest first, then by raw age so that among equally free evictions
	// the youngest job goes. The forgiveness rule flattens everything under
	// the line to zero, and picking genuinely young jobs is what keeps the
	// discarded compute down.
	sort.SliceStable(cands, func(a, b int) bool {
		if cands[a].waste != cands[b].waste {
			return cands[a].waste < cands[b].waste
		}
		return AgeAtClass(m.Dslots[cands[a].idx], bell, now) <
			AgeAtClass(m.Dslots[cands[b].idx], bell, now)
	})

	var out []Seat
	pool := m.Free
	used := 0
	for {
		if pool.fits(need) {
			ev := make([]int, 0, used)
			var waste time.Duration
			allFree := true
			for _, c := range cands[:used] {
				ev = append(ev, c.idx)
				waste += c.waste
				if c.waste > 0 {
					allFree = false
				}
			}
			out = append(out, Seat{Machine: m.Name, Evict: ev, Waste: waste,
				Guaranteed: allFree, TimeLeft: m.soonestFree()})
			pool = subtract(pool, need)
			continue
		}
		if used >= len(cands) {
			return out
		}
		pool = pool.add(cands[used].res)
		used++
	}
}

// soonestFree is how long until m is predicted to free a slot. An idle
// machine, or one whose estimate is unknown, is treated as free now.
func (m Machine) soonestFree() time.Duration {
	if len(m.Dslots) == 0 {
		return 0
	}
	best := time.Duration(-1)
	for _, d := range m.Dslots {
		if d.Started.IsZero() {
			return 0
		}
		if d.Remaining > 0 && (best < 0 || d.Remaining < best) {
			best = d.Remaining
		}
	}
	if best < 0 {
		return 0
	}
	return best
}

func subtract(r, o Resources) Resources {
	return Resources{r.Cpus - o.Cpus, r.Gpus - o.Gpus, r.MemoryMB - o.MemoryMB, r.DiskMB - o.DiskMB}
}

// Demand is one reservation's ask at a moment.
type Demand struct {
	ID    string
	Need  Resources
	Seats int
	Bell  time.Time
	// Standing marks an ask for headroom between windows rather than
	// for a window itself.
	//
	// Headroom has no moment it must be ready by, so it cannot be
	// ordered against windows by time: its Bell is now, which would
	// otherwise sort it ahead of everything. A window is a commitment
	// at a time and spare capacity is not, so headroom is served last
	// however soon it is wanted.
	Standing bool
}

// Allocation is what Assign decided for one reservation.
type Allocation struct {
	ID string
	// Seats are the places held for it, cheapest first.
	Seats []Seat
	// Guaranteed counts the seats that are certain to be free at the bell.
	Guaranteed int
	// Short is how many seats the pool could not offer at all.
	Short int
}

// Assign divides the pool across reservations so that no core is promised
// twice.
//
// Reservations are served in bell order, soonest first: a reservation that
// starts in an hour has no time to find another core, while one tomorrow
// does. Within a reservation the cheapest seats go first. The guarantee
// count is per reservation and falls as earlier reservations consume the
// cores it would have relied on, which is the interaction that makes a
// single global census wrong.
func (p Policy) Assign(machines []Machine, demands []Demand, now time.Time) []Allocation {
	ds := append([]Demand(nil), demands...)
	sort.SliceStable(ds, func(a, b int) bool {
		if ds[a].Standing != ds[b].Standing {
			return !ds[a].Standing
		}
		return ds[a].Bell.Before(ds[b].Bell)
	})

	// taken[machine][dslot] marks a d-slot already promised, and freeLeft
	// tracks unclaimed capacity already spoken for.
	taken := map[string]map[int]bool{}
	freeLeft := map[string]Resources{}
	for _, m := range machines {
		taken[m.Name] = map[int]bool{}
		freeLeft[m.Name] = m.Free
	}

	out := make([]Allocation, 0, len(ds))
	for _, d := range ds {
		alloc := Allocation{ID: d.ID}
		for _, m := range machines {
			// Hide what earlier reservations already hold.
			view := Machine{Name: m.Name, Free: freeLeft[m.Name]}
			idx := make([]int, 0, len(m.Dslots))
			for i, s := range m.Dslots {
				if taken[m.Name][i] {
					continue
				}
				view.Dslots = append(view.Dslots, s)
				idx = append(idx, i)
			}
			for _, s := range p.SeatsOn(view, d.Need, d.Bell, now) {
				// Translate the view's indices back to the machine's.
				onMachine := make([]int, len(s.Evict))
				for j, k := range s.Evict {
					onMachine[j] = idx[k]
				}
				s.Evict = onMachine
				alloc.Seats = append(alloc.Seats, s)
			}
		}
		// Cheapest first, then soonest to free up: among seats that cost
		// the same to take, a tag is worth more on a machine that will
		// actually turn over before the bell.
		sort.SliceStable(alloc.Seats, func(a, b int) bool {
			if alloc.Seats[a].Waste != alloc.Seats[b].Waste {
				return alloc.Seats[a].Waste < alloc.Seats[b].Waste
			}
			return alloc.Seats[a].TimeLeft < alloc.Seats[b].TimeLeft
		})
		if len(alloc.Seats) > d.Seats {
			alloc.Seats = alloc.Seats[:d.Seats]
		}
		alloc.Short = d.Seats - len(alloc.Seats)
		for _, s := range alloc.Seats {
			if s.Guaranteed {
				alloc.Guaranteed++
			}
			for _, i := range s.Evict {
				taken[s.Machine][i] = true
			}
			freeLeft[s.Machine] = subtract(freeLeft[s.Machine], d.Need)
		}
		out = append(out, alloc)
	}
	return out
}

// convertRate is how much of a tag converts into a guaranteed core by the
// bell. The controller is a closed loop -- it re-sizes every tick -- so this
// only has to be in the right neighbourhood; being optimistic costs a tick,
// not a reservation.
const convertRate = 0.9

// Margin is the slack held above the seats actually needed. It tracks two
// standard deviations of the binomial on the measured conversion rates,
// which grows as the square root of the reservation because the pool a
// reservation draws from grows with it.
func Margin(seats int) int {
	if seats <= 0 {
		return 0
	}
	return int(math.Ceil(2 * math.Sqrt(float64(seats))))
}

// Want is how many cores to hold tagged, given how many are already
// guaranteed. It is the closed-loop target: re-evaluated every tick, it
// falls to zero as guarantees accumulate in the final Forgive.
func Want(seats, guaranteed int) int {
	n := seats + Margin(seats) - guaranteed
	if n <= 0 {
		return 0
	}
	return int(math.Ceil(float64(n) / convertRate))
}
