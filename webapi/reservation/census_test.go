package reservation

import (
	"testing"
	"time"
)

var (
	now  = time.Unix(1_700_000_000, 0)
	pol  = Policy{Forgive: 30 * time.Minute}
	one  = Resources{Cpus: 1, Gpus: 1, MemoryMB: 8192, DiskMB: 1024}
	wide = Resources{Cpus: 8, Gpus: 4, MemoryMB: 65536, DiskMB: 102400}
)

func running(ageMin int, res Resources) Dslot {
	return Dslot{Started: now.Add(-time.Duration(ageMin) * time.Minute), Res: res}
}

// TestAgeAtClassIsInvariant is the property the whole ranking rests on: for
// a job that keeps running, the clock advancing and the bell approaching
// cancel, so nothing reshuffles between ticks.
func TestAgeAtClassIsInvariant(t *testing.T) {
	bell := now.Add(4 * time.Hour)
	d := running(10, one)
	want := AgeAtClass(d, bell, now)
	for _, elapsed := range []time.Duration{time.Minute, time.Hour, 3 * time.Hour} {
		if got := AgeAtClass(d, bell, now.Add(elapsed)); got != want {
			t.Errorf("after %v: age at bell %v, want %v", elapsed, got, want)
		}
	}
}

// TestGuaranteedIsAbsorbing checks the claim that lets the controller treat
// a guarantee as certain: once a core qualifies it cannot stop qualifying,
// because both ways in imply the bell is within Forgive.
func TestGuaranteedIsAbsorbing(t *testing.T) {
	bell := now.Add(20 * time.Minute)
	d := running(5, one) // 5 + 20 = 25 min at the bell, under 30
	if !pol.Guaranteed(d, bell, now) {
		t.Fatal("expected the core to be guaranteed")
	}
	// The job keeps running.
	for _, elapsed := range []time.Duration{time.Minute, 10 * time.Minute, 19 * time.Minute} {
		if !pol.Guaranteed(d, bell, now.Add(elapsed)) {
			t.Errorf("after %v the running job stopped being guaranteed", elapsed)
		}
	}
	// The job ends and the core picks up something new: whatever it is, it
	// cannot be older at the bell than the time left.
	for _, elapsed := range []time.Duration{time.Minute, 19 * time.Minute} {
		at := now.Add(elapsed)
		fresh := Dslot{Started: at, Res: one}
		if !pol.Guaranteed(fresh, bell, at) {
			t.Errorf("after %v a freshly started job was not guaranteed", elapsed)
		}
		if !pol.Guaranteed(Dslot{Res: one}, bell, at) {
			t.Errorf("after %v an idle core was not guaranteed", elapsed)
		}
	}
}

func TestProjectedWasteForgives(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bellMin int
		ageMin  int
		want    time.Duration
	}{
		// Inside Forgive of the bell, a young job costs nothing.
		{"young, bell close", 20, 5, 0},
		// Same bell, but it will have been running 35 minutes by then.
		{"old, bell close", 20, 15, 35 * time.Minute},
		// An hour out, nothing running can be under the line: this is why
		// guarantees only start accruing in the last Forgive.
		{"bell an hour out", 60, 1, 61 * time.Minute},
		// An idle core is bounded by the time left, so it qualifies as soon
		// as the bell is within Forgive.
		{"idle, bell close", 20, 0, 0},
	} {
		bell := now.Add(time.Duration(tc.bellMin) * time.Minute)
		d := running(tc.ageMin, one)
		if tc.name == "idle, bell close" {
			d = Dslot{Res: one}
		}
		if got := pol.ProjectedWaste(d, bell, now); got != tc.want {
			t.Errorf("%s: waste %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSeatsIsTheLimitingResource(t *testing.T) {
	// Plenty of GPU, not enough memory: the memory decides.
	have := Resources{Cpus: 64, Gpus: 8, MemoryMB: 16384, DiskMB: 1 << 20}
	if got := have.seats(one); got != 2 {
		t.Errorf("seats = %d, want 2 (memory bound)", got)
	}
	// A resource the seat does not ask for never limits it.
	noGpu := Resources{Cpus: 4, MemoryMB: 8192, DiskMB: 4096}
	if got := have.seats(noGpu); got != 2 {
		t.Errorf("seats without a GPU ask = %d, want 2", got)
	}
}

func TestSeatsOnPrefersFreeCapacityThenCheapEvictions(t *testing.T) {
	bell := now.Add(4 * time.Hour)
	m := Machine{
		Name: "ep1",
		Free: one, // one seat going spare
		Dslots: []Dslot{
			running(200, one), // ancient: expensive
			running(5, one),   // young, but 4h from now it is old too
		},
	}
	seats := pol.SeatsOn(m, one, bell, now)
	if len(seats) != 3 {
		t.Fatalf("got %d seats, want 3", len(seats))
	}
	if len(seats[0].Evict) != 0 || !seats[0].Guaranteed {
		t.Errorf("the first seat should be free capacity, got %+v", seats[0])
	}
	if seats[1].Waste > seats[2].Waste {
		t.Errorf("seats not cheapest-first: %v then %v", seats[1].Waste, seats[2].Waste)
	}
	// The younger job is evicted before the ancient one.
	if seats[1].Evict[0] != 1 {
		t.Errorf("expected the young job (index 1) evicted first, got %v", seats[1].Evict)
	}
}

func TestSeatsOnNeverTakesAnotherReservationsSeat(t *testing.T) {
	bell := now.Add(2 * time.Hour)
	m := Machine{
		Name:   "ep1",
		Dslots: []Dslot{{Started: now.Add(-time.Minute), Res: one, Project: "other"}},
	}
	if seats := pol.SeatsOn(m, one, bell, now); len(seats) != 0 {
		t.Errorf("took a seat belonging to another reservation: %+v", seats)
	}
}

// TestAssignErodesTheLaterReservationsGuarantee is the interaction that a
// single global census gets wrong: the same cores cannot be promised twice,
// so a reservation later in the day sees fewer guarantees once an earlier
// one has taken its pick.
func TestAssignErodesTheLaterReservationsGuarantee(t *testing.T) {
	bell := now.Add(10 * time.Minute) // inside Forgive, so these are guarantees
	machines := []Machine{
		{Name: "ep1", Free: one},
		{Name: "ep2", Free: one},
	}
	soon := Demand{ID: "soon", Need: one, Seats: 2, Bell: bell}
	later := Demand{ID: "later", Need: one, Seats: 2, Bell: bell.Add(time.Minute)}

	alone := pol.Assign(machines, []Demand{later}, now)
	if alone[0].Guaranteed != 2 || alone[0].Short != 0 {
		t.Fatalf("on its own, later should hold 2 guaranteed seats: %+v", alone[0])
	}

	both := pol.Assign(machines, []Demand{later, soon}, now)
	byID := map[string]Allocation{}
	for _, a := range both {
		byID[a.ID] = a
	}
	if byID["soon"].Guaranteed != 2 {
		t.Errorf("the sooner bell should win both cores: %+v", byID["soon"])
	}
	if got := byID["later"].Guaranteed; got != 0 {
		t.Errorf("later guaranteed = %d, want 0 once soon has taken the pool", got)
	}
	if got := byID["later"].Short; got != 2 {
		t.Errorf("later short = %d, want 2", got)
	}
}

func TestAssignDoesNotPromiseACoreTwice(t *testing.T) {
	bell := now.Add(3 * time.Hour)
	machines := []Machine{{Name: "ep1", Free: wide, Dslots: []Dslot{running(1, one)}}}
	ds := []Demand{
		{ID: "a", Need: one, Seats: 3, Bell: bell},
		{ID: "b", Need: one, Seats: 3, Bell: bell.Add(time.Hour)},
	}
	allocs := pol.Assign(machines, ds, now)
	seen := map[int]string{}
	total := 0
	for _, a := range allocs {
		total += len(a.Seats)
		for _, s := range a.Seats {
			for _, i := range s.Evict {
				if prev, dup := seen[i]; dup {
					t.Errorf("d-slot %d promised to both %s and %s", i, prev, a.ID)
				}
				seen[i] = a.ID
			}
		}
	}
	// wide holds 4 GPUs, plus one evictable d-slot: five seats, not six.
	if total != 5 {
		t.Errorf("handed out %d seats, want 5", total)
	}
}

func TestWantFallsAsGuaranteesArrive(t *testing.T) {
	const seats = 35
	if m := Margin(seats); m != 12 {
		t.Errorf("margin = %d, want 12", m)
	}
	full := Want(seats, 0)
	if full != 53 {
		t.Errorf("Want(35, 0) = %d, want 53", full)
	}
	if got := Want(seats, 20); got >= full {
		t.Errorf("Want should fall as guarantees arrive: %d vs %d", got, full)
	}
	if got := Want(seats, seats+Margin(seats)); got != 0 {
		t.Errorf("Want with the margin covered = %d, want 0", got)
	}
	if got := Want(seats, 1000); got != 0 {
		t.Errorf("Want with a surplus = %d, want 0", got)
	}
}
