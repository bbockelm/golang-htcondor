package reservation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakePool struct {
	machines []Machine
	held     map[string]time.Time
	err      error
}

func (f *fakePool) Machines(context.Context) ([]Machine, error) { return f.machines, f.err }
func (f *fakePool) Held(context.Context) (map[string]time.Time, error) {
	if f.held == nil {
		return map[string]time.Time{}, nil
	}
	return f.held, nil
}

type fakeJobs map[string]int

func (f fakeJobs) RunningByProject(context.Context) (map[string]int, error) { return f, nil }

type fakeSpecs []*Spec

func (f fakeSpecs) List(context.Context) ([]*Spec, error) { return f, nil }

type call struct {
	verb    string
	machine string
	dslot   int
	project string
}

type fakeActuator struct {
	calls   []call
	failOn  string
	ordered []string
	holds   []HoldRequest
	evicted []string
}

func (a *fakeActuator) Hold(_ context.Context, h HoldRequest) error {
	a.ordered = append(a.ordered, "hold")
	if a.failOn == h.Machine {
		return errors.New("startd unreachable")
	}
	a.calls = append(a.calls, call{"hold", h.Machine, 0, h.Project})
	a.holds = append(a.holds, h)
	return nil
}
func (a *fakeActuator) Release(_ context.Context, m string) error {
	a.ordered = append(a.ordered, "release")
	a.calls = append(a.calls, call{"release", m, 0, ""})
	return nil
}
func (a *fakeActuator) Evict(_ context.Context, e EvictRequest) error {
	a.ordered = append(a.ordered, "evict")
	a.calls = append(a.calls, call{"evict", e.Machine, 0, ""})
	a.evicted = append(a.evicted, e.Slot)
	return nil
}

// seatSized machines each hold one d-slot the size of the reservation's
// real seat, as rendered from its submit file: 4 CPUs, 1 GPU, 16 GiB.
// Sizing them any smaller means no machine can host a seat and the
// controller correctly does nothing, which tests nothing.
var seatRes = Resources{Cpus: 4, Gpus: 1, MemoryMB: 16384, DiskMB: 10240}

func seatSizedMachines(n int, age, left time.Duration) []Machine {
	out := make([]Machine, 0, n)
	for i := range n {
		out = append(out, Machine{
			Name: string(rune('a'+i)) + "-ep",
			Dslots: []Dslot{{
				Slot:      "slot1_1@" + string(rune('a'+i)) + "-ep",
				Started:   planNow.Add(-age),
				Res:       seatRes,
				Remaining: left,
			}},
		})
	}
	return out
}

func ctl(t *testing.T, spec *Spec, machines []Machine, held map[string]time.Time, running fakeJobs, now time.Time) (*Controller, *fakeActuator) {
	t.Helper()
	act := &fakeActuator{}
	return &Controller{
		Policy:   Policy{Forgive: 30 * time.Minute},
		Config:   DefaultPlanConfig(),
		Pool:     &fakePool{machines: machines, held: held},
		Jobs:     running,
		Specs:    fakeSpecs{spec},
		Actuator: act,
		Now:      func() time.Time { return now },
	}, act
}

func TestControllerHoldsMachines(t *testing.T) {
	spec := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1")
	c, act := ctl(t, spec, seatSizedMachines(20, time.Hour, 2*time.Hour), nil, fakeJobs{}, planNow)
	res, err := c.Tick(context.Background())
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if res.Held == 0 {
		t.Fatalf("held nothing: %+v", res.Plan)
	}
	if res.Held != len(res.Plan.Hold) {
		t.Errorf("held %d of %d planned", res.Held, len(res.Plan.Hold))
	}
	for _, c := range act.calls {
		if c.verb == "hold" && c.project != "cs301-f26" {
			t.Errorf("held %s for project %q, want the reservation's", c.machine, c.project)
		}
	}
}

// TestControllerReadsHeldFromThePool: the controller keeps no memory
// between ticks, so a deadline left behind by a previous process -- or a
// dead one -- is visible and can be cleared.
func TestControllerReadsHeldFromThePool(t *testing.T) {
	spec := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1")
	spec.Enabled = false // nothing wanted, so everything held is stale
	stale := map[string]time.Time{}
	for i := range 10 {
		stale[string(rune('a'+i))+"-ep"] = planNow.Add(-time.Hour)
	}
	c, act := ctl(t, spec, seatSizedMachines(10, time.Hour, 2*time.Hour), stale, fakeJobs{}, planNow)
	res, err := c.Tick(context.Background())
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if res.Released != len(stale) {
		t.Errorf("released %d of %d stale holds", res.Released, len(stale))
	}
	for _, call := range act.calls {
		if call.verb != "release" {
			t.Errorf("unexpected %s on a disabled reservation", call.verb)
		}
	}
}

// TestControllerReleasesBeforeHolding: a machine moving between
// reservations must never be briefly held for neither, and nothing is
// preempted before the holds that secure the seats are in place.
func TestControllerOrdersTheActuation(t *testing.T) {
	spec := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1")
	stale := map[string]time.Time{"zz-ep": planNow.Add(-time.Hour)}
	machines := append(seatSizedMachines(20, time.Hour, 2*time.Hour), Machine{Name: "zz-ep", Free: seatRes})
	c, act := ctl(t, spec, machines, stale, fakeJobs{}, planNow)
	if _, err := c.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	seen := map[string]int{}
	for i, verb := range act.ordered {
		if _, ok := seen[verb]; !ok {
			seen[verb] = i
		}
	}
	if r, h := seen["release"], seen["hold"]; act.ordered != nil && r > h {
		t.Errorf("held before releasing (release at %d, hold at %d)", r, h)
	}
}

// TestControllerEvictsAtTheBell, and holds the machines it took the
// seats from for the project until the window ends.
func TestControllerEvictsAtTheBell(t *testing.T) {
	spec := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1")
	machines := seatSizedMachines(10, 3*time.Hour, 20*time.Hour)
	bell := planNow.Add(6 * time.Hour)
	c, act := ctl(t, spec, machines, nil, fakeJobs{}, bell)
	res, err := c.Tick(context.Background())
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if res.Evicted != spec.Seats {
		t.Errorf("evicted %d, want %d", res.Evicted, spec.Seats)
	}
	if len(act.holds) == 0 {
		t.Fatalf("held nothing at the bell, so a freed seat goes back to the pool")
	}
	for _, h := range act.holds {
		if h.Project != spec.Project {
			t.Errorf("%s held for %q, want %q", h.Machine, h.Project, spec.Project)
		}
		if want := bell.Add(spec.Duration); !h.Until.Equal(want) {
			t.Errorf("%s: until %v, want the window end %v", h.Machine, h.Until, want)
		}
	}
}

// TestControllerEvictsBySlotName: the startd vacates a claim by the
// slot ad's Name. An index into the census means nothing to it, and
// vacating the wrong slot preempts somebody who was not in the way
// while leaving the one that was.
func TestControllerEvictsBySlotName(t *testing.T) {
	spec := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1")
	machines := seatSizedMachines(10, 3*time.Hour, 20*time.Hour)
	c, act := ctl(t, spec, machines, nil, fakeJobs{}, planNow.Add(6*time.Hour))
	if _, err := c.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(act.evicted) == 0 {
		t.Fatalf("evicted nothing")
	}
	for _, slot := range act.evicted {
		if !strings.Contains(slot, "@") {
			t.Errorf("vacated %q, which is not a slot name", slot)
		}
	}
}

// TestControllerRefusesToEvictWithoutASlotName: a census built without
// slot names has nothing to vacate by, and guessing is worse than
// failing.
func TestControllerRefusesToEvictWithoutASlotName(t *testing.T) {
	spec := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1")
	machines := seatSizedMachines(10, 3*time.Hour, 20*time.Hour)
	for i := range machines {
		for j := range machines[i].Dslots {
			machines[i].Dslots[j].Slot = ""
		}
	}
	c, act := ctl(t, spec, machines, nil, fakeJobs{}, planNow.Add(6*time.Hour))
	res, err := c.Tick(context.Background())
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if res.Evicted != 0 {
		t.Errorf("evicted %d slots with no name to evict by", res.Evicted)
	}
	if len(act.evicted) != 0 {
		t.Errorf("vacated %v", act.evicted)
	}
	if res.Err() == nil {
		t.Errorf("reported no error for evictions it could not make")
	}
}

// TestControllerCountsRunningJobsAsSeats.
func TestControllerCountsRunningJobsAsSeats(t *testing.T) {
	spec := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1")
	c, act := ctl(t, spec, seatSizedMachines(20, time.Hour, 2*time.Hour), nil,
		fakeJobs{"cs301-f26": spec.Seats}, planNow)
	res, err := c.Tick(context.Background())
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if res.Held != 0 || len(act.calls) != 0 {
		t.Errorf("a fully seated reservation acted: held=%d calls=%v", res.Held, act.calls)
	}
}

// TestControllerKeepsGoingWhenOneMachineFails: one unreachable startd
// must not stop the others being held.
func TestControllerKeepsGoingWhenOneMachineFails(t *testing.T) {
	spec := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1")
	machines := seatSizedMachines(20, time.Hour, 2*time.Hour)
	c, act := ctl(t, spec, machines, nil, fakeJobs{}, planNow)
	act.failOn = machines[0].Name
	c.Actuator = act
	res, err := c.Tick(context.Background())
	if err != nil {
		t.Fatalf("Tick returned a fatal error for one bad machine: %v", err)
	}
	if res.Err() == nil {
		t.Error("the failure was not reported")
	}
	if res.Held < len(res.Plan.Hold)-1 {
		t.Errorf("held only %d of %d after one failure", res.Held, len(res.Plan.Hold))
	}
}

// TestControllerFailsLoudlyWhenThePoolIsUnreadable: a tick that cannot
// read the pool changes nothing, which is safe because every deadline
// already pushed expires on its own.
func TestControllerFailsLoudlyWhenThePoolIsUnreadable(t *testing.T) {
	spec := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1")
	act := &fakeActuator{}
	c := &Controller{
		Policy: Policy{Forgive: 30 * time.Minute}, Config: DefaultPlanConfig(),
		Pool: &fakePool{err: errors.New("collector down")},
		Jobs: fakeJobs{}, Specs: fakeSpecs{spec}, Actuator: act,
		Now: func() time.Time { return planNow },
	}
	if _, err := c.Tick(context.Background()); err == nil {
		t.Fatal("a tick with an unreadable pool reported success")
	}
	if len(act.calls) != 0 {
		t.Errorf("acted on the pool anyway: %v", act.calls)
	}
}

func TestSeatResources(t *testing.T) {
	got, err := seatSpec(gpuSeat).SeatResources()
	if err != nil {
		t.Fatalf("SeatResources: %v", err)
	}
	if got.Cpus != 4 || got.Gpus != 1 || got.MemoryMB != 16384 {
		t.Errorf("seat shape = %+v", got)
	}
	if got.DiskMB <= 0 {
		t.Errorf("disk did not survive the KiB conversion: %+v", got)
	}
}
