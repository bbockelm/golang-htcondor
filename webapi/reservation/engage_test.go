package reservation

import (
	"context"
	"errors"
	"testing"
	"time"
)

// engageSpec is the plan fixture with Enabled set: a one-hour class at
// 14:00 Monday with a six-hour planning lead, so it is engaged from
// 08:00 and its window closes at 15:00.
func engageSpec(t *testing.T) *Spec {
	t.Helper()
	s := planSpec(t, "cs301", "cs301-f26", "0 14 * * 1")
	s.Enabled = true
	return s
}

const engageForgive = 30 * time.Minute

func TestEngagedOnlyFromTheLeadUntilTheWindowSettles(t *testing.T) {
	spec := engageSpec(t)
	specs := []*Spec{spec}
	bell := time.Date(2026, 3, 2, 14, 0, 0, 0, time.UTC)
	end := bell.Add(spec.Duration)

	cases := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"before the lead", bell.Add(-spec.Lead - time.Minute), false},
		{"the lead begins", bell.Add(-spec.Lead), true},
		{"inside the window", bell.Add(30 * time.Minute), true},
		{"the bell has rung and the window closed", end, true},
		{"settling", end.Add(SettleAfter - time.Minute), true},
		{"settled", end.Add(SettleAfter + time.Minute), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Engaged(specs, c.at, engageForgive, SettleAfter); got != c.want {
				t.Fatalf("Engaged at %s = %v, want %v", c.at.Format(time.Kitchen), got, c.want)
			}
		})
	}
}

func TestEngagedIgnoresDisabledReservations(t *testing.T) {
	spec := engageSpec(t)
	bell := time.Date(2026, 3, 2, 14, 0, 0, 0, time.UTC)
	mid := bell.Add(30 * time.Minute)

	// Non-vacuous: the same instant engages the spec while it is on.
	if !Engaged([]*Spec{spec}, mid, engageForgive, SettleAfter) {
		t.Fatal("the enabled spec is not engaged mid-window; the case below proves nothing")
	}
	spec.Enabled = false
	if Engaged([]*Spec{spec}, mid, engageForgive, SettleAfter) {
		t.Fatal("a disabled reservation engaged the subsystem")
	}
}

func TestStandingReservationIsAlwaysEngaged(t *testing.T) {
	spec := engageSpec(t)
	// Wednesday, nowhere near a Monday class.
	quiet := time.Date(2026, 3, 4, 3, 0, 0, 0, time.UTC)
	if Engaged([]*Spec{spec}, quiet, engageForgive, SettleAfter) {
		t.Fatal("engaged with no standing seats and no window in sight")
	}
	spec.Standing = 2
	if !Engaged([]*Spec{spec}, quiet, engageForgive, SettleAfter) {
		t.Fatal("a standing reservation holds seats around the clock; it must stay engaged")
	}
}

func TestEngagedWithNoReservationsAtAll(t *testing.T) {
	if Engaged(nil, time.Now(), engageForgive, SettleAfter) {
		t.Fatal("engaged with no reservations")
	}
}

func TestSpecGateLooksAhead(t *testing.T) {
	spec := engageSpec(t)
	specs := fakeSpecs{spec}
	bell := time.Date(2026, 3, 2, 14, 0, 0, 0, time.UTC)
	// Ten minutes before the lead opens: engaged only to a gate that
	// looks further ahead than that.
	at := bell.Add(-spec.Lead - 10*time.Minute)
	now := func() time.Time { return at }

	on, err := SpecGate(specs, engageForgive, SettleAfter, 0, now)(context.Background())
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	if on {
		t.Fatal("a gate with no warmup engaged before the lead")
	}
	on, err = SpecGate(specs, engageForgive, SettleAfter, StampWarmup, now)(context.Background())
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	if !on {
		t.Fatalf("a gate looking %s ahead missed a lead opening in 10m", StampWarmup)
	}
}

// countingQueue records that the schedd was read at all, which is the
// whole point: a quiescent pass must not query the queue.
type countingQueue struct {
	fakeQueue
	reads int
}

func (q *countingQueue) IdleJobs(ctx context.Context) ([]JobView, error) {
	q.reads++
	return q.fakeQueue.IdleJobs(ctx)
}

func (q *countingQueue) Clusters(ctx context.Context) ([]ClusterView, error) {
	q.reads++
	return q.fakeQueue.Clusters(ctx)
}

func gateReturning(on bool) Gate {
	return func(context.Context) (bool, error) { return on, nil }
}

func TestStamperDoesNothingWhileNothingIsReserved(t *testing.T) {
	jobs := []JobView{{Cluster: 1, Want: 1800}, {Cluster: 2, Want: 3600}}

	// Non-vacuous: with the gate open the same queue is read and written.
	q := &countingQueue{fakeQueue: fakeQueue{jobs: jobs}}
	w := &fakeStampWriter{}
	open := &Stamper{Queue: q, Writer: w, Engaged: gateReturning(true)}
	res, err := open.Pass(context.Background())
	if err != nil {
		t.Fatalf("Pass with the gate open: %v", err)
	}
	if res.Quiescent {
		t.Fatal("an engaged pass reported itself quiescent")
	}
	if q.reads == 0 || len(w.wrote) != 2 {
		t.Fatalf("an engaged pass read %d times and wrote %d stamps; want reads and 2 stamps", q.reads, len(w.wrote))
	}

	q = &countingQueue{fakeQueue: fakeQueue{jobs: jobs}}
	w = &fakeStampWriter{}
	shut := &Stamper{Queue: q, Writer: w, Engaged: gateReturning(false)}
	res, err = shut.Pass(context.Background())
	if err != nil {
		t.Fatalf("Pass with the gate shut: %v", err)
	}
	if !res.Quiescent {
		t.Fatal("a gated-off pass did not report itself quiescent")
	}
	if q.reads != 0 {
		t.Fatalf("a gated-off pass read the queue %d times", q.reads)
	}
	if len(w.wrote) != 0 {
		t.Fatalf("a gated-off pass wrote %d cluster ads", len(w.wrote))
	}
	if got := shut.Last(); !got.Quiescent {
		t.Fatal("Last did not record the quiescent pass")
	}
}

func TestStamperReportsAGateItCannotAnswer(t *testing.T) {
	q := &countingQueue{}
	s := &Stamper{
		Queue:  q,
		Writer: &fakeStampWriter{},
		Engaged: func(context.Context) (bool, error) {
			return false, errors.New("database is down")
		},
	}
	if _, err := s.Pass(context.Background()); err == nil {
		t.Fatal("Pass swallowed a gate that could not be answered")
	}
	if q.reads != 0 {
		t.Fatal("Pass read the queue after the gate failed")
	}
}

// countingPool records reads of the pool, which is the cost quiescence
// is meant to avoid.
type countingPool struct {
	fakePool
	reads int
}

func (p *countingPool) Machines(ctx context.Context) ([]Machine, error) {
	p.reads++
	return p.fakePool.Machines(ctx)
}

func (p *countingPool) Held(ctx context.Context) (map[string]time.Time, error) {
	p.reads++
	return p.fakePool.Held(ctx)
}

func TestControllerGoesQuietOnlyOnceThePoolIsClean(t *testing.T) {
	now := time.Date(2026, 3, 4, 3, 0, 0, 0, time.UTC) // nothing booked
	machines := seatSizedMachines(2, time.Hour, time.Hour)
	pool := &countingPool{fakePool: fakePool{
		machines: machines,
		// Left behind by a reservation that was deleted while it held
		// these: nothing in the store asks for them any more.
		held: map[string]time.Time{"a-ep": now.Add(time.Hour)},
	}}
	act := &fakeActuator{}
	c := &Controller{
		Policy: Policy{Forgive: engageForgive}, Config: DefaultPlanConfig(),
		Pool: pool, Jobs: fakeJobs{}, Specs: fakeSpecs{}, Actuator: act,
		Now: func() time.Time { return now },
	}

	// First tick: nothing is reserved, but a machine is still held, so
	// the pool is read and the machine released.
	res, err := c.Tick(context.Background())
	if err != nil {
		t.Fatalf("first tick: %v", err)
	}
	if res.Quiescent {
		t.Fatal("the first tick went quiet with a machine still held")
	}
	if res.Released != 1 {
		t.Fatalf("released %d machines, want the one that was held", res.Released)
	}
	after := pool.reads
	if after == 0 {
		t.Fatal("the first tick never read the pool")
	}

	// Second tick: the pool now reports nothing held, so this one reads
	// once more, confirms it, and latches.
	pool.held = map[string]time.Time{}
	if res, err = c.Tick(context.Background()); err != nil {
		t.Fatalf("second tick: %v", err)
	}
	if res.Quiescent {
		t.Fatal("the second tick claimed to be quiescent before it had confirmed the pool")
	}
	if pool.reads == after {
		t.Fatal("the second tick did not re-read the pool")
	}
	after = pool.reads

	// Third tick: nothing reserved and a pool confirmed clean, so it
	// must not touch the pool at all.
	if res, err = c.Tick(context.Background()); err != nil {
		t.Fatalf("third tick: %v", err)
	}
	if !res.Quiescent {
		t.Fatal("the third tick was not quiescent")
	}
	if pool.reads != after {
		t.Fatalf("a quiescent tick read the pool %d more times", pool.reads-after)
	}
}

func TestControllerWakesWhenAReservationAppears(t *testing.T) {
	now := time.Date(2026, 3, 4, 3, 0, 0, 0, time.UTC)
	pool := &countingPool{fakePool: fakePool{machines: seatSizedMachines(2, time.Hour, time.Hour)}}
	specs := fakeSpecs{}
	c := &Controller{
		Policy: Policy{Forgive: engageForgive}, Config: DefaultPlanConfig(),
		Pool: pool, Jobs: fakeJobs{}, Specs: specs, Actuator: &fakeActuator{},
		Now: func() time.Time { return now },
	}
	// Settle into quiescence.
	for range 2 {
		if _, err := c.Tick(context.Background()); err != nil {
			t.Fatalf("settling tick: %v", err)
		}
	}
	res, err := c.Tick(context.Background())
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if !res.Quiescent {
		t.Fatal("the controller never went quiet, so waking it proves nothing")
	}
	quiet := pool.reads

	// A standing reservation is booked. The store is listed before the
	// gate, so the next tick sees it.
	spec := engageSpec(t)
	spec.Standing = 1
	c.Specs = fakeSpecs{spec}
	if res, err = c.Tick(context.Background()); err != nil {
		t.Fatalf("tick after booking: %v", err)
	}
	if res.Quiescent {
		t.Fatal("the controller stayed quiet with a standing reservation booked")
	}
	if pool.reads == quiet {
		t.Fatal("the controller did not read the pool after a reservation was booked")
	}
}

func TestProberDoesNotTouchThePoolWhileNothingIsReserved(t *testing.T) {
	starts := map[string]string{"a-ep": StartStanza}

	// Non-vacuous: with the gate open the prober writes to a machine.
	w := &fakeWriter{}
	p := newProber(starts, w)
	p.Engaged = gateReturning(true)
	if _, err := p.Visit(context.Background()); err != nil {
		t.Fatalf("Visit with the gate open: %v", err)
	}
	if len(w.probed) != 1 {
		t.Fatalf("an engaged visit probed %d machines, want 1", len(w.probed))
	}

	w = &fakeWriter{}
	p = newProber(starts, w)
	p.Engaged = gateReturning(false)
	probe, err := p.Visit(context.Background())
	if err != nil {
		t.Fatalf("Visit with the gate shut: %v", err)
	}
	if len(w.probed) != 0 {
		t.Fatalf("a gated-off visit probed %v", w.probed)
	}
	if probe.Outcome != "" {
		t.Fatalf("a gated-off visit reported outcome %q", probe.Outcome)
	}
	if len(p.Recent()) != 0 {
		t.Fatal("a gated-off visit was recorded as a probe")
	}
}
