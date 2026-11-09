package httpserver

import (
	"context"
	"fmt"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/reservation"
)

// reservationTick is how often the controller re-reads the pool and
// decides.
//
// The ranking it decides by is built on age at the bell, which is
// invariant for a job that keeps running -- the clock advancing and the
// bell approaching cancel exactly -- so a short interval does not make
// the decisions flap, and a minute is short enough that a seat freed
// early is noticed while it is still free.
const reservationTick = time.Minute

// reservationForgiveDefault is the age below which evicting a job is
// treated as free. It is the one policy number the operator is really
// choosing, and it is also the grain the estimates are bucketed to.
const reservationForgiveDefault = 30 * time.Minute

// collectorPool is Controller.Pool backed by the collector.
//
// Both halves read the pool rather than remember anything. A controller
// restarted mid-drain, a push that failed, and a deadline left by a
// process that died all have to be visible before they can be
// corrected.
type collectorPool struct {
	h *Handler
}

func (p collectorPool) Machines(ctx context.Context) ([]reservation.Machine, error) {
	return reservation.Census(ctx, p.h.collector, p.h.reservationEPConstraint)
}

func (p collectorPool) Held(ctx context.Context) (map[string]time.Time, error) {
	return reservation.HeldPool(ctx, p.h.collector, p.h.reservationEPConstraint, time.Now())
}

// collectorJobs counts each project's running jobs from the pool rather
// than from this access point's queue.
//
// A reservation's seats are pool-wide: a student's job that landed from
// another access point is still a seat the project holds, and counting
// only this schedd's would make the controller drain for seats the
// project already has.
type collectorJobs struct {
	h *Handler
}

func (j collectorJobs) RunningByProject(ctx context.Context) (map[string]int, error) {
	machines, err := reservation.Census(ctx, j.h.collector, j.h.reservationEPConstraint)
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, m := range machines {
		for _, d := range m.Dslots {
			if d.Project != "" && !d.Started.IsZero() {
				out[d.Project]++
			}
		}
	}
	return out, nil
}

// storeSpecs is Controller.Specs backed by the application database.
type storeSpecs struct {
	h *Handler
}

func (s storeSpecs) List(ctx context.Context) ([]*reservation.Spec, error) {
	store := s.h.reservationStore()
	if store == nil {
		return nil, nil
	}
	return store.List(ctx)
}

// startReservations runs the controller and the permission prober.
//
// Both are started only when the subsystem is switched on and there is
// a collector to read: a reservation holds capacity by evicting other
// people's jobs, so nothing here happens because somebody upgraded.
func (h *Handler) startReservations(ctx context.Context) {
	if !h.reservationsEnabled || h.collector == nil {
		return
	}

	// Marked once, here, because everything below runs on a timer off a
	// context nobody else classifies: the census, the probe and the
	// machine-ad writes are this daemon reading and steering the pool on
	// its own authority, with no caller to act for. Without the mark they
	// reach CEDAR unclassified and authenticate as this daemon by falling
	// through, which is the same outcome by accident -- and the fallback
	// is on its way to being refused outright.
	ctx = htcondor.WithDaemonCredential(ctx,
		"reservations: pool census and machine-ad updates")

	actuator := &reservation.PoolActuator{
		Query:    h.collector,
		Only:     h.reservationEPConstraint,
		OnReload: h.reportCapabilities(),
		// Graceful: a vacated job takes its soft-kill signal and, if it
		// checkpoints, writes one. The cost model says evicting a young
		// job is free; it does not say throwing away a checkpoint it
		// was about to write is.
		Graceful: true,
	}

	h.reservationProber = &reservation.Prober{
		Source:   reservation.CollectorStarts{Query: h.collector, Only: h.reservationEPConstraint},
		Writer:   actuator,
		Interval: reservation.DefaultProbeInterval,
		// Awake with the stamper rather than with the controller: an
		// operator who has to add the stanza or grant the permission
		// wants to hear about it before the bell, not at it.
		Engaged: reservation.SpecGate(storeSpecs{h}, reservationForgiveDefault,
			reservation.SettleAfter, reservation.StampWarmup, nil),
	}
	go h.reservationProber.Run(ctx, func(p reservation.Probe, err error) {
		switch {
		case err != nil:
			h.logger.Warnf(logging.DestinationCollector, "reservation probe failed: %v", err)
		case p.Outcome == reservation.ProbeDenied:
			// The failure with no other symptom. Without authorization
			// to update machine ads nothing errors, no reservation
			// complains, and every class starts on a pool that was
			// never drained.
			h.logger.Errorf(logging.DestinationCollector,
				"reservations: %s refused a machine-ad update, so reservations hold nothing: %s", p.Machine, p.Detail)
		case p.Outcome == reservation.ProbeUnprovisioned:
			h.logger.Warnf(logging.DestinationCollector,
				"reservations: %s does not consult ReservationStart; add to its config: %s", p.Machine, reservation.StartStanza)
		}
	})

	controller := &reservation.Controller{
		Policy:   reservation.Policy{Forgive: reservationForgiveDefault},
		Config:   reservation.DefaultPlanConfig(),
		Pool:     collectorPool{h},
		Jobs:     collectorJobs{h},
		Specs:    storeSpecs{h},
		Actuator: actuator,
	}
	go controller.Run(ctx, reservationTick, func(res reservation.TickResult, err error) {
		if err != nil {
			h.logger.Warnf(logging.DestinationCollector, "reservation tick failed: %v", err)
			return
		}
		if res.Held > 0 || res.Released > 0 || res.Evicted > 0 {
			h.logger.Infof(logging.DestinationCollector,
				"reservations: held %d, released %d, evicted %d", res.Held, res.Released, res.Evicted)
		}
		for id, short := range res.Plan.Short {
			// Not something the controller can fix by holding harder:
			// the pool is too small, or the lead too short.
			h.logger.Warnf(logging.DestinationCollector,
				"reservation %s is %d seats short of what it asked for", id, short)
		}
		if err := res.Err(); err != nil {
			h.logger.Warnf(logging.DestinationCollector, "reservation tick could not apply part of its plan: %v", err)
		}
	})
}

// capabilityLevel is how loudly a reading of the pool deserves to be
// reported.
type capabilityLevel int

const (
	capabilityOK capabilityLevel = iota
	capabilityWarn
	capabilityBroken
)

// capabilityReport decides what to say about one reading of the pool.
//
// Separated from the logging so the choice can be tested: the case that
// matters is the silent one, where every command will go as this access
// point and be refused by execute points that never agreed to take
// orders from it.
func capabilityReport(c reservation.Capabilities) (capabilityLevel, string) {
	switch {
	case c.Machines == 0:
		return capabilityWarn, "reservations: no execute point matched, so there is nothing to hold"
	case c.WithCapability == 0:
		return capabilityBroken, fmt.Sprintf(
			"reservations: none of %d execute points published an administrative capability, so every command goes as this access point; "+
				"check that it holds ADMINISTRATOR at the collector and that the execute points have SEC_ENABLE_REMOTE_ADMINISTRATION",
			c.Machines)
	case c.Degraded():
		return capabilityWarn, fmt.Sprintf(
			"reservations: %d of %d execute points published an administrative capability; the rest are commanded as this access point",
			c.WithCapability, c.Machines)
	default:
		return capabilityOK, fmt.Sprintf(
			"reservations: all %d execute points published an administrative capability", c.Machines)
	}
}

// reportCapabilities logs how many execute points this access point can
// administer, on the first read of the pool and whenever the answer
// changes.
//
// Without this the one thing an operator needs is invisible. A machine
// that publishes no administrative capability is still commanded, with
// this process's own credentials, and on most pools refused -- and the
// refusal looks identical to a capability that was used and rejected.
// Only the access point knows which it sent.
//
// Logged on change rather than every read: the pool is re-read every
// few minutes and a steady state is not news.
func (h *Handler) reportCapabilities() func(reservation.Capabilities) {
	return h.capabilityReporter(func(level capabilityLevel, msg string) {
		switch level {
		case capabilityBroken:
			h.logger.Errorf(logging.DestinationCollector, "%s", msg)
		case capabilityWarn:
			h.logger.Warnf(logging.DestinationCollector, "%s", msg)
		default:
			h.logger.Infof(logging.DestinationCollector, "%s", msg)
		}
	})
}

// capabilityReporter is reportCapabilities with the saying of it passed
// in, so a test can read what would be said without a logger.
func (h *Handler) capabilityReporter(say func(capabilityLevel, string)) func(reservation.Capabilities) {
	var last reservation.Capabilities
	first := true
	return func(c reservation.Capabilities) {
		same := !first &&
			c.Machines == last.Machines &&
			c.WithCapability == last.WithCapability &&
			c.Usable == last.Usable &&
			(c.Err == nil) == (last.Err == nil)
		last, first = c, false
		if same {
			return
		}
		if c.Err != nil {
			say(capabilityWarn, fmt.Sprintf("reservations: reading execute points: %v", c.Err))
		}
		level, msg := capabilityReport(c)
		say(level, msg)
	}
}
