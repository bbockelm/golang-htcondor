package reservation

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"time"
)

// An execute point has to be told to consult the sieve before any of
// this governs it, and that has to be done in its configuration:
//
//	START = $(START) && ( ReservationStart ?: True )
//
// It cannot be pushed. A startd republishes START from its own
// configuration every time it refreshes its ad, so an attribute named
// START merged into the machine ad is overwritten within seconds and
// the machine goes on admitting everything while a controller counts it
// as held. The operands the sieve reads are pushed, and they stay; only
// START itself behaves this way.
//
// So this file does two things instead of provisioning. It reports
// which permissible execute points are not carrying the stanza, which
// is a line the operator has to add and until then a reservation
// silently holds nothing. And it confirms this access point may still
// update machine ads, which is the other way reservations fail with
// nothing to show for it.

// Provisioner writes the sieve to one execute point.
//
// Writing it is the probe: the startd answers a request it cannot act
// on the same way it answers one it can, so a check that connects
// without writing proves only that the connection was accepted.
// Writing the sieve is idempotent -- it is a constant, and the operands
// that give it meaning are not touched.
type Provisioner interface {
	Probe(ctx context.Context, machine string) error
}

// StartSource reports each candidate execute point's published START,
// unevaluated. The census query must ask for the expression rather than
// its value: a slot ad's START evaluates to true or false, and a
// provisioning decision taken on "false" would be nonsense.
type StartSource interface {
	Starts(ctx context.Context) (map[string]string, error)
}

// ProbeOutcome is what one visit to an execute point found.
type ProbeOutcome string

const (
	// ProbeOK means the execute point carries the stanza and accepted a
	// write.
	ProbeOK ProbeOutcome = "ok"
	// ProbeUnprovisioned means the write was accepted but the execute
	// point's START does not consult the sieve, so holding it has no
	// effect. The operator has to add StartStanza to its configuration.
	ProbeUnprovisioned ProbeOutcome = "unprovisioned"
	// ProbeDenied means the write was refused. This is the one an
	// operator has to see: without the authorisation to update machine
	// ads, every reservation silently holds nothing.
	ProbeDenied ProbeOutcome = "denied"
	// ProbeUnreachable means the execute point did not answer.
	ProbeUnreachable ProbeOutcome = "unreachable"
	// ProbeNoStart means the slot ad carried no START to judge.
	ProbeNoStart ProbeOutcome = "no-start"
)

// Probe is the result of one visit.
type Probe struct {
	At      time.Time
	Machine string
	Outcome ProbeOutcome
	// Detail carries the error when the outcome is a failure, and the
	// execute point's own START when it is not provisioned, so an
	// operator can see what they are adding the stanza to.
	Detail string
}

// OK reports whether the probe found an execute point a reservation can
// actually govern.
func (p Probe) OK() bool { return p.Outcome == ProbeOK }

// Prober visits one execute point at a time, confirming that the pool
// still accepts updates from this access point and that the execute
// points carry the stanza.
//
// It is deliberately slow. Visiting one randomly chosen machine per
// interval spreads the write load over the pool, and -- with the jitter
// below -- keeps several access points running their own controllers
// from converging on the same machine at the same moment. They would
// not corrupt each other if they did: the sieve is a constant, so two
// controllers probing the same machine write identical bytes. The
// jitter is to keep the pool from seeing a thundering herd at the top
// of every interval.
type Prober struct {
	Source StartSource
	Writer Provisioner
	// Interval is the floor between visits. The next visit is drawn
	// uniformly from [Interval, 2*Interval).
	Interval time.Duration
	// Now and Rand are overridable for tests.
	Now  func() time.Time
	Rand *rand.Rand

	last []Probe
}

// DefaultProbeInterval is the floor between visits.
const DefaultProbeInterval = 5 * time.Minute

// probeHistory is how many visits are remembered for the admin page.
const probeHistory = 20

func (p *Prober) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Prober) intn(n int) int {
	if n <= 0 {
		return 0
	}
	if p.Rand != nil {
		return p.Rand.IntN(n)
	}
	return rand.IntN(n) //nolint:gosec // G404: spreading load, not a secret
}

// Wait is how long to sleep before the next visit: the interval plus up
// to one more interval of jitter.
func (p *Prober) Wait() time.Duration {
	iv := p.Interval
	if iv <= 0 {
		iv = DefaultProbeInterval
	}
	return iv + time.Duration(p.intn(int(iv)))
}

// Visit inspects one randomly chosen execute point and returns what it
// found. It writes to at most one machine.
func (p *Prober) Visit(ctx context.Context) (Probe, error) {
	starts, err := p.Source.Starts(ctx)
	if err != nil {
		return Probe{}, fmt.Errorf("reading execute points: %w", err)
	}
	if len(starts) == 0 {
		return Probe{}, nil
	}
	names := make([]string, 0, len(starts))
	for name := range starts {
		names = append(names, name)
	}
	// Sorted before choosing so the choice depends on the random draw
	// and not on Go's map iteration order, which would make a test that
	// fixes the seed still flake.
	sort.Strings(names)
	name := names[p.intn(len(names))]

	probe := Probe{At: p.now(), Machine: name}
	start := strings.TrimSpace(starts[name])

	// Permission first. Whether the stanza is there is a fact about the
	// operator's configuration; whether this access point may write is
	// a fact about whether any of this works at all.
	if err := p.Writer.Probe(ctx, name); err != nil {
		probe.Outcome, probe.Detail = ProbeDenied, err.Error()
		p.record(probe)
		return probe, nil
	}

	switch {
	case start == "":
		probe.Outcome = ProbeNoStart
		probe.Detail = "the slot ad carried no START expression"
	case !Provisioned(start):
		probe.Outcome = ProbeUnprovisioned
		probe.Detail = start
	default:
		probe.Outcome = ProbeOK
	}
	p.record(probe)
	return probe, nil
}

func (p *Prober) record(probe Probe) {
	p.last = append(p.last, probe)
	if len(p.last) > probeHistory {
		p.last = p.last[len(p.last)-probeHistory:]
	}
}

// Recent is the probes remembered so far, oldest first.
func (p *Prober) Recent() []Probe {
	out := make([]Probe, len(p.last))
	copy(out, p.last)
	return out
}

// Health summarises the recent probes for the admin page.
type Health struct {
	// Healthy is false when the most recent visit could not write.
	Healthy bool   `json:"healthy"`
	Outcome string `json:"outcome,omitempty"`
	Machine string `json:"machine,omitempty"`
	Detail  string `json:"detail,omitempty"`
	// CheckedAt is when the last visit happened; zero when none has.
	CheckedAt time.Time `json:"checked_at,omitempty"`
	// Unprovisioned names the execute points seen recently whose START
	// does not consult the sieve. Holding one has no effect, so this is
	// the difference between a reservation that works and one that
	// looks like it does.
	Unprovisioned []string `json:"unprovisioned,omitempty"`
	// Stanza is the line those execute points are missing, so the admin
	// page can show what to add rather than describe it.
	Stanza string `json:"stanza,omitempty"`
}

// Health reports what the admin page should say.
//
// Two things fail silently and only show up here. An access point that
// cannot update machine ads: nothing errors, no reservation complains,
// and every class starts on a pool that was never drained. And an
// execute point whose START never consults the sieve: it is held, it
// reports as held, and it admits everything anyway.
func (p *Prober) Health() Health {
	h := Health{Healthy: true, Stanza: StartStanza}
	// Deduplicated over the remembered visits, so a machine probed
	// twice is named once, and one that has since been fixed drops off
	// as the window rolls forward.
	seen := map[string]bool{}
	for _, probe := range p.last {
		if probe.Outcome == ProbeUnprovisioned && !seen[probe.Machine] {
			seen[probe.Machine] = true
			h.Unprovisioned = append(h.Unprovisioned, probe.Machine)
		}
	}
	sort.Strings(h.Unprovisioned)
	if len(p.last) == 0 {
		return h
	}
	last := p.last[len(p.last)-1]
	h.Outcome, h.Machine, h.CheckedAt = string(last.Outcome), last.Machine, last.At
	switch last.Outcome {
	case ProbeDenied, ProbeUnreachable:
		h.Healthy, h.Detail = false, last.Detail
	case ProbeUnprovisioned:
		// Not unhealthy: this access point is working, and what is
		// missing is a line in somebody else's configuration file.
		h.Detail = last.Detail
	}
	return h
}

// Run visits one execute point per interval until ctx is cancelled.
func (p *Prober) Run(ctx context.Context, report func(Probe, error)) {
	for {
		probe, err := p.Visit(ctx)
		if report != nil {
			report(probe, err)
		}
		t := time.NewTimer(p.Wait())
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
