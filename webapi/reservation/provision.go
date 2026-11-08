package reservation

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"time"
)

// StartClause is what a held execute point's START must contain for the
// sieve to govern it.
//
// `?:` is the ClassAd defaulting operator: ReservationStart when it is
// defined, True when it is not. An execute point with no reservation on
// it is therefore unconstrained.
const StartClause = `( ReservationStart ?: True )`

// startMarker is what ProvisionNeeded looks for. It is the operand name
// rather than the whole clause, so an operator who wrote the stanza into
// their own config by hand -- in any spelling -- is left alone.
const startMarker = "ReservationStart"

// ProvisionNeeded reports whether an execute point's published START has
// to be rewritten before the sieve can govern it.
//
// An empty expression is never provisioned. START missing from a slot ad
// means the census asked for it and the startd did not answer, and
// composing against nothing would replace whatever the site's real
// policy is with the reservation clause alone.
func ProvisionNeeded(start string) bool {
	start = strings.TrimSpace(start)
	if start == "" {
		return false
	}
	return !strings.Contains(start, startMarker)
}

// ComposeStart is the expression to push: the execute point's own START,
// as published, with the reservation clause ANDed on.
//
// The site's expression is parenthesised. A top-level || in it would
// otherwise swallow the clause and the machine would admit anything
// while appearing to be held.
func ComposeStart(current string) string {
	return "(" + strings.TrimSpace(current) + ") && " + StartClause
}

// ProbeOutcome is what one visit to an execute point found.
type ProbeOutcome string

const (
	// ProbeProvisioned means START was rewritten to include the clause.
	ProbeProvisioned ProbeOutcome = "provisioned"
	// ProbeAlreadySet means it already referenced the clause.
	ProbeAlreadySet ProbeOutcome = "already-set"
	// ProbeDenied means the push was refused. This is the one an
	// operator has to see: without the authorisation to update machine
	// ads, every reservation silently holds nothing.
	ProbeDenied ProbeOutcome = "denied"
	// ProbeUnreachable means the execute point did not answer.
	ProbeUnreachable ProbeOutcome = "unreachable"
	// ProbeNoStart means the slot ad carried no START to compose against.
	ProbeNoStart ProbeOutcome = "no-start"
)

// Probe is the result of one visit.
type Probe struct {
	At      time.Time
	Machine string
	Outcome ProbeOutcome
	// Detail carries the error when the outcome is a failure, and the
	// composed expression when one was pushed, so an operator can see
	// exactly what was written to their pool.
	Detail string
}

// OK reports whether the probe found a usable execute point.
func (p Probe) OK() bool { return p.Outcome == ProbeProvisioned || p.Outcome == ProbeAlreadySet }

// Provisioner writes START to one execute point.
type Provisioner interface {
	// SetStart pushes a START expression to a machine's ad.
	SetStart(ctx context.Context, machine, expr string) error
}

// StartSource reports each candidate execute point's published START,
// unevaluated. The census query must ask for the expression rather than
// its value: a slot ad's START evaluates to true or false, and composing
// against "false" would wedge the machine.
type StartSource interface {
	Starts(ctx context.Context) (map[string]string, error)
}

// Prober visits one execute point at a time, provisioning START where it
// is missing and confirming the pool still accepts updates where it is
// not.
//
// It is deliberately slow. Visiting one randomly chosen machine per
// interval spreads the write load over the pool, and -- with the jitter
// below -- keeps several access points running their own controllers
// from converging on the same machine at the same moment. They would not
// corrupt each other if they did: the composition is deterministic, so
// two controllers pushing the same machine push identical bytes. The
// jitter is to keep the pool from seeing a thundering herd at the top of
// every interval.
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
	start := starts[name]
	switch {
	case strings.TrimSpace(start) == "":
		probe.Outcome = ProbeNoStart
		probe.Detail = "the slot ad carried no START expression"
	case ProvisionNeeded(start):
		expr := ComposeStart(start)
		if err := p.Writer.SetStart(ctx, name, expr); err != nil {
			probe.Outcome, probe.Detail = ProbeDenied, err.Error()
			break
		}
		probe.Outcome, probe.Detail = ProbeProvisioned, expr
	default:
		// Already carries the clause. Push it back unchanged: an
		// identical write is the only way to learn whether this access
		// point may still update machine ads, and without that
		// authorisation every reservation would hold nothing while
		// looking healthy.
		if err := p.Writer.SetStart(ctx, name, start); err != nil {
			probe.Outcome, probe.Detail = ProbeDenied, err.Error()
			break
		}
		probe.Outcome = ProbeAlreadySet
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
	// Healthy is false when the most recent visit failed.
	Healthy bool   `json:"healthy"`
	Outcome string `json:"outcome,omitempty"`
	Machine string `json:"machine,omitempty"`
	Detail  string `json:"detail,omitempty"`
	// CheckedAt is when the last visit happened; zero when none has.
	CheckedAt time.Time `json:"checked_at,omitempty"`
	// Provisioned counts execute points this process has rewritten.
	Provisioned int `json:"provisioned"`
}

// Health reports what the admin page should say.
//
// An access point that cannot update machine ads is the failure worth
// surfacing: nothing errors, no reservation complains, and every class
// quietly starts on a pool that was never drained.
func (p *Prober) Health() Health {
	h := Health{Healthy: true}
	for _, probe := range p.last {
		if probe.Outcome == ProbeProvisioned {
			h.Provisioned++
		}
	}
	if len(p.last) == 0 {
		return h
	}
	last := p.last[len(p.last)-1]
	h.Outcome, h.Machine, h.CheckedAt = string(last.Outcome), last.Machine, last.At
	if !last.OK() {
		h.Healthy, h.Detail = false, last.Detail
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
