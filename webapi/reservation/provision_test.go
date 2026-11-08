package reservation

import (
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"
)

type fakeStarts struct {
	starts map[string]string
	err    error
}

func (f *fakeStarts) Starts(context.Context) (map[string]string, error) { return f.starts, f.err }

type fakeWriter struct {
	probed []string
	err    error
}

func (w *fakeWriter) Probe(_ context.Context, m string) error {
	if w.err != nil {
		return w.err
	}
	w.probed = append(w.probed, m)
	return nil
}

func newProber(starts map[string]string, w *fakeWriter) *Prober {
	return &Prober{
		Source: &fakeStarts{starts: starts}, Writer: w,
		Interval: 5 * time.Minute,
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0) },
		Rand:     rand.New(rand.NewPCG(1, 2)), //nolint:gosec // deterministic test
	}
}

// TestVisitNamesAnUnprovisionedExecutePoint. An execute point whose
// START never consults the sieve is held, reports as held, and admits
// everything anyway. Nothing else in the system can tell, so naming it
// here is the only way an operator finds out.
func TestVisitNamesAnUnprovisionedExecutePoint(t *testing.T) {
	w := &fakeWriter{}
	p := newProber(map[string]string{"ep1": `Owner =?= "alice"`}, w)
	probe, err := p.Visit(context.Background())
	if err != nil {
		t.Fatalf("Visit: %v", err)
	}
	if probe.Outcome != ProbeUnprovisioned {
		t.Fatalf("outcome = %q, want unprovisioned", probe.Outcome)
	}
	if !strings.Contains(probe.Detail, `Owner =?= "alice"`) {
		t.Errorf("the probe does not report the execute point's own START: %q", probe.Detail)
	}

	h := p.Health()
	if !h.Healthy {
		// This access point is working. What is missing is a line in
		// somebody else's configuration file.
		t.Errorf("an unprovisioned execute point made this access point read as unhealthy")
	}
	if !slices.Contains(h.Unprovisioned, "ep1") {
		t.Errorf("health does not name the unprovisioned machine: %+v", h)
	}
	if h.Stanza != StartStanza {
		t.Errorf("health carries stanza %q, want the one to paste", h.Stanza)
	}
}

// TestVisitAcceptsAProvisionedExecutePoint, in whatever spelling the
// site wrote the clause: the attribute name is what matters.
func TestVisitAcceptsAProvisionedExecutePoint(t *testing.T) {
	for name, start := range map[string]string{
		"the stanza as documented": `(Owner =?= "alice") && ( ReservationStart ?: True )`,
		"an older spelling":        `ReservationStart =?= undefined || ReservationStart`,
		"lowercase":                `(Foo) && (reservationstart ?: 1)`,
	} {
		t.Run(name, func(t *testing.T) {
			w := &fakeWriter{}
			p := newProber(map[string]string{"ep1": start}, w)
			probe, err := p.Visit(context.Background())
			if err != nil {
				t.Fatalf("Visit: %v", err)
			}
			if probe.Outcome != ProbeOK {
				t.Errorf("outcome = %q, want ok", probe.Outcome)
			}
			if len(p.Health().Unprovisioned) != 0 {
				t.Errorf("a provisioned execute point was reported as missing the stanza")
			}
		})
	}
}

// TestVisitWritesOnlyOneMachine: the whole point of the pacing is that
// a pool is not written to in one go.
func TestVisitWritesOnlyOneMachine(t *testing.T) {
	starts := map[string]string{}
	for _, n := range []string{"ep1", "ep2", "ep3", "ep4", "ep5"} {
		starts[n] = StartStanza
	}
	w := &fakeWriter{}
	p := newProber(starts, w)
	if _, err := p.Visit(context.Background()); err != nil {
		t.Fatalf("Visit: %v", err)
	}
	if len(w.probed) != 1 {
		t.Errorf("one visit wrote to %d machines, want 1", len(w.probed))
	}
}

// TestVisitWritesEvenWhenNothingNeedsChanging: the write is how this
// access point learns it may still update machine ads at all. A check
// that only connected would prove nothing -- the startd accepts the
// connection either way.
func TestVisitWritesEvenWhenNothingNeedsChanging(t *testing.T) {
	w := &fakeWriter{}
	p := newProber(map[string]string{"ep1": StartStanza}, w)
	if _, err := p.Visit(context.Background()); err != nil {
		t.Fatalf("Visit: %v", err)
	}
	if len(w.probed) != 1 {
		t.Errorf("a provisioned execute point was not written to, so permission was never tested")
	}
}

// TestVisitSurfacesADeniedWrite is the failure an operator must see:
// without authorisation nothing errors, no reservation complains, and
// every class starts on a pool that was never drained.
func TestVisitSurfacesADeniedWrite(t *testing.T) {
	w := &fakeWriter{err: errors.New("DENIED: not authorized to update machine ad")}
	p := newProber(map[string]string{"ep1": StartStanza}, w)
	probe, err := p.Visit(context.Background())
	if err != nil {
		t.Fatalf("Visit returned a fatal error for a denied write: %v", err)
	}
	if probe.Outcome != ProbeDenied {
		t.Fatalf("outcome = %q, want denied", probe.Outcome)
	}
	h := p.Health()
	if h.Healthy {
		t.Error("health still reads healthy after a denied write")
	}
	if !strings.Contains(h.Detail, "not authorized") {
		t.Errorf("health detail does not carry the reason: %q", h.Detail)
	}
	if h.Machine != "ep1" {
		t.Errorf("health does not name the machine: %q", h.Machine)
	}
}

func TestVisitSkipsAMachineWithNoStart(t *testing.T) {
	w := &fakeWriter{}
	p := newProber(map[string]string{"ep1": ""}, w)
	probe, err := p.Visit(context.Background())
	if err != nil {
		t.Fatalf("Visit: %v", err)
	}
	if probe.Outcome != ProbeNoStart {
		t.Errorf("outcome = %q, want no-start", probe.Outcome)
	}
	if len(p.Health().Unprovisioned) != 0 {
		// A missing START means the census did not ask for it, not that
		// the operator forgot the stanza. Naming the machine would send
		// them to edit a file that is already right.
		t.Errorf("a machine whose START was unknown was reported as missing the stanza")
	}
}

// TestHealthDeduplicatesAndSorts: a machine probed twice over the
// remembered window is named once, so the admin page shows a list of
// execute points rather than a list of visits.
func TestHealthDeduplicatesAndSorts(t *testing.T) {
	p := newProber(nil, &fakeWriter{})
	for _, m := range []string{"ep2", "ep1", "ep2"} {
		p.record(Probe{Machine: m, Outcome: ProbeUnprovisioned})
	}
	h := p.Health()
	want := []string{"ep1", "ep2"}
	if !slices.Equal(h.Unprovisioned, want) {
		t.Errorf("Unprovisioned = %v, want %v", h.Unprovisioned, want)
	}
}

// TestWaitJitters: several access points running their own controllers
// must not converge on the top of every interval.
func TestWaitJitters(t *testing.T) {
	p := newProber(nil, &fakeWriter{})
	seen := map[time.Duration]bool{}
	for range 50 {
		w := p.Wait()
		if w < p.Interval || w >= 2*p.Interval {
			t.Fatalf("wait %v outside [%v, %v)", w, p.Interval, 2*p.Interval)
		}
		seen[w] = true
	}
	if len(seen) < 10 {
		t.Errorf("only %d distinct waits in 50 draws: the jitter is not spreading", len(seen))
	}
}

func TestHealthIsCleanBeforeAnyProbe(t *testing.T) {
	p := newProber(nil, &fakeWriter{})
	h := p.Health()
	if !h.Healthy || h.Outcome != "" || !h.CheckedAt.IsZero() {
		t.Errorf("health before any probe = %+v, want clean and unchecked", h)
	}
	if len(h.Unprovisioned) != 0 {
		t.Errorf("health names execute points before anything was probed: %v", h.Unprovisioned)
	}
}

func TestVisitReportsAnUnreadablePool(t *testing.T) {
	boom := errors.New("collector down")
	p := &Prober{Source: &fakeStarts{err: boom}, Writer: &fakeWriter{}}
	if _, err := p.Visit(context.Background()); !errors.Is(err, boom) {
		t.Errorf("Visit error = %v, want the source's", err)
	}
}
