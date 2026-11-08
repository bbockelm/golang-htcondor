package reservation

import (
	"context"
	"errors"
	"math/rand/v2"
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
	wrote map[string]string
	err   error
}

func (w *fakeWriter) SetStart(_ context.Context, m, expr string) error {
	if w.err != nil {
		return w.err
	}
	if w.wrote == nil {
		w.wrote = map[string]string{}
	}
	w.wrote[m] = expr
	return nil
}

func TestProvisionNeeded(t *testing.T) {
	for _, tc := range []struct {
		name, start string
		want        bool
	}{
		{"plain site policy", "Owner =?= \"alice\"", true},
		{"already composed", "(Owner =?= \"alice\") && ( ReservationStart ?: True )", false},
		{"hand-written in another spelling", "ReservationStart =?= undefined || ReservationStart", false},
		// START absent means the startd did not answer, not that the site
		// has no policy. Composing against nothing would replace the real
		// policy with the clause alone.
		{"absent", "", false},
		{"whitespace", "   ", false},
	} {
		if got := ProvisionNeeded(tc.start); got != tc.want {
			t.Errorf("%s: ProvisionNeeded(%q) = %v, want %v", tc.name, tc.start, got, tc.want)
		}
	}
}

// TestComposeStartParenthesisesTheSitePolicy: a top-level || in the
// site's expression would otherwise swallow the clause, and the machine
// would admit anything while looking held.
func TestComposeStartParenthesisesTheSitePolicy(t *testing.T) {
	got := ComposeStart("A || B")
	if !strings.HasPrefix(got, "(A || B) &&") {
		t.Errorf("ComposeStart(%q) = %q, want the site expression parenthesised", "A || B", got)
	}
	if !strings.Contains(got, StartClause) {
		t.Errorf("composed expression lost the clause: %q", got)
	}
	// Composing is idempotent in the sense that matters: the result no
	// longer needs provisioning.
	if ProvisionNeeded(got) {
		t.Errorf("a composed expression still reads as needing provisioning: %q", got)
	}
}

func newProber(starts map[string]string, w *fakeWriter) *Prober {
	return &Prober{
		Source: &fakeStarts{starts: starts}, Writer: w,
		Interval: 5 * time.Minute,
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0) },
		Rand:     rand.New(rand.NewPCG(1, 2)), //nolint:gosec // deterministic test
	}
}

func TestVisitProvisionsAMachineThatNeedsIt(t *testing.T) {
	w := &fakeWriter{}
	p := newProber(map[string]string{"ep1": `Owner =?= "alice"`}, w)
	probe, err := p.Visit(context.Background())
	if err != nil {
		t.Fatalf("Visit: %v", err)
	}
	if probe.Outcome != ProbeProvisioned {
		t.Fatalf("outcome = %q, want provisioned", probe.Outcome)
	}
	got := w.wrote["ep1"]
	if !strings.Contains(got, `Owner =?= "alice"`) {
		t.Errorf("the site's own policy was not carried into %q", got)
	}
	if !strings.Contains(got, StartClause) {
		t.Errorf("the clause was not added: %q", got)
	}
}

// TestVisitWritesOnlyOneMachine: the whole point of the pacing is that a
// pool is not rewritten in one go.
func TestVisitWritesOnlyOneMachine(t *testing.T) {
	starts := map[string]string{}
	for _, n := range []string{"ep1", "ep2", "ep3", "ep4", "ep5"} {
		starts[n] = `Owner =?= "alice"`
	}
	w := &fakeWriter{}
	p := newProber(starts, w)
	if _, err := p.Visit(context.Background()); err != nil {
		t.Fatalf("Visit: %v", err)
	}
	if len(w.wrote) != 1 {
		t.Errorf("one visit wrote %d machines, want 1", len(w.wrote))
	}
}

// TestVisitStillProbesAnAlreadyProvisionedMachine: the write is how we
// learn whether this access point may still update machine ads at all.
func TestVisitStillProbesAnAlreadyProvisionedMachine(t *testing.T) {
	composed := ComposeStart(`Owner =?= "alice"`)
	w := &fakeWriter{}
	p := newProber(map[string]string{"ep1": composed}, w)
	probe, err := p.Visit(context.Background())
	if err != nil {
		t.Fatalf("Visit: %v", err)
	}
	if probe.Outcome != ProbeAlreadySet {
		t.Errorf("outcome = %q, want already-set", probe.Outcome)
	}
	if w.wrote["ep1"] != composed {
		t.Errorf("the probe changed the expression: %q", w.wrote["ep1"])
	}
}

// TestVisitSurfacesADeniedWrite is the failure an operator must see:
// without authorisation nothing errors, no reservation complains, and
// every class starts on a pool that was never drained.
func TestVisitSurfacesADeniedWrite(t *testing.T) {
	w := &fakeWriter{err: errors.New("DENIED: not authorized to update machine ad")}
	p := newProber(map[string]string{"ep1": `Owner =?= "alice"`}, w)
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
	if len(w.wrote) != 0 {
		t.Errorf("wrote to a machine whose START was unknown: %v", w.wrote)
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
}

func TestVisitReportsAnUnreadablePool(t *testing.T) {
	boom := errors.New("collector down")
	p := &Prober{Source: &fakeStarts{err: boom}, Writer: &fakeWriter{}}
	if _, err := p.Visit(context.Background()); !errors.Is(err, boom) {
		t.Errorf("Visit error = %v, want the source's", err)
	}
}
