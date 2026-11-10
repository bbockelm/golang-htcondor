package reservation

import (
	"strings"
	"testing"
	"time"
)

func testSpec(t *testing.T, expr string) *Spec {
	t.Helper()
	return &Spec{
		ID: "cs301", Owner: "prof-moriarty", Project: "cs301-f26", Submit: "executable = /bin/true\nqueue\n",
		Seats: 35, Standing: 4,
		Duration: time.Hour, Lead: 6 * time.Hour, Hold: 15 * time.Minute,
		Schedule: mustSchedule(t, expr, time.UTC), Enabled: true,
	}
}

func TestSpecValidate(t *testing.T) {
	if err := testSpec(t, "0 14 * * 1").Validate(); err != nil {
		t.Fatalf("a well-formed spec was rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		mut  func(*Spec)
		want string
	}{
		{"no project", func(s *Spec) { s.Project = "" }, "Project is required"},
		{"no submit", func(s *Spec) { s.Submit = "" }, "Submit is required"},
		{"no seats", func(s *Spec) { s.Seats = 0 }, "Seats must be positive"},
		{"standing over seats", func(s *Spec) { s.Standing = 40 }, "cannot exceed Seats"},
		{"hold over duration", func(s *Spec) { s.Hold = 2 * time.Hour }, "Hold must be between"},
		{"no schedule", func(s *Spec) { s.Schedule = nil }, "Schedule is required"},
	} {
		s := testSpec(t, "0 14 * * 1")
		tc.mut(s)
		err := s.Validate()
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not mention %q", tc.name, err, tc.want)
		}
	}
}

// TestWindowsMergeBackToBack is the result that two consecutive classes are
// one hold: releasing the cores between them and draining again costs more
// than keeping them, and a gap under the forgiveness threshold is free
// anyway.
func TestWindowsMergeBackToBack(t *testing.T) {
	from := time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)
	forgive := 30 * time.Minute

	// Two one-hour classes starting at 14:00 and 15:00: no gap at all.
	s := testSpec(t, "0 14,15 * * 1")
	got := s.Windows(from, 48*time.Hour, forgive)
	if len(got) != 1 {
		t.Fatalf("back-to-back classes gave %d windows, want 1: %+v", len(got), got)
	}
	if got[0].Occurrences != 2 {
		t.Errorf("merged window covers %d occurrences, want 2", got[0].Occurrences)
	}
	if want := time.Date(2026, 3, 2, 16, 0, 0, 0, time.UTC); !got[0].End.Equal(want) {
		t.Errorf("merged window ends %v, want %v", got[0].End, want)
	}

	// A gap wider than forgive is two windows.
	s = testSpec(t, "0 14,16 * * 1")
	if got := s.Windows(from, 48*time.Hour, forgive); len(got) != 2 {
		t.Errorf("classes two hours apart gave %d windows, want 2", len(got))
	}

	// A gap inside forgive still merges.
	s = testSpec(t, "0,45 14 * * 1")
	s.Duration = 30 * time.Minute
	if got := s.Windows(from, 48*time.Hour, forgive); len(got) != 1 {
		t.Errorf("classes 15 minutes apart gave %d windows, want 1", len(got))
	}
}

func TestPhaseAt(t *testing.T) {
	s := testSpec(t, "0 14 * * 1")
	start := time.Date(2026, 3, 2, 14, 0, 0, 0, time.UTC)
	w := Window{SpecID: s.ID, Start: start, End: start.Add(time.Hour), Occurrences: 1}
	for _, tc := range []struct {
		at   time.Time
		want Phase
	}{
		{start.Add(-7 * time.Hour), PhaseOff},
		{start.Add(-6*time.Hour + time.Minute), PhasePlanning},
		{start.Add(-time.Minute), PhasePlanning},
		{start, PhaseHolding},
		{start.Add(14 * time.Minute), PhaseHolding},
		{start.Add(15 * time.Minute), PhaseOpen},
		{start.Add(59 * time.Minute), PhaseOpen},
		{start.Add(time.Hour), PhaseOff},
	} {
		if got := s.PhaseAt(w, tc.at); got != tc.want {
			t.Errorf("at %v: phase %v, want %v", tc.at.Sub(start), got, tc.want)
		}
	}
}

// TestTarget: Standing is headroom on top of what the project is using,
// not a floor the running jobs count against. Somebody arriving between
// windows should find an instance already held rather than wait for the
// next tick and a drain after it, so running jobs do not cancel it out.
func TestTarget(t *testing.T) {
	s := testSpec(t, "0 14 * * 1")
	s.Seats, s.Standing = 20, 2
	for _, tc := range []struct {
		name    string
		phase   Phase
		running int
		want    int
	}{
		{"outside, nothing running", PhaseOff, 0, 2},
		{"outside, five running still want two spare", PhaseOff, 5, 2},
		{"outside, one place left under the cap", PhaseOff, 19, 1},
		{"outside, at the cap", PhaseOff, 20, 0},
		{"outside, over the cap", PhaseOff, 25, 0},
		{"planning, nothing running", PhasePlanning, 0, 20},
		{"planning, partly filled", PhasePlanning, 10, 10},
		{"open, fully occupied", PhaseOpen, 20, 0},
	} {
		if got := s.Target(tc.phase, tc.running); got != tc.want {
			t.Errorf("%s: target %d, want %d", tc.name, got, tc.want)
		}
	}
	// Headroom is capped by the reservation, not by itself: a Standing
	// larger than the room left cannot promise capacity the project may
	// not occupy.
	s.Standing = s.Seats
	if got := s.Target(PhaseOff, 18); got != 2 {
		t.Errorf("with standing at the cap and 18 running, target %d, want 2", got)
	}
	s.Enabled = false
	if got := s.Target(PhasePlanning, 0); got != 0 {
		t.Errorf("a disabled reservation targeted %d seats", got)
	}
}

func TestWindowsHonoursHorizon(t *testing.T) {
	s := testSpec(t, "0 14 * * *")
	from := time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)
	if got := s.Windows(from, 72*time.Hour, 30*time.Minute); len(got) != 3 {
		t.Errorf("three days gave %d windows, want 3", len(got))
	}
	if got := s.Windows(from, 0, 30*time.Minute); len(got) != 0 {
		t.Errorf("a zero horizon gave %d windows, want 0", len(got))
	}
}

// TestSpecRequiresAnOwner: the owner is who the capacity is held for,
// and it is not the project. A reservation with a project and no owner
// names the seats but nobody to hold them for.
func TestSpecRequiresAnOwner(t *testing.T) {
	s := seatSpec("executable = /bin/true\nqueue\n")
	s.Owner = ""
	err := s.Validate()
	if err == nil {
		t.Fatal("a reservation with no owner was accepted")
	}
	if !strings.Contains(err.Error(), "Owner") {
		t.Errorf("error does not name the missing field: %v", err)
	}

	// An owner is not a substitute for a project, nor the other way
	// round: both are required, and they answer different questions.
	s = seatSpec("executable = /bin/true\nqueue\n")
	s.Project = ""
	if err := s.Validate(); err == nil {
		t.Error("a reservation with an owner but no project was accepted")
	}
}
