package reservation

import (
	"errors"
	"fmt"
	"time"
)

// Spec is a standing reservation: a recurring window during which a project
// is guaranteed seats, and a smaller number of seats kept between windows so
// the project's users are not left waiting in the general queue.
type Spec struct {
	// ID identifies the reservation. It never appears in a machine
	// attribute name: the startd cannot forget an attribute, so naming
	// attributes after reservations would accumulate dead keys on every
	// execute point until it restarts.
	ID string
	// Project is the ProjectName a job must carry to take a seat.
	Project string
	// Submit is the submit file describing the seat. It is rendered to a
	// job ad to work out which machines can host one.
	Submit string
	// Seats is how many seats the window holds, and the cap on how many
	// the project may occupy at once.
	Seats int
	// Standing is how many seats are kept between windows. Zero keeps
	// none.
	Standing int
	// Duration is how long one window lasts.
	Duration time.Duration
	// Lead is how far ahead of a window the controller starts holding
	// cores back. Six hours is where the measured benefit saturates; at
	// one hour it is materially worse.
	Lead time.Duration
	// Hold is how long seats stay reserved for the project after the
	// window opens, before unclaimed ones return to the pool.
	Hold time.Duration
	// Schedule says when windows start.
	Schedule *Schedule
	// Enabled is whether the controller acts on this reservation.
	Enabled bool
}

// Validate reports whether the spec describes something the controller can
// act on.
func (s *Spec) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if s.ID == "" {
		add("ID is required")
	}
	if s.Project == "" {
		add("Project is required: it is what lets a job claim a seat")
	}
	if s.Submit == "" {
		add("Submit is required: the seat's shape comes from it")
	}
	if s.Seats <= 0 {
		add("Seats must be positive, got %d", s.Seats)
	}
	if s.Standing < 0 {
		add("Standing cannot be negative, got %d", s.Standing)
	}
	if s.Standing > s.Seats {
		add("Standing (%d) cannot exceed Seats (%d)", s.Standing, s.Seats)
	}
	if s.Duration <= 0 {
		add("Duration must be positive")
	}
	if s.Lead <= 0 {
		add("Lead must be positive")
	}
	if s.Hold < 0 || s.Hold > s.Duration {
		add("Hold must be between zero and Duration")
	}
	if s.Schedule == nil {
		add("Schedule is required")
	}
	return errors.Join(errs...)
}

// Window is a contiguous period during which a spec holds its seats.
//
// Consecutive occurrences close enough together are one window, because
// releasing cores between them and draining again costs more than holding:
// a gap shorter than the forgiveness threshold is free either way, since
// anything started in it is still cheap to evict at the next bell.
type Window struct {
	SpecID string
	Start  time.Time
	End    time.Time
	// Occurrences is how many scheduled starts this window covers.
	Occurrences int
}

// Bell is when the window opens and seats must be free.
func (w Window) Bell() time.Time { return w.Start }

// Windows lists the spec's windows beginning within horizon of from,
// merging occurrences separated by forgive or less.
func (s *Spec) Windows(from time.Time, horizon, forgive time.Duration) []Window {
	if s.Schedule == nil || s.Duration <= 0 {
		return nil
	}
	deadline := from.Add(horizon)
	var out []Window
	at := from
	for {
		start, ok := s.Schedule.Next(at)
		if !ok || start.After(deadline) {
			return out
		}
		end := start.Add(s.Duration)
		if n := len(out); n > 0 && !start.After(out[n-1].End.Add(forgive)) {
			// Back to back: extend rather than start a new hold.
			if end.After(out[n-1].End) {
				out[n-1].End = end
			}
			out[n-1].Occurrences++
		} else {
			out = append(out, Window{SpecID: s.ID, Start: start, End: end, Occurrences: 1})
		}
		at = start
	}
}

// Phase is what the controller should be doing for a window.
type Phase int

const (
	// PhaseOff is outside any window and its planning lead. Only the
	// standing seats apply.
	PhaseOff Phase = iota
	// PhasePlanning is inside the lead: hold cores back so the seats are
	// cheap by the bell.
	PhasePlanning
	// PhaseHolding is just after the bell, while unclaimed seats are still
	// reserved for the project.
	PhaseHolding
	// PhaseOpen is the rest of the window: the project keeps the seats it
	// claimed, and freed ones go back to the project rather than the pool.
	PhaseOpen
)

func (p Phase) String() string {
	switch p {
	case PhasePlanning:
		return "planning"
	case PhaseHolding:
		return "holding"
	case PhaseOpen:
		return "open"
	default:
		return "off"
	}
}

// PhaseAt says where now sits relative to w.
func (s *Spec) PhaseAt(w Window, now time.Time) Phase {
	switch {
	case now.Before(w.Start.Add(-s.Lead)):
		return PhaseOff
	case now.Before(w.Start):
		return PhasePlanning
	case now.Before(w.Start.Add(s.Hold)):
		return PhaseHolding
	case now.Before(w.End):
		return PhaseOpen
	default:
		return PhaseOff
	}
}

// Target is how many seats to secure now, given how many of the project's
// jobs are already running.
//
// Jobs the project is already running are seats it already has, so they
// count against the target. Once it holds Seats there is nothing to
// reserve: a reservation exists to make room, not to idle capacity the
// project is not using.
func (s *Spec) Target(phase Phase, running int) int {
	if !s.Enabled {
		return 0
	}
	want := s.Standing
	if phase != PhaseOff {
		want = s.Seats
	}
	if running >= s.Seats {
		return 0
	}
	if n := want - running; n > 0 {
		return n
	}
	return 0
}
