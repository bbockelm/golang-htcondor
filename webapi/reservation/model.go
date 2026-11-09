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
	// Owner is the person the capacity is held for -- the teacher of
	// the class, not the students.
	//
	// Separate from Project because they answer different questions.
	// Project is what a job carries to claim a seat; Owner is who the
	// reservation belongs to. HTCondor's own persistent claims hang off
	// a user record and are matched against both, so a claim held for
	// an owner serves that owner's jobs and any job of the owner's
	// project -- which is exactly a class and its students.
	Owner string
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
	// Starts is the first instant an occurrence may begin. The zero
	// time means the recurrence has always been running.
	Starts time.Time
	// Ends is the instant past which no occurrence may begin. The zero
	// time means the recurrence never stops.
	//
	// An occurrence beginning before Ends runs its full Duration: a
	// class is not cut short because the term ended between its bell
	// and its last minute.
	Ends time.Time
	// Occurrences is how many times the recurrence runs, counted from
	// Starts. Zero means without limit.
	//
	// It counts scheduled starts rather than windows, because two
	// classes close enough together are merged into one hold and
	// "fifteen lectures" must still mean fifteen lectures.
	Occurrences int
	// Enabled is whether the controller acts on this reservation.
	Enabled bool
}

// maxOccurrences bounds the count an admin may ask for.
//
// Resolving a count to an instant means walking the schedule one
// occurrence at a time, so an unbounded count is an unbounded walk on
// every tick. Weekly for a thousand weeks is nineteen years, which is
// past the point where somebody should be booking a new reservation
// instead.
const maxOccurrences = 1000

// Validate reports whether the spec describes something the controller can
// act on.
func (s *Spec) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if s.ID == "" {
		add("ID is required")
	}
	if s.Owner == "" {
		add("Owner is required: it is who the capacity is held for")
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
	if s.Occurrences < 0 {
		add("Occurrences cannot be negative, got %d", s.Occurrences)
	}
	if s.Occurrences > maxOccurrences {
		add("Occurrences cannot exceed %d, got %d", maxOccurrences, s.Occurrences)
	}
	if s.Occurrences > 0 && !s.Ends.IsZero() {
		add("give an end date or a number of occurrences, not both")
	}
	if s.Occurrences > 0 && s.Starts.IsZero() {
		add("Occurrences needs a start date: counting occurrences means nothing without a first one")
	}
	if !s.Starts.IsZero() && !s.Ends.IsZero() && s.Starts.After(s.Ends) {
		add("Starts (%s) is after Ends (%s)", s.Starts.Format(time.RFC3339), s.Ends.Format(time.RFC3339))
	}
	return errors.Join(errs...)
}

// recurrenceEnd is the instant from which no further occurrence begins,
// and whether the recurrence has such an instant at all.
//
// A count of occurrences resolves to the start of the one after the
// last, so both ways of bounding a recurrence answer the same
// strictly-before comparison and nothing downstream has to know which
// was given. The walk is bounded by maxOccurrences and by the
// schedule's own search horizon.
func (s *Spec) recurrenceEnd() (time.Time, bool) {
	if s.Occurrences <= 0 || s.Schedule == nil || s.Starts.IsZero() {
		return s.Ends, !s.Ends.IsZero()
	}
	at, ok := nextAtOrAfter(s.Schedule, s.Starts)
	if !ok {
		// The schedule fires nothing at all after Starts, so the count
		// bounds nothing that the enumeration does not already.
		return s.Ends, !s.Ends.IsZero()
	}
	for i := 1; i <= s.Occurrences && i <= maxOccurrences; i++ {
		next, found := s.Schedule.Next(at)
		if !found {
			return s.Ends, !s.Ends.IsZero()
		}
		at = next
	}
	return at, true
}

// nextAtOrAfter is the first occurrence at or after t.
//
// Schedule.Next answers strictly after a whole minute, so stepping back
// a minute is what includes an occurrence landing exactly on t -- and
// the result has to be re-checked, because a t carrying seconds would
// otherwise pick up the occurrence on the minute before it.
func nextAtOrAfter(sched *Schedule, t time.Time) (time.Time, bool) {
	for at := t.Add(-time.Minute); ; {
		next, ok := sched.Next(at)
		if !ok {
			return time.Time{}, false
		}
		if !next.Before(t) {
			return next, true
		}
		at = next
	}
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
//
// Occurrences outside the recurrence -- before Starts, or at or after
// the end its Ends or Occurrences resolves to -- do not exist, so a
// reservation whose term is over produces nothing at all.
func (s *Spec) Windows(from time.Time, horizon, forgive time.Duration) []Window {
	if s.Schedule == nil || s.Duration <= 0 {
		return nil
	}
	deadline := from.Add(horizon)
	endsAt, bounded := s.recurrenceEnd()
	var out []Window
	at := from
	if !s.Starts.IsZero() && at.Before(s.Starts) {
		// Jump rather than walk. Next advances one occurrence at a
		// time, and a per-minute schedule whose term begins next
		// semester would otherwise cost a step for every minute
		// between now and then.
		at = s.Starts.Add(-time.Minute)
	}
	for {
		start, ok := s.Schedule.Next(at)
		if !ok || start.After(deadline) {
			return out
		}
		if bounded && !start.Before(endsAt) {
			return out
		}
		if start.Before(s.Starts) {
			// Only reachable for a Starts carrying seconds, which the
			// jump above lands a minute short of.
			at = start
			continue
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
