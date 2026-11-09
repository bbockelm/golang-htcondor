package reservation

import (
	"errors"
	"fmt"
	"time"
)

// Spec is a standing reservation: a recurring window during which a project
// is guaranteed capacity, and a smaller amount kept available between
// windows so the project's users are not left waiting in the general queue.
type Spec struct {
	// ID identifies the reservation. It never appears in a machine
	// attribute name: the startd cannot forget an attribute, so naming
	// attributes after reservations would accumulate dead keys on every
	// execute point until it restarts.
	ID string
	// Owner is the person the capacity is held for, as distinct from the
	// people whose jobs use it.
	//
	// Separate from Project because they answer different questions.
	// Project is what a job carries to use the reservation; Owner is who
	// the reservation belongs to. HTCondor's own persistent claims hang
	// off a user record and are matched against both, so a claim held
	// for an owner serves that owner's jobs and any job of the owner's
	// project.
	Owner string
	// Project is the ProjectName a job must carry to use the
	// reservation.
	Project string
	// Submit is the submit file describing one instance the reservation
	// holds. It is rendered to a job ad to work out which machines can
	// host one.
	Submit string
	// Seats is how much capacity the window holds, and the cap on how
	// much the project may occupy at once.
	Seats int
	// Standing is how much unused capacity to keep available on top of
	// whatever the project is using, up to Seats. Zero keeps none.
	//
	// It is headroom, not a floor: a project with five instances
	// running and a Standing of two should have two more held and idle,
	// so the sixth user to arrive finds capacity waiting instead of
	// waiting for the next controller tick and a drain after it.
	Standing int
	// Duration is how long one window lasts.
	Duration time.Duration
	// Lead is how far ahead of a window the controller starts holding
	// cores back. Six hours is where the measured benefit saturates; at
	// one hour it is materially worse.
	Lead time.Duration
	// Hold is how long capacity stays reserved for the project after the
	// window opens, before unclaimed instances return to the pool.
	Hold time.Duration
	// Kind says which of Schedule and Recurrence is authoritative, and
	// whether the reservation has a timing at all.
	//
	// The empty string means KindCron, because every reservation stored
	// before the recurrence existed is one and a row that does not say
	// has to keep meaning what it already meant.
	Kind ScheduleKind
	// Schedule says when windows start, as a cron expression. It is
	// authoritative for KindCron.
	Schedule *Schedule
	// Recurrence says when windows start, structurally. It is
	// authoritative for KindRecurrence.
	//
	// The two are peers rather than layers: neither is derived from the
	// other, because a recurrence saying "every other Tuesday" has no
	// cron spelling and a converter would have to round it to one that
	// runs on different days from the one the admin typed.
	Recurrence *Recurrence
	// Zone is where the reservation's dates are read when it carries no
	// schedule of its own, which is only the always-on case. A
	// reservation with a schedule takes the zone from it, so there is
	// still exactly one answer at any moment.
	Zone *time.Location
	// Starts is the first instant an occurrence may begin, and what an
	// interval above one counts from. The zero time means the
	// recurrence has always been running.
	Starts time.Time
	// Ends is the instant past which no occurrence may begin. The zero
	// time means the recurrence never stops.
	//
	// An occurrence beginning before Ends runs its full Duration: a
	// window that opened in time is not cut short because the
	// recurrence ended part way through it.
	Ends time.Time
	// Occurrences is how many times the recurrence runs, counted from
	// Starts. Zero means without limit.
	//
	// It counts scheduled starts rather than windows, because two
	// occurrences close enough together are merged into one hold and
	// "fifteen sessions" must still mean fifteen sessions.
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

// ScheduleKind is Kind with the zero value resolved, which is the only
// form anything should decide on. The default lives here and nowhere
// else: a second copy of it is a second thing to forget to update.
func (s *Spec) ScheduleKind() ScheduleKind {
	if s.Kind == "" {
		return KindCron
	}
	return s.Kind
}

// Location is where the reservation's wall clock times and dates are
// read, whichever representation it carries.
//
// An always-on reservation has no wall clock times, but it can still
// have a start and an end date, and those should read as the days the
// admin typed rather than as the server's local days -- so the zone it
// was given is kept in Zone and answered here.
func (s *Spec) Location() *time.Location {
	switch s.ScheduleKind() {
	case KindRecurrence:
		if s.Recurrence != nil {
			return s.Recurrence.Location()
		}
	case KindCron:
		if s.Schedule != nil && s.Schedule.Location() != nil {
			return s.Schedule.Location()
		}
	}
	if s.Zone != nil {
		return s.Zone
	}
	return time.Local
}

// alwaysOn reports whether the reservation holds capacity continuously
// rather than in windows.
func (s *Spec) alwaysOn() bool { return s.ScheduleKind() == KindAlways }

// nexter is all the enumeration needs of a timing: the first occurrence
// strictly after t, and whether there was one.
//
// Both representations answer it, which is what keeps everything above
// this line -- windows, phases, engagement, the admin preview -- from
// having to know which kind of schedule a reservation carries.
type nexter interface {
	Next(t time.Time) (time.Time, bool)
}

// timing is the spec's authoritative schedule, and whether it has one at
// all.
//
// An always-on reservation has none. It is not a recurrence with very
// long windows; it is the absence of windows, which is why the
// enumeration below produces nothing for it rather than something
// enormous.
func (s *Spec) timing() (nexter, bool) {
	switch s.ScheduleKind() {
	case KindAlways:
		return nil, false
	case KindRecurrence:
		if s.Recurrence == nil {
			return nil, false
		}
		return anchoredRecurrence{rec: s.Recurrence, anchor: s.Starts}, true
	default:
		if s.Schedule == nil {
			return nil, false
		}
		return s.Schedule, true
	}
}

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
		add("Project is required: a job must be in this project to use the reservation")
	}
	if s.Submit == "" {
		add("Submit is required: it describes one instance of the capacity being held")
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
	// Duration, Lead and Hold describe a window. An always-on
	// reservation has none, so requiring them would make an admin fill
	// in three boxes that change nothing.
	if !s.alwaysOn() {
		if s.Duration <= 0 {
			add("Duration must be positive")
		}
		if s.Lead <= 0 {
			add("Lead must be positive")
		}
		if s.Hold < 0 || s.Hold > s.Duration {
			add("Hold must be between zero and Duration")
		}
	}
	if err := s.ValidateTiming(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ValidateTiming reports whether the spec's schedule and its bounds can
// be enumerated, ignoring everything else about the reservation.
//
// It is split out for the draft preview: an admin part way through a new
// reservation wants to see which days it lands on before they have
// written the submit file, and refusing to show them because the
// submit file is empty would make the preview useless exactly when it
// is most wanted.
func (s *Spec) ValidateTiming() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	switch s.ScheduleKind() {
	case KindAlways:
		// Nothing to check: an always-on reservation is timed by being
		// enabled.
	case KindRecurrence:
		if s.Recurrence == nil {
			add("a recurrence is required when schedule_kind is %q", KindRecurrence)
		} else {
			if err := s.Recurrence.Validate(); err != nil {
				errs = append(errs, err)
			}
			if s.Recurrence.Interval > 1 && s.Starts.IsZero() {
				// "Every other week" has no meaning until somebody says
				// which week. Anchoring on an arbitrary instant instead
				// -- the epoch, or whenever the row was written -- would
				// pick the alternating weeks by accident and give no way
				// to tell which set was chosen.
				add("an interval above one needs a start date: %q has to be counted from somewhere", s.Recurrence.String())
			}
		}
	default:
		if s.Schedule == nil {
			add("Schedule is required")
		}
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
	if s.Occurrences > 0 && s.alwaysOn() {
		// An always-on reservation has no occurrences to count. Taking
		// the number as a hint and ending the reservation somewhere
		// would stop it on a date nobody chose.
		add("an always-on reservation has no occurrences to count: give an end date instead")
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
	sched, ok := s.timing()
	if s.Occurrences <= 0 || !ok || s.Starts.IsZero() {
		return s.Ends, !s.Ends.IsZero()
	}
	at, found := nextAtOrAfter(sched, s.Starts)
	if !found {
		// The schedule fires nothing at all after Starts, so the count
		// bounds nothing that the enumeration does not already.
		return s.Ends, !s.Ends.IsZero()
	}
	for i := 1; i <= s.Occurrences && i <= maxOccurrences; i++ {
		next, ok := sched.Next(at)
		if !ok {
			return s.Ends, !s.Ends.IsZero()
		}
		at = next
	}
	return at, true
}

// nextAtOrAfter is the first occurrence at or after t.
//
// Next answers strictly after a whole minute, so stepping back a minute
// is what includes an occurrence landing exactly on t -- and the result
// has to be re-checked, because a t carrying seconds would otherwise
// pick up the occurrence on the minute before it.
func nextAtOrAfter(sched nexter, t time.Time) (time.Time, bool) {
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

// Window is a contiguous period during which a spec holds its capacity.
//
// Consecutive occurrences close enough together are one window, because
// releasing cores between them and draining again costs more than holding:
// a gap shorter than the forgiveness threshold is free either way, since
// anything started in it is still cheap to evict when the next window
// opens.
type Window struct {
	SpecID string
	Start  time.Time
	End    time.Time
	// Occurrences is how many scheduled starts this window covers.
	Occurrences int
}

// Bell is when the window opens and the capacity must be free.
func (w Window) Bell() time.Time { return w.Start }

// Windows lists the spec's windows beginning within horizon of from,
// merging occurrences separated by forgive or less.
//
// Occurrences outside the recurrence -- before Starts, or at or after
// the end its Ends or Occurrences resolves to -- do not exist, so a
// reservation whose recurrence is over produces nothing at all. So does
// an always-on reservation, which holds its capacity continuously and
// therefore has no windows to list.
func (s *Spec) Windows(from time.Time, horizon, forgive time.Duration) []Window {
	sched, ok := s.timing()
	if !ok || s.Duration <= 0 {
		return nil
	}
	deadline := from.Add(horizon)
	endsAt, bounded := s.recurrenceEnd()
	var out []Window
	at := from
	if !s.Starts.IsZero() && at.Before(s.Starts) {
		// Jump rather than walk. Next advances one occurrence at a
		// time, and a per-minute schedule that does not begin for
		// months would otherwise cost a step for every minute between
		// now and then.
		at = s.Starts.Add(-time.Minute)
	}
	for {
		start, ok := sched.Next(at)
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
	// standing capacity applies.
	PhaseOff Phase = iota
	// PhasePlanning is inside the lead: hold cores back so the capacity
	// is cheap to free by the time the window opens.
	PhasePlanning
	// PhaseHolding is just after the window opens, while unclaimed
	// capacity is still reserved for the project.
	PhaseHolding
	// PhaseOpen is the rest of the window: the project keeps what it
	// claimed, and anything it frees goes back to the project rather
	// than the pool.
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

// Target is how much capacity to secure now, given how much of it the
// project is already using.
//
// Inside a window the whole reservation is held, so what is left to
// secure is Seats less what the project is already running.
//
// Outside one, Standing is headroom on top of that: the point of
// standing capacity is that somebody arriving between windows finds an
// instance already held and idle rather than waiting for the next
// controller tick and a drain after it. So a project running five
// instances with a Standing of two still wants two -- the five it is
// using are not spare. The total is capped at Seats, which is why the
// headroom shrinks as the project approaches its cap and reaches zero
// at it: past Seats the reservation is full, and holding more would
// promise capacity the project may not occupy.
func (s *Spec) Target(phase Phase, running int) int {
	if !s.Enabled {
		return 0
	}
	room := s.Seats - running
	if room <= 0 {
		return 0
	}
	if phase == PhaseOff {
		return min(s.Standing, room)
	}
	return room
}

// standingApplies reports whether the spec's standing headroom is wanted
// at now: the reservation has begun and its recurrence is not over.
//
// An always-on reservation is this with no window ever opening, so it
// needs no case of its own here.
func (s *Spec) standingApplies(now time.Time) bool {
	if !s.Enabled || s.Standing <= 0 {
		return false
	}
	if !s.Starts.IsZero() && now.Before(s.Starts) {
		return false
	}
	if end, bounded := s.recurrenceEnd(); bounded && !now.Before(end) {
		return false
	}
	return true
}
