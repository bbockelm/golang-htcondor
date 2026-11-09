package reservation

import (
	"strings"
	"testing"
	"time"
)

// A term's worth of fixtures: a daily 14:00 class in UTC, enumerated
// from the start of 2 March 2026 (a Monday).
func recurSpec(t *testing.T, expr string) *Spec {
	t.Helper()
	s := testSpec(t, expr)
	s.Standing = 0
	return s
}

var (
	recurFrom    = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	recurForgive = 30 * time.Minute
)

func starts(got []Window) []time.Time {
	out := make([]time.Time, 0, len(got))
	for _, w := range got {
		out = append(out, w.Start)
	}
	return out
}

// TestWindowsRespectTheStartBound: a reservation booked for next term
// holds nothing this term. The unbounded case is checked first, so the
// bounded one is not passing because the schedule was empty anyway.
func TestWindowsRespectTheStartBound(t *testing.T) {
	s := recurSpec(t, "0 14 * * *")
	horizon := 10 * 24 * time.Hour

	unbounded := s.Windows(recurFrom, horizon, recurForgive)
	if len(unbounded) != 10 {
		t.Fatalf("unbounded gave %d windows over ten days, want 10: %v", len(unbounded), starts(unbounded))
	}
	if want := time.Date(2026, 3, 1, 14, 0, 0, 0, time.UTC); !unbounded[0].Start.Equal(want) {
		t.Fatalf("unbounded starts at %v, want %v", unbounded[0].Start, want)
	}

	s.Starts = time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC)
	got := s.Windows(recurFrom, horizon, recurForgive)
	if len(got) != 6 {
		t.Fatalf("from 5 March gave %d windows, want 6: %v", len(got), starts(got))
	}
	for _, w := range got {
		if w.Start.Before(s.Starts) {
			t.Errorf("window at %v starts before the recurrence does", w.Start)
		}
	}

	// A Starts carrying seconds still excludes the occurrence on the
	// minute it falls in: the class had not begun yet.
	s.Starts = time.Date(2026, 3, 5, 14, 0, 30, 0, time.UTC)
	got = s.Windows(recurFrom, horizon, recurForgive)
	if len(got) != 5 {
		t.Fatalf("from 5 March 14:00:30 gave %d windows, want 5: %v", len(got), starts(got))
	}
	if want := time.Date(2026, 3, 6, 14, 0, 0, 0, time.UTC); !got[0].Start.Equal(want) {
		t.Errorf("first window is %v, want %v", got[0].Start, want)
	}
}

// TestWindowsRespectTheEndBound: a term that is over holds nothing,
// which is the difference between a finished class quietly keeping part
// of the pool and not.
func TestWindowsRespectTheEndBound(t *testing.T) {
	s := recurSpec(t, "0 14 * * *")
	horizon := 10 * 24 * time.Hour

	if got := s.Windows(recurFrom, horizon, recurForgive); len(got) != 10 {
		t.Fatalf("unbounded gave %d windows, want 10", len(got))
	}

	s.Ends = time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC)
	got := s.Windows(recurFrom, horizon, recurForgive)
	if len(got) != 3 {
		t.Fatalf("ending 4 March gave %d windows, want 3: %v", len(got), starts(got))
	}

	// An occurrence that begins before the end runs its full duration.
	// A class is not cut short because the term ended between its bell
	// and its last minute.
	s.Ends = time.Date(2026, 3, 1, 14, 30, 0, 0, time.UTC)
	got = s.Windows(recurFrom, horizon, recurForgive)
	if len(got) != 1 {
		t.Fatalf("ending mid-class gave %d windows, want 1: %v", len(got), starts(got))
	}
	if want := time.Date(2026, 3, 1, 15, 0, 0, 0, time.UTC); !got[0].End.Equal(want) {
		t.Errorf("the last window ends %v, want its full hour at %v", got[0].End, want)
	}

	// Past the end there is nothing left at all.
	after := time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)
	if got := s.Windows(after, horizon, recurForgive); len(got) != 0 {
		t.Errorf("a finished recurrence still produced %d windows: %v", len(got), starts(got))
	}
}

// TestWindowsRespectAnOccurrenceCount is the "after N times" form of the
// same bound.
func TestWindowsRespectAnOccurrenceCount(t *testing.T) {
	s := recurSpec(t, "0 14 * * *")
	horizon := 10 * 24 * time.Hour
	s.Starts = time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)

	if got := s.Windows(recurFrom, horizon, recurForgive); len(got) != 9 {
		t.Fatalf("with no count gave %d windows, want 9", len(got))
	}

	s.Occurrences = 3
	got := s.Windows(recurFrom, horizon, recurForgive)
	if len(got) != 3 {
		t.Fatalf("three occurrences gave %d windows: %v", len(got), starts(got))
	}
	if want := time.Date(2026, 3, 4, 14, 0, 0, 0, time.UTC); !got[2].Start.Equal(want) {
		t.Errorf("the third occurrence is %v, want %v", got[2].Start, want)
	}

	// The count runs from Starts, not from the moment somebody asks:
	// enumerating on the second day leaves the two that are left, not
	// three more.
	later := time.Date(2026, 3, 3, 12, 0, 0, 0, time.UTC)
	if got := s.Windows(later, horizon, recurForgive); len(got) != 2 {
		t.Errorf("asked on the second day, %d windows are left, want 2: %v", len(got), starts(got))
	}
}

// TestOccurrenceCountIsScheduledStartsNotWindows: two classes back to
// back are one hold, so counting windows would make "three lectures"
// mean six. The count has to follow the bell.
func TestOccurrenceCountIsScheduledStartsNotWindows(t *testing.T) {
	s := recurSpec(t, "0 14,15 * * *")
	horizon := 10 * 24 * time.Hour
	s.Starts = time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)

	unbounded := s.Windows(recurFrom, horizon, recurForgive)
	if len(unbounded) != 9 || unbounded[0].Occurrences != 2 {
		t.Fatalf("unbounded gave %d windows, first covering %d occurrences; want 9 and 2",
			len(unbounded), unbounded[0].Occurrences)
	}

	s.Occurrences = 3
	got := s.Windows(recurFrom, horizon, recurForgive)
	if len(got) != 2 {
		t.Fatalf("three occurrences gave %d windows, want 2 (14:00+15:00 merged, then 14:00): %v",
			len(got), starts(got))
	}
	total := 0
	for _, w := range got {
		total += w.Occurrences
	}
	if total != 3 {
		t.Errorf("the windows cover %d occurrences, want 3", total)
	}
	if got[0].Occurrences != 2 || got[1].Occurrences != 1 {
		t.Errorf("occurrences split %d/%d, want 2/1", got[0].Occurrences, got[1].Occurrences)
	}
}

// TestValidateRecurrenceBounds: the admin sees the reason in the form,
// so every rejection has to say what is wrong with it.
func TestValidateRecurrenceBounds(t *testing.T) {
	sep := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	dec := time.Date(2026, 12, 18, 0, 0, 0, 0, time.UTC)

	for _, ok := range []struct {
		name string
		mut  func(*Spec)
	}{
		{"unbounded", func(*Spec) {}},
		{"a start alone", func(s *Spec) { s.Starts = sep }},
		{"an end alone", func(s *Spec) { s.Ends = dec }},
		{"a term", func(s *Spec) { s.Starts, s.Ends = sep, dec }},
		{"a count from a start", func(s *Spec) { s.Starts, s.Occurrences = sep, 15 }},
	} {
		s := recurSpec(t, "0 14 * * 1")
		ok.mut(s)
		if err := s.Validate(); err != nil {
			t.Errorf("%s was rejected: %v", ok.name, err)
		}
	}

	for _, tc := range []struct {
		name string
		mut  func(*Spec)
		want string
	}{
		{"both an end and a count", func(s *Spec) { s.Starts, s.Ends, s.Occurrences = sep, dec, 15 }, "not both"},
		{"a count with no start", func(s *Spec) { s.Occurrences = 15 }, "needs a start date"},
		{"a negative count", func(s *Spec) { s.Starts, s.Occurrences = sep, -1 }, "cannot be negative"},
		{"a count past the cap", func(s *Spec) { s.Starts, s.Occurrences = sep, maxOccurrences+1 }, "cannot exceed"},
		{"a start after the end", func(s *Spec) { s.Starts, s.Ends = dec, sep }, "is after Ends"},
	} {
		s := recurSpec(t, "0 14 * * 1")
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

// TestEngagedStopsWhenTheRecurrenceEnds is the one that matters most: a
// class that finished must not keep the subsystem awake, standing seats
// included. Nobody is left watching a reservation whose term is over.
func TestEngagedStopsWhenTheRecurrenceEnds(t *testing.T) {
	// Monday 9 March 08:00, the planning lead of that day's 14:00 class.
	lead := time.Date(2026, 3, 9, 8, 0, 0, 0, time.UTC)
	end := time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name     string
		standing int
	}{
		{"with no standing seats", 0},
		{"with standing seats", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := engageSpec(t)
			spec.Standing = tc.standing
			if !Engaged([]*Spec{spec}, lead, engageForgive, SettleAfter) {
				t.Fatal("not engaged while unbounded; the case below would prove nothing")
			}
			spec.Ends = end
			if Engaged([]*Spec{spec}, lead, engageForgive, SettleAfter) {
				t.Fatal("a reservation whose term is over engaged the subsystem")
			}
		})
	}

	// The last occurrence may begin a moment before the end and still
	// runs its full hour, and releasing what it held is a tick like
	// any other -- so the end of the recurrence is not the end of the
	// work. This one ends at 14:30, mid-class.
	spec := engageSpec(t)
	spec.Ends = time.Date(2026, 3, 2, 14, 30, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		at   time.Time
		want bool
	}{
		{"the last lead", time.Date(2026, 3, 2, 8, 0, 0, 0, time.UTC), true},
		{"the recurrence ends mid-class", spec.Ends, true},
		{"the class runs its full hour", time.Date(2026, 3, 2, 14, 59, 0, 0, time.UTC), true},
		{"settling after the last window", time.Date(2026, 3, 2, 15, 10, 0, 0, time.UTC), true},
		{"settled", time.Date(2026, 3, 2, 16, 0, 0, 0, time.UTC), false},
	} {
		if got := Engaged([]*Spec{spec}, tc.at, engageForgive, SettleAfter); got != tc.want {
			t.Errorf("%s: Engaged at %s = %v, want %v", tc.name, tc.at.Format(time.Kitchen), got, tc.want)
		}
	}
}

// TestEngagedWaitsForTheRecurrenceToStart: a reservation booked for next
// term wakes the subsystem for its planning lead and not before, and its
// standing seats are not held through a term it is not part of.
func TestEngagedWaitsForTheRecurrenceToStart(t *testing.T) {
	spec := engageSpec(t)
	spec.Standing = 4
	// A Monday lead a week before the term opens.
	early := time.Date(2026, 3, 2, 8, 0, 0, 0, time.UTC)
	if !Engaged([]*Spec{spec}, early, engageForgive, SettleAfter) {
		t.Fatal("not engaged while unbounded; the case below would prove nothing")
	}

	spec.Starts = time.Date(2026, 3, 9, 0, 0, 0, 0, time.UTC)
	if Engaged([]*Spec{spec}, early, engageForgive, SettleAfter) {
		t.Error("engaged a week before the recurrence starts")
	}
	// The lead of the first occurrence does engage it.
	if !Engaged([]*Spec{spec}, spec.Starts.Add(8*time.Hour), engageForgive, SettleAfter) {
		t.Error("not engaged during the first occurrence's planning lead")
	}
	// Once the term is running, the standing seats apply between
	// classes as they always did.
	midweek := time.Date(2026, 3, 11, 3, 0, 0, 0, time.UTC)
	if !Engaged([]*Spec{spec}, midweek, engageForgive, SettleAfter) {
		t.Error("standing seats are not engaged inside the term")
	}
}

// TestRecurrenceEndFromACount: a count resolves to the start of the
// occurrence after the last one allowed, which is what lets the same
// comparison serve both forms of bound.
func TestRecurrenceEndFromACount(t *testing.T) {
	s := recurSpec(t, "0 14 * * *")
	if _, ok := s.recurrenceEnd(); ok {
		t.Fatal("an unbounded recurrence reported an end")
	}
	s.Starts = time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)
	s.Occurrences = 3
	got, ok := s.recurrenceEnd()
	if !ok {
		t.Fatal("a counted recurrence reported no end")
	}
	if want := time.Date(2026, 3, 5, 14, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("three daily occurrences from 2 March end at %v, want %v", got, want)
	}

	// A count whose schedule runs out inside the search horizon --
	// 29 February, in a year that has none -- bounds nothing beyond
	// what the enumeration already does.
	s = recurSpec(t, "0 14 29 2 *")
	s.Starts = time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)
	s.Occurrences = 3
	if _, ok := s.recurrenceEnd(); ok {
		t.Error("a schedule that never fires again reported an end instant")
	}
}
