package reservation

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// The fixtures below are all in 2026, where 1 March is a Sunday: March
// has five Mondays and February has four, which is the pair the set
// position cases need.

func mustRecurrence(t *testing.T, in Recurrence, loc *time.Location) *Recurrence {
	t.Helper()
	rec, err := NewRecurrence(in, loc)
	if err != nil {
		t.Fatalf("NewRecurrence(%+v): %v", in, err)
	}
	return rec
}

// recurrenceSpec is a one-hour reservation timed by a recurrence.
func recurrenceSpec(t *testing.T, in Recurrence, loc *time.Location) *Spec {
	t.Helper()
	s := testSpec(t, "0 14 * * *")
	s.Kind, s.Schedule = KindRecurrence, nil
	s.Recurrence = mustRecurrence(t, in, loc)
	s.Standing = 0
	return s
}

// stamps renders window starts with their zone, so a test that is really
// about daylight saving fails with the offset visible.
func stamps(ws []Window) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.Start.Format("2006-01-02 15:04 MST"))
	}
	return out
}

func enumerate(s *Spec, from time.Time, days int) []string {
	return stamps(s.Windows(from, time.Duration(days)*24*time.Hour, recurForgive))
}

// TestRecurrenceWeeklyIntervalSkipsWholeWeeks is the request cron cannot
// express: a step on cron's day-of-week field steps weekday indices, not
// weeks. Every week is enumerated first, so the fortnightly case is not
// passing because the recurrence matched nothing.
func TestRecurrenceWeeklyIntervalSkipsWholeWeeks(t *testing.T) {
	from := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	s := recurrenceSpec(t, Recurrence{Freq: FreqWeekly, ByWeekday: []int{1}, TimeOfDay: "14:00"}, time.UTC)
	s.Starts = time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)

	every := enumerate(s, from, 28)
	wantEvery := []string{
		"2026-03-02 14:00 UTC", "2026-03-09 14:00 UTC",
		"2026-03-16 14:00 UTC", "2026-03-23 14:00 UTC",
	}
	if !reflect.DeepEqual(every, wantEvery) {
		t.Fatalf("every week gave %v, want %v", every, wantEvery)
	}

	s.Recurrence = mustRecurrence(t, Recurrence{
		Freq: FreqWeekly, Interval: 2, ByWeekday: []int{1}, TimeOfDay: "14:00",
	}, time.UTC)
	got := enumerate(s, from, 28)
	want := []string{"2026-03-02 14:00 UTC", "2026-03-16 14:00 UTC"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("every other week gave %v, want %v", got, want)
	}
}

// TestRecurrenceWeeklyIntervalAnchorsOnStarts: the week the start date
// falls in is the first week the interval admits, whether or not the
// start date is itself one of the chosen weekdays.
func TestRecurrenceWeeklyIntervalAnchorsOnStarts(t *testing.T) {
	from := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	s := recurrenceSpec(t, Recurrence{
		Freq: FreqWeekly, Interval: 2, ByWeekday: []int{1}, TimeOfDay: "14:00",
	}, time.UTC)
	// Wednesday. Its week -- the one beginning Sunday 1 March -- is the
	// anchor week, so that week's Monday is admitted by the interval and
	// excluded only because it is before the reservation starts.
	s.Starts = time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC)

	got := enumerate(s, from, 35)
	want := []string{"2026-03-16 14:00 UTC", "2026-03-30 14:00 UTC"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// Named explicitly because each is wrong for a different reason:
	// the 2nd is in the anchor week but before the start date, and the
	// 9th is a week the interval does not admit at all.
	for _, absent := range []string{"2026-03-02 14:00 UTC", "2026-03-09 14:00 UTC"} {
		for _, have := range got {
			if have == absent {
				t.Errorf("%s should not occur", absent)
			}
		}
	}
}

// TestRecurrenceMonthlyOnSelectedDays is the plain monthly form.
func TestRecurrenceMonthlyOnSelectedDays(t *testing.T) {
	s := recurrenceSpec(t, Recurrence{
		Freq: FreqMonthly, ByMonthday: []int{15, 1}, TimeOfDay: "09:00",
	}, time.UTC)
	// Given out of order on purpose: a form ticks boxes in whatever
	// order the operator clicks them, and occurrences happen in date
	// order.
	got := enumerate(s, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), 80)
	want := []string{
		"2026-01-01 09:00 UTC", "2026-01-15 09:00 UTC",
		"2026-02-01 09:00 UTC", "2026-02-15 09:00 UTC",
		"2026-03-01 09:00 UTC", "2026-03-15 09:00 UTC",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestRecurrenceMonthdayAMonthDoesNotHaveIsSkipped: the 31st means the
// 31st. Moving it to the 28th would hold capacity on a day nobody
// booked, and the month boundary is where that would go unnoticed.
func TestRecurrenceMonthdayAMonthDoesNotHaveIsSkipped(t *testing.T) {
	s := recurrenceSpec(t, Recurrence{
		Freq: FreqMonthly, ByMonthday: []int{31}, TimeOfDay: "08:00",
	}, time.UTC)
	got := enumerate(s, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), 160)
	want := []string{
		"2026-01-31 08:00 UTC", "2026-03-31 08:00 UTC", "2026-05-31 08:00 UTC",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v -- February and April have no 31st and April no 30th here", got, want)
	}
}

// TestRecurrenceMonthlyEveryMatchingWeekday is monthly with weekdays and
// no set position: every matching weekday in the month.
func TestRecurrenceMonthlyEveryMatchingWeekday(t *testing.T) {
	s := recurrenceSpec(t, Recurrence{
		Freq: FreqMonthly, Interval: 2, ByWeekday: []int{1}, TimeOfDay: "10:00",
	}, time.UTC)
	s.Starts = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	got := enumerate(s, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), 70)
	// March's five Mondays, then nothing in April -- the interval skips
	// it -- and May's from the 4th.
	want := []string{
		"2026-03-02 10:00 UTC", "2026-03-09 10:00 UTC", "2026-03-16 10:00 UTC",
		"2026-03-23 10:00 UTC", "2026-03-30 10:00 UTC",
		"2026-05-04 10:00 UTC",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestRecurrenceFifthWeekdayOnlyInMonthsThatHaveOne: most months have
// four Mondays. Taking the fourth when there is no fifth would open the
// reservation a week early, every time.
func TestRecurrenceFifthWeekdayOnlyInMonthsThatHaveOne(t *testing.T) {
	s := recurrenceSpec(t, Recurrence{
		Freq: FreqMonthly, BySetPos: 5, ByWeekday: []int{1}, TimeOfDay: "13:00",
	}, time.UTC)
	// A whole year, so the months with four Mondays are passed over
	// rather than merely absent from a short horizon.
	got := enumerate(s, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), 365)
	want := []string{
		"2026-03-30 13:00 UTC", "2026-06-29 13:00 UTC",
		"2026-08-31 13:00 UTC", "2026-11-30 13:00 UTC",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// The fourth Monday of February exists, so the fifth case above is
	// a real absence rather than the whole monthly form being broken.
	s.Recurrence = mustRecurrence(t, Recurrence{
		Freq: FreqMonthly, BySetPos: 4, ByWeekday: []int{1}, TimeOfDay: "13:00",
	}, time.UTC)
	feb := enumerate(s, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), 27)
	if want := []string{"2026-02-23 13:00 UTC"}; !reflect.DeepEqual(feb, want) {
		t.Errorf("fourth Monday of February: %v, want %v", feb, want)
	}
}

// TestRecurrenceLastAndNextToLastDay covers the negative positions,
// including February, whose last day is the one most likely to be got
// wrong.
func TestRecurrenceLastAndNextToLastDay(t *testing.T) {
	for _, tc := range []struct {
		name string
		pos  int
		from time.Time
		days int
		want []string
	}{
		{
			name: "last day of each month",
			pos:  -1,
			from: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			days: 120,
			want: []string{
				"2026-01-31 17:00 UTC", "2026-02-28 17:00 UTC",
				"2026-03-31 17:00 UTC", "2026-04-30 17:00 UTC",
			},
		},
		{
			name: "next to last day of each month",
			pos:  -2,
			from: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			days: 90,
			want: []string{
				"2026-01-30 17:00 UTC", "2026-02-27 17:00 UTC", "2026-03-30 17:00 UTC",
			},
		},
		{
			// 2028 is a leap year: the last day of February is the 29th,
			// which is the case a hard-coded 28 would get wrong.
			name: "last day of a leap February",
			pos:  -1,
			from: time.Date(2028, 2, 1, 0, 0, 0, 0, time.UTC),
			days: 29,
			want: []string{"2028-02-29 17:00 UTC"},
		},
	} {
		s := recurrenceSpec(t, Recurrence{
			Freq: FreqMonthly, BySetPos: tc.pos, DayKind: DayKindDay, TimeOfDay: "17:00",
		}, time.UTC)
		if got := enumerate(s, tc.from, tc.days); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestRecurrenceDayKinds: a set position can count days, weekdays or
// weekend days. August 2026 begins on a Saturday, so the three answers
// differ and a mistake cannot pass by coincidence.
func TestRecurrenceDayKinds(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind DayKind
		pos  int
		want string
	}{
		{"first day", DayKindDay, 1, "2026-08-01 11:00 UTC"},
		{"first weekday", DayKindWeekday, 1, "2026-08-03 11:00 UTC"},
		{"first weekend day", DayKindWeekend, 1, "2026-08-01 11:00 UTC"},
		{"last weekday", DayKindWeekday, -1, "2026-08-31 11:00 UTC"},
		{"last weekend day", DayKindWeekend, -1, "2026-08-30 11:00 UTC"},
	} {
		s := recurrenceSpec(t, Recurrence{
			Freq: FreqMonthly, BySetPos: tc.pos, DayKind: tc.kind, TimeOfDay: "11:00",
		}, time.UTC)
		got := enumerate(s, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), 31)
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("%s: got %v, want [%s]", tc.name, got, tc.want)
		}
	}
}

// TestRecurrenceDailyInterval: every third day, counted from the start
// date rather than from whenever the preview happens to begin.
func TestRecurrenceDailyInterval(t *testing.T) {
	s := recurrenceSpec(t, Recurrence{Freq: FreqDaily, Interval: 3, TimeOfDay: "07:30"}, time.UTC)
	s.Starts = time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)
	// Enumerated from part way through the series: the parity has to
	// come from the start date, not from the day the question is asked.
	got := enumerate(s, time.Date(2026, 3, 6, 0, 0, 0, 0, time.UTC), 10)
	want := []string{
		"2026-03-08 07:30 UTC", "2026-03-11 07:30 UTC", "2026-03-14 07:30 UTC",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestRecurrenceKeepsWallClockAcrossDST: 14:00 means 14:00. A fortnight
// across a spring-forward is 14 days on the calendar and 335 hours on
// the clock, and a recurrence that counted seconds would come out an
// hour early for the rest of the year.
func TestRecurrenceKeepsWallClockAcrossDST(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tzdata has no America/New_York: %v", err)
	}
	s := recurrenceSpec(t, Recurrence{
		Freq: FreqWeekly, Interval: 2, ByWeekday: []int{1}, TimeOfDay: "14:00",
	}, ny)
	s.Starts = time.Date(2026, 3, 2, 0, 0, 0, 0, ny)

	// The spring-forward is Sunday 8 March 2026, between the first two.
	windows := s.Windows(time.Date(2026, 3, 1, 0, 0, 0, 0, ny), 35*24*time.Hour, recurForgive)
	got := stamps(windows)
	want := []string{"2026-03-02 14:00 EST", "2026-03-16 14:00 EDT", "2026-03-30 14:00 EDT"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if gap := windows[1].Start.Sub(windows[0].Start); gap != 14*24*time.Hour-time.Hour {
		t.Errorf("across the transition the gap is %v, want %v: the wall clock was not held", gap, 14*24*time.Hour-time.Hour)
	}
	if gap := windows[2].Start.Sub(windows[1].Start); gap != 14*24*time.Hour {
		t.Errorf("clear of the transition the gap is %v, want 336h", gap)
	}
}

// TestRecurrenceSkippedWallClockTimeMovesForward pins what happens to a
// time the spring-forward deleted. 02:30 did not exist on 8 March 2026
// in New York; the occurrence happens at the next real instant on that
// date rather than being dropped, which is what the cron schedule does
// with the same expression. Dropping it would silently miss a day.
func TestRecurrenceSkippedWallClockTimeMovesForward(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tzdata has no America/New_York: %v", err)
	}
	s := recurrenceSpec(t, Recurrence{Freq: FreqDaily, TimeOfDay: "02:30"}, ny)
	got := enumerate(s, time.Date(2026, 3, 7, 0, 0, 0, 0, ny), 3)
	want := []string{
		"2026-03-07 02:30 EST", "2026-03-08 03:30 EDT", "2026-03-09 02:30 EDT",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestRecurrenceNormalises: what comes back out of the database has to
// be what the form meant, spelled one way.
func TestRecurrenceNormalises(t *testing.T) {
	rec := mustRecurrence(t, Recurrence{
		Freq: FreqWeekly, ByWeekday: []int{5, 1, 5, 3}, TimeOfDay: "9:5",
	}, time.UTC)
	if want := []int{1, 3, 5}; !reflect.DeepEqual(rec.ByWeekday, want) {
		t.Errorf("by_weekday normalised to %v, want %v", rec.ByWeekday, want)
	}
	if rec.TimeOfDay != "09:05" {
		t.Errorf("time_of_day normalised to %q, want \"09:05\"", rec.TimeOfDay)
	}
	if rec.Interval != 1 {
		t.Errorf("an omitted interval became %d, want 1", rec.Interval)
	}
	if got := rec.String(); got != "every week on Monday, Wednesday, Friday at 09:05" {
		t.Errorf("String() = %q", got)
	}
}

// TestRecurrenceValidate: every combination that is not offered is
// refused rather than interpreted. A recurrence nobody meant holds part
// of the pool on days nobody booked, and nothing downstream can tell
// that from one working as asked.
func TestRecurrenceValidate(t *testing.T) {
	ok := Recurrence{Freq: FreqWeekly, Interval: 2, ByWeekday: []int{1}, TimeOfDay: "14:00"}
	if _, err := NewRecurrence(ok, time.UTC); err != nil {
		t.Fatalf("a well-formed recurrence was rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		in   Recurrence
		want string
	}{
		{"no frequency", Recurrence{TimeOfDay: "14:00"}, "freq is required"},
		{"unknown frequency", Recurrence{Freq: "yearly", TimeOfDay: "14:00"}, "not one of daily"},
		{"negative interval", Recurrence{Freq: FreqDaily, Interval: -1, TimeOfDay: "14:00"}, "interval must be positive"},
		{"huge interval", Recurrence{Freq: FreqDaily, Interval: 500, TimeOfDay: "14:00"}, "interval cannot exceed"},
		{"no time of day", Recurrence{Freq: FreqDaily}, "time_of_day is required"},
		{"bad time of day", Recurrence{Freq: FreqDaily, TimeOfDay: "25:00"}, "between 00:00 and 23:59"},
		{"time of day without a colon", Recurrence{Freq: FreqDaily, TimeOfDay: "1400"}, "must be HH:MM"},
		{"weekday out of range", Recurrence{Freq: FreqWeekly, ByWeekday: []int{7}, TimeOfDay: "14:00"}, "between 0 (Sunday)"},
		{"monthday out of range", Recurrence{Freq: FreqMonthly, ByMonthday: []int{32}, TimeOfDay: "14:00"}, "between 1 and 31"},
		{"set position out of range", Recurrence{Freq: FreqMonthly, BySetPos: 6, ByWeekday: []int{1}, TimeOfDay: "14:00"}, "by_setpos 6 is not between"},
		{"unknown day kind", Recurrence{Freq: FreqMonthly, BySetPos: 1, DayKind: "holiday", TimeOfDay: "14:00"}, "not one of day, weekday"},
		{"daily with weekdays", Recurrence{Freq: FreqDaily, ByWeekday: []int{1}, TimeOfDay: "14:00"}, "daily recurrence takes no"},
		{"weekly without weekdays", Recurrence{Freq: FreqWeekly, TimeOfDay: "14:00"}, "needs by_weekday"},
		{"weekly with monthdays", Recurrence{Freq: FreqWeekly, ByWeekday: []int{1}, ByMonthday: []int{1}, TimeOfDay: "14:00"}, "weekly recurrence takes no"},
		{"monthly with nothing to go on", Recurrence{Freq: FreqMonthly, TimeOfDay: "14:00"}, "needs by_monthday"},
		{"monthly both ways at once", Recurrence{Freq: FreqMonthly, ByMonthday: []int{1}, ByWeekday: []int{1}, TimeOfDay: "14:00"}, "not both"},
		{"set position over two weekdays", Recurrence{Freq: FreqMonthly, BySetPos: 1, ByWeekday: []int{1, 3}, TimeOfDay: "14:00"}, "counts one weekday"},
		{"set position with both a weekday and a kind", Recurrence{Freq: FreqMonthly, BySetPos: 1, ByWeekday: []int{1}, DayKind: DayKindDay, TimeOfDay: "14:00"}, "not both"},
		{"set position and a monthday", Recurrence{Freq: FreqMonthly, BySetPos: 1, ByWeekday: []int{1}, ByMonthday: []int{4}, TimeOfDay: "14:00"}, "by_monthday cannot also"},
		{"day kind with no position", Recurrence{Freq: FreqMonthly, DayKind: DayKindWeekday, TimeOfDay: "14:00"}, "day_kind needs a by_setpos"},
	} {
		_, err := NewRecurrence(tc.in, time.UTC)
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not mention %q", tc.name, err, tc.want)
		}
	}
}

// TestSpecValidateNeedsAnAnchorForAnInterval: "every other week" has no
// meaning until somebody says which week. Anchoring on an arbitrary
// instant instead would pick the alternating weeks by accident, with no
// way to tell which set was chosen.
func TestSpecValidateNeedsAnAnchorForAnInterval(t *testing.T) {
	s := recurrenceSpec(t, Recurrence{Freq: FreqWeekly, ByWeekday: []int{1}, TimeOfDay: "14:00"}, time.UTC)
	if err := s.Validate(); err != nil {
		t.Fatalf("every week with no start date was rejected: %v", err)
	}
	s.Recurrence = mustRecurrence(t, Recurrence{
		Freq: FreqWeekly, Interval: 2, ByWeekday: []int{1}, TimeOfDay: "14:00",
	}, time.UTC)
	err := s.Validate()
	if err == nil {
		t.Fatalf("every other week with no start date was accepted")
	}
	if !strings.Contains(err.Error(), "needs a start date") {
		t.Errorf("error %q does not say what is missing", err)
	}
	s.Starts = time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)
	if err := s.Validate(); err != nil {
		t.Errorf("every other week from a start date was rejected: %v", err)
	}
}

// TestSpecValidateRequiresARecurrenceForTheKind: the kind is what
// decides, so a reservation claiming a recurrence it does not carry is
// a reservation that would silently never happen.
func TestSpecValidateRequiresARecurrenceForTheKind(t *testing.T) {
	s := recurrenceSpec(t, Recurrence{Freq: FreqDaily, TimeOfDay: "14:00"}, time.UTC)
	if err := s.Validate(); err != nil {
		t.Fatalf("a recurrence reservation was rejected: %v", err)
	}
	s.Recurrence = nil
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "recurrence is required") {
		t.Errorf("a recurrence kind with no recurrence gave %v", err)
	}
}

// TestRecurrenceBoundsApplyToTheStructuredForm: the start, end and
// count bounds are above the schedule, so they have to work the same
// whichever representation the reservation uses.
func TestRecurrenceBoundsApplyToTheStructuredForm(t *testing.T) {
	s := recurrenceSpec(t, Recurrence{Freq: FreqDaily, TimeOfDay: "14:00"}, time.UTC)
	from := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	if got := enumerate(s, from, 10); len(got) != 10 {
		t.Fatalf("unbounded gave %d windows over ten days, want 10: %v", len(got), got)
	}
	s.Starts = time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC)
	s.Occurrences = 3
	got := enumerate(s, from, 10)
	want := []string{"2026-03-03 14:00 UTC", "2026-03-04 14:00 UTC", "2026-03-05 14:00 UTC"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("three occurrences from 3 March gave %v, want %v", got, want)
	}
}

// TestRecurrenceWeekArithmeticEastOfUTC: a week is seven dates, counted
// on the calendar. Counting elapsed seconds instead comes out a day
// wrong in any zone whose local midnight falls on the previous UTC date,
// which is every zone east of Greenwich -- and the symptom is a
// fortnightly reservation landing on the wrong weekday.
func TestRecurrenceWeekArithmeticEastOfUTC(t *testing.T) {
	tokyo, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Skipf("tzdata has no Asia/Tokyo: %v", err)
	}
	s := recurrenceSpec(t, Recurrence{
		Freq: FreqWeekly, Interval: 2, ByWeekday: []int{1}, TimeOfDay: "09:00",
	}, tokyo)
	s.Starts = time.Date(2026, 3, 2, 0, 0, 0, 0, tokyo)
	got := enumerate(s, time.Date(2026, 3, 1, 0, 0, 0, 0, tokyo), 35)
	want := []string{"2026-03-02 09:00 JST", "2026-03-16 09:00 JST", "2026-03-30 09:00 JST"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	// A fortnight spanning the week boundary is the sharpest case: the
	// week begins on Sunday, so a Sunday and the Saturday six days
	// later are the same fortnight. A week counted from elapsed seconds
	// rather than from dates has its boundary a day out in this zone,
	// which would split the pair across two intervals and drop one.
	s.Recurrence = mustRecurrence(t, Recurrence{
		Freq: FreqWeekly, Interval: 2, ByWeekday: []int{0, 6}, TimeOfDay: "09:00",
	}, tokyo)
	s.Starts = time.Date(2026, 3, 1, 0, 0, 0, 0, tokyo)
	spanning := enumerate(s, time.Date(2026, 3, 1, 0, 0, 0, 0, tokyo), 35)
	wantSpanning := []string{
		"2026-03-01 09:00 JST", "2026-03-07 09:00 JST",
		"2026-03-15 09:00 JST", "2026-03-21 09:00 JST",
		"2026-03-29 09:00 JST", "2026-04-04 09:00 JST",
	}
	if !reflect.DeepEqual(spanning, wantSpanning) {
		t.Errorf("across the week boundary got %v, want %v", spanning, wantSpanning)
	}

	// Monthly intervals read the anchor's month the same way.
	s.Recurrence = mustRecurrence(t, Recurrence{
		Freq: FreqMonthly, BySetPos: 1, ByWeekday: []int{1}, TimeOfDay: "09:00",
	}, tokyo)
	s.Starts = time.Date(2026, 3, 2, 0, 0, 0, 0, tokyo)
	monthly := enumerate(s, time.Date(2026, 3, 1, 0, 0, 0, 0, tokyo), 70)
	wantMonthly := []string{"2026-03-02 09:00 JST", "2026-04-06 09:00 JST", "2026-05-04 09:00 JST"}
	if !reflect.DeepEqual(monthly, wantMonthly) {
		t.Errorf("monthly got %v, want %v", monthly, wantMonthly)
	}
}
