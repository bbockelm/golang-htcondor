package reservation

import (
	"testing"
	"time"
)

func mustSchedule(t *testing.T, expr string, loc *time.Location) *Schedule {
	t.Helper()
	s, err := ParseSchedule(expr, loc)
	if err != nil {
		t.Fatalf("ParseSchedule(%q): %v", expr, err)
	}
	return s
}

func TestScheduleNext(t *testing.T) {
	utc := time.UTC
	for _, tc := range []struct {
		expr string
		from time.Time
		want time.Time
	}{
		{"0 14 * * *", time.Date(2026, 3, 2, 9, 0, 0, 0, utc), time.Date(2026, 3, 2, 14, 0, 0, 0, utc)},
		// Strictly after: the same minute does not match itself.
		{"0 14 * * *", time.Date(2026, 3, 2, 14, 0, 0, 0, utc), time.Date(2026, 3, 3, 14, 0, 0, 0, utc)},
		{"*/15 9 * * *", time.Date(2026, 3, 2, 9, 1, 0, 0, utc), time.Date(2026, 3, 2, 9, 15, 0, 0, utc)},
		{"0 9-11 * * *", time.Date(2026, 3, 2, 9, 30, 0, 0, utc), time.Date(2026, 3, 2, 10, 0, 0, 0, utc)},
		// Monday and Wednesday: 2 March 2026 is a Monday.
		{"0 14 * * 1,3", time.Date(2026, 3, 2, 15, 0, 0, 0, utc), time.Date(2026, 3, 4, 14, 0, 0, 0, utc)},
		{"30 8 1 * *", time.Date(2026, 3, 2, 0, 0, 0, 0, utc), time.Date(2026, 4, 1, 8, 30, 0, 0, utc)},
	} {
		got, ok := mustSchedule(t, tc.expr, utc).Next(tc.from)
		if !ok {
			t.Errorf("%s from %v: no occurrence found", tc.expr, tc.from)
			continue
		}
		if !got.Equal(tc.want) {
			t.Errorf("%s from %v: got %v, want %v", tc.expr, tc.from, got, tc.want)
		}
	}
}

// TestScheduleDayOfMonthOrDayOfWeek pins cron's rule that two restricted day
// fields are ORed, not ANDed.
func TestScheduleDayOfMonthOrDayOfWeek(t *testing.T) {
	// The 1st of the month, or any Friday. 2026-03-02 is a Monday.
	s := mustSchedule(t, "0 0 1 * 5", time.UTC)
	got, ok := s.Next(time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC))
	if !ok {
		t.Fatal("no occurrence")
	}
	if want := time.Date(2026, 3, 6, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("got %v, want the Friday %v", got, want)
	}
	// With only the day of month restricted it is an AND with "every day".
	s = mustSchedule(t, "0 0 4 * *", time.UTC)
	got, _ = s.Next(time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC))
	if want := time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestScheduleKeepsWallClockAcrossDST is why occurrences are built with
// time.Date in a location: a class at 2pm stays at 2pm when the offset
// changes under it.
func TestScheduleKeepsWallClockAcrossDST(t *testing.T) {
	chi, err := time.LoadLocation("America/Chicago")
	if err != nil {
		t.Skipf("no tzdata: %v", err)
	}
	s := mustSchedule(t, "0 14 * * *", chi)
	// US DST ends on the first Sunday of November; 2026-11-01.
	at := time.Date(2026, 10, 30, 0, 0, 0, 0, chi)
	var offsets []int
	for i := 0; i < 4; i++ {
		got, ok := s.Next(at)
		if !ok {
			t.Fatalf("no occurrence after %v", at)
		}
		if got.Hour() != 14 || got.Minute() != 0 {
			t.Errorf("occurrence %v is not 14:00 wall clock", got)
		}
		_, off := got.Zone()
		offsets = append(offsets, off)
		at = got
	}
	if offsets[0] == offsets[len(offsets)-1] {
		t.Errorf("expected the UTC offset to change across the transition, got %v", offsets)
	}
}

func TestScheduleParseErrors(t *testing.T) {
	for _, expr := range []string{
		"", "0 14 * *", "0 14 * * * *",
		"60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 7",
		"5-1 * * * *", "*/0 * * * *", "a * * * *", "0 , * * *",
	} {
		if _, err := ParseSchedule(expr, time.UTC); err == nil {
			t.Errorf("ParseSchedule(%q) accepted an invalid expression", expr)
		}
	}
}

// TestScheduleHorizon makes sure an expression that never fires terminates.
func TestScheduleHorizon(t *testing.T) {
	s := mustSchedule(t, "0 0 30 2 *", time.UTC) // 30 February
	if _, ok := s.Next(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); ok {
		t.Error("found an occurrence of 30 February")
	}
}
