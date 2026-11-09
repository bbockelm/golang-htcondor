package reservation

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ScheduleKind says which of a reservation's timings is authoritative.
//
// A reservation carries both a cron expression and a structured
// recurrence because the two cannot express the same things and the
// older one is already in the table. Rather than guess from which field
// is populated -- a guess that breaks the moment somebody edits a
// reservation from cron to a recurrence and leaves the old text behind
// -- the kind is recorded and nothing but the kind decides.
type ScheduleKind string

const (
	// KindCron reads the five-field cron expression in Schedule. It is
	// the zero value because every reservation written before the
	// recurrence existed is one, and a missing kind has to keep meaning
	// what the row already meant.
	KindCron ScheduleKind = "cron"
	// KindRecurrence reads the structured Recurrence.
	KindRecurrence ScheduleKind = "recurrence"
	// KindAlways has no timing at all: the reservation holds its
	// capacity continuously for as long as it is enabled.
	KindAlways ScheduleKind = "always"
)

// Freq is how often a recurrence repeats before Interval is applied.
type Freq string

// The three frequencies an admin asks for. There is no yearly form: a
// reservation held once a year is better booked for the year it is
// wanted in than left standing, and a monthly interval of twelve says
// the same thing for the cases that really do repeat.
const (
	FreqDaily   Freq = "daily"
	FreqWeekly  Freq = "weekly"
	FreqMonthly Freq = "monthly"
)

// DayKind is a category of days a monthly set position may count, for the
// positions that are not about a single weekday -- "the first weekday
// of the month", "the last day of the month".
type DayKind string

const (
	// DayKindNone leaves the set position counting the weekday in
	// ByWeekday instead.
	DayKindNone DayKind = ""
	// DayKindDay counts every day of the month.
	DayKindDay DayKind = "day"
	// DayKindWeekday counts Monday through Friday.
	DayKindWeekday DayKind = "weekday"
	// DayKindWeekend counts Saturday and Sunday.
	DayKindWeekend DayKind = "weekend"
)

// maxInterval bounds the "every N" an admin may ask for.
//
// The search for the next occurrence steps one period at a time, so a
// large interval is a long walk on every tick; and an interval past
// this is better said as a different frequency -- every 60 days is two
// months, which the monthly form says exactly.
const maxInterval = 52

// maxRecurrenceSteps bounds how many periods the search for the next
// occurrence will step through before giving up.
//
// Some periods hold no occurrence at all: there is no 31st of February
// and no fifth Monday in most months, so the search has to be able to
// skip a period rather than conclude the recurrence is over. The bound
// is generous because a step is a handful of arithmetic, and small
// enough that a recurrence matching nothing terminates.
const maxRecurrenceSteps = 120

// Recurrence is when a reservation's windows begin, in the subset of
// RFC 5545's RRULE that an admin actually asks for.
//
// A five-field cron expression cannot say "every other Tuesday" or "the
// last Friday of the month": its day-of-week field is a set of weekday
// indices, so a step of two on it means every other weekday index
// rather than every other week, and it has no notion of counting
// weekdays within a month. Those are the two requests this type exists
// to answer, which is why it is a model change and not a parser change.
//
// The zero value is not usable. NewRecurrence validates and normalises
// one, and binds it to the location its wall clock times are read in.
type Recurrence struct {
	// Freq is the unit Interval counts in.
	Freq Freq `json:"freq"`
	// Interval is the "every N": every N days, weeks or months. One is
	// every period. Above one the recurrence needs an anchor to count
	// from, which is the reservation's Starts.
	Interval int `json:"interval"`
	// ByWeekday is the weekdays an occurrence may fall on, 0 for Sunday
	// through 6 for Saturday, matching time.Weekday.
	//
	// Weekly requires it. Monthly uses it either as the weekday a set
	// position counts -- "the last Friday" -- or, with no set position,
	// as the weekdays within the month that match.
	ByWeekday []int `json:"by_weekday,omitempty"`
	// ByMonthday is the days of the month an occurrence may fall on,
	// 1 through 31.
	//
	// A day the month does not have is skipped rather than clamped: the
	// 31st means the 31st, and a reservation that quietly moved to the
	// 28th of February would hold capacity on a day nobody booked.
	ByMonthday []int `json:"by_monthday,omitempty"`
	// BySetPos selects one day out of the month's matching days:
	// 1 through 5 for the first through fifth, -1 for the last, -2 for
	// the next to last. Zero is unused.
	//
	// A position the month does not reach produces no occurrence that
	// month. There is no fifth Monday in most months, and inventing one
	// on the fourth would hold capacity a week early.
	BySetPos int `json:"by_setpos,omitempty"`
	// DayKind is what BySetPos counts when it is not counting a single
	// weekday: every day, every weekday, or every weekend day.
	DayKind DayKind `json:"day_kind,omitempty"`
	// TimeOfDay is the wall clock time an occurrence begins, "HH:MM" on
	// a 24-hour clock.
	//
	// Wall clock rather than an offset from midnight, because that is
	// what makes a daily reservation stay at 14:00 across a daylight
	// saving change instead of drifting to 13:00 or 15:00.
	TimeOfDay string `json:"time_of_day"`

	// loc is where TimeOfDay is read. It is not part of the JSON: the
	// reservation already carries one zone, shared with the cron form,
	// and two places to say it is one place to disagree.
	loc *time.Location
	// hour and minute are TimeOfDay parsed, so enumerating a few
	// hundred occurrences does not re-parse it a few hundred times.
	hour, minute int
}

// NewRecurrence validates and normalises a recurrence and binds it to
// loc, which may be nil for time.Local.
//
// The value is copied rather than taken by pointer: the caller usually
// decoded it straight from a request body, and normalising their copy
// in place would leave the request and the stored reservation
// disagreeing about what was asked for.
func NewRecurrence(in Recurrence, loc *time.Location) (*Recurrence, error) {
	if loc == nil {
		loc = time.Local
	}
	r := in
	r.loc = loc
	if r.Interval == 0 {
		// An omitted interval is every period. Zero is what a JSON body
		// that left the field out decodes to, and "every period" is
		// what the form's default means.
		r.Interval = 1
	}
	r.ByWeekday = normaliseInts(r.ByWeekday)
	r.ByMonthday = normaliseInts(r.ByMonthday)
	if err := r.Validate(); err != nil {
		return nil, err
	}
	h, m, err := parseTimeOfDay(r.TimeOfDay)
	if err != nil {
		return nil, err
	}
	r.hour, r.minute = h, m
	// Store the time back in its canonical spelling so "9:5" does not
	// come back out of the database looking different from what every
	// other reservation holds.
	r.TimeOfDay = fmt.Sprintf("%02d:%02d", h, m)
	return &r, nil
}

// normaliseInts sorts and de-duplicates a by-list. The order a form
// ticks boxes in is not the order occurrences happen in, and the search
// walks the list expecting ascending days.
func normaliseInts(in []int) []int {
	if len(in) == 0 {
		return nil
	}
	seen := map[int]bool{}
	out := make([]int, 0, len(in))
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

// parseTimeOfDay reads "HH:MM" on a 24-hour clock.
func parseTimeOfDay(raw string) (int, int, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return 0, 0, errors.New("time_of_day is required: a recurrence with no time of day would book midnight without anybody asking for it")
	}
	hh, mm, ok := strings.Cut(text, ":")
	if !ok {
		return 0, 0, fmt.Errorf("time_of_day %s must be HH:MM on a 24-hour clock", strconv.Quote(raw))
	}
	h, herr := strconv.Atoi(strings.TrimSpace(hh))
	m, merr := strconv.Atoi(strings.TrimSpace(mm))
	if herr != nil || merr != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("time_of_day %s must be HH:MM between 00:00 and 23:59", strconv.Quote(raw))
	}
	return h, m, nil
}

// Validate reports whether the recurrence describes occurrences that can
// be enumerated.
//
// Every combination not listed above is refused rather than
// interpreted. A recurrence the admin did not mean is the expensive
// failure here: it holds part of the pool on days nobody booked, and
// nothing downstream can tell that from a reservation working as asked.
func (r *Recurrence) Validate() error {
	errs := r.validateFields()
	errs = append(errs, r.validateCombination()...)
	if _, _, err := parseTimeOfDay(r.TimeOfDay); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// validateFields checks each field against its own range, without
// reference to the others.
func (r *Recurrence) validateFields() []error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	switch r.Freq {
	case FreqDaily, FreqWeekly, FreqMonthly:
	case "":
		add("freq is required: one of daily, weekly or monthly")
	default:
		add("freq %s is not one of daily, weekly or monthly", strconv.Quote(string(r.Freq)))
	}
	if r.Interval < 1 {
		add("interval must be positive, got %d", r.Interval)
	}
	if r.Interval > maxInterval {
		add("interval cannot exceed %d, got %d", maxInterval, r.Interval)
	}
	for _, wd := range r.ByWeekday {
		if wd < 0 || wd > 6 {
			add("by_weekday %d is not between 0 (Sunday) and 6 (Saturday)", wd)
		}
	}
	for _, md := range r.ByMonthday {
		if md < 1 || md > 31 {
			add("by_monthday %d is not between 1 and 31", md)
		}
	}
	if r.BySetPos < -2 || r.BySetPos > 5 {
		add("by_setpos %d is not between 1 and 5, -1 (last) or -2 (next to last)", r.BySetPos)
	}
	switch r.DayKind {
	case DayKindNone, DayKindDay, DayKindWeekday, DayKindWeekend:
	default:
		add("day_kind %s is not one of day, weekday or weekend", strconv.Quote(string(r.DayKind)))
	}
	return errs
}

// validateCombination checks the fields against each other: which
// by-lists each frequency admits, and what a set position counts.
func (r *Recurrence) validateCombination() []error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	switch r.Freq {
	case FreqDaily:
		// A daily recurrence is every Nth day and nothing else. A
		// by-list on it would be a weekly or monthly recurrence wearing
		// the wrong frequency, and "every 3 days, but only on Mondays"
		// is a question with no useful answer.
		if len(r.ByWeekday) > 0 || len(r.ByMonthday) > 0 || r.BySetPos != 0 || r.DayKind != DayKindNone {
			add("a daily recurrence takes no by_weekday, by_monthday, by_setpos or day_kind")
		}
	case FreqWeekly:
		if len(r.ByWeekday) == 0 {
			add("a weekly recurrence needs by_weekday: which days of the week it falls on")
		}
		if len(r.ByMonthday) > 0 || r.BySetPos != 0 || r.DayKind != DayKindNone {
			add("a weekly recurrence takes no by_monthday, by_setpos or day_kind")
		}
	case FreqMonthly:
		if r.BySetPos != 0 {
			// A set position counts one kind of day. Counting "the
			// first Monday or Wednesday" has two readings -- the first
			// of either, or the first of each -- so neither is offered.
			switch {
			case r.DayKind != DayKindNone && len(r.ByWeekday) > 0:
				add("give by_setpos either one by_weekday or a day_kind, not both")
			case r.DayKind == DayKindNone && len(r.ByWeekday) != 1:
				add("by_setpos counts one weekday or a day_kind, got %d weekdays", len(r.ByWeekday))
			}
			if len(r.ByMonthday) > 0 {
				add("by_setpos selects a day within the month, so by_monthday cannot also be given")
			}
		} else {
			if r.DayKind != DayKindNone {
				add("day_kind needs a by_setpos: it says what to count, not which one to take")
			}
			if len(r.ByMonthday) == 0 && len(r.ByWeekday) == 0 {
				add("a monthly recurrence needs by_monthday, or by_setpos with a weekday or day_kind")
			}
			if len(r.ByMonthday) > 0 && len(r.ByWeekday) > 0 {
				add("give a monthly recurrence by_monthday or by_weekday, not both")
			}
		}
	}
	return errs
}

// Location is where the recurrence's wall clock times are read.
func (r *Recurrence) Location() *time.Location {
	if r == nil || r.loc == nil {
		return time.Local
	}
	return r.loc
}

// String is a one-line rendering for logs and error messages. The admin
// page writes its own wording; this exists so an operator reading a log
// does not have to decode a struct.
func (r *Recurrence) String() string {
	if r == nil {
		return "no recurrence"
	}
	var b strings.Builder
	b.WriteString("every ")
	if r.Interval != 1 {
		fmt.Fprintf(&b, "%d ", r.Interval)
	}
	switch r.Freq {
	case FreqDaily:
		b.WriteString(plural("day", r.Interval))
	case FreqWeekly:
		b.WriteString(plural("week", r.Interval) + " on " + weekdayNames(r.ByWeekday))
	case FreqMonthly:
		b.WriteString(plural("month", r.Interval))
		switch {
		case r.BySetPos != 0 && r.DayKind != DayKindNone:
			fmt.Fprintf(&b, " on the %s %s", setPosName(r.BySetPos), r.DayKind)
		case r.BySetPos != 0:
			fmt.Fprintf(&b, " on the %s %s", setPosName(r.BySetPos), weekdayNames(r.ByWeekday))
		case len(r.ByMonthday) > 0:
			b.WriteString(" on day " + joinInts(r.ByMonthday))
		default:
			b.WriteString(" on " + weekdayNames(r.ByWeekday))
		}
	default:
		b.WriteString(string(r.Freq))
	}
	if r.TimeOfDay != "" {
		b.WriteString(" at " + r.TimeOfDay)
	}
	return b.String()
}

func plural(unit string, n int) string {
	if n == 1 {
		return unit
	}
	return unit + "s"
}

func setPosName(pos int) string {
	switch pos {
	case -1:
		return "last"
	case -2:
		return "next to last"
	default:
		return [...]string{"", "first", "second", "third", "fourth", "fifth"}[pos]
	}
}

func weekdayNames(days []int) string {
	out := make([]string, 0, len(days))
	for _, d := range days {
		if d >= 0 && d <= 6 {
			out = append(out, time.Weekday(d).String())
		}
	}
	return strings.Join(out, ", ")
}

func joinInts(vs []int) string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, strconv.Itoa(v))
	}
	return strings.Join(out, ", ")
}

// Next is the first occurrence strictly after t, and whether one was
// found within the search bound.
//
// anchor is where an Interval above one counts from -- the
// reservation's Starts. The period containing the anchor is period
// zero, whether or not the anchor's own day matches: "every other week
// from Wednesday the 4th, on Mondays" means the Monday of the week the
// 4th is in and every second Monday after, not the Monday after the
// 4th. A zero anchor leaves every period matching, which makes an
// interval above one behave as one; Spec.Validate refuses that
// combination so no stored reservation can reach it.
func (r *Recurrence) Next(t, anchor time.Time) (time.Time, bool) {
	if r == nil {
		return time.Time{}, false
	}
	loc := r.Location()
	// Strictly after, on the same whole-minute grid as the cron
	// schedule, so the two forms are interchangeable to everything
	// above them.
	t = t.In(loc).Truncate(time.Minute).Add(time.Minute)
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc)
	switch r.Freq {
	case FreqDaily:
		return r.nextDaily(t, day, anchor)
	case FreqWeekly:
		return r.nextWeekly(t, day, anchor)
	case FreqMonthly:
		return r.nextMonthly(t, day, anchor)
	}
	return time.Time{}, false
}

// at builds the occurrence on the given date, and reports whether it is
// a real instant on that date at or after t.
//
// A wall clock time a spring-forward skipped does not exist. time.Date
// normalises it to the next real instant, which can land on the
// following day, so the date is re-checked: an occurrence that would
// jump to the next day is better dropped than silently moved, since the
// next day may not be one the recurrence matches at all.
func (r *Recurrence) at(day time.Time, t time.Time) (time.Time, bool) {
	loc := r.Location()
	cand := time.Date(day.Year(), day.Month(), day.Day(), r.hour, r.minute, 0, 0, loc)
	if cand.Hour() != r.hour || cand.Minute() != r.minute {
		// The wall clock time does not exist on this date: a
		// spring-forward deleted it. time.Date normalises such a time to
		// an instant on the far side of the gap, which reads an hour
		// *earlier* on the clock than what was asked for -- 02:30
		// becomes 01:30 -- and a reservation must not open before the
		// time it says it opens.
		//
		// Counting the time of day from local midnight instead lands on
		// the first instant past the gap, so the occurrence happens as
		// soon as that time of day exists. It is derived rather than
		// hard-coded at an hour because a transition is not always an
		// hour.
		midnight := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, loc)
		cand = midnight.Add(time.Duration(r.hour)*time.Hour + time.Duration(r.minute)*time.Minute)
	}
	if cand.Before(t) || cand.Day() != day.Day() {
		return time.Time{}, false
	}
	return cand, true
}

// civilDay is the number of whole days from the epoch to a date,
// ignoring the clock entirely.
//
// Day and week arithmetic has to be done on the calendar, not on
// elapsed seconds: a week is seven dates, and in a zone with daylight
// saving one of those weeks is 167 or 169 hours long. Reading the date
// into UTC is what makes the count independent of the zone it came
// from.
func civilDay(t time.Time) int64 {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Unix() / 86400
}

// alignForward is the first period index at or after idx that the
// interval admits, counting from the anchor's period.
//
// An idx before the anchor's own period snaps forward to it: the
// recurrence has not begun, and the first period it admits is the
// anchor's. (Occurrences before Starts are dropped by Spec.Windows,
// which is where the bound belongs; this only picks the period.)
func alignForward(idx, anchorIdx int64, interval int, anchored bool) int64 {
	if interval <= 1 || !anchored {
		return idx
	}
	if idx <= anchorIdx {
		return anchorIdx
	}
	step := int64(interval)
	ahead := idx - anchorIdx
	// Round up to the next whole number of intervals past the anchor.
	return anchorIdx + ((ahead + step - 1) / step * step)
}

func (r *Recurrence) nextDaily(t, day, anchor time.Time) (time.Time, bool) {
	anchored := !anchor.IsZero()
	var anchorDay int64
	if anchored {
		anchorDay = civilDay(anchor.In(r.Location()))
	}
	cur := alignForward(civilDay(day), anchorDay, r.Interval, anchored)
	loc := r.Location()
	for step := 0; step < maxRecurrenceSteps; step++ {
		d := time.Unix(cur*86400, 0).UTC()
		date := time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, loc)
		if cand, ok := r.at(date, t); ok {
			return cand, true
		}
		cur += int64(r.Interval)
	}
	return time.Time{}, false
}

func (r *Recurrence) nextWeekly(t, day, anchor time.Time) (time.Time, bool) {
	loc := r.Location()
	anchored := !anchor.IsZero()
	var anchorWeek int64
	if anchored {
		anchorWeek = weekIndex(anchor.In(loc))
	}
	cur := alignForward(weekIndex(day), anchorWeek, r.Interval, anchored)
	for step := 0; step < maxRecurrenceSteps; step++ {
		sunday := time.Unix(weekStartDay(cur)*86400, 0).UTC()
		for _, wd := range r.ByWeekday {
			date := time.Date(sunday.Year(), sunday.Month(), sunday.Day()+wd, 0, 0, 0, 0, loc)
			if cand, ok := r.at(date, t); ok {
				return cand, true
			}
		}
		cur += int64(r.Interval)
	}
	return time.Time{}, false
}

// firstSundayDay is 4 January 1970 as a civil day count: the epoch fell
// on a Thursday, so the first Sunday is three days past it. The week
// count is measured from there.
const firstSundayDay = 3

// weekIndex numbers the weeks, with Sunday starting each one.
//
// Sunday because ByWeekday numbers Sunday zero, the way time.Weekday
// does: a week that began on Monday would put Sunday at its far end,
// and "every other week on Sunday and Monday" would then put those two
// days a fortnight apart rather than next to each other.
func weekIndex(t time.Time) int64 {
	day := civilDay(t) - firstSundayDay
	if day < 0 {
		// Floor division: a date before the first Sunday still belongs
		// to a whole week, and truncating towards zero would put two
		// weeks in one index.
		day -= 6
	}
	return day / 7
}

// weekStartDay reverses weekIndex: the civil day the week begins on.
func weekStartDay(idx int64) int64 { return idx*7 + firstSundayDay }

func (r *Recurrence) nextMonthly(t, day, anchor time.Time) (time.Time, bool) {
	loc := r.Location()
	anchored := !anchor.IsZero()
	var anchorMonth int64
	if anchored {
		anchorMonth = monthIndex(anchor.In(loc))
	}
	cur := alignForward(monthIndex(day), anchorMonth, r.Interval, anchored)
	for step := 0; step < maxRecurrenceSteps; step++ {
		year, month := int(cur/12), time.Month(cur%12+1)
		for _, dom := range r.monthDays(year, month, loc) {
			date := time.Date(year, month, dom, 0, 0, 0, 0, loc)
			if cand, ok := r.at(date, t); ok {
				return cand, true
			}
		}
		cur += int64(r.Interval)
	}
	return time.Time{}, false
}

// monthIndex numbers the months so an interval can be counted on them.
func monthIndex(t time.Time) int64 { return int64(t.Year())*12 + int64(t.Month()) - 1 }

// monthDays is the days of the given month the recurrence matches, in
// ascending order. A month it matches nothing in gives none, which is
// what makes the search step over February for a recurrence on the
// 31st.
func (r *Recurrence) monthDays(year int, month time.Month, loc *time.Location) []int {
	last := daysInMonth(year, month, loc)
	if r.BySetPos != 0 {
		pool := make([]int, 0, last)
		for dom := 1; dom <= last; dom++ {
			if r.countsDay(time.Date(year, month, dom, 0, 0, 0, 0, loc).Weekday()) {
				pool = append(pool, dom)
			}
		}
		idx := r.BySetPos - 1
		if r.BySetPos < 0 {
			// -1 is the last, -2 the one before it.
			idx = len(pool) + r.BySetPos
		}
		if idx < 0 || idx >= len(pool) {
			// The month does not reach that position -- no fifth
			// Monday, say -- so it holds no occurrence.
			return nil
		}
		return []int{pool[idx]}
	}
	if len(r.ByMonthday) > 0 {
		out := make([]int, 0, len(r.ByMonthday))
		for _, dom := range r.ByMonthday {
			if dom >= 1 && dom <= last {
				out = append(out, dom)
			}
		}
		return out
	}
	out := make([]int, 0, last)
	for dom := 1; dom <= last; dom++ {
		wd := int(time.Date(year, month, dom, 0, 0, 0, 0, loc).Weekday())
		for _, want := range r.ByWeekday {
			if wd == want {
				out = append(out, dom)
				break
			}
		}
	}
	return out
}

// countsDay reports whether a weekday is one the set position counts.
func (r *Recurrence) countsDay(wd time.Weekday) bool {
	switch r.DayKind {
	case DayKindDay:
		return true
	case DayKindWeekday:
		return wd >= time.Monday && wd <= time.Friday
	case DayKindWeekend:
		return wd == time.Saturday || wd == time.Sunday
	}
	// No day kind: the position counts the one weekday that Validate
	// insisted on.
	for _, want := range r.ByWeekday {
		if int(wd) == want {
			return true
		}
	}
	return false
}

// daysInMonth is the last day of the month.
//
// Day zero of the next month is the last day of this one, which is how
// February gets its leap years right without a table.
func daysInMonth(year int, month time.Month, loc *time.Location) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, loc).Day()
}

// anchoredRecurrence pairs a recurrence with the instant its interval
// counts from, so it answers the same one-argument Next that the cron
// schedule does and the enumeration above does not have to know which
// kind it is walking.
type anchoredRecurrence struct {
	rec    *Recurrence
	anchor time.Time
}

func (a anchoredRecurrence) Next(t time.Time) (time.Time, bool) {
	return a.rec.Next(t, a.anchor)
}
