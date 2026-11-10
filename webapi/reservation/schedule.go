package reservation

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule is a five-field cron expression -- minute, hour, day of month,
// month, day of week -- evaluated in a named location.
//
// Occurrences are found by walking forward a day at a time and then over
// the matching hours and minutes of that day, building each candidate with
// time.Date in the schedule's location. That is what makes the daylight
// saving transitions come out right: "14:00 every Monday" is a wall clock
// time, and time.Date resolves it against the offset in force that day
// rather than against a fixed number of seconds.
type Schedule struct {
	minute, hour, dom, month, dow fieldSet
	// domRestricted and dowRestricted record whether each was given as
	// something other than "*". Cron's rule is that when both are
	// restricted a day matches either one, not both.
	domRestricted, dowRestricted bool
	loc                          *time.Location
	text                         string
}

// fieldSet is the set of values a cron field admits, indexed from zero.
type fieldSet uint64

func (f fieldSet) has(v int) bool { return v >= 0 && v < 64 && f&(1<<uint(v)) != 0 }

// horizon bounds the search for the next occurrence. A schedule that never
// fires -- 30 February -- would otherwise loop forever.
const horizonDays = 400

// ParseSchedule reads a five-field cron expression. loc may be nil, which
// means time.Local.
func ParseSchedule(expr string, loc *time.Location) (*Schedule, error) {
	if loc == nil {
		loc = time.Local
	}
	parts := strings.Fields(expr)
	if len(parts) != 5 {
		return nil, fmt.Errorf("schedule %q has %d fields, want 5 (minute hour day-of-month month day-of-week)", expr, len(parts))
	}
	s := &Schedule{loc: loc, text: strings.Join(parts, " ")}
	var err error
	for i, spec := range []struct {
		name     string
		lo, hi   int
		dst      *fieldSet
		restrict *bool
	}{
		{"minute", 0, 59, &s.minute, nil},
		{"hour", 0, 23, &s.hour, nil},
		{"day of month", 1, 31, &s.dom, &s.domRestricted},
		{"month", 1, 12, &s.month, nil},
		{"day of week", 0, 6, &s.dow, &s.dowRestricted},
	} {
		if *spec.dst, err = parseField(parts[i], spec.lo, spec.hi); err != nil {
			return nil, fmt.Errorf("%s field %q: %w", spec.name, parts[i], err)
		}
		if spec.restrict != nil {
			*spec.restrict = parts[i] != "*"
		}
	}
	return s, nil
}

// String is the expression as parsed.
func (s *Schedule) String() string { return s.text }

// Location is where the schedule's wall clock times are read.
func (s *Schedule) Location() *time.Location { return s.loc }

func parseField(spec string, lo, hi int) (fieldSet, error) {
	var out fieldSet
	for _, part := range strings.Split(spec, ",") {
		if part == "" {
			return 0, fmt.Errorf("empty element")
		}
		step := 1
		if slash := strings.IndexByte(part, '/'); slash >= 0 {
			var err error
			if step, err = strconv.Atoi(part[slash+1:]); err != nil || step < 1 {
				return 0, fmt.Errorf("bad step %q", part[slash+1:])
			}
			part = part[:slash]
		}
		first, last := lo, hi
		switch {
		case part == "*":
			// the whole range
		case strings.ContainsRune(part, '-'):
			a, b, _ := strings.Cut(part, "-")
			var err error
			if first, err = strconv.Atoi(a); err != nil {
				return 0, fmt.Errorf("bad range start %q", a)
			}
			if last, err = strconv.Atoi(b); err != nil {
				return 0, fmt.Errorf("bad range end %q", b)
			}
		default:
			v, err := strconv.Atoi(part)
			if err != nil {
				return 0, fmt.Errorf("bad value %q", part)
			}
			first, last = v, v
		}
		if first < lo || last > hi || first > last {
			return 0, fmt.Errorf("%d-%d out of range %d-%d", first, last, lo, hi)
		}
		for v := first; v <= last; v += step {
			out |= 1 << uint(v)
		}
	}
	if out == 0 {
		return 0, fmt.Errorf("matches nothing")
	}
	return out, nil
}

// matchesDay reports whether the schedule fires on the given date, applying
// cron's rule that a restricted day-of-month and day-of-week are ORed.
func (s *Schedule) matchesDay(t time.Time) bool {
	if !s.month.has(int(t.Month())) {
		return false
	}
	dom, dow := s.dom.has(t.Day()), s.dow.has(int(t.Weekday()))
	switch {
	case s.domRestricted && s.dowRestricted:
		return dom || dow
	default:
		return dom && dow
	}
}

// Next is the first occurrence strictly after t, and whether one was found
// within the search horizon.
func (s *Schedule) Next(t time.Time) (time.Time, bool) {
	t = t.In(s.loc).Truncate(time.Minute).Add(time.Minute)
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, s.loc)
	for d := 0; d < horizonDays; d++ {
		if s.matchesDay(day) {
			for h := 0; h < 24; h++ {
				if !s.hour.has(h) {
					continue
				}
				for m := 0; m < 60; m++ {
					if !s.minute.has(m) {
						continue
					}
					cand := time.Date(day.Year(), day.Month(), day.Day(), h, m, 0, 0, s.loc)
					// A wall clock time skipped by a spring-forward does not
					// exist; time.Date normalises it to the next real
					// instant, which may land on another day or before t.
					if cand.Before(t) || cand.Day() != day.Day() {
						continue
					}
					return cand, true
				}
			}
		}
		day = time.Date(day.Year(), day.Month(), day.Day()+1, 0, 0, 0, 0, s.loc)
	}
	return time.Time{}, false
}
