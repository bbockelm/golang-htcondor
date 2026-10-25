import type { CalendarDay, CalendarResponse } from '../../src/lib/api';
import { SMOKE_NOW } from './clock';

// A quarter of per-day activity for the dashboard's calendar.
//
// Built from SMOKE_NOW, the fixed instant the smoke suite lives at, and
// not from the real clock. The calendar lays days out as weeks and names
// the months, so which weekday the window starts on decides where every
// square lands and which columns carry a label -- a window measured from
// the real "now" would redraw itself every day and fail the layout
// assertions at midnight UTC.
const DAY = 86400;

// The day in progress: midnight UTC of the suite's instant.
const TODAY = Math.floor(SMOKE_NOW / DAY) * DAY;
const DAYS = 90;

// What the queue is now. The last day's depth is this figure, because
// that is the one the rest of the line is worked back from.
const ANCHOR = 1240;

// A shape with something to read in it: a campaign that ramps up, a
// burst, a quiet patch, and one day in the middle of it all where
// nothing happened at all. Deterministic from the day's index -- the
// suite asserts on these numbers.
function dayAt(i: number): CalendarDay {
  // Index 40 is the quiet day: present, and all zeros. A calendar has to
  // show that as a zero rather than as a hole.
  if (i === 40) {
    return { day: TODAY - (DAYS - 1 - i) * DAY, submitted: 0, completed: 0, removed: 0, in_queue: 980 };
  }
  const submitted = i === 62 ? 4120 : 20 + ((i * 37) % 180);
  const completed = i === 63 ? 3980 : 18 + ((i * 29) % 170);
  return {
    day: TODAY - (DAYS - 1 - i) * DAY,
    submitted,
    completed,
    removed: i % 11 === 0 ? 6 : 0,
    in_queue: 600 + ((i * 53) % 700),
  };
}

export function calendarDays(): CalendarDay[] {
  const days = Array.from({ length: DAYS }, (_, i) => dayAt(i));
  days[DAYS - 1].in_queue = ANCHOR;
  return days;
}

export const calendarFixture: CalendarResponse = {
  enabled: true,
  days: calendarDays(),
  window_days: DAYS,
  queue_depth: { derived: true, anchor: ANCHOR },
  source: 'smoke fixture',
  computed_at: SMOKE_NOW - 120,
  partial: false,
  note: '',
};

// The day the suite clicks through on, and its bounds. Far enough back
// that everything that happened on it is in the archive.
export const CALENDAR_PAST_DAY = TODAY - 30 * DAY;
export const CALENDAR_PAST_DAY_END = CALENDAR_PAST_DAY + DAY;
// The day nothing happened on.
export const CALENDAR_QUIET_DAY = TODAY - (DAYS - 1 - 40) * DAY;
