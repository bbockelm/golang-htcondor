// A reservation's timing, as a calendar asks for it.
//
// A reservation is timed in one of three ways, and which one is
// authoritative is recorded rather than inferred: a structured
// recurrence, a hand-typed cron expression, or nothing at all for one
// that holds its capacity continuously.
//
// The recurrence and the cron expression are **peers, not layers**.
// Nothing here converts between them in either direction. A recurrence
// says things cron cannot -- every other week, the last Friday of the
// month -- so a converter would have to round exactly the schedules the
// recurrence exists to express, and a page that displayed the rounded
// version would be showing a schedule that is not the one being run.
//
// That is also what makes the two freely interchangeable in the form.
// Switching from the controls to the expression and back changes only
// which one is authoritative; both stay in the draft, untouched, until
// the reservation is saved. Clicking the wrong repeat is an undo away
// rather than a reload.
//
// The bounds are separate again. `starts_at`, `ends_at` and
// `occurrences` limit a schedule that otherwise runs forever; they are
// not part of either representation, so an operator can set them over a
// hand-written expression just as well as over a picked recurrence.

import type { AdminReservation, WireRecurrence } from '@/lib/api';

/** Which timing a reservation is run from. The names are the wire's. */
export type ScheduleKind = 'cron' | 'recurrence' | 'always';

/** How a recurrence repeats. `once` is a daily recurrence bounded to a
 *  single window -- the same thing the wire says, named as an operator
 *  asks for it. */
export type RepeatMode = 'once' | 'daily' | 'weekly' | 'monthly';

/** Which way a monthly recurrence picks its days: by the date, or by
 *  counting a kind of day within the month. The wire refuses both at
 *  once, so the picker offers them as alternatives. */
export type MonthlyMode = 'monthday' | 'setpos';

/** What a set position counts when it is not counting one weekday. */
export type DayKind = '' | 'day' | 'weekday' | 'weekend';

/** When a schedule stops: never, on a date, or after a count. The three
 *  are exclusive because the server refuses two bounds at once. */
export type EndMode = 'never' | 'on' | 'after';

/** The one choice the repeat control offers, across all three timings.
 *  They are alternatives to each other, so they are one radio group
 *  rather than a kind and then a frequency. */
export type RepeatChoice = 'always' | RepeatMode | 'custom';

export interface Recurrence {
  /** `YYYY-MM-DD` in the reservation's zone, or "" for no start bound. */
  startDate: string;
  /** `HH:MM`, 24-hour, in the reservation's zone: the time of day
   *  windows begin. */
  startTime: string;
  repeat: RepeatMode;
  /** The "every N" -- days, weeks or months. Above one it needs a start
   *  date to count from. */
  interval: number;
  /** Days a weekly recurrence fires on, 0 = Sunday through 6 = Saturday. */
  weekdays: number[];
  monthlyMode: MonthlyMode;
  /** Days of the month a monthly recurrence fires on, 1 through 31. */
  monthdays: number[];
  /** 1..5 for first through fifth, -1 last, -2 next to last. */
  setpos: number;
  /** The weekday a set position counts, when it counts a weekday. Kept
   *  alongside `dayKind` rather than in one field so that choosing "the
   *  first weekday" and changing your mind does not forget which day
   *  was picked. */
  setposWeekday: number;
  dayKind: DayKind;
  end: EndMode;
  /** `YYYY-MM-DD`, used when `end` is `on`. */
  endDate: string;
  /** Used when `end` is `after`. */
  occurrences: number;
}

/** The three wire fields that bound a schedule. */
export interface RecurrenceBounds {
  starts_at: string;
  ends_at: string;
  occurrences: number;
}

/** Everything the form sends about when a reservation runs. */
export interface ScheduleFields extends RecurrenceBounds {
  schedule_kind: ScheduleKind;
  schedule: string;
  recurrence: WireRecurrence | null;
}

// Mid-morning: a time that is plainly a choice, so a schedule left at
// the default does not look deliberate. Midnight would.
export const DEFAULT_START_TIME = '09:00';

/** Sunday first, as every calendar's weekday row has it. The repeated
 *  letters are why each toggle needs a full name for a screen reader. */
export const WEEKDAYS: readonly { index: number; letter: string; name: string }[] = [
  { index: 0, letter: 'S', name: 'Sunday' },
  { index: 1, letter: 'M', name: 'Monday' },
  { index: 2, letter: 'T', name: 'Tuesday' },
  { index: 3, letter: 'W', name: 'Wednesday' },
  { index: 4, letter: 'T', name: 'Thursday' },
  { index: 5, letter: 'F', name: 'Friday' },
  { index: 6, letter: 'S', name: 'Saturday' },
] as const;

/** The positions a monthly recurrence can count to. Negative counts from
 *  the end, which is the only way to say "the last Friday" in a month
 *  that may have four or five of them. */
export const SET_POSITIONS: readonly { value: number; label: string }[] = [
  { value: 1, label: 'First' },
  { value: 2, label: 'Second' },
  { value: 3, label: 'Third' },
  { value: 4, label: 'Fourth' },
  { value: 5, label: 'Fifth' },
  { value: -1, label: 'Last' },
  { value: -2, label: 'Next to last' },
] as const;

/** What a set position may count: one weekday, or a category of days.
 *  One list because they are one choice -- "the first Monday" and "the
 *  first weekday" are answers to the same question. */
export const SETPOS_DAYS: readonly { value: string; label: string }[] = [
  ...WEEKDAYS.map((d) => ({ value: String(d.index), label: d.name })),
  { value: 'day', label: 'day' },
  { value: 'weekday', label: 'weekday' },
  { value: 'weekend', label: 'weekend day' },
] as const;

function pad2(n: number): string {
  return String(n).padStart(2, '0');
}

/** parseTimeOfDay reads `HH:MM`. Anything else is not a time of day,
 *  including the `HH:MM:SS` some browsers emit: the schedule has no
 *  second field to put the seconds in. */
export function parseTimeOfDay(time: string): { hour: number; minute: number } | null {
  const m = /^(\d{1,2}):(\d{2})$/.exec(time.trim());
  if (!m) return null;
  const hour = Number(m[1]);
  const minute = Number(m[2]);
  if (hour > 23 || minute > 59) return null;
  return { hour, minute };
}

function parseISODate(date: string): { year: number; month: number; day: number } | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date.trim());
  if (!m) return null;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  if (month < 1 || month > 12 || day < 1 || day > 31) return null;
  return { year, month, day };
}

/** Ascending and without duplicates, which is the order occurrences
 *  happen in rather than the order boxes were ticked in. The server
 *  normalises the same way, so a reservation does not come back looking
 *  different from what was sent. */
function sortedUnique(values: number[]): number[] {
  return [...new Set(values)].sort((a, b) => a - b);
}

/** defaultRecurrence is what a new reservation's controls start on:
 *  weekly, with no day chosen yet, because a weekly reservation is what
 *  almost every one of these is and guessing the day would be a
 *  schedule nobody asked for. */
export function defaultRecurrence(): Recurrence {
  return {
    startDate: '',
    startTime: DEFAULT_START_TIME,
    repeat: 'weekly',
    interval: 1,
    weekdays: [],
    monthlyMode: 'monthday',
    monthdays: [],
    setpos: 1,
    setposWeekday: 1,
    dayKind: '',
    end: 'never',
    endDate: '',
    occurrences: 1,
  };
}

// --- The wire recurrence ---

/** recurrenceToWire renders the controls as the recurrence the server
 *  reads. Only the fields the chosen frequency admits are sent: the
 *  server refuses a daily recurrence carrying weekdays, and rightly so,
 *  since that is a weekly one wearing the wrong frequency. */
export function recurrenceToWire(rec: Recurrence): WireRecurrence {
  const base: WireRecurrence = {
    // A one-off is a daily recurrence bounded to a single window. There
    // is no "once" frequency on the wire, and inventing one here would
    // be a fourth thing for the server to understand.
    freq: rec.repeat === 'once' ? 'daily' : rec.repeat,
    interval: rec.repeat === 'once' ? 1 : intervalOf(rec),
    time_of_day: rec.startTime,
  };
  if (rec.repeat === 'weekly') {
    return { ...base, by_weekday: sortedUnique(rec.weekdays) };
  }
  if (rec.repeat === 'monthly') {
    if (rec.monthlyMode === 'setpos') {
      return {
        ...base,
        by_setpos: rec.setpos,
        // A set position counts one kind of day. With a category there
        // is no weekday to send, and sending both is refused.
        ...(rec.dayKind
          ? { day_kind: rec.dayKind }
          : { by_weekday: [rec.setposWeekday] }),
      };
    }
    return { ...base, by_monthday: sortedUnique(rec.monthdays) };
  }
  return base;
}

function intervalOf(rec: Recurrence): number {
  const n = Math.floor(rec.interval);
  return Number.isFinite(n) && n > 0 ? n : 1;
}

/** canonicalWire is a stored recurrence in the spelling the controls
 *  would send it in, so the two can be compared. Normalising both sides
 *  is what keeps the comparison about meaning rather than about field
 *  order or the order weekdays were listed in. */
function canonicalWire(w: WireRecurrence): WireRecurrence {
  const out: WireRecurrence = {
    freq: w.freq,
    interval: w.interval && w.interval > 0 ? Math.floor(w.interval) : 1,
    time_of_day: w.time_of_day ?? '',
  };
  if (w.by_weekday?.length) out.by_weekday = sortedUnique(w.by_weekday);
  if (w.by_monthday?.length) out.by_monthday = sortedUnique(w.by_monthday);
  if (w.by_setpos) out.by_setpos = w.by_setpos;
  if (w.day_kind) out.day_kind = w.day_kind;
  return out;
}

function sameNumbers(a: number[] | undefined, b: number[] | undefined): boolean {
  const x = a ?? [];
  const y = b ?? [];
  return x.length === y.length && x.every((v, i) => v === y[i]);
}

function sameWire(a: WireRecurrence, b: WireRecurrence): boolean {
  return (
    a.freq === b.freq &&
    a.interval === b.interval &&
    a.time_of_day === b.time_of_day &&
    (a.by_setpos ?? 0) === (b.by_setpos ?? 0) &&
    (a.day_kind ?? '') === (b.day_kind ?? '') &&
    sameNumbers(a.by_weekday, b.by_weekday) &&
    sameNumbers(a.by_monthday, b.by_monthday)
  );
}

/** recurrenceFromWire reads a stored recurrence into the controls, and
 *  says whether they can state it exactly.
 *
 *  The wire admits a few shapes the controls do not offer -- a monthly
 *  recurrence listing weekdays with no position to count them to, for
 *  one -- and those can only arrive from something other than this form.
 *  Showing them as the nearest thing the controls can draw would make
 *  opening a reservation and pressing Save a silent edit of its
 *  schedule, so they are reported as inexact and kept verbatim instead.
 */
export function recurrenceFromWire(
  w: WireRecurrence,
  base: Recurrence,
  occurrences: number,
): { rec: Recurrence; exact: boolean } {
  const canonical = canonicalWire(w);
  const rec: Recurrence = {
    ...base,
    startTime: canonical.time_of_day || base.startTime,
    repeat: canonical.freq,
    interval: canonical.interval,
  };
  // A daily recurrence bounded to one window is a one-off, which is how
  // an operator asked for it and how the controls should show it back.
  if (canonical.freq === 'daily' && canonical.interval === 1 && occurrences === 1) {
    rec.repeat = 'once';
  }
  if (canonical.freq === 'weekly') {
    rec.weekdays = canonical.by_weekday ?? [];
  }
  if (canonical.freq === 'monthly') {
    if (canonical.by_setpos) {
      rec.monthlyMode = 'setpos';
      rec.setpos = canonical.by_setpos;
      rec.dayKind = canonical.day_kind ?? '';
      if (canonical.by_weekday?.length === 1) {
        rec.setposWeekday = canonical.by_weekday[0];
      }
    } else {
      rec.monthlyMode = 'monthday';
      rec.monthdays = canonical.by_monthday ?? [];
    }
  }
  return { rec, exact: sameWire(recurrenceToWire(rec), canonical) };
}

// --- The draft the form holds ---
//
// All three timings live in the draft at once. Only `kind` says which
// one is sent, so switching between them is reversible: the expression
// somebody typed is still there when they come back from the controls,
// and the controls are still set when they come back from the
// expression.

export interface ScheduleDraft {
  kind: ScheduleKind;
  rec: Recurrence;
  /** What the expression box shows, and what goes on the wire for
   *  `cron`. */
  cron: string;
  /** A stored recurrence the controls cannot state, kept exactly as it
   *  came so that saving without touching the repeat does not rewrite
   *  it. Cleared the moment a repeat control is used. */
  stored: WireRecurrence | null;
}

/** draftFromReservation opens the form on a stored reservation. */
export function draftFromReservation(res: AdminReservation): ScheduleDraft {
  const zone = res.timezone;
  const start = res.starts_at ? zonedDateTime(res.starts_at, zone) : null;
  const end = res.ends_at ? zonedDateTime(res.ends_at, zone) : null;
  const base: Recurrence = {
    ...defaultRecurrence(),
    startDate: start?.date ?? '',
    startTime: start?.time ?? DEFAULT_START_TIME,
    endDate: end?.date ?? '',
    end: res.ends_at ? 'on' : res.occurrences > 0 ? 'after' : 'never',
    occurrences: res.occurrences > 0 ? res.occurrences : 1,
  };
  // An empty kind is cron: that is what every reservation stored before
  // the recurrence existed is, and the server reads it the same way.
  const kind: ScheduleKind =
    res.schedule_kind === 'recurrence' || res.schedule_kind === 'always'
      ? res.schedule_kind
      : 'cron';
  if (kind === 'recurrence' && res.recurrence) {
    const { rec, exact } = recurrenceFromWire(res.recurrence, base, res.occurrences);
    return { kind, rec, cron: res.schedule, stored: exact ? null : res.recurrence };
  }
  return { kind, rec: base, cron: res.schedule, stored: null };
}

/** repeatChoice is which repeat control is selected. */
export function repeatChoice(d: ScheduleDraft): RepeatChoice {
  if (d.kind === 'always') return 'always';
  if (d.kind === 'cron') return 'custom';
  return d.rec.repeat;
}

/** withRepeatChoice applies the repeat control.
 *
 *  Nothing is discarded: the expression and the controls both stay in
 *  the draft whichever is chosen, so this is reversible and a mistaken
 *  click costs nothing. */
export function withRepeatChoice(
  d: ScheduleDraft,
  choice: RepeatChoice,
  zone: string,
): ScheduleDraft {
  if (choice === 'always') return { ...d, kind: 'always' };
  if (choice === 'custom') return { ...d, kind: 'cron' };
  return withRecurrence({ ...d, kind: 'recurrence' }, { ...d.rec, repeat: choice }, zone);
}

/** withRecurrence applies a change made in the repeat controls.
 *
 *  A stored recurrence these controls could not state is dropped here,
 *  because using one of them is the operator saying to replace it. */
export function withRecurrence(
  d: ScheduleDraft,
  rec: Recurrence,
  zone: string,
): ScheduleDraft {
  return { ...settle(d, rec, zone), stored: null };
}

/** withBounds applies a change made in the start or end controls.
 *
 *  Bounds limit whichever schedule is in force rather than being part
 *  of one, so setting one neither changes which schedule that is nor
 *  touches a recurrence being kept verbatim. An operator who typed an
 *  expression can still say when it stops. */
export function withBounds(
  d: ScheduleDraft,
  rec: Recurrence,
  zone: string,
): ScheduleDraft {
  return settle(d, rec, zone);
}

/** settle fills in what a newly chosen repeat needs before it describes
 *  anything, where the operator can see and change it.
 *
 *  Each fill happens on the way into the state that needs it and not
 *  again, which is the difference between a default and an override: a
 *  value refilled on every edit cannot be cleared, and an operator
 *  clearing a date the schedule needs is asking to be asked for it
 *  rather than to have it put back. */
function settle(d: ScheduleDraft, rec: Recurrence, zone: string): ScheduleDraft {
  let next = rec;
  if (next.repeat === 'once') {
    // One window, which is the bound rather than the frequency.
    next = { ...next, end: 'after', occurrences: 1 };
  }
  if (byMonthday(next) && !byMonthday(d.rec) && next.monthdays.length === 0) {
    // The start date's own day of the month, which is the day somebody
    // choosing "monthly" almost always means.
    const on = parseISODate(next.startDate || todayInZone(zone));
    if (on) next = { ...next, monthdays: [on.day] };
  }
  if (needsAnchor(next) && !needsAnchor(d.rec) && !next.startDate) {
    next = { ...next, startDate: todayInZone(zone) };
  }
  return { ...d, rec: next };
}

function byMonthday(rec: Recurrence): boolean {
  return rec.repeat === 'monthly' && rec.monthlyMode === 'monthday';
}

/** needsAnchor is whether this recurrence has to be counted from a
 *  start date. "Every other week" means nothing until somebody says
 *  which week, and a count of windows has no first one to count from. */
function needsAnchor(rec: Recurrence): boolean {
  if (rec.repeat === 'once') return true;
  if (intervalOf(rec) > 1) return true;
  return rec.end === 'after' && rec.occurrences > 0;
}

/** withCron is the expression box being typed in. */
export function withCron(d: ScheduleDraft, cron: string): ScheduleDraft {
  return { ...d, kind: 'cron', cron };
}

/** setposDayValue is the one value the position's day control holds: a
 *  weekday index, or the category being counted. */
export function setposDayValue(rec: Recurrence): string {
  return rec.dayKind ? rec.dayKind : String(rec.setposWeekday);
}

/** withSetposDay reads that control back. A weekday clears the category
 *  and a category leaves the weekday where it was, so changing your
 *  mind twice returns to the same day. */
export function withSetposDay(rec: Recurrence, value: string): Recurrence {
  if (/^[0-6]$/.test(value)) {
    return { ...rec, dayKind: '', setposWeekday: Number(value) };
  }
  if (value === 'day' || value === 'weekday' || value === 'weekend') {
    return { ...rec, dayKind: value };
  }
  return rec;
}

/** toggleWeekday ticks or unticks one day of a weekly recurrence. */
export function toggleWeekday(rec: Recurrence, day: number): Recurrence {
  const weekdays = rec.weekdays.includes(day)
    ? rec.weekdays.filter((d) => d !== day)
    : sortedUnique([...rec.weekdays, day]);
  return { ...rec, weekdays };
}

/** toggleMonthday ticks or unticks one day of the month. */
export function toggleMonthday(rec: Recurrence, day: number): Recurrence {
  const monthdays = rec.monthdays.includes(day)
    ? rec.monthdays.filter((d) => d !== day)
    : sortedUnique([...rec.monthdays, day]);
  return { ...rec, monthdays };
}

// --- What the form sends ---

/** recurrenceToBounds maps the start and end controls onto the three
 *  wire fields, in `zone`.
 *
 *  Only one of `ends_at` and `occurrences` is ever set, which is what
 *  the server requires; the end control is a radio group for that
 *  reason.
 *
 *  The start bound carries the recurrence's time of day even for the
 *  timings that have no time-of-day control. It is an instant either
 *  way, and rounding a stored bound to midnight because this form has
 *  nowhere to show its time would be an edit nobody asked for. */
export function recurrenceToBounds(r: Recurrence, zone: string): RecurrenceBounds {
  const starts_at = r.startDate
    ? zonedRFC3339(r.startDate, r.startTime || '00:00', zone)
    : '';
  switch (r.end) {
    case 'on':
      return {
        starts_at,
        // The last second of the chosen day, so a window on that day
        // still happens.
        ends_at: r.endDate ? zonedRFC3339(r.endDate, '23:59', zone, 59) : '',
        occurrences: 0,
      };
    case 'after':
      return {
        starts_at,
        ends_at: '',
        occurrences: Number.isFinite(r.occurrences) && r.occurrences > 0
          ? Math.floor(r.occurrences)
          : 1,
      };
    case 'never':
      return { starts_at, ends_at: '', occurrences: 0 };
  }
}

/** scheduleFields is everything the form sends about when a reservation
 *  runs.
 *
 *  The timings that are not authoritative go out empty rather than
 *  populated. The server drops them anyway -- a reservation must not be
 *  able to come back from the database timed by text that nothing
 *  displayed -- and sending them would only make a stored reservation
 *  disagree with what the page showed. */
export function scheduleFields(d: ScheduleDraft, zone: string): ScheduleFields {
  const bounds = recurrenceToBounds(d.rec, zone);
  if (d.kind === 'always') {
    return {
      schedule_kind: 'always',
      schedule: '',
      recurrence: null,
      ...bounds,
      // An always-on reservation has no occurrences to count, so a
      // count left over from another repeat is dropped rather than sent
      // for the server to refuse.
      occurrences: 0,
    };
  }
  if (d.kind === 'recurrence') {
    return {
      schedule_kind: 'recurrence',
      schedule: '',
      recurrence: d.stored ?? recurrenceToWire(d.rec),
      ...bounds,
    };
  }
  return {
    schedule_kind: 'cron',
    schedule: d.cron.trim(),
    recurrence: null,
    ...bounds,
  };
}

/** draftReservation is the whole reservation a preview is asked about:
 *  the form's own values with its schedule applied. */
export function draftReservation(
  base: AdminReservation,
  d: ScheduleDraft,
  zone: string,
): AdminReservation {
  return { ...base, timezone: zone, ...scheduleFields(d, zone) };
}

/** Something the schedule still needs, and which control needs it. */
export interface ScheduleNeed {
  field: 'start' | 'repeat';
  message: string;
}

/** scheduleNeeds names what the schedule still needs, in words that say
 *  what to do about it, against the control to do it to.
 *
 *  These are the server's own rules, checked here because the operator
 *  can see which control to fix and a 400 cannot point at one.
 *  Everything else is still left to the server: this is the subset
 *  where the form knows enough to name a box. */
export function scheduleNeeds(d: ScheduleDraft): ScheduleNeed[] {
  const out: ScheduleNeed[] = [];
  const rec = d.rec;
  const counting = rec.end === 'after' && rec.occurrences > 0;
  if (d.kind !== 'always' && !rec.startDate) {
    if (intervalOf(rec) > 1) {
      out.push({
        field: 'start',
        message: `Repeating every ${intervalOf(rec)} ${unitPlural(rec)} needs a start date to count from.`,
      });
    } else if (counting) {
      out.push({
        field: 'start',
        message: 'Ending after a number of windows needs a start date to count from.',
      });
    }
  }
  if (d.kind === 'recurrence' && !d.stored) {
    if (rec.repeat === 'weekly' && rec.weekdays.length === 0) {
      out.push({ field: 'repeat', message: 'Choose at least one day of the week.' });
    }
    if (
      rec.repeat === 'monthly' &&
      rec.monthlyMode === 'monthday' &&
      rec.monthdays.length === 0
    ) {
      out.push({ field: 'repeat', message: 'Choose at least one day of the month.' });
    }
  }
  return out;
}

function unitPlural(rec: Recurrence): string {
  const n = intervalOf(rec);
  const unit = rec.repeat === 'monthly' ? 'month' : rec.repeat === 'daily' ? 'day' : 'week';
  return n === 1 ? unit : `${unit}s`;
}

// --- Rendering a schedule as words ---

const SETPOS_WORDS = new Map(SET_POSITIONS.map((p) => [p.value, p.label.toLowerCase()]));

function joinNames(names: string[]): string {
  if (names.length <= 1) return names[0] ?? '';
  if (names.length === 2) return `${names[0]} and ${names[1]}`;
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

function ordinal(day: number): string {
  const tens = day % 100;
  if (tens >= 11 && tens <= 13) return `${day}th`;
  switch (day % 10) {
    case 1:
      return `${day}st`;
    case 2:
      return `${day}nd`;
    case 3:
      return `${day}rd`;
    default:
      return `${day}th`;
  }
}

/** describeRecurrence is a stored recurrence in words, for the list and
 *  for the one case the controls cannot show. The server has its own
 *  one-line rendering for logs; this is the one an operator reads. */
export function describeRecurrence(w: WireRecurrence): string {
  const c = canonicalWire(w);
  const every = c.interval === 1 ? '' : `${c.interval} `;
  switch (c.freq) {
    case 'daily':
      return `Every ${every}${c.interval === 1 ? 'day' : 'days'}`;
    case 'weekly': {
      const days = joinNames(
        (c.by_weekday ?? []).map((d) => WEEKDAYS[d]?.name ?? String(d)),
      );
      const weeks = `Every ${every}${c.interval === 1 ? 'week' : 'weeks'}`;
      return days ? `${weeks} on ${days}` : weeks;
    }
    case 'monthly': {
      const months = `every ${every}${c.interval === 1 ? 'month' : 'months'}`;
      if (c.by_setpos) {
        const where = SETPOS_WORDS.get(c.by_setpos) ?? `position ${c.by_setpos}`;
        const what = c.day_kind
          ? c.day_kind === 'weekend'
            ? 'weekend day'
            : c.day_kind
          : (WEEKDAYS[(c.by_weekday ?? [])[0]]?.name ?? 'day');
        return `The ${where} ${what} of ${months}`;
      }
      if (c.by_monthday?.length) {
        return `The ${joinNames(c.by_monthday.map(ordinal))} of ${months}`;
      }
      if (c.by_weekday?.length) {
        return `Every ${joinNames(c.by_weekday.map((d) => WEEKDAYS[d]?.name ?? String(d)))} of ${months}`;
      }
      return months.charAt(0).toUpperCase() + months.slice(1);
    }
  }
}

/** describeSchedule is the schedule as the list shows it. A cron
 *  expression is returned as it was typed: it is not prose and
 *  pretending otherwise would mean reading it, which nothing here
 *  does. */
export function describeSchedule(res: AdminReservation): string {
  switch (res.schedule_kind) {
    case 'always':
      return 'Always on';
    case 'recurrence':
      return res.recurrence ? describeRecurrence(res.recurrence) : 'No recurrence';
    default:
      return res.schedule;
  }
}

// --- Zones ---
//
// A reservation's times are wall-clock times in its own zone -- that is
// the point of the zone field, so a class keeps its hour across a
// daylight-saving change. The bounds therefore have to be written with
// that zone's offset at that date, not the browser's.

/** safeZone falls back to the browser's zone for the server's "Local"
 *  and for anything Intl does not recognise. tzdata can move underneath
 *  a running browser, and a date box is not worth an exception. */
export function safeZone(zone: string): string {
  const local = (() => {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    } catch {
      return 'UTC';
    }
  })();
  if (!zone || zone === 'Local') return local;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: zone }).format();
    return zone;
  } catch {
    return local;
  }
}

interface ZoneParts {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
}

function zoneParts(zone: string, ms: number): ZoneParts {
  const dtf = new Intl.DateTimeFormat('en-US', {
    timeZone: zone,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
  const out: Record<string, string> = {};
  for (const part of dtf.formatToParts(new Date(ms))) out[part.type] = part.value;
  return {
    year: Number(out.year),
    month: Number(out.month),
    day: Number(out.day),
    hour: Number(out.hour),
    minute: Number(out.minute),
    second: Number(out.second),
  };
}

/** How many minutes ahead of UTC `zone` is at this instant. */
function zoneOffsetMinutes(zone: string, ms: number): number {
  const p = zoneParts(zone, ms);
  const asUTC = Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second);
  return Math.round((asUTC - ms) / 60000);
}

/** The instant at which `zone`'s clocks read this wall time.
 *
 *  Two passes, because the offset depends on the answer: the first
 *  guess uses the offset at the same numbers read as UTC, which is
 *  wrong by at most an hour, and the second uses the offset where that
 *  guess lands. A wall time that a spring-forward skipped has no
 *  instant and comes back as the hour after it. */
function wallToInstant(zone: string, p: ZoneParts): number {
  const naive = Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second);
  const first = naive - zoneOffsetMinutes(zone, naive) * 60000;
  return naive - zoneOffsetMinutes(zone, first) * 60000;
}

function offsetSuffix(minutes: number): string {
  if (minutes === 0) return 'Z';
  const sign = minutes < 0 ? '-' : '+';
  const abs = Math.abs(minutes);
  return `${sign}${pad2(Math.floor(abs / 60))}:${pad2(abs % 60)}`;
}

/** zonedRFC3339 writes a date and time of day in `zone` as the server
 *  reads it: the wall-clock numbers, with the offset that zone was on
 *  that day. Keeping the numbers rather than converting to UTC means an
 *  operator can read back what they typed. */
export function zonedRFC3339(
  date: string,
  time: string,
  zone: string,
  seconds = 0,
): string {
  const d = parseISODate(date);
  const t = parseTimeOfDay(time);
  if (!d || !t) return '';
  const tz = safeZone(zone);
  const parts: ZoneParts = {
    year: d.year,
    month: d.month,
    day: d.day,
    hour: t.hour,
    minute: t.minute,
    second: seconds,
  };
  const instant = wallToInstant(tz, parts);
  const offset = zoneOffsetMinutes(tz, instant);
  return (
    `${date}T${pad2(t.hour)}:${pad2(t.minute)}:${pad2(seconds)}` + offsetSuffix(offset)
  );
}

/** zonedDateTime is the inverse: the date and time of day an instant
 *  falls on in `zone`, for putting a stored bound back in its boxes.
 *  Null for anything that is not a timestamp. */
export function zonedDateTime(
  iso: string,
  zone: string,
): { date: string; time: string } | null {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return null;
  const p = zoneParts(safeZone(zone), ms);
  return {
    date: `${String(p.year).padStart(4, '0')}-${pad2(p.month)}-${pad2(p.day)}`,
    time: `${pad2(p.hour)}:${pad2(p.minute)}`,
  };
}

/** Today's date in `zone`, for the repeats that need one before they
 *  mean anything. */
export function todayInZone(zone: string, now: number = Date.now()): string {
  const p = zoneParts(safeZone(zone), now);
  return `${String(p.year).padStart(4, '0')}-${pad2(p.month)}-${pad2(p.day)}`;
}

/** describeBounds is the one line the list adds under a schedule: what
 *  stops it, when anything does. Empty when nothing does, because a
 *  reservation that runs until somebody deletes it has nothing to say
 *  here. */
export function describeBounds(res: AdminReservation): string {
  const zone = safeZone(res.timezone);
  const day = (iso: string) => {
    const ms = Date.parse(iso);
    if (!Number.isFinite(ms)) return '';
    return new Date(ms).toLocaleDateString(undefined, {
      timeZone: zone,
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };
  const from = res.starts_at ? day(res.starts_at) : '';
  if (res.occurrences === 1) return from ? `once, ${from}` : 'once';
  if (res.occurrences > 1) {
    const count = `${res.occurrences} windows`;
    return from ? `${count} from ${from}` : count;
  }
  const until = res.ends_at ? day(res.ends_at) : '';
  if (from && until) return `${from} – ${until}`;
  if (until) return `until ${until}`;
  if (from) return `from ${from}`;
  return '';
}

/** hasEnded says whether a schedule's end date has already passed. Only
 *  the date bound answers this: a count of windows is resolved by
 *  walking the schedule, which is the server's job and not something to
 *  reimplement for a caption. */
function hasEnded(res: AdminReservation, now: number): boolean {
  if (!res.ends_at) return false;
  const ms = Date.parse(res.ends_at);
  return Number.isFinite(ms) && ms < now;
}

/** whyNoWindows is what a preview with nothing in it means.
 *
 *  An empty list is three different things, and reading them all as
 *  "nothing upcoming" would report a reservation holding capacity right
 *  now as one that does nothing. The kind comes from the preview rather
 *  than from the form, so what is said describes the reservation the
 *  windows were enumerated for. */
export function whyNoWindows(
  kind: ScheduleKind | '' | undefined,
  res: AdminReservation,
  days: number,
  now: number = Date.now(),
): string {
  if (kind === 'always') {
    return 'Capacity is held continuously, so there are no windows to list.';
  }
  if (hasEnded(res, now)) {
    return 'This schedule has ended, so nothing further is held.';
  }
  return `Nothing scheduled in the next ${days} days.`;
}
