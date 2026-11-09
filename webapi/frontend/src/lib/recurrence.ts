// A reservation's schedule, as a calendar asks for it rather than as
// cron states it.
//
// The schedule on the wire is a five-field cron expression, and the
// server is the authority on what one may be. Nothing here parses cron
// so the page can validate it; it parses cron so the page can offer a
// recurrence picker over it, the way a calendar does: a start, a
// repeat, and an end.
//
// Two rules run through the whole file, and both exist to keep the
// picker from quietly rewriting a schedule somebody typed.
//
//   * The picker is only ever shown over a cron it can reproduce
//     exactly. `adoptCron` parses an expression, builds the picker
//     state it implies, regenerates the cron from that state, and
//     refuses the whole thing unless the result is the original string
//     byte for byte. So `0 14 * * 3,1` and `0  14 * * 1,3` both fall
//     through to the cron box: the picker would render them as
//     `0 14 * * 1,3`, and opening a reservation and pressing Save is
//     not an invitation to renumber its schedule.
//   * Anything the picker cannot say, it declines to say. There is no
//     every-other-week option because five-field cron has no way to
//     express one -- `*/2` on the day-of-week field means "every other
//     weekday", not "every other week" -- and an option that generated
//     a schedule the operator did not ask for would be worse than no
//     option.
//
// The bounds are separate from the recurrence. `starts_at`, `ends_at`
// and `occurrences` are limits on a cron that otherwise runs forever;
// they are not in the expression and cannot be, so an operator can set
// them over a hand-written cron just as well as over a picked one.

import type { AdminReservation } from '@/lib/api';

/** How a schedule repeats. `never` is one window and then nothing,
 *  which cron reaches only with a bound of one occurrence. */
export type RepeatMode = 'never' | 'daily' | 'weekly' | 'monthly';

/** When a schedule stops: never, on a date, or after a count. The three
 *  are exclusive because the server refuses two bounds at once. */
export type EndMode = 'never' | 'on' | 'after';

export interface Recurrence {
  /** `YYYY-MM-DD` in the reservation's zone, or "" for no start bound. */
  startDate: string;
  /** `HH:MM`, 24-hour, in the reservation's zone. This is the cron's
   *  minute and hour, not merely a bound. */
  startTime: string;
  repeat: RepeatMode;
  /** Days a weekly schedule fires on, 0 = Sunday through 6 = Saturday. */
  weekdays: number[];
  end: EndMode;
  /** `YYYY-MM-DD`, used when `end` is `on`. */
  endDate: string;
  /** Used when `end` is `after`. */
  occurrences: number;
}

/** The shape a cron expression has, when it has one the picker knows.
 *  `dayOfMonth` and `month` are null for the repeats that do not pin
 *  them. */
export interface CronShape {
  time: string;
  repeat: RepeatMode;
  weekdays: number[];
  dayOfMonth: number | null;
  month: number | null;
}

/** The three wire fields that bound a schedule. */
export interface RecurrenceBounds {
  starts_at: string;
  ends_at: string;
  occurrences: number;
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

/** recurrenceToCron renders picker state as the expression that fires
 *  it, or null when the state does not describe a schedule yet -- a
 *  weekly repeat with no day ticked, a monthly one with no date to take
 *  the day of the month from. Null is a schedule the page leaves blank
 *  rather than a guess. */
export function recurrenceToCron(r: Recurrence): string | null {
  const t = parseTimeOfDay(r.startTime);
  if (!t) return null;
  const hm = `${t.minute} ${t.hour}`;
  switch (r.repeat) {
    case 'daily':
      return `${hm} * * *`;
    case 'weekly': {
      const days = [...new Set(r.weekdays)].sort((a, b) => a - b);
      if (days.length === 0) return null;
      if (days.some((d) => !Number.isInteger(d) || d < 0 || d > 6)) return null;
      return `${hm} * * ${days.join(',')}`;
    }
    case 'monthly': {
      const d = parseISODate(r.startDate);
      if (!d) return null;
      return `${hm} ${d.day} * *`;
    }
    case 'never': {
      // One window, pinned to its own date. Cron cannot say "once", so
      // the expression repeats annually and the bound of a single
      // occurrence is what actually stops it -- see recurrenceToBounds.
      const d = parseISODate(r.startDate);
      if (!d) return null;
      return `${hm} ${d.day} ${d.month} *`;
    }
  }
}

function parseField(field: string, min: number, max: number): number | null {
  if (!/^\d{1,2}$/.test(field)) return null;
  const n = Number(field);
  return n >= min && n <= max ? n : null;
}

/** parseCron recognises the handful of shapes the picker can draw, and
 *  returns null for every other legal expression.
 *
 *  It is deliberately strict about spelling as well as meaning. `7` and
 *  `SUN` both name Sunday to cron and neither is accepted, because the
 *  picker would redraw them as `0`; a step expression such as every
 *  fifteenth minute is a perfectly good schedule the picker has no
 *  control for. All of those keep their cron box. */
export function parseCron(cron: string): CronShape | null {
  const fields = cron.trim().split(/\s+/);
  if (fields.length !== 5) return null;
  const [minField, hourField, domField, monthField, dowField] = fields;

  const minute = parseField(minField, 0, 59);
  const hour = parseField(hourField, 0, 23);
  if (minute === null || hour === null) return null;
  const time = `${pad2(hour)}:${pad2(minute)}`;

  const anyDom = domField === '*';
  const anyMonth = monthField === '*';
  const anyDow = dowField === '*';

  if (anyDom && anyMonth && anyDow) {
    return { time, repeat: 'daily', weekdays: [], dayOfMonth: null, month: null };
  }
  if (anyDom && anyMonth && !anyDow) {
    const parts = dowField.split(',');
    const days: number[] = [];
    for (const part of parts) {
      const d = parseField(part, 0, 6);
      if (d === null) return null;
      days.push(d);
    }
    // Ascending only: the picker has no way to show an order, so it
    // would redraw `3,1` as `1,3`.
    for (let i = 1; i < days.length; i++) {
      if (days[i] <= days[i - 1]) return null;
    }
    return { time, repeat: 'weekly', weekdays: days, dayOfMonth: null, month: null };
  }
  if (!anyDom && anyMonth && anyDow) {
    const day = parseField(domField, 1, 31);
    if (day === null) return null;
    return { time, repeat: 'monthly', weekdays: [], dayOfMonth: day, month: null };
  }
  if (!anyDom && !anyMonth && anyDow) {
    const day = parseField(domField, 1, 31);
    const month = parseField(monthField, 1, 12);
    if (day === null || month === null) return null;
    return { time, repeat: 'never', weekdays: [], dayOfMonth: day, month };
  }
  return null;
}

/** adoptCron merges a stored expression into picker state, or returns
 *  null when the picker cannot reproduce it exactly.
 *
 *  The regeneration check at the end is the whole point: without it the
 *  picker would open on an approximation of the stored schedule and
 *  write the approximation back on the next save. */
export function adoptCron(cron: string, base: Recurrence): Recurrence | null {
  const shape = parseCron(cron);
  if (!shape) return null;
  const next: Recurrence = {
    ...base,
    startTime: shape.time,
    repeat: shape.repeat,
    weekdays: shape.weekdays,
  };
  if (shape.dayOfMonth !== null) {
    // A monthly or one-off expression takes its day from the start
    // date. With no start date, or one that disagrees, the picker has
    // nowhere to show the day it would fire on.
    const d = parseISODate(next.startDate);
    if (!d || d.day !== shape.dayOfMonth) return null;
    if (shape.month !== null && d.month !== shape.month) return null;
  }
  return recurrenceToCron(next) === cron.trim() ? next : null;
}

/** recurrenceToBounds maps the start and end controls onto the three
 *  wire fields, in `zone`.
 *
 *  Only one of `ends_at` and `occurrences` is ever set, which is what
 *  the server requires; the end control is a radio group for that
 *  reason.
 *
 *  There is no special case for a schedule that does not repeat. Its
 *  bound of one occurrence is set when the operator picks that repeat
 *  (see `withRecurrence`), so it is state the picker shows rather than
 *  something this function infers -- which keeps it correct for a
 *  hand-written expression too. */
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

/** initialRecurrence is what the form opens on: the picker state a
 *  stored reservation implies, and whether its schedule has to stay in
 *  the cron box.
 *
 *  `custom` means the expression is beyond the picker, so the picker is
 *  shown read-only and the cron box is the control. A reservation with
 *  no schedule at all is not custom -- it is a new one, and the picker
 *  is exactly what it wants. */
export function initialRecurrence(res: AdminReservation): {
  rec: Recurrence;
  custom: boolean;
} {
  const zone = res.timezone;
  const start = res.starts_at ? zonedDateTime(res.starts_at, zone) : null;
  const end = res.ends_at ? zonedDateTime(res.ends_at, zone) : null;
  const base: Recurrence = {
    startDate: start?.date ?? '',
    startTime: start?.time ?? DEFAULT_START_TIME,
    repeat: 'weekly',
    weekdays: [],
    endDate: end?.date ?? '',
    end: res.ends_at ? 'on' : res.occurrences > 0 ? 'after' : 'never',
    occurrences: res.occurrences > 0 ? res.occurrences : 1,
  };
  if (!res.schedule.trim()) return { rec: base, custom: false };

  const adopted = adoptCron(res.schedule, base);
  if (!adopted) return { rec: base, custom: true };
  // A one-off that is not bounded to one window is not a one-off: the
  // annual expression behind it fires again next year. Showing it as
  // "does not repeat" would make the next save impose a bound nobody
  // asked for.
  if (adopted.repeat === 'never' && res.occurrences !== 1) {
    return { rec: base, custom: true };
  }
  return { rec: adopted, custom: false };
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

/** Today's date in `zone`, for the modes that need a date before they
 *  mean anything. */
export function todayInZone(zone: string, now: number = Date.now()): string {
  const p = zoneParts(safeZone(zone), now);
  return `${String(p.year).padStart(4, '0')}-${pad2(p.month)}-${pad2(p.day)}`;
}

/** describeBounds is the one line the table adds under a schedule: what
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

// --- The draft the form holds ---
//
// The picker and the cron box are two views of one schedule, and which
// of them is in charge is part of the state rather than something
// inferred on each render. Inferring it is how a picker ends up
// redrawing an expression somebody typed.

export interface ScheduleDraft {
  rec: Recurrence;
  /** What goes on the wire, and what the cron box shows. */
  cron: string;
  /** True while the cron box is in charge: the repeat controls are
   *  shown but read-only, and nothing regenerates the expression. */
  custom: boolean;
}

/** draftFromReservation opens the form on a stored reservation. */
export function draftFromReservation(res: AdminReservation): ScheduleDraft {
  const { rec, custom } = initialRecurrence(res);
  return { rec, cron: res.schedule, custom };
}

/** withRecurrence applies a change made in the picker.
 *
 *  The start date and the end bound stay live even in custom mode,
 *  because they are bounds on the expression rather than part of it:
 *  an operator who hand-wrote a cron can still say when it stops. The
 *  repeat and the time of day are the expression, so in custom mode a
 *  change to them changes nothing. */
export function withRecurrence(
  d: ScheduleDraft,
  rec: Recurrence,
  zone: string,
): ScheduleDraft {
  if (d.custom) return { ...d, rec };
  let next = rec;
  // Monthly and one-off schedules take their day from the start date.
  // Without one they generate nothing at all, so the date is filled in
  // where the operator can see it rather than left blank.
  if ((next.repeat === 'monthly' || next.repeat === 'never') && !next.startDate) {
    next = { ...next, startDate: todayInZone(zone) };
  }
  if (next.repeat === 'never') {
    next = { ...next, end: 'after', occurrences: 1 };
  }
  return { rec: next, cron: recurrenceToCron(next) ?? '', custom: false };
}

/** withCron is a hand-typed expression taking over. */
export function withCron(d: ScheduleDraft, cron: string): ScheduleDraft {
  return { rec: d.rec, cron, custom: true };
}

/** withPicker hands control back to the picker.
 *
 *  This is the only thing that overwrites a typed expression, and it
 *  happens because somebody pressed the control that says so. The
 *  picker adopts the typed cron where it can, so switching back keeps
 *  a schedule that was merely typed rather than picked. */
export function withPicker(d: ScheduleDraft, zone: string): ScheduleDraft {
  const rec = adoptCron(d.cron, d.rec) ?? d.rec;
  return withRecurrence({ rec, cron: d.cron, custom: false }, rec, zone);
}
