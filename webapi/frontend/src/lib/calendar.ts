// The dashboard calendar's arithmetic, kept out of the component.
//
// A calendar of days is mostly bookkeeping -- which cell is which day,
// which days the server did not answer for, how dark a cell should be --
// and all of it is worth testing without rendering anything.
//
// Two things run through this file.
//
// Days are UTC days, because that is how the server buckets them. A
// cell rendered in the reader's own timezone would name a day the count
// does not cover: the bucket starting midnight UTC is "yesterday
// evening" in Chicago, and labelling it so would quietly shift every
// figure by a day. So every label here is formatted in UTC and the
// panel says the days are UTC.
//
// A day with no jobs and a day with no answer are different facts. The
// server sends an all-zero day for the first; the second is a day
// missing from the response, and it gets a mark of its own rather than
// reading as a quiet Tuesday.

import type { CalendarDay } from '@/lib/api';
import { archiveDrilldown, jobsDrilldown } from '@/lib/drilldown';

export const DAY_SECONDS = 86400;

// How much window to ask for. Long enough that a month-long campaign is
// a shape rather than a few cells, short enough to stay one screen wide.
export const CALENDAR_DAYS = 90;

/** The three things that happened to jobs on a day. Flows, in the sense
 *  that each is a count of events in that day -- as opposed to in_queue,
 *  which is a level and is not measured at all. */
export type Flow = 'submitted' | 'completed' | 'removed';

export interface FlowSpec {
  key: Flow;
  /** The facet's title. */
  title: string;
  /** "120 jobs <past>", for a cell's hover text and its label. */
  past: string;
}

// Submitted first, then the two ways work leaves: read left to right,
// that is the order a job goes through.
export const FLOWS: readonly FlowSpec[] = [
  { key: 'submitted', title: 'Submitted', past: 'submitted' },
  { key: 'completed', title: 'Finished', past: 'finished' },
  { key: 'removed', title: 'Removed', past: 'removed' },
] as const;

/** One square in the grid.
 *
 *  `counts` is null for a day inside the window that the server did not
 *  report -- the gap case, drawn as a gap rather than as a zero. */
export interface CalendarCell {
  day: number;
  counts: CalendarDay | null;
}

/** A column of the grid: seven slots, Monday at the top. A null slot is
 *  a day outside the window, which is padding rather than data -- the
 *  window rarely starts on a Monday. */
export type CalendarWeek = (CalendarCell | null)[];

// weekdayIndex puts Monday at 0, so a week reads Monday to Sunday down a
// column. UTC, like every other date decision here.
export function weekdayIndex(day: number): number {
  return (new Date(day * 1000).getUTCDay() + 6) % 7;
}

/** buildWeeks lays the reported days out as calendar columns.
 *
 *  The first and last columns are padded out to whole weeks so the grid
 *  is a rectangle; the padding slots are null and draw nothing, which is
 *  how a day before the window reads as "not asked about" rather than as
 *  a day with no jobs. */
export function buildWeeks(days: readonly CalendarDay[]): CalendarWeek[] {
  if (days.length === 0) return [];
  const byDay = new Map<number, CalendarDay>();
  for (const d of days) byDay.set(d.day, d);
  const first = days[0].day;
  const last = days[days.length - 1].day;
  const start = first - weekdayIndex(first) * DAY_SECONDS;
  const end = last + (6 - weekdayIndex(last)) * DAY_SECONDS;

  const weeks: CalendarWeek[] = [];
  for (let d = start; d <= end; d += 7 * DAY_SECONDS) {
    const week: CalendarWeek = [];
    for (let i = 0; i < 7; i++) {
      const day = d + i * DAY_SECONDS;
      week.push(day < first || day > last ? null : { day, counts: byDay.get(day) ?? null });
    }
    weeks.push(week);
  }
  return weeks;
}

/** monthLabels names the month at each column that starts one.
 *
 *  A label per column would repeat "Oct" four times; this labels the
 *  first column of each month and leaves the rest empty, which is enough
 *  to find August in a quarter of squares. */
export function monthLabels(weeks: readonly CalendarWeek[]): string[] {
  let previous = '';
  return weeks.map((week) => {
    const cell = week.find((c) => c !== null);
    if (!cell) return '';
    const month = formatUTC(cell.day, { month: 'short' });
    if (month === previous) return '';
    previous = month;
    return month;
  });
}

/** The largest single day in the window, across every flow.
 *
 *  One scale for all three grids: the question the panel answers is
 *  whether as much work finished as arrived, and per-grid scales would
 *  make a day of 10 completions look exactly like a day of 10,000
 *  submissions. */
export function flowPeak(days: readonly CalendarDay[]): number {
  let peak = 0;
  for (const d of days) {
    peak = Math.max(peak, d.submitted, d.completed, d.removed);
  }
  return peak;
}

// The ramp: the blues RangePlot and the utilization charts already use
// for "an amount" (box, used, tick), light to dark, with one documented
// step between the first two. One hue, four steps -- more jobs, darker
// -- so a cell's colour can never be read as a category.
//
// It starts at a step that is clearly blue against the page rather than
// at the palest one. The palest blue is hard to tell from an empty cell
// at this size, and "one job" and "no jobs" are exactly the two a
// calendar must not blur.
export const DAY_RAMP = ['#86b6ef', '#5598e7', '#2a78d6', '#1f5fbf'] as const;

// A day with jobs on it but nothing to speak of is still a day with
// jobs: the lightest step is reserved for it rather than for zero, so a
// single job in a window that peaked at four thousand is visible. (The
// same floor Sparkline keeps for a one-pixel bar.) Zero wears no ramp
// step at all -- see the component.
export function rampStep(n: number, peak: number): number {
  if (n <= 0) return 0;
  if (peak <= 0) return 1;
  // Log, not linear: an access point's day is either idle or a burst,
  // and against a 40,000-job burst a linear ramp paints every ordinary
  // day the same lightest blue.
  const f = Math.log1p(n) / Math.log1p(peak);
  return Math.min(DAY_RAMP.length, Math.max(1, Math.ceil(f * DAY_RAMP.length)));
}

/** The colour for a cell with `n` jobs on it, or null for zero. */
export function rampColor(n: number, peak: number): string | null {
  const step = rampStep(n, peak);
  return step === 0 ? null : DAY_RAMP[step - 1];
}

// formatUTC renders a day in the timezone the buckets are in. Not the
// reader's: see the header.
export function formatUTC(day: number, opts: Intl.DateTimeFormatOptions): string {
  return new Date(day * 1000).toLocaleDateString(undefined, { timeZone: 'UTC', ...opts });
}

/** A day, spelled out: "Wed, Oct 14, 2026". */
export function dayLabel(day: number): string {
  return formatUTC(day, { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' });
}

/** What a cell says when you hover it or read it aloud. */
export function cellLabel(flow: FlowSpec, cell: CalendarCell): string {
  const when = dayLabel(cell.day);
  if (!cell.counts) {
    // Not "0 jobs": nobody counted this day, and saying zero would be a
    // confident wrong answer.
    return `${when}: not counted`;
  }
  const n = cell.counts[flow.key];
  if (n === 0) return `${when}: no jobs ${flow.past}`;
  return `${when}: ${n.toLocaleString()} ${n === 1 ? 'job' : 'jobs'} ${flow.past}`;
}

/** dayHref is the link from one square to the jobs behind it.
 *
 *  Each constraint asks the same question the square answered, bounded
 *  by the same day -- a list whose length disagrees with the number that
 *  was clicked reads as a bug in the data rather than as a difference of
 *  definition.
 *
 *  Which page it asks is the other half. A finished job lives in the
 *  queue for seconds and in the archive thereafter, so everything about
 *  finished work goes to /archive; only jobs submitted during the day
 *  still in progress are reliably still in the queue, and those go to
 *  /jobs. (A job submitted three weeks ago and still idle is in neither
 *  place's answer for that day, which is the one count on the calendar
 *  no single page can reproduce exactly.)
 *
 *  Returns null where there is nothing to look at: a day with no jobs
 *  has no list, and a link to an empty list is worse than no link. */
export function dayHref(
  flow: Flow,
  cell: CalendarCell,
  opts: { inProgress: boolean },
): string | null {
  if (!cell.counts || cell.counts[flow] <= 0) return null;
  const from = cell.day;
  const to = cell.day + DAY_SECONDS;
  const when = dayLabel(cell.day);
  switch (flow) {
    case 'submitted': {
      const constraint = `QDate >= ${from} && QDate < ${to}`;
      const why = `jobs submitted ${when}`;
      return opts.inProgress
        ? jobsDrilldown(constraint, why)
        : archiveDrilldown(constraint, why);
    }
    case 'completed':
      return archiveDrilldown(
        `JobStatus == 4 && CompletionDate >= ${from} && CompletionDate < ${to}`,
        `jobs that finished ${when}`,
      );
    case 'removed':
      // EnteredCurrentStatus, not CompletionDate: a removed job often
      // has no completion date at all, and matching on one would select
      // none of them.
      return archiveDrilldown(
        `JobStatus == 3 && EnteredCurrentStatus >= ${from} && EnteredCurrentStatus < ${to}`,
        `jobs removed ${when}`,
      );
  }
}

/** The whole window's total for one flow, for the figure beside a grid's
 *  title. A calendar shows shape; the total is the number. */
export function flowTotal(days: readonly CalendarDay[], flow: Flow): number {
  return days.reduce((sum, d) => sum + (d[flow] ?? 0), 0);
}

/** True when any day inside the window went unanswered. The gap mark
 *  only appears in the key when the calendar can actually show one. */
export function hasGaps(weeks: readonly CalendarWeek[]): boolean {
  return weeks.some((w) => w.some((c) => c !== null && c.counts === null));
}

/** Every day in the window in order, gaps included.
 *
 *  Built from the laid-out weeks rather than from the response so a day
 *  the server did not answer for is a row in the table view too. A gap
 *  that is visible as a square and absent from the text would be a
 *  reader's only clue disappearing the moment they look for the number.
 */
export function allCells(weeks: readonly CalendarWeek[]): CalendarCell[] {
  const out: CalendarCell[] = [];
  for (const week of weeks) {
    for (const cell of week) {
      if (cell) out.push(cell);
    }
  }
  return out;
}
