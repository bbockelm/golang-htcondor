import { describe, expect, it } from 'vitest';

import type { CalendarDay } from '@/lib/api';
import {
  DAY_SECONDS,
  allCells,
  buildWeeks,
  cellLabel,
  dayHref,
  flowPeak,
  flowTotal,
  hasGaps,
  monthLabels,
  rampStep,
  FLOWS,
  type CalendarCell,
} from '@/lib/calendar';

// Every date here is absolute. A fixture built from "now" makes the
// weekday a window starts on depend on the day the suite runs, and the
// whole layout -- which column a day lands in, where the padding is --
// is a function of that.
//
// Mon 3 Aug 2026, midnight UTC.
const MONDAY = 1785715200;
// Wed 14 Oct 2026, midnight UTC.
const WEDNESDAY = 1791936000;

function day(at: number, over: Partial<CalendarDay> = {}): CalendarDay {
  return { day: at, submitted: 0, completed: 0, removed: 0, in_queue: 0, ...over };
}

const SUBMITTED = FLOWS[0];

describe('buildWeeks', () => {
  it('pads the first and last columns out to whole weeks', () => {
    // Ten days from a Wednesday: two columns, with Monday and Tuesday
    // of the first missing and the weekend of the last.
    const weeks = buildWeeks(
      Array.from({ length: 10 }, (_, i) => day(WEDNESDAY + i * DAY_SECONDS)),
    );
    expect(weeks).toHaveLength(2);
    expect(weeks[0].slice(0, 2)).toEqual([null, null]);
    // The padding is null rather than a zero day: nobody asked about the
    // Monday before the window, so it must not render as a quiet Monday.
    expect(weeks[0][2]?.day).toBe(WEDNESDAY);
    expect(weeks[1].slice(5)).toEqual([null, null]);
  });

  it('starts a column on Monday when the window does', () => {
    const weeks = buildWeeks(Array.from({ length: 7 }, (_, i) => day(MONDAY + i * DAY_SECONDS)));
    expect(weeks).toHaveLength(1);
    expect(weeks[0].every((c) => c !== null)).toBe(true);
    expect(weeks[0][0]?.day).toBe(MONDAY);
  });

  it('marks a day the server did not answer for', () => {
    // The contract sends every day in the window, zeros included, so a
    // day that is missing means nobody counted it -- a different fact
    // from "nothing happened", and it gets its own cell state.
    const weeks = buildWeeks([
      day(MONDAY, { submitted: 3 }),
      day(MONDAY + 2 * DAY_SECONDS, { submitted: 5 }),
    ]);
    const cells = allCells(weeks);
    expect(cells.map((c) => c.counts !== null)).toEqual([true, false, true]);
    expect(hasGaps(weeks)).toBe(true);
  });

  it('reports no gaps for a window with a zero day in it', () => {
    const weeks = buildWeeks([
      day(MONDAY, { submitted: 3 }),
      day(MONDAY + DAY_SECONDS),
      day(MONDAY + 2 * DAY_SECONDS, { submitted: 5 }),
    ]);
    expect(hasGaps(weeks)).toBe(false);
  });

  it('is empty for an empty window', () => {
    expect(buildWeeks([])).toEqual([]);
  });
});

describe('monthLabels', () => {
  it('names a month once, at the column it starts in', () => {
    const weeks = buildWeeks(
      Array.from({ length: 70 }, (_, i) => day(MONDAY + i * DAY_SECONDS)),
    );
    const labels = monthLabels(weeks).filter(Boolean);
    expect(labels).toEqual(['Aug', 'Sep', 'Oct']);
  });
});

describe('rampStep', () => {
  it('gives zero its own step, outside the ramp', () => {
    expect(rampStep(0, 4000)).toBe(0);
  });

  it('keeps a single job visible against a burst', () => {
    // The day one job ran must not come out the same as the day none
    // did, however big the window's peak is.
    expect(rampStep(1, 40_000)).toBeGreaterThan(0);
  });

  it('puts the peak at the darkest step and never past it', () => {
    expect(rampStep(4000, 4000)).toBe(4);
    expect(rampStep(9000, 4000)).toBe(4);
  });

  it('never goes backwards as the count rises', () => {
    const steps = [1, 10, 100, 1000, 4000].map((n) => rampStep(n, 4000));
    expect(steps).toEqual([...steps].sort((a, b) => a - b));
  });
});

describe('flowPeak and flowTotal', () => {
  it('scales all three flows together', () => {
    // One scale across the grids is what makes "more arrived than left"
    // readable; a per-grid peak would paint 10 completions and 10,000
    // submissions the same shade.
    const days = [day(MONDAY, { submitted: 10, completed: 900 }), day(MONDAY + DAY_SECONDS, { removed: 4 })];
    expect(flowPeak(days)).toBe(900);
    expect(flowTotal(days, 'submitted')).toBe(10);
    expect(flowTotal(days, 'removed')).toBe(4);
  });
});

describe('cellLabel', () => {
  it('says a counted zero is a zero', () => {
    const cell: CalendarCell = { day: WEDNESDAY, counts: day(WEDNESDAY) };
    expect(cellLabel(SUBMITTED, cell)).toBe('Wed, Oct 14, 2026: no jobs submitted');
  });

  it('says an uncounted day is uncounted', () => {
    expect(cellLabel(SUBMITTED, { day: WEDNESDAY, counts: null })).toBe(
      'Wed, Oct 14, 2026: not counted',
    );
  });

  it('names the day in UTC, which is how the counts are bucketed', () => {
    const cell: CalendarCell = { day: WEDNESDAY, counts: day(WEDNESDAY, { submitted: 12 }) };
    // Not the reader's timezone: midnight UTC is the previous evening in
    // Chicago, and labelling the bucket "Oct 13" would move every figure
    // a day.
    expect(cellLabel(SUBMITTED, cell)).toBe('Wed, Oct 14, 2026: 12 jobs submitted');
  });
});

describe('dayHref', () => {
  const counted = (over: Partial<CalendarDay>): CalendarCell => ({
    day: WEDNESDAY,
    counts: day(WEDNESDAY, over),
  });
  const bounds = `>= ${WEDNESDAY} && `;

  it('sends a past day of submissions to the archive, bounded by that day', () => {
    const href = dayHref('submitted', counted({ submitted: 7 }), { inProgress: false });
    expect(href).toContain('/archive?constraint=');
    const constraint = decodeURIComponent(new URL(href!, 'http://x').searchParams.get('constraint')!);
    // The same question the square answered, one day wide: a list whose
    // length disagrees with the number clicked reads as a data bug.
    expect(constraint).toBe(`QDate ${bounds}QDate < ${WEDNESDAY + DAY_SECONDS}`);
  });

  it('sends the day in progress to the queue instead', () => {
    // Jobs submitted today are still in the queue; the archive does not
    // have them yet.
    const href = dayHref('submitted', counted({ submitted: 7 }), { inProgress: true });
    expect(href).toContain('/jobs?constraint=');
  });

  it('sends finished work to the archive, never to the queue', () => {
    // A finished job lives in the queue for seconds and in the archive
    // thereafter, so /jobs would land on "not found".
    const href = dayHref('completed', counted({ completed: 3 }), { inProgress: true })!;
    expect(href.startsWith('/archive?')).toBe(true);
    const constraint = decodeURIComponent(new URL(href, 'http://x').searchParams.get('constraint')!);
    expect(constraint).toBe(
      `JobStatus == 4 && CompletionDate ${bounds}CompletionDate < ${WEDNESDAY + DAY_SECONDS}`,
    );
  });

  it('matches removed jobs on when they were removed', () => {
    // A removed job often has no CompletionDate at all, so matching on
    // one would select none of them.
    const href = dayHref('removed', counted({ removed: 2 }), { inProgress: false })!;
    const constraint = decodeURIComponent(new URL(href, 'http://x').searchParams.get('constraint')!);
    expect(constraint).toBe(
      `JobStatus == 3 && EnteredCurrentStatus ${bounds}EnteredCurrentStatus < ${
        WEDNESDAY + DAY_SECONDS
      }`,
    );
  });

  it('has no link for a day with nothing on it', () => {
    // A link to an empty list is worse than no link.
    expect(dayHref('submitted', counted({ submitted: 0 }), { inProgress: false })).toBeNull();
    expect(dayHref('submitted', { day: WEDNESDAY, counts: null }, { inProgress: false })).toBeNull();
  });

  it('says what the drill-down was for', () => {
    const href = dayHref('completed', counted({ completed: 3 }), { inProgress: false })!;
    expect(new URL(href, 'http://x').searchParams.get('why')).toBe(
      'jobs that finished Wed, Oct 14, 2026',
    );
  });
});
