'use client';

// "How to read" for this app's charts: a small toggle beside a chart
// that opens a key to its marks, inline. Its swatches are drawn from the
// charts' own tokens, so the key cannot drift from the chart. Each chart
// lists only the marks it can show.
//
// Shared rather than per-chart on purpose: a mark that means "not
// counted" on the job page has to mean that on the dashboard too, and
// has to look the same there. The entries below cover the range plots
// (a job against its peers) and the dashboard calendar (a day's work).

import { useId, useState } from 'react';

import { DAY_RAMP } from '@/lib/calendar';
import { HATCH, RANGE_TOKENS } from './RangePlot';

export type LegendEntry =
  | 'band'
  | 'box'
  | 'tick'
  | 'job'
  | 'jobUnusual'
  | 'rough'
  | 'requested'
  | 'count'
  | 'none'
  | 'uncounted';

// What each mark means, in the user's terms.
export const LEGEND_TEXT: Record<LegendEntry, string> = {
  band: 'Most similar jobs',
  box: 'Half of similar jobs',
  tick: 'Typical',
  job: 'This job',
  jobUnusual: 'This job, unusually high',
  rough: 'Rough guess',
  requested: 'Requested',
  count: 'More jobs, darker',
  none: 'No jobs that day',
  uncounted: 'Not counted',
};

// The order the key lists marks in, whatever order a chart names them.
// The calendar's marks sit before the rough-guess band: a calendar
// names what a square is before it explains which line is a guess, and
// no range plot draws the three of them, so the range plots' own order
// is unchanged.
const ORDER: LegendEntry[] = [
  'band',
  'box',
  'tick',
  'count',
  'none',
  'uncounted',
  'rough',
  'job',
  'jobUnusual',
  'requested',
];

// Swatch is one mark in miniature, 20px wide.
export function Swatch({ entry }: { entry: LegendEntry }) {
  const frame = 'relative inline-block h-3.5 w-5 shrink-0 align-middle';
  const band = `absolute inset-x-0 top-[3px] h-2 rounded-full`;
  const tick = 'absolute left-1/2 top-0 h-3.5 w-[3px] -translate-x-1/2 rounded-full';
  switch (entry) {
    case 'band':
      return (
        <span className={frame} data-swatch="band">
          <span className={`${band} ${RANGE_TOKENS.band}`} />
        </span>
      );
    case 'box':
      return (
        <span className={frame} data-swatch="box">
          <span className={`${band} ${RANGE_TOKENS.band}`} />
          <span className={`absolute inset-x-1 top-[3px] h-2 rounded-sm ${RANGE_TOKENS.box}`} />
        </span>
      );
    case 'tick':
      return (
        <span className={frame} data-swatch="tick">
          <span className={`${tick} ${RANGE_TOKENS.tick}`} />
        </span>
      );
    case 'rough':
      return (
        <span className={frame} data-swatch="rough">
          <span className={band} style={{ backgroundImage: HATCH }} />
          <span className={`${tick} ${RANGE_TOKENS.tickRough}`} />
        </span>
      );
    case 'job':
    case 'jobUnusual': {
      const fill = entry === 'job' ? RANGE_TOKENS.job : RANGE_TOKENS.jobUnusual;
      return (
        <span className={frame} data-swatch={entry}>
          <span className={`absolute left-0 right-1.5 top-[5px] h-1 rounded-full ${fill}`} />
          <span className={`absolute right-0 top-[2px] size-2.5 rounded-full ${fill}`} />
        </span>
      );
    }
    case 'requested':
      return (
        <span className={frame} data-swatch="requested">
          <span className={`absolute left-1/2 top-0 h-3.5 border-l border-dashed ${RANGE_TOKENS.ref}`} />
        </span>
      );
    // The calendar's marks. A day is a square, so these are squares --
    // the shape says which chart the key belongs to, while the fills are
    // the same ones everything else uses for an amount and for a figure
    // nobody counted.
    case 'count':
      return (
        <span className={frame} data-swatch="count">
          <span
            className="absolute inset-y-0 left-0 w-3.5 rounded-[2px]"
            style={{
              backgroundImage: `linear-gradient(to right, ${DAY_RAMP.map(
                (c, i) => `${c} ${(i * 100) / DAY_RAMP.length}% ${((i + 1) * 100) / DAY_RAMP.length}%`,
              ).join(', ')})`,
            }}
          />
        </span>
      );
    case 'none':
      return (
        <span className={frame} data-swatch="none">
          <span className="absolute inset-y-0 left-0 w-3.5 rounded-[2px] bg-gray-100 ring-1 ring-inset ring-gray-200" />
        </span>
      );
    case 'uncounted':
      return (
        <span className={frame} data-swatch="uncounted">
          <span
            className="absolute inset-y-0 left-0 w-3.5 rounded-[2px]"
            style={{ backgroundImage: HATCH }}
          />
        </span>
      );
  }
}

// RangeLegend is the key itself: one row per mark, wrapping on a narrow
// screen.
export function RangeLegend({ entries, id }: { entries: readonly LegendEntry[]; id?: string }) {
  const shown = ORDER.filter((e) => entries.includes(e));
  return (
    <ul id={id} data-testid="range-legend" className="flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-gray-600">
      {shown.map((e) => (
        <li key={e} className="inline-flex items-center gap-1.5" data-entry={e}>
          <Swatch entry={e} />
          {LEGEND_TEXT[e]}
        </li>
      ))}
    </ul>
  );
}

// HowToRead is the "How to read" toggle and, once opened, the key under
// it.
export function HowToRead({ entries }: { entries: readonly LegendEntry[] }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  if (entries.length === 0) return null;
  return (
    <div className="text-xs" data-testid="how-to-read">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen((v) => !v)}
        className="text-brand-700 underline decoration-dotted underline-offset-2 hover:decoration-solid"
      >
        How to read
      </button>
      {open && (
        <div className="mt-1.5 rounded-sm bg-gray-50 px-2 py-1.5">
          <RangeLegend entries={entries} id={id} />
        </div>
      )}
    </div>
  );
}

// chartEntries is the key for a chart from what it draws: the band and
// typical tick (or, for a rough guess, the hatched band in their place),
// the middle half when it has one, this job when it is drawn -- with its
// unusual colour where the chart can show that -- and the request.
export function chartEntries(c: {
  box?: boolean;
  rough?: boolean;
  job?: boolean;
  canBeUnusual?: boolean;
  requested?: boolean;
}): LegendEntry[] {
  const out: LegendEntry[] = c.rough ? ['rough'] : ['band', 'tick'];
  if (c.box) out.push('box');
  if (c.job) {
    out.push('job');
    if (c.canBeUnusual) out.push('jobUnusual');
  }
  if (c.requested) out.push('requested');
  return out;
}
