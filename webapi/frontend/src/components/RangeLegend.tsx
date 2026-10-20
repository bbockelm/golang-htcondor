'use client';

// "How to read" for the charts RangePlot draws: a small toggle beside a
// chart that opens a key to its marks, inline. Its swatches are drawn
// from RangePlot's own tokens, so the key cannot drift from the chart.
// Each chart lists only the marks it can show.

import { useId, useState } from 'react';

import { HATCH, RANGE_TOKENS } from './RangePlot';

export type LegendEntry = 'band' | 'box' | 'tick' | 'job' | 'jobUnusual' | 'rough' | 'requested';

// What each mark means, in the user's terms.
export const LEGEND_TEXT: Record<LegendEntry, string> = {
  band: 'Most similar jobs',
  box: 'Half of similar jobs',
  tick: 'Typical',
  job: 'This job',
  jobUnusual: 'This job, unusually high',
  rough: 'Rough guess',
  requested: 'Requested',
};

// The order the key lists marks in, whatever order a chart names them.
const ORDER: LegendEntry[] = ['band', 'box', 'tick', 'rough', 'job', 'jobUnusual', 'requested'];

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
