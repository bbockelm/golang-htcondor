// RangePlot draws one job against its similar jobs on an axis from zero.
// Every such chart -- the run time and memory cards, the similar-jobs
// plots, the jobs listing's small bars -- is drawn by it, so they share
// one set of marks:
//
//   - a grey track from zero;
//   - a light-blue band where most similar jobs land;
//   - a medium-blue box inside it over the middle half, where the chart
//     has one;
//   - a dark-blue tick at the typical value;
//   - this job as a green fill from zero ending in a dot, amber when it
//     is unusual (running longer, or using more memory, than usual);
//   - a rough guess as a hatched band and a grey tick;
//   - dashed grey reference lines with their labels (a request).
//
// It is decorative: the text beside it states every figure it draws, so
// it is hidden from assistive technology. The difference between rough
// and not, and usual and not, never rests on colour alone: the text says
// so too. RangeLegend (the "How to read" legend) draws its swatches from
// the same tokens.
//
// The job's fill is drawn over the band, thinner than it, so the band
// stays visible around a job that has gone past it.

import type { ReactNode } from 'react';

// The marks' colours, shared with RangeLegend and the other charts that
// draw a range (PoolDrain's timeline).
export const RANGE_TOKENS = {
  track: 'bg-gray-200',
  band: 'bg-[#cde2fb]',
  box: 'bg-[#86b6ef]',
  tick: 'bg-[#1f5fbf]',
  tickRough: 'bg-gray-500',
  job: 'bg-green-700',
  jobUnusual: 'bg-amber-600',
  ref: 'border-gray-500',
} as const;

// Stripes for a rough guess's band: two greys, wide enough to read as a
// pattern at 12px tall. Hatching means one thing everywhere in this app
// -- the figure under it was not counted -- so the two greys are
// exported for the charts that have to draw the same stripes in SVG,
// where a CSS gradient is not available.
export const HATCH_STRIPE = '#d1d5db';
export const HATCH_GAP = '#f3f4f6';
export const HATCH = `repeating-linear-gradient(-45deg, ${HATCH_STRIPE} 0 4px, ${HATCH_GAP} 4px 8px)`;

export interface RangePlotProps {
  // All positions are fractions of the plot's width, 0..1.
  // Where most similar jobs land; absent when there is no range to draw.
  band?: { from: number; to: number };
  // The middle half, inside the band.
  box?: { from: number; to: number };
  // The typical value.
  tick?: number;
  // This job, and whether it ran past the end of the axis (then the fill
  // is cut there and has no end dot).
  job?: number;
  jobCapped?: boolean;
  // Labelled dashed lines, such as the job's request.
  refs?: { at: number; label: string }[];
  rough?: boolean;
  // This job is unusual: amber rather than green.
  unusual?: boolean;
  // md for a chart; sm for a listing cell.
  size?: 'md' | 'sm';
  testID?: string;
  // Further marks a chart of its own draws on the same axis.
  children?: ReactNode;
}

const pct = (f: number) => `${(Math.min(1, Math.max(0, f)) * 100).toFixed(2)}%`;

// Geometry per size: vertical placement of each mark.
const GEOM = {
  md: {
    root: 'h-7',
    track: 'top-3 h-1',
    band: 'top-2 h-3',
    tick: 'top-1 h-5 w-[3px]',
    fill: 'top-[11px] h-1.5',
    dot: 'top-2 size-3 ring-2',
    ref: 'top-0 h-7',
  },
  sm: {
    root: 'h-2.5',
    track: 'top-[4px] h-0.5',
    band: 'top-[2px] h-1.5',
    tick: 'top-0 h-2.5 w-0.5',
    fill: 'top-[3px] h-1',
    dot: 'top-[1px] size-2 ring-1',
    ref: 'top-0 h-2.5',
  },
} as const;

export function RangePlot({
  band,
  box,
  tick,
  job,
  jobCapped,
  refs = [],
  rough,
  unusual,
  size = 'md',
  testID,
  children,
}: RangePlotProps) {
  const g = GEOM[size];
  const fill = unusual ? RANGE_TOKENS.jobUnusual : RANGE_TOKENS.job;
  // Labels sit above the plot, so a plot with reference lines is taller.
  const labelled = refs.length > 0 && size === 'md';
  return (
    <div className={labelled ? 'relative pt-4' : 'relative'} aria-hidden="true" data-testid={testID}>
      {labelled &&
        refs.map((r) => (
          <span
            key={`label-${r.label}`}
            data-part="ref-label"
            className={`absolute top-0 whitespace-nowrap text-[11px] leading-4 text-gray-500 ${
              r.at > 0.75 ? '-translate-x-full pr-1' : 'pl-1'
            }`}
            style={{ left: pct(r.at) }}
          >
            {r.label}
          </span>
        ))}
      <div className={`relative ${g.root}`}>
        <div data-part="track" className={`absolute inset-x-0 rounded-full ${g.track} ${RANGE_TOKENS.track}`} />
        {band && band.to > band.from && (
          <div
            data-part="band"
            className={`absolute rounded-full ${g.band} ${rough ? '' : RANGE_TOKENS.band}`}
            style={{
              left: pct(band.from),
              width: pct(band.to - band.from),
              ...(rough ? { backgroundImage: HATCH } : {}),
            }}
          />
        )}
        {box && box.to >= box.from && (
          <div
            data-part="box"
            className={`absolute rounded-sm ${g.band} ${RANGE_TOKENS.box}`}
            style={{ left: pct(box.from), width: `max(3px, ${pct(box.to - box.from)})` }}
          />
        )}
        {job !== undefined && job > 0 && (
          <>
            <div
              data-part="job"
              className={`absolute left-0 z-10 ${g.fill} ${jobCapped ? 'rounded-l-full' : 'rounded-full'} ${fill}`}
              style={{ width: pct(job) }}
            />
            {/* Where the job is. A fill cut at the end of the axis has
                run past it, so it gets no end dot. */}
            {!jobCapped && (
              <div
                data-part="job-end"
                className={`absolute z-10 -translate-x-1/2 rounded-full ring-white ${g.dot} ${fill}`}
                style={{ left: pct(job) }}
              />
            )}
          </>
        )}
        {tick !== undefined && (
          <div
            data-part="tick"
            className={`absolute z-20 -translate-x-1/2 rounded-full ${g.tick} ${
              rough ? RANGE_TOKENS.tickRough : RANGE_TOKENS.tick
            }`}
            style={{ left: pct(tick) }}
          />
        )}
        {refs.map((r) => (
          <div
            key={r.label}
            data-part="ref"
            className={`absolute z-20 border-l border-dashed ${g.ref} ${RANGE_TOKENS.ref}`}
            style={{ left: pct(r.at) }}
          />
        ))}
        {children}
      </div>
    </div>
  );
}
