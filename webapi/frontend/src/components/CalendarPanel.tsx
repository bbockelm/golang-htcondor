'use client';

// The dashboard's calendar: a quarter of this access point's work, one
// square per day.
//
// It answers the question the live panels cannot. "2,536 jobs finished
// in the last hour" says nothing about whether the campaign submitted in
// August is nearly done, stalled in week three, or has been quietly
// failing every Monday since. A season of days laid out as a calendar
// shows that as a shape, before any number is read.
//
// Three grids, not one. Submitted, finished and removed are counts of
// things that happened on a day; they share a unit and a scale, so the
// same square in the same blue means the same number of jobs in all
// three, and "more arrived than left" is visible by looking across.
//
// Queue depth is not one of them, and is deliberately drawn as
// something else entirely. It is not a count of what happened -- it is
// how deep the queue was, worked backwards from today's real count
// through the daily flows, so every step back carries the error of the
// step before it. Treating it as a measurement is how a reader concludes
// something confident and wrong about a month ago. So it is hatched
// rather than filled, it says it is an estimate, it fades out going
// backwards, and it is the one figure on this panel with nothing to
// click: there is no set of jobs it names.

import Link from 'next/link';
import { useId } from 'react';

import type { CalendarQueueDepth, CalendarResponse, CalendarDay } from '@/lib/api';
import {
  allCells,
  buildWeeks,
  cellLabel,
  dayHref,
  dayLabel,
  flowPeak,
  flowTotal,
  formatUTC,
  hasGaps,
  monthLabels,
  rampColor,
  DAY_RAMP,
  FLOWS,
  type CalendarCell,
  type CalendarWeek,
  type FlowSpec,
} from '@/lib/calendar';
import { ago } from '@/components/DashboardPanels';
import { HowToRead, type LegendEntry } from '@/components/RangeLegend';
import { HATCH, HATCH_GAP, HATCH_STRIPE } from '@/components/RangePlot';

// A square and the space around it. Small enough that a quarter fits
// across a panel three times over, big enough to hover and to click.
const CELL = 11;
const GAP = 2;
const PITCH = CELL + GAP;

export function CalendarPanel({ calendar }: { calendar?: CalendarResponse }) {
  const days = calendar?.days ?? [];
  // Nothing at all where there is no history to count -- the same rule
  // the live ticker follows. An empty calendar that never fills reads as
  // a broken feature rather than an absent one, and the deployments
  // without a history mirror are exactly the ones that cannot have this.
  if (!calendar?.enabled || days.length === 0) return null;

  const weeks = buildWeeks(days);
  const months = monthLabels(weeks);
  const peak = flowPeak(days);
  // The last bucket is the day still in progress: its counts are hours
  // old at most, and jobs submitted during it are still in the queue.
  const inProgress = days[days.length - 1].day;
  const gaps = hasGaps(weeks);

  const entries: LegendEntry[] = ['count', 'none'];
  if (gaps) entries.push('uncounted');
  if (calendar.queue_depth?.derived) entries.push('rough');

  return (
    <section>
      <div className="mb-2 flex items-baseline gap-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-gray-500">
          Daily activity
        </h2>
        <span className="text-xs text-gray-400">
          last {calendar.window_days ?? days.length} days, UTC
        </span>
        {!!calendar.computed_at && (
          <span className="text-xs text-gray-400">updated {ago(calendar.computed_at)} ago</span>
        )}
      </div>

      {/* A window with holes in it has to say so. A calendar that is
          quietly missing a fortnight looks exactly like a fortnight
          nobody worked. */}
      {calendar.partial && (
        <p className="mb-2 text-xs text-amber-700">
          {calendar.note || 'Incomplete — some days could not be counted.'}
        </p>
      )}

      <div className="rounded border border-gray-200 p-3">
        <div className="flex flex-wrap gap-x-8 gap-y-4">
          {FLOWS.map((flow) => (
            <FlowCalendar
              key={flow.key}
              flow={flow}
              weeks={weeks}
              months={months}
              peak={peak}
              total={flowTotal(days, flow.key)}
              inProgress={inProgress}
            />
          ))}
        </div>

        <QueueDepth days={days} depth={calendar.queue_depth} />

        <div className="mt-3 flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-t border-gray-100 pt-2">
          <Scale peak={peak} />
          <HowToRead entries={entries} />
        </div>

        {/* Every figure the squares carry, in text. A hover tooltip is
            unreachable from a keyboard and from a screen reader, and
            this is also the only place the whole window can be read
            without comparing shades of blue. */}
        <details className="mt-2 text-xs text-gray-600">
          <summary className="cursor-pointer select-none text-gray-500 hover:text-gray-800">
            Show as table
          </summary>
          <div className="mt-1 max-h-64 overflow-auto">
            <DayTable cells={allCells(weeks)} depth={calendar.queue_depth} />
          </div>
        </details>
      </div>
    </section>
  );
}

// FlowCalendar is one measure's quarter: a column per week, Monday at
// the top, the month named where it changes.
function FlowCalendar({
  flow,
  weeks,
  months,
  peak,
  total,
  inProgress,
}: {
  flow: FlowSpec;
  weeks: CalendarWeek[];
  months: string[];
  peak: number;
  total: number;
  inProgress: number;
}) {
  return (
    <figure className="min-w-0">
      <figcaption className="mb-1">
        <span className="text-sm font-semibold text-gray-900">{flow.title}</span>{' '}
        {/* The calendar shows the shape; the window's own total is the
            number, and it should not have to be added up by eye. */}
        <span className="text-xs tabular-nums text-gray-500">
          {total.toLocaleString()} {total === 1 ? 'job' : 'jobs'}
        </span>
      </figcaption>

      <div className="flex" style={{ gap: GAP }} aria-hidden="true">
        {months.map((label, i) => (
          <div key={i} className="relative" style={{ width: CELL, height: 11 }}>
            {label && (
              <span className="absolute left-0 top-0 whitespace-nowrap text-[9px] leading-[11px] text-gray-400">
                {label}
              </span>
            )}
          </div>
        ))}
      </div>

      <div className="flex" style={{ gap: GAP }}>
        {weeks.map((week, i) => (
          <div key={i} className="flex flex-col" style={{ gap: GAP }}>
            {week.map((cell, j) => (
              <DaySquare
                key={j}
                cell={cell}
                flow={flow}
                peak={peak}
                inProgress={inProgress}
              />
            ))}
          </div>
        ))}
      </div>
    </figure>
  );
}

// DaySquare is one day. Four states, and they must not look alike:
//
//   - a day outside the window: nothing, so the grid stays a rectangle
//     without implying anything about days nobody asked about;
//   - a day nobody counted: hatched, which means "not counted"
//     everywhere in this app;
//   - a day with no jobs: an empty outline. Not the palest blue -- at
//     eleven pixels that is indistinguishable from one job, and those
//     are the two a calendar most has to keep apart;
//   - a day with jobs: the ramp, and a link to them.
function DaySquare({
  cell,
  flow,
  peak,
  inProgress,
}: {
  cell: CalendarCell | null;
  flow: FlowSpec;
  peak: number;
  inProgress: number;
}) {
  const box = 'rounded-[2px]';
  const size = { width: CELL, height: CELL };
  if (!cell) {
    return <span style={size} aria-hidden="true" />;
  }

  const label = cellLabel(flow, cell);

  if (!cell.counts) {
    return (
      <span
        className={box}
        style={{ ...size, backgroundImage: HATCH }}
        title={label}
        data-day={cell.day}
        data-day-state="uncounted"
      />
    );
  }

  const n = cell.counts[flow.key];
  const color = rampColor(n, peak);
  if (!color) {
    return (
      <span
        className={`${box} bg-gray-100 ring-1 ring-inset ring-gray-200`}
        style={size}
        title={label}
        data-day={cell.day}
        data-day-state="zero"
      />
    );
  }

  const href = dayHref(flow.key, cell, { inProgress: cell.day === inProgress });
  return (
    <Link
      href={href ?? '#'}
      className={`${box} block hover:ring-2 hover:ring-gray-800 hover:ring-offset-1`}
      style={{ ...size, backgroundColor: color }}
      title={label}
      aria-label={label}
      data-day={cell.day}
      data-day-state="count"
    />
  );
}

// Scale says what the shades mean, with both ends of the range named.
// Without the numbers a reader can compare two squares but cannot say
// what either one is.
function Scale({ peak }: { peak: number }) {
  return (
    <div className="flex items-center gap-1.5 text-xs text-gray-500" data-testid="calendar-scale">
      <span>1 job</span>
      {DAY_RAMP.map((c) => (
        <span
          key={c}
          className="inline-block rounded-[2px]"
          style={{ width: CELL, height: CELL, backgroundColor: c }}
          aria-hidden="true"
        />
      ))}
      <span>{peak.toLocaleString()} a day</span>
    </div>
  );
}

// --- Queue depth ---

const DEPTH_W = 640;
const DEPTH_H = 52;
const DEPTH_TOP = 8;
// Room at the right-hand end for the anchor's dot, which sits on the
// last day and would otherwise be half outside the plot.
const DEPTH_RIGHT = 5;
const DEPTH_PLOT = DEPTH_H - DEPTH_TOP;

// The ink a derived figure wears: the same grey a rough guess wears on
// the job page. Solid blue is reserved for a number somebody counted.
const DEPTH_LINE = '#6b7280';
const DEPTH_LINE_FAR = '#d1d5db';
const DEPTH_COUNTED = '#2a78d6';

function QueueDepth({
  days,
  depth,
}: {
  days: CalendarDay[];
  depth?: CalendarQueueDepth;
}) {
  const hatchId = useId();
  const fadeId = useId();
  if (!depth || days.length < 2) return null;

  const derived = depth.derived;
  const peak = Math.max(1, ...days.map((d) => d.in_queue));
  const plotW = DEPTH_W - DEPTH_RIGHT;
  const x = (i: number) => (i / (days.length - 1)) * plotW;
  const y = (v: number) => DEPTH_TOP + DEPTH_PLOT - (v / peak) * DEPTH_PLOT;
  const points = days.map((d, i) => `${x(i).toFixed(1)},${y(d.in_queue).toFixed(1)}`);
  const area = `M0,${DEPTH_H} L${points.join(' L')} L${plotW},${DEPTH_H} Z`;
  const last = days[days.length - 1];

  return (
    <figure className="mt-4 min-w-0" data-testid="queue-depth" data-derived={derived}>
      <figcaption className="mb-1 flex flex-wrap items-baseline gap-x-2">
        <span className="text-sm font-semibold text-gray-900">Queue depth</span>
        {/* Said once, in plain words, beside the title -- not buried in a
            tooltip. A reader who takes this line for a measurement draws
            wrong conclusions about a month ago. */}
        <span className="text-xs text-gray-500">
          {derived
            ? 'estimated; only the figure for today was counted'
            : 'counted each day'}
        </span>
        {/* The one end of the line that is a real number, and the only
            part of it with jobs to show. */}
        <Link
          href="/jobs"
          className="ml-auto text-xs text-brand-700 hover:underline"
          data-testid="queue-depth-anchor"
        >
          {depth.anchor.toLocaleString()} in the queue now
        </Link>
      </figcaption>

      <svg
        viewBox={`0 0 ${DEPTH_W} ${DEPTH_H}`}
        width="100%"
        // Scaled evenly, not stretched to the panel's width: a stretched
        // viewBox turns the anchor's dot into a smear and the hatching
        // into something that no longer matches the hatching anywhere
        // else.
        preserveAspectRatio="xMidYMid meet"
        className="overflow-visible"
        role="img"
        aria-label={
          derived
            ? `Queue depth over the window, estimated from the daily counts and anchored to ${depth.anchor.toLocaleString()} jobs in the queue now`
            : `Queue depth over the window, ${depth.anchor.toLocaleString()} jobs in the queue now`
        }
      >
        <defs>
          {/* The same two greys as the hatched band on the job page, as
              an SVG pattern: hatching means "not counted" wherever it
              appears, so it cannot be a different texture here. */}
          <pattern
            id={hatchId}
            patternUnits="userSpaceOnUse"
            width={8}
            height={8}
            patternTransform="rotate(-45)"
          >
            <rect width={8} height={8} fill={HATCH_GAP} />
            <rect width={4} height={8} fill={HATCH_STRIPE} />
          </pattern>
          {/* The estimate is anchored at the right-hand end and gets
              rougher with every day walked back from it, so the line
              fades out going backwards. */}
          <linearGradient id={fadeId} x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stopColor={DEPTH_LINE_FAR} />
            <stop offset="1" stopColor={DEPTH_LINE} />
          </linearGradient>
        </defs>

        <path d={area} fill={derived ? `url(#${hatchId})` : '#cde2fb'} />
        <polyline
          points={points.join(' ')}
          fill="none"
          stroke={derived ? `url(#${fadeId})` : DEPTH_COUNTED}
          strokeWidth={2}
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
        />
        {/* Hover anywhere over a day's slice. The figures are also in
            the table below, which is where a keyboard gets them. */}
        {days.map((d, i) => (
          <rect
            key={d.day}
            x={Math.max(0, x(i) - plotW / (days.length - 1) / 2)}
            y={0}
            width={plotW / (days.length - 1)}
            height={DEPTH_H}
            fill="transparent"
          >
            <title>{depthTitle(d, derived)}</title>
          </rect>
        ))}
        {/* The anchor: the one counted figure, in the blue everything
            counted is drawn in, ringed so it reads over the line. */}
        <circle
          cx={plotW}
          cy={y(last.in_queue)}
          r={3.5}
          fill={DEPTH_COUNTED}
          stroke="#ffffff"
          strokeWidth={2}
        />
      </svg>

      <div className="flex justify-between text-[10px] text-gray-400">
        <span>{formatUTC(days[0].day, { month: 'short', day: 'numeric' })}</span>
        <span className="tabular-nums">peak about {peak.toLocaleString()}</span>
        <span>{formatUTC(last.day, { month: 'short', day: 'numeric' })}</span>
      </div>
    </figure>
  );
}

// depthTitle hedges where the figure is a reconstruction, in the words
// somebody would use out loud.
function depthTitle(d: CalendarDay, derived: boolean): string {
  const n = d.in_queue.toLocaleString();
  return derived
    ? `${dayLabel(d.day)}: about ${n} in the queue`
    : `${dayLabel(d.day)}: ${n} in the queue`;
}

// DayTable is the whole window in text, newest first -- the order a
// reader scans when the question is "what has been happening lately".
function DayTable({ cells, depth }: { cells: CalendarCell[]; depth?: CalendarQueueDepth }) {
  const rows = [...cells].reverse();
  return (
    <table className="min-w-full text-xs tabular-nums">
      <thead className="text-gray-500">
        <tr>
          <th className="px-2 py-1 text-left font-medium">Day (UTC)</th>
          {FLOWS.map((f) => (
            <th key={f.key} className="px-2 py-1 text-right font-medium">
              {f.title}
            </th>
          ))}
          <th className="px-2 py-1 text-right font-medium">
            In queue{depth?.derived ? ' (estimated)' : ''}
          </th>
        </tr>
      </thead>
      <tbody className="divide-y divide-gray-100">
        {rows.map((cell) => (
          <DayRow key={cell.day} cell={cell} depth={depth} />
        ))}
      </tbody>
    </table>
  );
}

function DayRow({ cell, depth }: { cell: CalendarCell; depth?: CalendarQueueDepth }) {
  const counts = cell.counts;
  return (
    <tr>
      <td className="whitespace-nowrap px-2 py-1 text-gray-700">{dayLabel(cell.day)}</td>
      {counts ? (
        <>
          {FLOWS.map((f) => (
            <td key={f.key} className="px-2 py-1 text-right text-gray-700">
              {/* A counted zero is written as a zero. It is a fact about
                  the day, and the row has to read differently from the
                  one below it, which is a day nobody counted. */}
              {counts[f.key].toLocaleString()}
            </td>
          ))}
          <td className="px-2 py-1 text-right text-gray-500">
            {depth?.derived ? '~' : ''}
            {counts.in_queue.toLocaleString()}
          </td>
        </>
      ) : (
        // Nobody counted this day. Four zeros here would be a confident
        // wrong answer, and the gap would vanish for anyone reading the
        // table instead of the squares.
        <td className="px-2 py-1 text-left text-gray-500" colSpan={FLOWS.length + 1}>
          not counted
        </td>
      )}
    </tr>
  );
}
