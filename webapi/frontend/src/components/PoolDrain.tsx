// The Pool page's drain-estimate pieces: the summary cards, the "Empty if
// drained now" cell, the six-hour timeline and the expanded node's
// per-job cells. Words come from lib/drain; these only lay them out.

import { slotStateStyle } from '@/lib/pool';
import { HATCH, RANGE_TOKENS } from '@/components/RangePlot';
import {
  drainCell,
  slotEnd,
  submittedFrom,
  timelineMarks,
  type DrainSlot,
  type DrainTotals,
  type MachineDrain,
} from '@/lib/drain';

// DrainView is what the node table needs from the drain estimates: the
// nodes by name, the answer's age, the moment the page renders, and
// whether this access point estimates runtimes at all. null until the
// answer arrives; the column stays hidden when the server has none.
export interface DrainView {
  index: Map<string, MachineDrain>;
  age: number;
  now: Date;
  available: boolean;
}

// DrainCards are the pool's drain figures for the nodes in view.
export function DrainCards({ totals, available }: { totals: DrainTotals; available: boolean }) {
  const coverage = totals.jobsRunning > 0 ? totals.jobsEstimated / totals.jobsRunning : 0;
  return (
    <div className="grid gap-3 sm:grid-cols-3" data-testid="drain-cards">
      <div className="rounded-lg border border-gray-200 bg-white p-3">
        <div className="text-xs uppercase tracking-wide text-gray-500">
          Cores freeing in the next hour
        </div>
        <div className="mt-1 text-lg font-semibold text-gray-900">
          {available ? `≈ ${Math.round(totals.coresFreeingNextHour).toLocaleString()}` : '—'}
        </div>
        <div className="text-xs text-gray-500">
          {available
            ? 'from jobs submitted here only'
            : 'this access point does not estimate run times'}
        </div>
      </div>
      <div className="rounded-lg border border-gray-200 bg-white p-3">
        <div className="text-xs uppercase tracking-wide text-gray-500">
          Running jobs with an estimate
        </div>
        <div className="mt-1 text-lg font-semibold text-gray-900">
          {totals.jobsEstimated.toLocaleString()}{' '}
          <span className="text-sm font-normal text-gray-500">
            of {totals.jobsRunning.toLocaleString()}
          </span>
        </div>
        <div
          className="mt-1 h-1 w-full overflow-hidden rounded-full bg-gray-100"
          role="meter"
          aria-label="Running jobs with an estimate"
          aria-valuemin={0}
          aria-valuemax={totals.jobsRunning}
          aria-valuenow={totals.jobsEstimated}
        >
          <div className="h-full bg-blue-700" style={{ width: `${coverage * 100}%` }} />
        </div>
        {totals.jobsEstimated < totals.jobsRunning && (
          <div className="mt-1 text-xs text-gray-500">
            {available
              ? 'the rest come from other access points'
              : 'this access point does not estimate run times'}
          </div>
        )}
      </div>
      <div className="rounded-lg border border-gray-200 bg-white p-3">
        <div className="text-xs uppercase tracking-wide text-gray-500">Draining now</div>
        <div className="mt-1 text-lg font-semibold text-gray-900">
          {totals.drainingNodes.toLocaleString()}{' '}
          {totals.drainingNodes === 1 ? 'node' : 'nodes'}
        </div>
        {totals.drainingNodes > 0 && (
          <div className="text-xs text-gray-500">
            {totals.drainingLikelyEmptyWithin2h.toLocaleString()} likely empty within 2h
          </div>
        )}
      </div>
    </div>
  );
}

export function DrainingBadge() {
  return (
    <span
      className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${slotStateStyle(
        'Draining',
      )}`}
    >
      Draining
    </span>
  );
}

// DrainCellView is the "Empty if drained now" cell. running is the jobs
// the page's own slot query counts on the node: a node missing from the
// answer is empty only if that agrees, and otherwise the two reads
// simply have not caught up with each other.
export function DrainCellView({
  m,
  drain,
  running,
}: {
  m: MachineDrain | undefined;
  drain: DrainView;
  running: number;
}) {
  if (!m && running > 0) return <span className="text-gray-300">—</span>;
  const cell = drainCell(m, drain.age, drain.now);
  return (
    <div className="leading-tight">
      <div className="font-medium text-gray-900">{cell.primary}</div>
      {(cell.detail || cell.warning) && (
        <div className="text-xs text-gray-500">
          {cell.detail}
          {cell.detail && cell.warning && ' · '}
          {cell.warning && <span className="text-amber-700">{cell.warning}</span>}
        </div>
      )}
    </div>
  );
}

// Timeline is a node's next six hours: a tick at each estimated job's
// expected end over its usual range, a hatched band as far as the jobs
// with no estimate may run, and an amber tick when a job has outrun
// its usual time.
export function Timeline({ m, age }: { m: MachineDrain | undefined; age: number }) {
  if (!m || m.jobs_total === 0) return <div className="h-3 w-40" />;
  const t = timelineMarks(m, age);
  return (
    <span className="inline-flex items-center gap-1">
      <span className="relative inline-block h-3 w-40 overflow-hidden rounded-sm bg-gray-100">
        {t.unknown !== undefined && (
          <span
            className="absolute inset-y-0 left-0"
            style={{ width: `${t.unknown * 100}%`, backgroundImage: HATCH }}
          />
        )}
        {t.bands.map((b, i) => (
          <span
            key={`b${i}`}
            className={`absolute inset-y-0 ${RANGE_TOKENS.band}`}
            style={{ left: `${b.from * 100}%`, width: `${Math.max(0, b.to - b.from) * 100}%` }}
          />
        ))}
        {t.ticks.map((x, i) => (
          <span
            key={`t${i}`}
            className={`absolute inset-y-0 w-[3px] ${RANGE_TOKENS.tick}`}
            style={{ left: `calc(${x * 100}% - 1px)` }}
          />
        ))}
        {t.exceeded && <span className={`absolute inset-y-0 left-0 w-[3px] ${RANGE_TOKENS.jobUnusual}`} />}
      </span>
      {t.beyond && <span className="whitespace-nowrap text-xs text-gray-400">→ {t.beyond}</span>}
    </span>
  );
}

// TimelineLegend keys the timeline with the colours every job-against-
// its-usual-range chart uses (RangePlot's tokens). The marks themselves
// differ -- many jobs' ends on one node, not one job against its group
// -- so this key is its own.
export function TimelineLegend() {
  const swatch = 'inline-block h-3 w-3 rounded-sm align-middle';
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 border-b border-gray-100 px-3 py-2 text-xs text-gray-500">
      <span>
        <span className={`${swatch} w-[3px] ${RANGE_TOKENS.tick}`} /> expected end of a job from this access
        point
      </span>
      <span>
        <span className={`${swatch} ${RANGE_TOKENS.band}`} /> its usual range
      </span>
      <span>
        <span className={swatch} style={{ backgroundImage: HATCH }} />{' '}
        no estimate: could run until its retirement limit
      </span>
      <span>
        <span className={`${swatch} w-[3px] ${RANGE_TOKENS.jobUnusual}`} /> running longer than usual
      </span>
    </div>
  );
}

// SlotDrainCells are one slot's "Submitted from" and "Expected end".
export function SlotDrainCells({ d, now }: { d: DrainSlot | undefined; now: Date }) {
  if (!d) {
    return (
      <>
        <td className="px-2 py-1 text-gray-400">—</td>
        <td className="px-2 py-1 text-gray-400">—</td>
      </>
    );
  }
  const end = slotEnd(d, now);
  return (
    <>
      <td className="px-2 py-1 text-gray-600">{submittedFrom(d)}</td>
      <td className="px-2 py-1">
        {end.warning && <span className="text-amber-700">{end.warning}</span>}
        {end.primary && <span className="text-gray-800">{end.primary}</span>}
        {end.detail && (
          <span className="ml-1 text-gray-400">
            {end.primary || end.warning ? '· ' : ''}
            {end.detail}
          </span>
        )}
      </td>
    </>
  );
}
