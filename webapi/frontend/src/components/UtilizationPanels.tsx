'use client';

// The Utilization page's panels, split out of app/utilization/page.tsx so
// the tests can render them one state at a time (a route file's exports
// are a closed set; see DashboardPanels.tsx).
//
// What the page is for: a user who submitted thousands of jobs asking
// for 8 GB that peaked at 1.5 GB has no way to see that from a job list.
// The headline says how much of the reservation was used, the
// suggestions say what to change, and each workflow's page shows the
// evidence a suggestion rests on so it can be trusted or argued with.

import Link from 'next/link';
import { useMemo, useState } from 'react';
import {
  RESOURCE_LABEL,
  formatCores,
  formatHours,
  formatKiB,
  formatMiB,
  formatNumber,
  formatPercent,
  formatResourceHours,
  formatSaves,
  fitRatio,
  idleHours,
  rankAdvice,
  sortResources,
  usedFraction,
  windowPhrase,
  THROUGHPUT_SHOWN,
  changesRequest,
  formatGain,
  throughputColumn,
  throughputStatement,
  throughputAdviceId,
  splitSingles,
  type RankedAdvice,
  type UtilThroughput,
  type UtilGpu,
  type UtilRequest,
  type UtilOwner,
  moreOptions,
  type UtilAdvice,
  type UtilOverall,
  type UtilResourceSummary,
  type UtilWorkflow,
  type UtilizationResponse,
} from '@/lib/utilization';
import { SortableHeader, useSortedRows, useSortState } from '@/components/SortableTable';
import {
  Histogram,
  MemoryCurve,
  OutcomeScatter,
  RangeStrip,
  RangeStripKey,
  TrendChart,
  UsageBar,
  type ChartMarker,
} from '@/components/UtilizationCharts';

// --- Window selector ---

export function WindowToggle({
  value,
  onChange,
}: {
  value: number;
  onChange: (days: 1 | 7 | 30) => void;
}) {
  const options: { days: 1 | 7 | 30; label: string }[] = [
    { days: 1, label: 'Last day' },
    { days: 7, label: '7 days' },
    { days: 30, label: '30 days' },
  ];
  return (
    <div
      className="flex items-center gap-1 rounded-sm border border-gray-300 bg-white p-0.5 text-xs"
      role="group"
      aria-label="Time window"
    >
      {options.map((o) => (
        <button
          key={o.days}
          type="button"
          aria-pressed={value === o.days}
          onClick={() => onChange(o.days)}
          className={`rounded px-2 py-0.5 ${
            value === o.days ? 'bg-gray-200 text-gray-900' : 'text-gray-600 hover:bg-gray-100'
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

// --- Headline ---

// What the idle figure is called on each card: memory is the jobs' peak,
// so "never touched" is honest for it; for CPU the cores were reserved
// but not kept busy.
const IDLE_PHRASE: Record<UtilResourceSummary['resource'], string> = {
  cpu: 'reserved but idle',
  memory: 'reserved above the peak',
  disk: 'reserved but unused',
  gpu: 'reserved but idle',
};

export function ResourceCard({ summary, jobs }: { summary: UtilResourceSummary; jobs: number }) {
  const f = usedFraction(summary);
  const idle = idleHours(summary);
  const label = summary.resource === 'memory' ? 'Peak memory' : RESOURCE_LABEL[summary.resource];
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4" data-testid={`resource-${summary.resource}`}>
      <div className="text-xs font-medium uppercase tracking-wide text-gray-500">{label}</div>
      {f === null && summary.resource === 'gpu' ? (
        // GPU-hours are the most expensive thing a job reserves; how many
        // were reserved is worth stating even when how busy they were is
        // not known.
        <>
          <div className="mt-1 flex items-baseline gap-1.5">
            <span className="text-3xl font-semibold text-gray-900">
              {formatNumber(summary.allocated_hours)}
            </span>{' '}
            <span className="text-sm text-gray-500">GPU-hours reserved</span>
          </div>
          <p className="mt-2 text-xs text-gray-600">Utilization not measured for these jobs.</p>
        </>
      ) : f === null ? (
        <p className="mt-2 text-sm text-gray-500">No usage was measured for these jobs.</p>
      ) : (
        <>
          <div className="mt-1 flex items-baseline gap-1.5">
            <span className="text-3xl font-semibold text-gray-900">{formatPercent(f)}</span>
            <span className="text-sm text-gray-500">used</span>
          </div>
          <div className="mt-2">
            <UsageBar
              fraction={f}
              label={`${label}: ${formatPercent(f)} of what was reserved was used`}
            />
          </div>
          <p className="mt-2 text-xs text-gray-600 tabular-nums">
            {idle !== null && idle >= 0 ? (
              <>
                <span className="font-semibold text-gray-900">
                  {formatResourceHours(summary.resource, idle)}
                </span>{' '}
                {IDLE_PHRASE[summary.resource]}
              </>
            ) : idle !== null ? (
              // Memory can go over its request before the job is stopped;
              // a negative idle figure would read as nonsense.
              <>
                <span className="font-semibold text-gray-900">
                  {formatResourceHours(summary.resource, -idle)}
                </span>{' '}
                more than was reserved
              </>
            ) : null}
          </p>
          <p className="mt-0.5 text-xs text-gray-400 tabular-nums">
            of {formatResourceHours(summary.resource, summary.allocated_hours_measured)} reserved
            {summary.resource === 'gpu' &&
              summary.allocated_hours > summary.allocated_hours_measured * 1.005 &&
              ` (${formatResourceHours('gpu', summary.allocated_hours)} in all)`}
            {/* Only GPU jobs have GPU usage, so "64 of 1,596 jobs" would
                read as most going unmeasured; GPU says how many it covers. */}
            {summary.resource === 'gpu'
              ? ` · ${summary.jobs_measured.toLocaleString()} GPU ${summary.jobs_measured === 1 ? 'job' : 'jobs'}`
              : summary.jobs_measured < jobs &&
                ` · measured on ${summary.jobs_measured.toLocaleString()} of ${jobs.toLocaleString()} jobs`}
          </p>
        </>
      )}
    </div>
  );
}

export function BadputCard({ overall }: { overall: { wall_hours: number; badput_hours: number } }) {
  const f = overall.wall_hours > 0 ? overall.badput_hours / overall.wall_hours : null;
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4" data-testid="badput">
      <div className="text-xs font-medium uppercase tracking-wide text-gray-500">Lost run time</div>
      <div className="mt-1 flex items-baseline gap-1.5">
        <span className="text-3xl font-semibold text-gray-900">{formatPercent(f)}</span>
        <span className="text-sm text-gray-500">of run time</span>
      </div>
      <p className="mt-2 text-xs text-gray-600 tabular-nums">
        <span className="font-semibold text-gray-900">{formatHours(overall.badput_hours)}</span> of{' '}
        {formatHours(overall.wall_hours)} went to runs that failed or started over
      </p>
    </div>
  );
}

// ThroughputHeadline is the figure people act on: not "you wasted 60% of
// your memory" but "you could have run this many more jobs".
export function ThroughputHeadline({ gain }: { gain: number | null | undefined }) {
  if (gain === null || gain === undefined || gain < THROUGHPUT_SHOWN) return null;
  return (
    <div className="rounded-lg border border-green-200 bg-green-50 px-4 py-3" data-testid="throughput-headline">
      <p className="text-gray-900">
        With all of these changes: <span className="text-xl font-semibold">up to {formatGain(gain)}</span> as many
        jobs running at once.
      </p>
      <p className="mt-0.5 text-xs text-gray-600">Estimated from the machines currently in the pool.</p>
    </div>
  );
}

export function Headline({ overall, mine = true }: { overall: UtilOverall; mine?: boolean }) {
  return (
    <section aria-labelledby="util-headline" className="space-y-3">
      <h2 id="util-headline" className="mb-2 text-sm font-semibold uppercase tracking-wide text-gray-500">
        Of what {mine ? 'your' : 'these'} jobs reserved, how much they used
      </h2>
      <ThroughputHeadline gain={overall.throughput_gain} />
      <div className="grid grid-cols-[repeat(auto-fit,minmax(13rem,1fr))] gap-3">
        {sortResources(overall.resources).map((r) => (
          <ResourceCard key={r.resource} summary={r} jobs={overall.jobs} />
        ))}
        <BadputCard overall={overall} />
      </div>
      <p className="mt-2 text-xs text-gray-500">
        Weighted by run time, so a long job counts for more than a short one. Memory figures are each job&apos;s peak.
      </p>
    </section>
  );
}

// --- Advice ---

const SEVERITY: Record<UtilAdvice['severity'], { label: string; cls: string; icon: string }> = {
  warn: { label: 'Fix this', cls: 'bg-amber-100 text-amber-900', icon: '!' },
  suggest: { label: 'Suggestion', cls: 'bg-blue-50 text-blue-800', icon: '→' },
  info: { label: 'Note', cls: 'bg-gray-100 text-gray-700', icon: 'i' },
};

const CONFIDENCE_LABEL: Record<UtilAdvice['confidence'], string> = {
  high: 'High confidence',
  medium: 'Medium confidence',
  low: 'Low confidence: few jobs to go on',
};

export function CopyButton({ text }: { text: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setState('copied');
        } catch {
          // No clipboard permission (older Safari, insecure origins):
          // the lines are on screen and selectable, so say so.
          setState('failed');
        }
        setTimeout(() => setState('idle'), 2000);
      }}
      className="rounded-sm border border-gray-300 bg-white px-2 py-0.5 text-xs text-gray-700 hover:bg-gray-50"
    >
      {state === 'copied' ? 'Copied' : state === 'failed' ? 'Select to copy' : 'Copy'}
    </button>
  );
}

export function AdviceCard({
  advice,
  workflow,
  hrefFor,
  throughput,
}: {
  advice: UtilAdvice;
  // Set when the card is listed away from its workflow, so it can say
  // which workflow it is about.
  workflow?: UtilWorkflow;
  hrefFor?: (key: string) => string;
  // The workflow's estimate, passed only to the one card that carries it
  // (see throughputAdviceId).
  throughput?: UtilThroughput | null;
}) {
  const sev = SEVERITY[advice.severity];
  const st = changesRequest(advice) ? throughputStatement(throughput) : null;
  // The pool-freeing note belongs on the workflow's page, once; on every
  // card it would repeat without saying anything about the card.
  const runLine = st && st.kind !== 'unlimited' ? st.line : null;
  const saves = formatSaves(advice.saves);
  const low = advice.confidence === 'low';
  return (
    <article
      className={`rounded-lg border bg-white p-4 ${low ? 'border-dashed border-gray-300' : 'border-gray-200'}`}
      data-testid="advice"
      data-advice-id={advice.id}
    >
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-medium ${sev.cls}`}>
          <span aria-hidden className="font-bold">
            {sev.icon}
          </span>
          {sev.label}
        </span>
        <span className="text-gray-500">
          {advice.resource === 'runtime' ? 'Run time' : RESOURCE_LABEL[advice.resource]}
        </span>
        <span className={low ? 'rounded-full bg-gray-100 px-2 py-0.5 text-gray-700' : 'text-gray-400'}>
          {CONFIDENCE_LABEL[advice.confidence]}
        </span>
      </div>
      <h3 className="mt-2 font-semibold text-gray-900">{advice.title}</h3>
      <p className="mt-1 text-sm text-gray-600">{advice.detail}</p>
      {runLine && (
        <p className="mt-1 text-sm font-medium text-gray-900" data-testid="advice-throughput">
          {runLine}
        </p>
      )}
      {(workflow || saves) && (
        <p className="mt-2 text-xs text-gray-500">
          {workflow && hrefFor && (
            <>
              For{' '}
              <Link href={hrefFor(workflow.key)} className="font-medium text-brand-700 hover:underline">
                {workflow.name}
              </Link>
              {saves && ' · '}
            </>
          )}
          {saves && (
            <>
              Saves about <span className="font-semibold text-gray-900 tabular-nums">{saves}</span> for the same work
            </>
          )}
        </p>
      )}
      {advice.submit.length > 0 && (
        <div className="mt-3 flex items-start gap-2">
          <pre className="min-w-0 flex-1 overflow-x-auto rounded-sm bg-gray-50 px-3 py-2 font-mono text-xs text-gray-800">
            {advice.submit.join('\n')}
          </pre>
          <CopyButton text={advice.submit.join('\n')} />
        </div>
      )}
    </article>
  );
}

const TOP_ADVICE = 5;

export function Suggestions({
  workflows,
  hrefFor,
}: {
  workflows: UtilWorkflow[];
  hrefFor: (key: string) => string;
}) {
  const [all, setAll] = useState(false);
  const ranked: RankedAdvice[] = rankAdvice(workflows);
  const shown = all ? ranked : ranked.slice(0, TOP_ADVICE);
  return (
    <section aria-labelledby="util-suggestions">
      <h2 id="util-suggestions" className="mb-2 text-sm font-semibold uppercase tracking-wide text-gray-500">
        What to change next time
      </h2>
      {ranked.length === 0 ? (
        <p className="text-sm text-gray-500">Nothing to change: these jobs fit what they asked for.</p>
      ) : (
        <>
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            {shown.map((r) => (
              <AdviceCard
                key={`${r.workflow.key}/${r.advice.id}`}
                advice={r.advice}
                workflow={r.workflow}
                hrefFor={hrefFor}
                throughput={throughputAdviceId(r.workflow) === r.advice.id ? r.workflow.throughput : null}
              />
            ))}
          </div>
          {ranked.length > TOP_ADVICE && (
            <button
              type="button"
              onClick={() => setAll((v) => !v)}
              className="mt-2 text-sm text-brand-700 hover:underline"
            >
              {all ? 'Show fewer' : `Show all ${ranked.length} suggestions`}
            </button>
          )}
        </>
      )}
    </section>
  );
}

// --- Workflows table ---

type SortKey = 'name' | 'jobs' | 'wall' | 'cpu' | 'memory' | 'disk' | 'throughput' | 'advice';

function actionable(w: UtilWorkflow): number {
  return w.advice.filter((a) => a.severity !== 'info').length;
}

function sortValue(w: UtilWorkflow, key: SortKey): string | number | undefined {
  switch (key) {
    case 'name':
      return w.name;
    case 'jobs':
      return w.jobs;
    case 'wall':
      return w.wall_hours;
    case 'advice':
      return actionable(w);
    case 'throughput':
      return throughputColumn(w);
    default:
      return fitRatio(w, key);
  }
}

// A row of the table is a workflow or the group of single-job ones,
// which sorts as one unit: its jobs and run time are the group's sums.
type TableUnit = { kind: 'workflow'; w: UtilWorkflow } | { kind: 'singles'; ws: UtilWorkflow[] };

function unitValue(u: TableUnit, key: SortKey): string | number | undefined {
  if (u.kind === 'workflow') return sortValue(u.w, key);
  switch (key) {
    case 'name':
      return 'single-job workflows';
    case 'jobs':
      return u.ws.reduce((a, w) => a + w.jobs, 0);
    case 'wall':
      return u.ws.reduce((a, w) => a + w.wall_hours, 0);
    case 'advice':
      return u.ws.reduce((a, w) => a + actionable(w), 0);
    default:
      // A fit ratio or throughput of a group of unrelated jobs means
      // nothing; the group sorts last on those columns.
      return undefined;
  }
}

export function WorkflowsTable({
  workflows,
  hrefFor,
  onOpen,
  onOwner,
}: {
  workflows: UtilWorkflow[];
  hrefFor: (key: string) => string;
  onOpen: (key: string) => void;
  // Set when the page can narrow to a user: owner names become buttons.
  onOwner?: (owner: string) => void;
}) {
  const [sort, setSort] = useSortState<SortKey>('wall', 'desc');
  const [singlesOpen, setSinglesOpen] = useState(false);
  const { multi, singles } = useMemo(() => splitSingles(workflows), [workflows]);
  const units = useMemo<TableUnit[]>(
    () => [
      ...multi.map((w): TableUnit => ({ kind: 'workflow', w })),
      ...(singles.length > 0 ? [{ kind: 'singles', ws: singles } as TableUnit] : []),
    ],
    [multi, singles],
  );
  const sortedUnits = useSortedRows(units, sort, unitValue);
  const sortedSingles = useSortedRows(singles, sort, sortValue);
  const showOwner = workflows.some((w) => w.owner);
  const showSchedd = workflows.some((w) => w.schedd);
  // A column of blanks is noise: only when some workflow has a figure.
  const showThroughput = workflows.some((w) => throughputColumn(w) !== undefined);
  const columns = 7 + (showThroughput ? 1 : 0);
  const row = (w: UtilWorkflow, nested = false) => (
    <WorkflowRow
      key={w.key}
      w={w}
      nested={nested}
      hrefFor={hrefFor}
      onOpen={onOpen}
      onOwner={onOwner}
      showOwner={showOwner}
      showSchedd={showSchedd}
      showThroughput={showThroughput}
    />
  );
  return (
    <section aria-labelledby="util-workflows">
      <h2 id="util-workflows" className="mb-2 text-sm font-semibold uppercase tracking-wide text-gray-500">
        Workflows
      </h2>
      <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
        <table className="min-w-full text-sm">
          <thead className="bg-gray-50 text-left text-xs text-gray-500">
            <tr>
              <SortableHeader label="Workflow" sortKey="name" sort={sort} onSort={setSort} />
              <SortableHeader label="Jobs" sortKey="jobs" sort={sort} onSort={setSort} className="text-right" />
              <SortableHeader label="Run time" sortKey="wall" sort={sort} onSort={setSort} className="text-right" />
              <SortableHeader label="CPU cores" sortKey="cpu" sort={sort} onSort={setSort} />
              <SortableHeader label="Peak memory" sortKey="memory" sort={sort} onSort={setSort} />
              <SortableHeader label="Disk" sortKey="disk" sort={sort} onSort={setSort} />
              {showThroughput && (
                <SortableHeader label="Throughput" sortKey="throughput" sort={sort} onSort={setSort} className="text-right" />
              )}
              <SortableHeader label="Advice" sortKey="advice" sort={sort} onSort={setSort} />
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {sortedUnits.map((u) =>
              u.kind === 'workflow' ? (
                row(u.w)
              ) : (
                <SinglesRows
                  key="singles"
                  ws={u.ws}
                  open={singlesOpen}
                  onToggle={() => setSinglesOpen((v) => !v)}
                  columns={columns}
                  rows={sortedSingles.map((w) => row(w, true))}
                />
              ),
            )}
          </tbody>
        </table>
      </div>
      <div className="mt-2">
        <RangeStripKey />
      </div>
    </section>
  );
}

// SinglesRows is the folded group of one-job workflows and, when open,
// the workflows themselves.
function SinglesRows({
  ws,
  open,
  onToggle,
  columns,
  rows,
}: {
  ws: UtilWorkflow[];
  open: boolean;
  onToggle: () => void;
  columns: number;
  rows: React.ReactNode[];
}) {
  const wall = ws.reduce((a, w) => a + w.wall_hours, 0);
  const advice = ws.reduce((a, w) => a + actionable(w), 0);
  return (
    <>
      <tr className="bg-gray-50/60" data-testid="singles-group">
        <td className="px-3 py-2">
          <button
            type="button"
            onClick={onToggle}
            aria-expanded={open}
            className="inline-flex items-center gap-1.5 font-medium text-gray-900 hover:underline"
          >
            <span aria-hidden className="inline-block w-3 text-gray-500">
              {open ? '▾' : '▸'}
            </span>
            {ws.length.toLocaleString()} single-job workflows
          </button>
        </td>
        <td className="px-3 py-2 text-right tabular-nums">{ws.length.toLocaleString()}</td>
        <td className="px-3 py-2 text-right tabular-nums whitespace-nowrap">{formatHours(wall)}</td>
        <td colSpan={columns - 4} />
        <td className="px-3 py-2">
          {advice > 0 && (
            <span className="inline-flex whitespace-nowrap rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-900 tabular-nums">
              {advice} {advice === 1 ? 'suggestion' : 'suggestions'}
            </span>
          )}
        </td>
      </tr>
      {open && rows}
    </>
  );
}

function WorkflowRow({
  w,
  nested,
  hrefFor,
  onOpen,
  onOwner,
  showOwner,
  showSchedd,
  showThroughput,
}: {
  w: UtilWorkflow;
  nested: boolean;
  hrefFor: (key: string) => string;
  onOpen: (key: string) => void;
  onOwner?: (owner: string) => void;
  showOwner: boolean;
  showSchedd: boolean;
  showThroughput: boolean;
}) {
  const n = actionable(w);
  return (
    <tr
      tabIndex={0}
      onClick={() => onOpen(w.key)}
      onKeyDown={(e) => {
        if (e.target !== e.currentTarget) return;
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onOpen(w.key);
        }
      }}
      aria-label={`${w.name}: ${w.jobs.toLocaleString()} ${w.jobs === 1 ? 'job' : 'jobs'}. Open details.`}
      className="cursor-pointer align-middle hover:bg-gray-50 focus:bg-brand-50 focus:outline-none"
    >
      <td className={`py-2 pr-3 ${nested ? 'pl-9' : 'pl-3'}`}>
        <div className="flex flex-wrap items-center gap-1.5">
          <Link
            href={hrefFor(w.key)}
            tabIndex={-1}
            onClick={(e) => e.stopPropagation()}
            className="font-medium text-gray-900 hover:underline"
          >
            {w.name}
          </Link>
          {w.is_dag && (
            <span className="rounded bg-indigo-100 px-1.5 py-0.5 text-[10px] font-semibold text-indigo-800">DAG</span>
          )}
        </div>
        <div className="mt-0.5 flex flex-wrap items-center gap-1 text-xs text-gray-500">
          <span className="font-mono">{w.executable}</span>
          {showOwner && w.owner && (
            <>
              <span aria-hidden>·</span>
              {onOwner ? (
                <button
                  type="button"
                  // Narrows the page to this user rather than opening the
                  // workflow the row belongs to.
                  onClick={(e) => {
                    e.stopPropagation();
                    onOwner(w.owner!);
                  }}
                  title={`Show only ${w.owner}'s workflows`}
                  className="rounded-full bg-indigo-100 px-2 py-0.5 font-medium text-indigo-800 hover:bg-indigo-200"
                  data-testid="owner-pill"
                >
                  {w.owner}
                </button>
              ) : (
                <span>{w.owner}</span>
              )}
            </>
          )}
          {showSchedd && w.schedd && (
            <>
              <span aria-hidden>·</span>
              <span>{w.schedd}</span>
            </>
          )}
        </div>
      </td>
      <td className="px-3 py-2 text-right tabular-nums">
        <div>{w.jobs.toLocaleString()}</div>
        {(w.failed > 0 || w.removed > 0) && (
          <div className="whitespace-nowrap text-xs text-gray-500">
            {w.failed > 0 && <span className="text-red-700">{w.failed.toLocaleString()} failed</span>}
            {w.failed > 0 && w.removed > 0 && ', '}
            {w.removed > 0 && <span>{w.removed.toLocaleString()} removed</span>}
          </div>
        )}
      </td>
      <td className="px-3 py-2 text-right tabular-nums whitespace-nowrap">{formatHours(w.wall_hours)}</td>
      <td className="px-3 py-2">
        <RangeStrip request={w.cpu.request} dist={w.cpu.cores_used} format={formatCores} label="CPU cores" />
      </td>
      <td className="px-3 py-2">
        <RangeStrip request={w.memory.request} dist={w.memory.peak_mib} format={formatMiB} label="Peak memory" />
      </td>
      <td className="px-3 py-2">
        <RangeStrip request={w.disk.request} dist={w.disk.used_kib} format={formatKiB} label="Disk" />
      </td>
      {showThroughput && (
        <td className="px-3 py-2 text-right tabular-nums whitespace-nowrap" data-testid="throughput-cell">
          {(() => {
            const g = throughputColumn(w);
            if (g === undefined) return null;
            return g >= 1 ? `up to ${formatGain(g)}` : formatGain(g);
          })()}
        </td>
      )}
      <td className="px-3 py-2">
        {n > 0 ? (
          <span className="inline-flex whitespace-nowrap rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-900 tabular-nums">
            {n} {n === 1 ? 'suggestion' : 'suggestions'}
          </span>
        ) : (
          <span className="text-xs text-gray-400">fits</span>
        )}
      </td>
    </tr>
  );
}

// --- States ---

export function EmptyState({ days }: { days: number }) {
  return (
    <p className="rounded-lg border border-gray-200 bg-white px-4 py-6 text-sm text-gray-600">
      No jobs finished in {windowPhrase(days)}.
    </p>
  );
}

export function TruncatedNotice({
  data,
  requested,
  onLimit,
}: {
  data: Pick<UtilizationResponse, 'truncated' | 'jobs_considered' | 'limit' | 'max_limit'>;
  // The limit the URL asked for, if any: the way back is offered whenever
  // the user chose a bigger analysis than the default.
  requested?: number;
  onLimit?: (limit: number | undefined) => void;
}) {
  const options = data.truncated && onLimit ? moreOptions(data.limit, data.max_limit) : [];
  const back =
    requested !== undefined && onLimit ? (
      <button type="button" onClick={() => onLimit(undefined)} className="font-medium underline">
        Back to the usual number
      </button>
    ) : null;
  if (!data.truncated) {
    if (!back) return null;
    return (
      <p className="text-xs text-gray-500">
        This covers all {data.jobs_considered.toLocaleString()} jobs in the window. {back}
      </p>
    );
  }
  return (
    <div className="rounded-sm border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900" data-testid="truncated">
      This covers your most recent {data.jobs_considered.toLocaleString()} jobs in the window, not all of them.{' '}
      {options.map((o, i) => (
        <span key={o.limit}>
          {i > 0 && ' or '}
          <button type="button" onClick={() => onLimit!(o.limit)} className="font-medium underline">
            {o.label}
          </button>
        </span>
      ))}
      {options.length > 0 && <span className="text-amber-800"> — slower to answer.</span>}{' '}
      {back}
    </div>
  );
}

// OwnerFilter narrows a pool-wide answer to some users: the chosen ones
// as removable chips, and a list of everyone in the answer to pick from.
export function OwnerFilter({
  options,
  selected,
  onChange,
}: {
  options: UtilOwner[];
  selected: string[];
  onChange: (owners: string[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const toggle = (o: string) =>
    onChange(selected.includes(o) ? selected.filter((x) => x !== o) : [...selected, o]);
  return (
    <div className="flex flex-wrap items-center gap-2" data-testid="owner-filter">
      <div className="relative">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-haspopup="listbox"
          className="rounded-sm border border-gray-300 bg-white px-2 py-1 text-sm text-gray-700 hover:bg-gray-50"
        >
          Users{selected.length ? ` (${selected.length})` : ''} ▾
        </button>
        {open && (
          <div
            role="listbox"
            aria-multiselectable="true"
            aria-label="Users"
            onKeyDown={(e) => {
              if (e.key === 'Escape') setOpen(false);
            }}
            className="absolute z-20 mt-1 max-h-72 w-64 overflow-auto rounded-md border border-gray-200 bg-white py-1 shadow-lg"
          >
            {options.length === 0 && <p className="px-3 py-2 text-xs text-gray-500">No users in this answer.</p>}
            {options.map((o) => (
              <label
                key={o.owner}
                className="flex cursor-pointer items-center gap-2 px-3 py-1.5 text-sm hover:bg-gray-50"
              >
                <input
                  type="checkbox"
                  checked={selected.includes(o.owner)}
                  onChange={() => toggle(o.owner)}
                />
                <span className="flex-1 truncate">{o.owner}</span>
                <span className="text-xs text-gray-500 tabular-nums">
                  {o.jobs.toLocaleString()} {o.jobs === 1 ? 'job' : 'jobs'}
                </span>
              </label>
            ))}
          </div>
        )}
      </div>
      {selected.map((o) => (
        <span
          key={o}
          className="inline-flex items-center gap-1 rounded-full bg-indigo-100 py-0.5 pl-2 pr-1 text-xs font-medium text-indigo-800"
          data-testid="owner-chip"
        >
          {o}
          <button
            type="button"
            onClick={() => onChange(selected.filter((x) => x !== o))}
            aria-label={`Remove ${o}`}
            className="rounded-full px-1 text-indigo-700 hover:bg-indigo-200"
          >
            ×
          </button>
        </span>
      ))}
      {selected.length > 1 && (
        <button type="button" onClick={() => onChange([])} className="text-xs text-gray-500 underline">
          clear
        </button>
      )}
    </div>
  );
}

// --- Workflow detail ---

// ThroughputLead opens a workflow's page with what its suggestions would
// change in practice.
export function ThroughputLead({ throughput }: { throughput: UtilThroughput | null | undefined }) {
  const st = throughputStatement(throughput);
  if (!st) return null;
  const tone = st.kind === 'gain' ? 'border-green-200 bg-green-50' : 'border-gray-200 bg-white';
  return (
    <div className={`rounded-lg border px-4 py-3 ${tone}`} data-testid="throughput-lead">
      <p className={st.kind === 'gain' ? 'font-semibold text-gray-900' : 'text-gray-800'}>{st.line}</p>
      {st.batch && <p className="mt-0.5 text-sm text-gray-700">{st.batch}</p>}
    </div>
  );
}

// jobsNoun agrees the noun with its count: "1 job", "21 jobs".
function jobsNoun(n: number): string {
  return `${n.toLocaleString()} ${n === 1 ? 'job' : 'jobs'}`;
}

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div>
      <div className="text-xs text-gray-500">{label}</div>
      <div className="text-lg font-semibold text-gray-900">{value}</div>
      {sub && <div className="text-xs text-gray-500">{sub}</div>}
    </div>
  );
}

// GpuSection leads a GPU workflow's page: GPUs are the scarcest and most
// expensive thing these jobs reserve, so they come before memory.
export function GpuSection({ gpu, cpuRequest }: { gpu: UtilGpu; cpuRequest: UtilRequest | null }) {
  const requested = gpu.request?.typical;
  const measured =
    gpu.measured < gpu.jobs
      ? `measured on ${gpu.measured.toLocaleString()} of ${gpu.jobs.toLocaleString()} GPU jobs`
      : `${gpu.jobs.toLocaleString()} GPU ${gpu.jobs === 1 ? 'job' : 'jobs'}`;
  return (
    <section aria-labelledby="wf-gpu" className="space-y-3" data-testid="gpu-section">
      <h3 id="wf-gpu" className="text-sm font-semibold uppercase tracking-wide text-gray-500">
        GPUs
      </h3>
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        {gpu.utilization ? (
          <Histogram
            title="How busy each job kept its GPUs"
            subtitle={`median ${formatPercent(gpu.utilization.p50)} busy · ${measured}${requested ? ` · ${formatNumber(requested)} GPU${requested === 1 ? '' : 's'} requested` : ''}`}
            dist={gpu.utilization}
            unit="fraction"
          />
        ) : (
          <p className="rounded-lg border border-gray-200 bg-white p-4 text-sm text-gray-600">
            GPU utilization was not measured for these {gpu.jobs.toLocaleString()} jobs.
          </p>
        )}
        {gpu.memory_peak_mib && (
          <Histogram
            title="Peak GPU memory per job"
            subtitle={`median ${formatMiB(gpu.memory_peak_mib.p50)}, largest ${formatMiB(gpu.memory_peak_mib.max)}${gpu.device_memory_mib ? ` · the GPUs had ${formatMiB(gpu.device_memory_mib)}` : ''}`}
            dist={gpu.memory_peak_mib}
            unit="mib"
            markers={
              gpu.device_memory_mib
                ? [{ value: gpu.device_memory_mib, label: `GPU memory ${formatMiB(gpu.device_memory_mib)}`, kind: 'request' }]
                : []
            }
          />
        )}
        {gpu.cores_used_while_gpu && (
          <Histogram
            title="CPU cores kept busy by GPU jobs"
            subtitle={`median ${formatCores(gpu.cores_used_while_gpu.p50)} cores${cpuRequest ? ` of ${formatCores(cpuRequest.typical)} requested` : ''}`}
            dist={gpu.cores_used_while_gpu}
            unit="plain"
            markers={
              cpuRequest
                ? [{ value: cpuRequest.typical, label: `requested ${formatCores(cpuRequest.typical)}`, kind: 'request' }]
                : []
            }
            note="A GPU job that keeps every requested core busy may be holding its GPU back."
          />
        )}
      </div>
    </section>
  );
}

export function WorkflowDetail({
  workflow: w,
  days,
  backHref,
}: {
  workflow: UtilWorkflow;
  days: number;
  backHref: string;
}) {
  const memReq = w.memory.request;
  const rec = w.memory_curve.find((p) => p.is_recommended);
  const memMarkers: ChartMarker[] = [];
  if (memReq) memMarkers.push({ value: memReq.typical, label: `requested ${formatMiB(memReq.typical)}`, kind: 'request' });
  // The suggestion only earns a marker when it differs from what was
  // asked for; a second line on top of the first says nothing.
  if (rec && (!memReq || rec.request_mib !== memReq.typical)) {
    memMarkers.push({ value: rec.request_mib, label: `suggested ${formatMiB(rec.request_mib)}`, kind: 'recommended' });
  }
  if (rec?.retry_mib) memMarkers.push({ value: rec.retry_mib, label: `retry ${formatMiB(rec.retry_mib)}`, kind: 'retry' });

  const tpCard = throughputAdviceId(w);
  const cpuReq = w.cpu.request;
  const diskReq = w.disk.request;
  const gpu = w.gpu;

  return (
    <div className="space-y-6">
      <div>
        <Link href={backHref} className="text-sm text-brand-700 hover:underline">
          ← All workflows
        </Link>
        <div className="mt-2 flex flex-wrap items-baseline gap-2">
          <h2 className="text-xl font-bold text-gray-900">{w.name}</h2>
          {w.is_dag && (
            <span className="rounded bg-indigo-100 px-1.5 py-0.5 text-xs font-semibold text-indigo-800">DAG</span>
          )}
          <span className="font-mono text-sm text-gray-500">{w.executable}</span>
          {w.owner && <span className="text-sm text-gray-500">· {w.owner}</span>}
          {w.schedd && <span className="text-sm text-gray-500">· {w.schedd}</span>}
        </div>
        <div className="mt-3 flex flex-wrap gap-x-8 gap-y-3 tabular-nums">
          <Stat
            label={`Jobs finished in ${windowPhrase(days)}`}
            value={w.jobs.toLocaleString()}
            sub={[
              `${w.succeeded.toLocaleString()} succeeded`,
              w.failed ? `${w.failed.toLocaleString()} failed` : '',
              w.removed ? `${w.removed.toLocaleString()} removed` : '',
            ]
              .filter(Boolean)
              .join(', ')}
          />
          <Stat
            label="Run time"
            value={formatHours(w.wall_hours)}
            sub={w.wall ? `median ${formatHours(w.wall.p50 / 3600)} per job` : undefined}
          />
          {w.restarts.jobs > 0 && (
            <Stat
              label="Restarted"
              value={jobsNoun(w.restarts.jobs)}
              sub={`${formatHours(w.restarts.lost_hours)} lost`}
            />
          )}
          {(w.holds.memory > 0 || w.holds.disk > 0) && (
            <Stat
              label="Held for going over"
              value={jobsNoun(w.holds.memory + w.holds.disk)}
              sub={[w.holds.memory ? `${w.holds.memory} memory` : '', w.holds.disk ? `${w.holds.disk} disk` : '']
                .filter(Boolean)
                .join(', ')}
            />
          )}
        </div>
      </div>

      <ThroughputLead throughput={w.throughput} />

      <div className="grid grid-cols-[repeat(auto-fit,minmax(13rem,1fr))] gap-3">
        {sortResources(w.resources).map((r) => (
          <ResourceCard key={r.resource} summary={r} jobs={w.jobs} />
        ))}
      </div>

      {w.advice.length > 0 && (
        <section aria-labelledby="wf-advice" className="space-y-3">
          <h3 id="wf-advice" className="text-sm font-semibold uppercase tracking-wide text-gray-500">
            What to change next time
          </h3>
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            {w.advice.map((a, i) => (
              <AdviceCard key={`${a.id}-${i}`} advice={a} throughput={a.id === tpCard ? w.throughput : null} />
            ))}
          </div>
        </section>
      )}

      {gpu && <GpuSection gpu={gpu} cpuRequest={cpuReq} />}

      {w.memory.peak_mib && (
        <section aria-labelledby="wf-memory" className="space-y-3">
          <h3 id="wf-memory" className="text-sm font-semibold uppercase tracking-wide text-gray-500">
            Memory
          </h3>
          <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
            <Histogram
              title="Peak memory per job"
              subtitle={`${w.memory.peak_mib.n.toLocaleString()} jobs · median ${formatMiB(w.memory.peak_mib.p50)}, 95% under ${formatMiB(w.memory.peak_mib.p95)}, largest ${formatMiB(w.memory.peak_mib.max)}`}
              dist={w.memory.peak_mib}
              unit="mib"
              markers={memMarkers}
              shadeFrom={rec && rec.retry_fraction > 0 ? rec.request_mib : undefined}
              shadeLabel={rec?.retry_mib ? `would rerun at ${formatMiB(rec.retry_mib)}` : 'would rerun'}
              note={
                memReq && memReq.distinct > 1
                  ? `Requests ranged from ${formatMiB(memReq.min)} to ${formatMiB(memReq.max)}; the line is the most common.`
                  : undefined
              }
            />
            {w.memory_curve.length > 0 ? (
              <MemoryCurve points={w.memory_curve} />
            ) : (
              <p className="rounded-lg border border-gray-200 bg-white p-4 text-sm text-gray-500">
                Too few jobs to weigh one memory request against another.
              </p>
            )}
            <OutcomeScatter samples={w.samples} request={memReq} />
            <TrendChart
              title="Memory requested and 95th-percentile peak, by submission"
              batches={w.batches}
              request={(b) => b.memory_request_mib}
              used={(b) => b.memory_p95_mib}
              usedLabel="95% peak"
              unit="mib"
            />
          </div>
        </section>
      )}

      {w.cpu.cores_used && (
        <section aria-labelledby="wf-cpu" className="space-y-3">
          <h3 id="wf-cpu" className="text-sm font-semibold uppercase tracking-wide text-gray-500">
            CPU
          </h3>
          <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
            {/* For a workflow of GPU jobs only, the GPU section already
                shows this histogram. */}
            {!(gpu?.cores_used_while_gpu && gpu.jobs === w.jobs) && (
              <Histogram
                title="CPU cores kept busy per job"
                subtitle={`median ${formatCores(w.cpu.cores_used.p50)} cores${cpuReq ? ` of ${formatCores(cpuReq.typical)} requested` : ''}${w.cpu.efficiency ? ` · median efficiency ${formatPercent(w.cpu.efficiency.p50)}` : ''}`}
                dist={w.cpu.cores_used}
                unit="plain"
                markers={cpuReq ? [{ value: cpuReq.typical, label: `requested ${formatCores(cpuReq.typical)}`, kind: 'request' }] : []}
              />
            )}
            <TrendChart
              title="CPUs requested and median cores used, by submission"
              batches={w.batches}
              request={(b) => b.cpu_request}
              used={(b) => b.cpu_cores_p50}
              usedLabel="median used"
              unit="plain"
            />
          </div>
        </section>
      )}

      {w.disk.used_kib && (
        <section aria-labelledby="wf-other" className="space-y-3">
          <h3 id="wf-other" className="text-sm font-semibold uppercase tracking-wide text-gray-500">
            Disk
          </h3>
          <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
            {w.disk.used_kib && (
              <Histogram
                title="Disk used per job"
                subtitle={`median ${formatKiB(w.disk.used_kib.p50)}, largest ${formatKiB(w.disk.used_kib.max)}`}
                dist={w.disk.used_kib}
                unit="kib"
                markers={diskReq ? [{ value: diskReq.typical, label: `requested ${formatKiB(diskReq.typical)}`, kind: 'request' }] : []}
              />
            )}
          </div>
        </section>
      )}
    </div>
  );
}
