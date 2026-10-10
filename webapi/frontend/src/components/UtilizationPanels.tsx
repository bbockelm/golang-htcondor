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
import { useState } from 'react';
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
  type RankedAdvice,
  type UtilThroughput,
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
      {f === null ? (
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

export function WorkflowsTable({
  workflows,
  hrefFor,
  onOpen,
}: {
  workflows: UtilWorkflow[];
  hrefFor: (key: string) => string;
  onOpen: (key: string) => void;
}) {
  const [sort, setSort] = useSortState<SortKey>('wall', 'desc');
  const rows = useSortedRows(workflows, sort, sortValue);
  const showOwner = workflows.some((w) => w.owner);
  const showSchedd = workflows.some((w) => w.schedd);
  // A column of blanks is noise: only when some workflow has a figure.
  const showThroughput = workflows.some((w) => throughputColumn(w) !== undefined);
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
            {rows.map((w) => {
              const n = actionable(w);
              return (
                <tr
                  key={w.key}
                  tabIndex={0}
                  onClick={() => onOpen(w.key)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onOpen(w.key);
                    }
                  }}
                  aria-label={`${w.name}: ${w.jobs.toLocaleString()} jobs. Open details.`}
                  className="cursor-pointer align-middle hover:bg-gray-50 focus:bg-brand-50 focus:outline-none"
                >
                  <td className="px-3 py-2">
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
                        <span className="rounded bg-indigo-100 px-1.5 py-0.5 text-[10px] font-semibold text-indigo-800">
                          DAG
                        </span>
                      )}
                    </div>
                    <div className="mt-0.5 text-xs text-gray-500">
                      <span className="font-mono">{w.executable}</span>
                      {showOwner && w.owner && <> · {w.owner}</>}
                      {showSchedd && w.schedd && <> · {w.schedd}</>}
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
            })}
          </tbody>
        </table>
      </div>
      <div className="mt-2">
        <RangeStripKey />
      </div>
    </section>
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

export function TruncatedNotice({ data }: { data: Pick<UtilizationResponse, 'truncated' | 'jobs_considered'> }) {
  if (!data.truncated) return null;
  return (
    <p className="rounded-sm border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
      This covers your most recent {data.jobs_considered.toLocaleString()} jobs in the window, not all of them.
    </p>
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
            <Histogram
              title="CPU cores kept busy per job"
              subtitle={`median ${formatCores(w.cpu.cores_used.p50)} cores${cpuReq ? ` of ${formatCores(cpuReq.typical)} requested` : ''}${w.cpu.efficiency ? ` · median efficiency ${formatPercent(w.cpu.efficiency.p50)}` : ''}`}
              dist={w.cpu.cores_used}
              unit="plain"
              markers={cpuReq ? [{ value: cpuReq.typical, label: `requested ${formatCores(cpuReq.typical)}`, kind: 'request' }] : []}
            />
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

      {(w.disk.used_kib || gpu?.utilization) && (
        <section aria-labelledby="wf-other" className="space-y-3">
          <h3 id="wf-other" className="text-sm font-semibold uppercase tracking-wide text-gray-500">
            {gpu?.utilization ? 'Disk and GPU' : 'Disk'}
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
            {gpu?.utilization && (
              <Histogram
                title="How busy each job kept its GPUs"
                subtitle={`median ${formatPercent(gpu.utilization.p50)} busy${gpu.request ? ` · ${formatNumber(gpu.request.typical)} GPU${gpu.request.typical === 1 ? '' : 's'} requested` : ''}`}
                dist={gpu.utilization}
                unit="fraction"
              />
            )}
          </div>
        </section>
      )}
    </div>
  );
}
