'use client';

// The sections of /batches/<id>: everything about one batch or DAG in
// one place. A batch is the group people submit and think in -- "my 300
// BLAST jobs", "the assembly DAG" -- and until this page the way to see
// one whole was to expand its row on /jobs, which shows only the jobs
// still in the queue.
//
// Each section takes plain data and renders it, so the tests can render
// one state at a time; app/batches/[id] fetches and composes them.

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, type DisplayStatus } from '@/lib/api';
import { BatchProgressBar } from '@/components/BatchProgressBar';
import { BatchUsagePanel } from '@/components/BatchUsagePanel';
import { BatchTimeLeftCell, JobTimeLeftCell } from '@/components/TimeLeft';
import { ConfirmButton } from '@/components/ConfirmButton';
import { DagGraphPanel } from '@/components/DagGraphPanel';
import { OwnerLink } from '@/components/OwnerLink';
import { useCards } from '@/lib/useNarrow';
import { statusPillCls } from '@/lib/statusPill';
import { progressSentence } from '@/lib/batchProgress';
import { BATCH_USAGE_PROJECTION, DISPLAY_STATUS_LABEL, DISPLAY_STATUS_ORDER, summarizeBatchUsage } from '@/lib/batches';
import { displayHoldReason } from '@/lib/holdReasons';
import { approxDuration, humanDuration } from '@/lib/duration';
import { rangeBarScale, type TimedJob } from '@/lib/timeLeft';
import { useRuntimeEstimates, type RuntimeEstimatesState } from '@/lib/useRuntimeEstimates';
import {
  dagNodeBreakdown,
  dagNodes,
  outcomeLabel,
  progressForDisplay,
  type BatchJobRow,
  type BatchJobSort,
  type BatchJobsResponse,
  type BatchResponse,
  type FinishedStats,
} from '@/lib/batchPage';

const sectionCls = 'rounded-sm border border-gray-200 bg-white p-4';
const headingCls = 'text-xs font-semibold uppercase tracking-wide text-gray-500';

function ago(t: number, now: number): string {
  return `${humanDuration(now - t)} ago`;
}

// --- Header ---

export function BatchHeader({
  batch,
  now,
  multiAP,
}: {
  batch: BatchResponse;
  now: number;
  multiAP?: boolean;
}) {
  const qc = useQueryClient();
  const done = () => {
    void qc.invalidateQueries({ queryKey: ['batch'] });
    void qc.invalidateQueries({ queryKey: ['batch-jobs'] });
    void qc.invalidateQueries({ queryKey: ['jobs'] });
  };
  // The same constraint /jobs's "Remove batch" uses: for a DAG it also
  // matches the DAGMan job, so the whole workflow goes.
  const remove = useMutation({ mutationFn: () => api.jobs.removeByConstraint(batch.remove_constraint), onSuccess: done });
  const hold = useMutation({ mutationFn: () => api.jobs.holdByConstraint(batch.remove_constraint), onSuccess: done });
  const release = useMutation({ mutationFn: () => api.jobs.releaseByConstraint(batch.remove_constraint), onSuccess: done });
  const live = batch.live;
  const active = (live.idle ?? 0) + (live.running ?? 0) + (live.transferring ?? 0) + (live.suspended ?? 0);
  const held = live.held ?? 0;
  // What Remove would take: everything still in the queue except jobs
  // already on their way out.
  const removable = batch.live_jobs - (live.completed ?? 0) - (live.removed ?? 0);
  const err = remove.error ?? hold.error ?? release.error;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h1 className="break-all text-2xl font-bold text-gray-900">{batch.name}</h1>
        {batch.kind === 'dag' && (
          <span className="rounded bg-indigo-100 px-1.5 py-0.5 text-xs font-semibold text-indigo-800">DAG</span>
        )}
        <span className="text-sm text-gray-500">
          {batch.kind === 'dag' ? 'DAG' : 'Batch'} {batch.id}
          {batch.clusters.length > 1 && ` · ${batch.clusters.length} clusters`}
        </span>
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm text-gray-600">
        {batch.owner && (
          <span>
            Owner <OwnerLink owner={batch.owner} />
          </span>
        )}
        {batch.submitted !== undefined && (
          <span title={new Date(batch.submitted * 1000).toLocaleString()}>Submitted {ago(batch.submitted, now)}</span>
        )}
        {batch.last_completion !== undefined && active === 0 && held === 0 && (
          <span title={new Date(batch.last_completion * 1000).toLocaleString()}>
            Last job finished {ago(batch.last_completion, now)}
          </span>
        )}
      </div>
      {!multiAP && removable > 0 && (
        <div className="flex flex-wrap items-center gap-2" data-testid="batch-actions">
          {held > 0 && (
            <ConfirmButton
              label={`Release ${held.toLocaleString()} held`}
              confirmLabel={`Release ${held.toLocaleString()} ${held === 1 ? 'job' : 'jobs'}`}
              onConfirm={() => release.mutate()}
              pending={release.isPending}
            />
          )}
          {active > 0 && (
            <ConfirmButton
              label="Hold batch"
              confirmLabel={`Hold ${active.toLocaleString()} ${active === 1 ? 'job' : 'jobs'}`}
              onConfirm={() => hold.mutate()}
              pending={hold.isPending}
            />
          )}
          <ConfirmButton
            label="Remove batch"
            confirmLabel={`Remove ${removable.toLocaleString()} ${removable === 1 ? 'job' : 'jobs'}`}
            onConfirm={() => remove.mutate()}
            pending={remove.isPending}
          />
          {err && <span className="text-sm text-red-700">{err.message}</span>}
        </div>
      )}
    </div>
  );
}

// --- Progress ---

export function ProgressSection({
  batch,
  timed,
  estimates,
  now,
}: {
  batch: BatchResponse;
  // The batch's waiting and running jobs with their estimates, for the
  // time left; undefined while they load.
  timed: TimedJob[] | undefined;
  estimates: RuntimeEstimatesState | undefined;
  now: number;
}) {
  const p = progressForDisplay(batch.progress);
  const live = DISPLAY_STATUS_ORDER.filter((s) => (batch.live[s] ?? 0) > 0);
  return (
    <section aria-labelledby="batch-progress" className={sectionCls} data-testid="batch-progress">
      <h2 id="batch-progress" className={headingCls}>
        Progress
      </h2>
      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-2">
        <BatchProgressBar progress={p} />
        <p className="whitespace-pre-line text-sm text-gray-700">{p.known ? progressSentence(p) : p.why}</p>
      </div>
      {live.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1" data-testid="live-counts">
          {live.map((s) => (
            <span key={s} className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium tabular-nums ${statusPillCls(s)}`}>
              {(batch.live[s] ?? 0).toLocaleString()} {DISPLAY_STATUS_LABEL[s]}
            </span>
          ))}
        </div>
      )}
      {/* Nothing to say without an estimate, except a DAG's node count. */}
      {timed && estimates && timed.length > 0 && (batch.kind === 'dag' || estimates.byId.size > 0) && (
        <div className="mt-3 flex items-baseline gap-3 [&_[data-testid=batch-time-left]]:w-auto" data-testid="batch-time-left-section">
          <span className="text-sm text-gray-500">Time left</span>
          <BatchTimeLeftCell
            jobs={timed}
            dag={batch.kind === 'dag' ? { nodes: dagNodes(batch.dag) } : undefined}
            fetchedAt={estimates.fetchedAt}
            now={now}
          />
        </div>
      )}
      {batch.live_truncated && (
        <p className="mt-2 text-xs text-gray-500">This batch has more jobs in the queue than this page reads at once.</p>
      )}
    </section>
  );
}

// --- DAG ---

export function DagSection({ batch }: { batch: BatchResponse }) {
  if (batch.kind !== 'dag') return null;
  const nodes = dagNodeBreakdown(batch.dag);
  return (
    <section aria-labelledby="batch-dag" className={sectionCls} data-testid="batch-dag">
      <h2 id="batch-dag" className={headingCls}>
        Workflow
      </h2>
      {nodes.length > 0 ? (
        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-sm text-gray-700 tabular-nums" data-testid="dag-nodes">
          {nodes.map((n) => (
            <span key={n.label}>
              <span className="font-semibold text-gray-900">{n.count.toLocaleString()}</span> {n.label}
            </span>
          ))}
        </div>
      ) : (
        <p className="mt-2 text-sm text-gray-500">This workflow has not reported its nodes yet.</p>
      )}
      {batch.dagman_job_id && (
        <div className="mt-3">
          <DagGraphPanel jobId={batch.dagman_job_id} />
        </div>
      )}
    </section>
  );
}

// --- Finished jobs ---

// RuntimeStrip draws finished jobs' run times on an axis from zero:
// whiskers p10 to p90, a tick at the median, a dot at the longest.
function RuntimeStrip({ r }: { r: NonNullable<FinishedStats['runtime']> }) {
  const max = Math.max(r.max, r.p90) * 1.05 || 1;
  const at = (s: number) => `${Math.min(100, (s / max) * 100).toFixed(2)}%`;
  return (
    <div className="relative h-6" aria-hidden="true" data-testid="runtime-strip">
      <div className="absolute inset-x-0 top-3 h-px bg-gray-300" />
      <div
        className="absolute top-2 h-2 rounded-sm bg-[#86b6ef]"
        style={{ left: at(r.p10), width: `max(3px, calc(${at(r.p90)} - ${at(r.p10)}))` }}
      />
      <div className="absolute top-1 h-4 w-0.5 bg-[#184f95]" style={{ left: at(r.p50) }} />
      <div className="absolute top-[9px] h-2 w-2 -translate-x-1/2 rounded-full bg-gray-700" style={{ left: at(r.max) }} />
    </div>
  );
}

export function OutcomesSection({ batch }: { batch: BatchResponse }) {
  const f = batch.finished;
  if (f.jobs === 0) {
    return (
      <section aria-labelledby="batch-outcomes" className={sectionCls} data-testid="batch-outcomes">
        <h2 id="batch-outcomes" className={headingCls}>
          Finished jobs
        </h2>
        <p className="mt-2 text-sm text-gray-500">None of this batch&apos;s jobs has finished yet.</p>
      </section>
    );
  }
  return (
    <section aria-labelledby="batch-outcomes" className={sectionCls} data-testid="batch-outcomes">
      <h2 id="batch-outcomes" className={headingCls}>
        Finished jobs
      </h2>
      <div className="mt-2 flex flex-wrap gap-x-6 gap-y-2 tabular-nums">
        <Figure label="succeeded" value={f.succeeded} />
        <Figure label="failed" value={f.failed} tone={f.failed > 0 ? 'bad' : undefined} />
        <Figure label="removed" value={f.removed} />
      </div>
      {f.outcomes.length > 1 && (
        <ul className="mt-2 flex flex-wrap gap-1.5 text-xs" data-testid="outcomes">
          {f.outcomes.map((o) => (
            <li
              key={`${o.outcome}-${o.code ?? ''}`}
              className={`rounded-full px-2 py-0.5 tabular-nums ${
                o.outcome === 'exit' && o.code === 0 ? 'bg-green-50 text-green-800' : o.outcome === 'removed' ? 'bg-gray-100 text-gray-700' : 'bg-red-50 text-red-800'
              }`}
            >
              {o.count.toLocaleString()} · {outcomeLabel(o)}
            </li>
          ))}
        </ul>
      )}
      {f.runtime && (
        <div className="mt-3 max-w-xl">
          <RuntimeStrip r={f.runtime} />
          <div className="flex justify-between text-[11px] text-gray-500 tabular-nums" aria-hidden="true">
            <span>0</span>
            <span>{approxDuration(Math.max(f.runtime.max, f.runtime.p90) * 1.05)}</span>
          </div>
          <p className="text-sm text-gray-700">
            Typically {approxDuration(f.runtime.p50)}; 9 in 10 within {approxDuration(f.runtime.p90)}; the longest{' '}
            {approxDuration(f.runtime.max)}.
          </p>
        </div>
      )}
      <p className="mt-2 text-sm text-gray-600 tabular-nums">
        {fmtHours(f.wall_hours)} of run time
        {f.badput_hours * 3600 >= 60 && (
          <>
            , <span className="font-medium text-gray-900">{fmtHours(f.badput_hours)}</span> of it lost to runs that
            started over
          </>
        )}
        {f.core_hours >= 1 && <> · {Math.round(f.core_hours).toLocaleString()} core-hours</>}
      </p>
      {f.memory && (
        <p className="mt-1 text-sm text-gray-600 tabular-nums">
          Peak memory typically {fmtMiB(f.memory.peak_p50)} of {fmtMiB(f.memory.request_p50)} requested; the largest{' '}
          {fmtMiB(f.memory.peak_max)}.
        </p>
      )}
      {f.truncated && (
        <p className="mt-1 text-xs text-gray-500">
          These cover the newest {f.limit.toLocaleString()} finished jobs.
        </p>
      )}
    </section>
  );
}

// Hours of run time, in hours once there are a few of them.
function fmtHours(h: number): string {
  return h >= 2 ? `${Math.round(h).toLocaleString()} h` : approxDuration(h * 3600);
}

// In the units the usage panel beside it uses.
function fmtMiB(mib: number): string {
  return mib >= 1024 ? `${(mib / 1024).toFixed(1).replace(/\.0$/, '')} GiB` : `${Math.round(mib)} MiB`;
}

function Figure({ label, value, tone }: { label: string; value: number; tone?: 'bad' }) {
  return (
    <div>
      <span className={`text-2xl font-semibold ${tone === 'bad' ? 'text-red-700' : 'text-gray-900'}`}>
        {value.toLocaleString()}
      </span>{' '}
      <span className="text-sm text-gray-500">{label}</span>
    </div>
  );
}

// --- Hold reasons ---

export function HoldsSection({ batch }: { batch: BatchResponse }) {
  const groups = batch.hold_reasons.filter((g) => !g.codes.every((c) => c.code === SPOOLING_HOLD_CODE));
  if (groups.length === 0) return null;
  return (
    <section aria-labelledby="batch-holds" className={sectionCls} data-testid="batch-holds">
      <h2 id="batch-holds" className={headingCls}>
        Hold reasons
      </h2>
      <ul className="mt-2 space-y-3">
        {groups.map((g, i) => (
          <li key={`${g.kind}-${i}`} className="text-sm">
            <div className="flex flex-wrap items-baseline gap-x-2">
              <span className="font-semibold tabular-nums text-gray-900">{g.count.toLocaleString()}</span>
              <span className="text-gray-500">{g.kind === 'held' ? (g.count === 1 ? 'job held now' : 'jobs held now') : g.count === 1 ? 'finished job was held' : 'finished jobs were held'}</span>
              {g.codes.map((c) => (
                <span key={`${c.code}/${c.subcode}`} className="rounded bg-gray-100 px-1.5 text-xs text-gray-600">
                  {c.label ?? `code ${c.code}`}
                </span>
              ))}
            </div>
            {/* One of the group's own messages: the group's pattern has
                its varying parts blanked out, which is no message at all. */}
            {g.examples[0]?.message && (
              <p className="mt-0.5 break-words font-mono text-xs text-gray-700" title={g.examples[0].message}>
                {displayHoldReason(g.examples[0].message)}
              </p>
            )}
            {g.examples.length > 0 && (
              <p className="mt-0.5 text-xs text-gray-500">
                e.g.{' '}
                {g.examples.map((e, j) => (
                  <span key={e.id}>
                    {j > 0 && ', '}
                    <Link href={`/jobs/${encodeURIComponent(e.id)}`} className="font-mono text-brand-700 hover:underline" title={e.message}>
                      {e.id}
                    </Link>
                  </span>
                ))}
              </p>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

// --- Resources ---

export function ResourcesSection({ batch }: { batch: BatchResponse }) {
  // Live usage of the jobs in the queue, as /jobs shows it for an open
  // batch; nothing when the batch has no jobs in the queue.
  const { data, isFetching } = useQuery({
    queryKey: ['batch-usage', batch.id, batch.remove_constraint],
    enabled: batch.live_jobs > 0,
    queryFn: () =>
      api.jobs.list({ constraint: batch.remove_constraint, projection: BATCH_USAGE_PROJECTION, limit: '*', owned_by_me: false }),
    refetchInterval: 30_000,
    retry: false,
  });
  const usage = useMemo(() => summarizeBatchUsage(data?.jobs ?? []), [data]);
  const showUsage = batch.live_jobs > 0 && (usage.running > 0 || usage.idle > 0 || isFetching);
  if (!showUsage && batch.workflows.length === 0) return null;
  return (
    <section aria-labelledby="batch-resources" className={sectionCls} data-testid="batch-resources">
      <h2 id="batch-resources" className={headingCls}>
        Resources
      </h2>
      {showUsage && (
        <div className="mt-2">
          <BatchUsagePanel usage={usage} loading={isFetching && !data} embedded />
        </div>
      )}
      {batch.workflows.length > 0 && (
        <div className="mt-2 text-sm">
          <span className="text-gray-600">How well the finished jobs used what they asked for: </span>
          <ul className="mt-1 flex flex-wrap gap-x-4 gap-y-1" data-testid="batch-workflows">
            {batch.workflows.map((w) => (
              <li key={w.key}>
                <Link href={`/utilization?w=${encodeURIComponent(w.key)}&days=30`} className="text-brand-700 hover:underline">
                  {w.name}
                </Link>{' '}
                <span className="text-xs text-gray-500 tabular-nums">
                  {w.jobs.toLocaleString()} {w.jobs === 1 ? 'job' : 'jobs'}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

// --- Jobs ---

type JobFilter = 'all' | 'live' | 'finished' | DisplayStatus;

const SORT_LABEL: Record<BatchJobSort, string> = {
  default: 'In the queue first',
  id: 'Job id',
  status: 'Status',
  submitted: 'Submitted',
  started: 'Started',
  finished: 'Finished',
  runtime: 'Run time',
  exit: 'Exit code',
  peak_memory: 'Peak memory',
};

const PAGE_SIZE = 50;

function rowTime(r: BatchJobRow, now: number): string | undefined {
  if (r.source === 'history') return r.runtime_seconds !== undefined ? `ran ${humanDuration(r.runtime_seconds)}` : undefined;
  if (r.status === 'running' && r.started) return `running ${humanDuration(now - r.started)}`;
  if (r.status === 'idle' && r.submitted) return `waiting ${humanDuration(now - r.submitted)}`;
  return undefined;
}

function rowEnding(r: BatchJobRow): string | undefined {
  if (r.outcome === 'removed') return 'removed';
  if (r.exit_signal !== undefined) return `signal ${r.exit_signal}`;
  if (r.exit_code !== undefined) return `exit ${r.exit_code}`;
  return undefined;
}

// The spool hold every remotely submitted job passes through before its
// input arrives: not something that went wrong.
const SPOOLING_HOLD_CODE = 16;

function shownHold(r: BatchJobRow): string | undefined {
  return r.hold_reason && r.hold_code !== SPOOLING_HOLD_CODE ? r.hold_reason : undefined;
}

// A held job's reason; for a finished job, the hold it had along the way.
function HoldLine({ r, className }: { r: BatchJobRow; className: string }) {
  const reason = shownHold(r);
  if (!reason) return null;
  return (
    <div className={className} title={reason}>
      {r.source === 'history' && <span className="text-gray-500">Was held: </span>}
      {displayHoldReason(reason)}
    </div>
  );
}

function StatusPill({ r }: { r: BatchJobRow }) {
  const failed = r.outcome === 'failed';
  return (
    <span
      className={`inline-flex whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium ${
        failed ? 'bg-red-100 text-red-800' : statusPillCls(r.status)
      }`}
    >
      {failed ? 'Failed' : DISPLAY_STATUS_LABEL[r.status]}
    </span>
  );
}

export function JobsSection({
  batch,
  estimates,
  now,
}: {
  batch: BatchResponse;
  estimates: RuntimeEstimatesState | undefined;
  now: number;
}) {
  const cards = useCards();
  const [filter, setFilter] = useState<JobFilter>('all');
  const [sort, setSort] = useState<BatchJobSort>('default');
  const status = filter === 'all' ? undefined : [filter];
  const q = useInfiniteQuery<BatchJobsResponse, Error>({
    queryKey: ['batch-jobs', batch.id, filter, sort],
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      api.batches.jobs(batch.id, { status, sort, offset: pageParam as number, page_size: PAGE_SIZE }),
    getNextPageParam: (last) => last.next_offset ?? undefined,
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  });
  const rows = (q.data?.pages ?? []).flatMap((p) => p.jobs);
  const total = q.data?.pages[0]?.total;
  // The chips: everything, the queue, the finished ones, and each state
  // the queue holds now.
  const chips: { key: JobFilter; label: string; count?: number }[] = [
    { key: 'all', label: 'All' },
    ...(batch.live_jobs > 0 ? [{ key: 'live' as JobFilter, label: 'In the queue', count: batch.live_jobs }] : []),
    ...(batch.finished.jobs > 0 ? [{ key: 'finished' as JobFilter, label: 'Finished', count: batch.finished.jobs }] : []),
    ...DISPLAY_STATUS_ORDER.filter((s) => (batch.live[s] ?? 0) > 0).map((s) => ({
      key: s as JobFilter,
      label: DISPLAY_STATUS_LABEL[s],
      count: batch.live[s],
    })),
  ];
  const timed = (r: BatchJobRow): TimedJob | undefined =>
    estimates && estimates.byId.has(r.id)
      ? { status: r.status === 'running' ? 'running' : r.status === 'idle' ? 'idle' : 'other', estimate: estimates.byId.get(r.id), dagman: r.dagman }
      : undefined;
  const scale = estimates
    ? rangeBarScale(
        rows.map(timed).filter((t): t is TimedJob => !!t),
        estimates.fetchedAt,
        now,
      )
    : 0;
  const showNode = batch.kind === 'dag';

  return (
    <section aria-labelledby="batch-jobs" className="space-y-2" data-testid="batch-jobs">
      <h2 id="batch-jobs" className={headingCls}>
        Jobs
      </h2>
      <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Show">
        {chips.map((c) => (
          <button
            key={c.key}
            type="button"
            aria-pressed={filter === c.key}
            onClick={() => setFilter(c.key)}
            className={`rounded-full border px-2.5 py-1 text-xs ${
              filter === c.key ? 'border-brand-600 bg-brand-50 text-brand-800' : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50'
            }`}
          >
            {c.label}
            {c.count !== undefined && <span className="ml-1 tabular-nums text-gray-500">{c.count.toLocaleString()}</span>}
          </button>
        ))}
        <label className="ml-auto flex items-center gap-1.5 text-sm text-gray-600">
          Sort
          <select
            value={sort}
            onChange={(e) => setSort(e.target.value as BatchJobSort)}
            className="rounded-sm border border-gray-300 bg-white px-2 py-1 text-sm"
          >
            {(Object.keys(SORT_LABEL) as BatchJobSort[]).map((k) => (
              <option key={k} value={k}>
                {SORT_LABEL[k]}
              </option>
            ))}
          </select>
        </label>
      </div>
      {q.error && <p className="text-sm text-red-700">Could not load the jobs: {q.error.message}</p>}
      {!q.data && !q.error && <p className="text-sm text-gray-400">Loading jobs…</p>}
      {q.data && rows.length === 0 && <p className="text-sm text-gray-500">No jobs here.</p>}
      {rows.length > 0 &&
        (cards ? (
          <ul className="divide-y divide-gray-200 rounded-sm border border-gray-200 bg-white" data-testid="batch-job-cards">
            {rows.map((r) => {
              const t = timed(r);
              const time = rowTime(r, now);
              const ending = rowEnding(r);
              return (
                <li key={r.id} className="space-y-1 px-3 py-2" data-testid="batch-job-card">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
                    <Link href={`/jobs/${encodeURIComponent(r.id)}`} className="font-mono text-sm text-brand-700 hover:underline">
                      {r.id}
                    </Link>
                    {(r.node || r.dagman) && <span className="break-all text-gray-500">{r.node ?? 'DAGMan'}</span>}
                    <StatusPill r={r} />
                    {time && <span className="tabular-nums text-gray-500">{time}</span>}
                    {ending && <span className="tabular-nums text-gray-500">{ending}</span>}
                  </div>
                  {t && estimates && <JobTimeLeftCell job={t} scale={scale} fetchedAt={estimates.fetchedAt} now={now} />}
                  <HoldLine r={r} className="line-clamp-2 break-words text-xs text-gray-700" />
                </li>
              );
            })}
          </ul>
        ) : (
          <div className="overflow-x-auto rounded-sm border border-gray-200 bg-white">
            <table className="min-w-full text-sm">
              <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
                <tr>
                  <th className="px-3 py-2 font-medium">Job</th>
                  {showNode && <th className="px-3 py-2 font-medium">Node</th>}
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Time</th>
                  <th className="px-3 py-2 font-medium">Finished</th>
                  <th className="px-3 py-2 text-right font-medium">Peak memory</th>
                  <th className="px-3 py-2 font-medium">Ending / hold</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {rows.map((r) => {
                  const t = timed(r);
                  return (
                    <tr key={r.id} className="align-top" data-testid="batch-job-row">
                      <td className="px-3 py-1.5 font-mono text-xs">
                        <Link href={`/jobs/${encodeURIComponent(r.id)}`} className="text-brand-700 hover:underline">
                          {r.id}
                        </Link>
                      </td>
                      {showNode && (
                        <td className="max-w-48 break-all px-3 py-1.5 text-xs text-gray-600">
                          {r.node ?? (r.dagman ? <span className="italic">DAGMan</span> : '—')}
                        </td>
                      )}
                      <td className="px-3 py-1.5">
                        <StatusPill r={r} />
                      </td>
                      <td className="px-3 py-1.5 text-xs text-gray-700 tabular-nums">
                        {rowTime(r, now) ?? '—'}
                        {t && estimates && (
                          <div className="mt-1">
                            <JobTimeLeftCell job={t} scale={scale} fetchedAt={estimates.fetchedAt} now={now} />
                          </div>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-3 py-1.5 text-xs text-gray-600 tabular-nums">
                        {r.finished ? new Date(r.finished * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }) : '—'}
                      </td>
                      <td className="whitespace-nowrap px-3 py-1.5 text-right text-xs tabular-nums">
                        {r.peak_memory_mib !== undefined
                          ? `${fmtMiB(r.peak_memory_mib)}${r.request_memory_mib ? ` of ${fmtMiB(r.request_memory_mib)}` : ''}`
                          : '—'}
                      </td>
                      <td className="max-w-72 px-3 py-1.5 text-xs text-gray-700">
                        {rowEnding(r) ?? (shownHold(r) ? null : '—')}
                        <HoldLine r={r} className="line-clamp-2 break-words" />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ))}
      {q.hasNextPage && (
        <button
          type="button"
          onClick={() => void q.fetchNextPage()}
          disabled={q.isFetchingNextPage}
          className="text-sm text-brand-700 hover:underline disabled:opacity-50"
        >
          {q.isFetchingNextPage ? 'Loading…' : `Show more (${rows.length.toLocaleString()} of ${total?.toLocaleString()})`}
        </button>
      )}
      {(q.data?.pages[0]?.history_truncated || q.data?.pages[0]?.live_truncated) && (
        <p className="text-xs text-gray-500">Only part of this batch&apos;s jobs is listed: it has more than this page reads.</p>
      )}
    </section>
  );
}

// --- Time left, from the batch's waiting and running jobs ---

/**
 * useBatchTimeLeft asks the runtime estimator about the batch's waiting
 * and running jobs, the way /jobs does, and returns them as the time-left
 * functions take them.
 */
export function useBatchTimeLeft(batch: BatchResponse | undefined): {
  timed: TimedJob[] | undefined;
  estimates: RuntimeEstimatesState | undefined;
} {
  const active = (batch?.live.idle ?? 0) + (batch?.live.running ?? 0) > 0;
  const { data } = useQuery({
    queryKey: ['batch-jobs', batch?.id, 'timed'],
    enabled: !!batch && active,
    queryFn: () => api.batches.jobs(batch!.id, { status: ['idle', 'running'], page_size: 500 }),
    refetchInterval: 60_000,
    retry: (n, e) => !(e instanceof ApiError && e.status < 500) && n < 1,
  });
  const rows = useMemo(() => (data?.jobs ?? []).filter((r) => r.source === 'queue'), [data]);
  const req = useMemo(
    () => rows.filter((r) => !r.dagman).map((r) => ({ id: r.id, status: r.status === 'running' ? ('running' as const) : r.status === 'idle' ? ('idle' as const) : ('other' as const) })),
    [rows],
  );
  const estimates = useRuntimeEstimates(req, active);
  const timed = useMemo(
    () =>
      data
        ? rows.map((r) => ({
            status: r.status === 'running' ? ('running' as const) : r.status === 'idle' ? ('idle' as const) : ('other' as const),
            estimate: estimates.byId.get(r.id),
            dagman: r.dagman,
          }))
        : undefined,
    [data, rows, estimates],
  );
  return { timed, estimates: estimates.available ? estimates : undefined };
}
