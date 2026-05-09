'use client';

// HTCondor is batch-oriented: a single submission produces one batch
// that may contain many jobs. This page mirrors that — one row per
// batch, with an aggregated jobs count + status breakdown + oldest
// submission time.
//
// Click anywhere on a batch row (except the action buttons) to expand
// it inline and see the individual jobs in that batch.
//
// Server-side projection has to include QDate explicitly: HTCondor's
// schedd does not backfill it, and the submit code now sets QDate at
// submit time (see submit.go).

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import Link from 'next/link';
import {
  api,
  ApiError,
  displayJobStatus,
  type ClassAd,
  type DisplayStatus,
  type DisplayStatusInfo,
} from '@/lib/api';
import { statusPillCls } from '@/app/jobs/[id]/JobDetailClient';
import { ConfirmButton } from '@/components/ConfirmButton';
import { ChatPanel } from '@/components/ChatPanel';

// HoldReasonCode is part of the projection so we can re-label "Held
// + spool" as "Uploading Inputs" client-side. See displayJobStatus
// in lib/api.ts.
const PROJECTION =
  'ClusterId,ProcId,JobStatus,HoldReason,HoldReasonCode,Owner,Cmd,Args,QDate,JobBatchName,Iwd';

export default function JobsPage() {
  // Admin browser sessions can opt into a pool-wide view; non-admin
  // sessions can't (the server enforces it). We default admins to
  // "show only mine" too — admin views are explicit, not surprising.
  const { data: session } = useQuery({
    queryKey: ['session'],
    queryFn: api.auth.me,
  });
  const isAdmin = !!session?.is_admin;

  const [scope, setScope] = useState<'mine' | 'all'>('mine');
  const ownedByMe = scope === 'mine';

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['jobs', scope],
    queryFn: () =>
      api.jobs.list({ projection: PROJECTION, limit: 1000, owned_by_me: ownedByMe }),
    refetchInterval: 15_000,
  });

  // Chat surface gating. We hit /api/v1/chat/info on mount; the
  // server returns enabled=false (with a reason) when the LLM key
  // isn't configured or MCP is off. We additionally require the
  // user to have at least one visible job — the assistant has
  // nothing useful to do on an empty queue. Hidden state means the
  // ChatPanel doesn't render at all (no idle pill, no requests).
  const { data: chatInfo } = useQuery({
    queryKey: ['chat-info'],
    queryFn: api.chat.info,
    // Cache for the lifetime of the tab — feature flag, not state.
    staleTime: Infinity,
    retry: false,
  });
  const chatVisible = !!chatInfo?.enabled && (data?.jobs.length ?? 0) > 0;

  // Lifted state so the chat's client-side tools can drive the
  // table view: filter substring, expanded-batch set, and a brief
  // highlight on a specific job row. The BatchTable consumes
  // them as props; the ChatPanel consumes them as imperative
  // hooks.
  const [filter, setFilter] = useState('');
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [highlighted, setHighlighted] = useState<string | null>(null); // "cluster.proc"
  const highlightTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const expandBatch = useCallback((clusterId: number) => {
    setExpanded((prev) => {
      if (prev.has(clusterId)) return prev;
      const next = new Set(prev);
      next.add(clusterId);
      return next;
    });
  }, []);

  const highlightJob = useCallback((clusterId: number, procId: number) => {
    const id = `${clusterId}.${procId}`;
    setHighlighted(id);
    // Also expand the containing batch so the row is visible.
    setExpanded((prev) => {
      if (prev.has(clusterId)) return prev;
      const next = new Set(prev);
      next.add(clusterId);
      return next;
    });
    if (highlightTimer.current) clearTimeout(highlightTimer.current);
    highlightTimer.current = setTimeout(() => setHighlighted(null), 4000);
  }, []);

  useEffect(
    () => () => {
      if (highlightTimer.current) clearTimeout(highlightTimer.current);
    },
    [],
  );

  const chatHooks = useMemo(
    () => ({
      setFilter,
      expandBatch,
      highlightJob,
    }),
    [expandBatch, highlightJob],
  );

  return (
    <div className="space-y-4">
      <div className="flex items-baseline gap-3 flex-wrap">
        <h1 className="text-2xl font-bold text-gray-900">
          {ownedByMe ? 'My Batches' : 'All Batches'}
        </h1>
        <span className="text-sm text-gray-500">
          One row per batch. Click a row to see the jobs in it.
        </span>
        {isAdmin && (
          <div className="flex items-center gap-1 rounded border border-gray-300 bg-white p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setScope('mine')}
              className={`rounded px-2 py-0.5 ${
                ownedByMe
                  ? 'bg-gray-200 text-gray-900'
                  : 'text-gray-600 hover:bg-gray-100'
              }`}
            >
              Mine
            </button>
            <button
              type="button"
              onClick={() => setScope('all')}
              className={`rounded px-2 py-0.5 ${
                !ownedByMe
                  ? 'bg-gray-200 text-gray-900'
                  : 'text-gray-600 hover:bg-gray-100'
              }`}
            >
              Everyone
            </button>
          </div>
        )}
        <Link
          href="/submit"
          className="ml-auto rounded bg-brand-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-700"
        >
          + Submit a batch
        </Link>
      </div>

      {isLoading && <p className="text-gray-400">Loading…</p>}

      {error && (
        <p className="text-red-600 text-sm">
          Could not load jobs: {(error as Error).message}
        </p>
      )}

      {data && data.jobs.length === 0 && (
        <p className="text-gray-500 text-sm">
          No batches in the queue.{' '}
          <Link href="/submit" className="text-brand-700 hover:underline">
            Submit one
          </Link>{' '}
          to get started.
        </p>
      )}

      {data && data.jobs.length > 0 && (
        <>
          <FilterBar value={filter} onChange={setFilter} />
          <BatchTable
            jobs={data.jobs}
            filter={filter}
            expanded={expanded}
            setExpanded={setExpanded}
            highlighted={highlighted}
            onChange={() => refetch()}
          />
        </>
      )}

      <ChatPanel visible={chatVisible} hooks={chatHooks} />
    </div>
  );
}

// FilterBar is the small substring-search input above the batches.
// Bound to the lifted `filter` state on JobsPage so the chat's
// `set_filter` tool can drive it programmatically.
function FilterBar({
  value,
  onChange,
}: {
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="text-gray-500">Filter:</span>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="batch name, cluster id, status…"
        className="min-w-0 flex-1 max-w-sm rounded border border-gray-300 bg-white px-2 py-1 text-sm focus:border-brand-400 focus:outline-none focus:ring-1 focus:ring-brand-400"
      />
      {value && (
        <button
          type="button"
          onClick={() => onChange('')}
          className="text-gray-500 hover:text-gray-800"
        >
          clear
        </button>
      )}
    </div>
  );
}

// Batch is what we render: one batch's worth of jobs aggregated.
interface Batch {
  batchID: number; // HTCondor's ClusterId — internal name only
  // Display name: BatchName if set, else batch id, else "?".
  name: string;
  // Representative command (the first job's Cmd we found). All jobs
  // in a batch nearly always share the same Cmd; we don't bother
  // showing multiple even when they differ.
  cmd?: string;
  args?: string;
  // QDate of the oldest job (= when the batch was submitted).
  submittedUnix?: number;
  // Per-status counts — keyed by DisplayStatus so spool-held shows
  // up as "Uploading Inputs" instead of being lumped under "Held".
  statusCounts: Record<DisplayStatus, number>;
  jobCount: number;
  // The individual jobs, kept around so the row can expand inline.
  jobs: BatchJob[];
}

interface BatchJob {
  // Display id used in URLs ("3.0").
  id: string;
  jobIdx: number; // ProcId
  display: DisplayStatusInfo;
  cmd?: string;
  args?: string;
  submittedUnix?: number;
}

function groupIntoBatches(jobs: ClassAd[]): Batch[] {
  const map = new Map<number, Batch>();
  for (const j of jobs) {
    const cluster = num(j.ClusterId);
    const proc = num(j.ProcId);
    if (cluster === undefined) continue;

    let b = map.get(cluster);
    if (!b) {
      b = {
        batchID: cluster,
        name: str(j.JobBatchName) ?? String(cluster),
        cmd: str(j.Cmd),
        args: str(j.Args),
        submittedUnix: num(j.QDate),
        statusCounts: {} as Record<DisplayStatus, number>,
        jobCount: 0,
        jobs: [],
      };
      map.set(cluster, b);
    }

    b.jobCount++;
    const display = displayJobStatus({
      status: j.JobStatus as number | string | null | undefined,
      holdReasonCode: j.HoldReasonCode as number | string | null | undefined,
    });
    b.statusCounts[display.key] = (b.statusCounts[display.key] ?? 0) + 1;
    const q = num(j.QDate);
    if (q !== undefined && (b.submittedUnix === undefined || q < b.submittedUnix)) {
      b.submittedUnix = q;
    }
    if (!b.cmd) b.cmd = str(j.Cmd);
    if (!b.args) b.args = str(j.Args);
    const bn = str(j.JobBatchName);
    if (bn && b.name === String(b.batchID)) {
      b.name = bn;
    }

    b.jobs.push({
      id: `${cluster}.${proc ?? 0}`,
      jobIdx: proc ?? 0,
      display,
      cmd: str(j.Cmd),
      args: str(j.Args),
      submittedUnix: q,
    });
  }

  // Sort jobs within each batch by job index for stable display.
  for (const b of map.values()) {
    b.jobs.sort((a, b) => a.jobIdx - b.jobIdx);
  }

  // Newest batch first.
  return Array.from(map.values()).sort((a, b) => b.batchID - a.batchID);
}

// applyBatchFilter does the user-facing substring filter. Both the
// FilterBar input and the chat's `set_filter` tool drive this. We
// match against a flat string built per batch — every field a user
// might reference in the input box: name, cluster id, owner,
// command line, and the display-status names of the jobs inside.
//
// Empty query returns the input unchanged. Multi-token queries
// (whitespace-separated) require ALL tokens to match SOMEWHERE
// in the haystack — feels natural for "held training-run" type
// inputs.
function applyBatchFilter(batches: Batch[], query: string): Batch[] {
  const q = query.trim().toLowerCase();
  if (q === '') return batches;
  const tokens = q.split(/\s+/);
  return batches.filter((b) => {
    const haystack = [
      b.name,
      String(b.batchID),
      b.cmd ?? '',
      b.args ?? '',
      // The status names the user actually reads in the row, e.g.
      // "running", "held", "uploading inputs". Lower-cased so the
      // substring compare against the lower-cased query is direct.
      Object.entries(b.statusCounts)
        .filter(([, n]) => n > 0)
        .map(([k]) => k)
        .join(' '),
    ]
      .join(' ')
      .toLowerCase();
    return tokens.every((t) => haystack.includes(t));
  });
}

function BatchTable({
  jobs,
  filter,
  expanded,
  setExpanded,
  highlighted,
  onChange,
}: {
  jobs: ClassAd[];
  filter: string;
  expanded: Set<number>;
  setExpanded: React.Dispatch<React.SetStateAction<Set<number>>>;
  highlighted: string | null; // "cluster.proc" of the chat-highlighted job
  onChange: () => void;
}) {
  const queryClient = useQueryClient();
  const allBatches = groupIntoBatches(jobs);
  const batches = applyBatchFilter(allBatches, filter);

  const toggle = (id: number) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const removeBatchMut = useMutation({
    mutationFn: (batchID: number) =>
      api.jobs.removeByConstraint(`ClusterId == ${batchID}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
      onChange();
    },
  });

  const removeJobMut = useMutation({
    mutationFn: (jobID: string) => api.jobs.remove(jobID),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
      onChange();
    },
  });

  const releaseJobMut = useMutation({
    mutationFn: (jobID: string) => api.jobs.release(jobID),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
      onChange();
    },
  });

  const removeError =
    removeBatchMut.error ?? removeJobMut.error ?? releaseJobMut.error;

  return (
    <div className="space-y-2">
      {removeError && (
        <div className="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {/* Failure message is shared between Remove and Release —
              both kinds of mutation surface here, label with whichever
              actually failed so the user can tell what happened. */}
          {releaseJobMut.error ? 'Release' : 'Remove'} failed:{' '}
          {removeError instanceof ApiError
            ? removeError.message
            : String(removeError)}
        </div>
      )}
      <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
        <table className="min-w-full text-sm">
          <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
            <tr>
              <th className="px-3 py-2 w-6"></th>
              <th className="px-3 py-2">Batch</th>
              <th className="px-3 py-2">Jobs</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Submitted</th>
              <th className="px-3 py-2">Command</th>
              <th className="px-3 py-2 w-1 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {batches.map((b) => (
              <BatchRow
                key={b.batchID}
                batch={b}
                expanded={expanded.has(b.batchID)}
                highlighted={highlighted}
                onToggle={() => toggle(b.batchID)}
                onRemoveBatch={() => removeBatchMut.mutate(b.batchID)}
                onRemoveJob={(jobID) => removeJobMut.mutate(jobID)}
                onReleaseJob={(jobID) => releaseJobMut.mutate(jobID)}
                pendingBatch={
                  removeBatchMut.isPending && removeBatchMut.variables === b.batchID
                }
                pendingJob={removeJobMut.variables}
                pendingJobActive={removeJobMut.isPending}
                pendingRelease={releaseJobMut.variables}
                pendingReleaseActive={releaseJobMut.isPending}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function BatchRow({
  batch,
  expanded,
  highlighted,
  onToggle,
  onRemoveBatch,
  onRemoveJob,
  onReleaseJob,
  pendingBatch,
  pendingJob,
  pendingJobActive,
  pendingRelease,
  pendingReleaseActive,
}: {
  batch: Batch;
  expanded: boolean;
  highlighted: string | null;
  onToggle: () => void;
  onRemoveBatch: () => void;
  onRemoveJob: (jobID: string) => void;
  onReleaseJob: (jobID: string) => void;
  pendingBatch: boolean;
  pendingJob: string | undefined;
  pendingJobActive: boolean;
  pendingRelease: string | undefined;
  pendingReleaseActive: boolean;
}) {
  return (
    <>
      <tr
        className="hover:bg-gray-50 cursor-pointer"
        onClick={onToggle}
        aria-expanded={expanded}
      >
        <td className="px-3 py-2 text-gray-400 text-center">
          <DisclosureCaret expanded={expanded} />
        </td>
        <td className="px-3 py-2 font-mono text-xs">
          <span className="text-gray-900">{batch.name}</span>
          {batch.name !== String(batch.batchID) && (
            <span className="ml-2 text-gray-400">#{batch.batchID}</span>
          )}
        </td>
        <td className="px-3 py-2 text-gray-700 tabular-nums">
          {batch.jobCount}
        </td>
        <td className="px-3 py-2">
          <StatusBreakdown counts={batch.statusCounts} />
        </td>
        <td className="px-3 py-2 text-gray-500 text-xs whitespace-nowrap">
          {batch.submittedUnix
            ? new Date(batch.submittedUnix * 1000).toLocaleString()
            : '—'}
        </td>
        <td className="px-3 py-2 text-gray-700 max-w-md truncate">
          {batch.cmd ? (
            <span className="font-mono text-xs">
              {batch.cmd}
              {batch.args ? ' ' + batch.args : ''}
            </span>
          ) : (
            '—'
          )}
        </td>
        <td
          className="px-3 py-2 whitespace-nowrap text-right"
          // Stop the row's click handler from firing when the user
          // interacts with the action buttons.
          onClick={(e) => e.stopPropagation()}
        >
          <ConfirmButton
            compact
            onConfirm={onRemoveBatch}
            pending={pendingBatch}
            title={`Remove batch ${batch.name} (${batch.jobCount} job${batch.jobCount === 1 ? '' : 's'})`}
          />
        </td>
      </tr>
      {expanded && (
        <tr>
          <td className="px-3 py-2 bg-gray-50" />
          <td colSpan={6} className="bg-gray-50 p-0">
            <JobsSubTable
              jobs={batch.jobs}
              highlighted={highlighted}
              onRemoveJob={onRemoveJob}
              onReleaseJob={onReleaseJob}
              pendingJob={pendingJob}
              pendingJobActive={pendingJobActive}
              pendingRelease={pendingRelease}
              pendingReleaseActive={pendingReleaseActive}
            />
          </td>
        </tr>
      )}
    </>
  );
}

function JobsSubTable({
  jobs,
  highlighted,
  onRemoveJob,
  onReleaseJob,
  pendingJob,
  pendingJobActive,
  pendingRelease,
  pendingReleaseActive,
}: {
  jobs: BatchJob[];
  highlighted: string | null;
  onRemoveJob: (id: string) => void;
  onReleaseJob: (id: string) => void;
  pendingJob: string | undefined;
  pendingJobActive: boolean;
  pendingRelease: string | undefined;
  pendingReleaseActive: boolean;
}) {
  return (
    <div className="border-t border-gray-200">
      <table className="min-w-full text-xs">
        <thead className="bg-gray-100 text-left text-[10px] uppercase tracking-wide text-gray-500">
          <tr>
            <th className="px-3 py-1.5">Job</th>
            <th className="px-3 py-1.5">Status</th>
            <th className="px-3 py-1.5">Submitted</th>
            <th className="px-3 py-1.5">Command</th>
            <th className="px-3 py-1.5 w-1 text-right">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200">
          {jobs.map((j) => (
            <tr
              key={j.id}
              className={
                j.id === highlighted
                  ? // animate-pulse-twice would be cute but we don't
                    // have a custom keyframe; a yellow flash via the
                    // standard pulse class for ~4 seconds (controlled
                    // by setHighlighted(null) on a timer in the
                    // parent) reads as "the assistant is pointing
                    // here right now".
                    'bg-yellow-100 animate-pulse'
                  : 'hover:bg-white'
              }>
              <td className="px-3 py-1.5 font-mono">
                <Link
                  href={`/jobs/${j.id}`}
                  className="text-brand-700 hover:underline"
                >
                  {j.id}
                </Link>
              </td>
              <td className="px-3 py-1.5">
                <JobStatusPill display={j.display} />
              </td>
              <td className="px-3 py-1.5 text-gray-500 whitespace-nowrap">
                {j.submittedUnix
                  ? new Date(j.submittedUnix * 1000).toLocaleString()
                  : '—'}
              </td>
              <td className="px-3 py-1.5 text-gray-700 max-w-md truncate">
                {j.cmd ? (
                  <span className="font-mono">
                    {j.cmd}
                    {j.args ? ' ' + j.args : ''}
                  </span>
                ) : (
                  '—'
                )}
              </td>
              <td
                className="px-3 py-1.5 text-right whitespace-nowrap"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="inline-flex items-center gap-1.5">
                  {j.display.key === 'held' && (
                    <button
                      type="button"
                      onClick={() => onReleaseJob(j.id)}
                      disabled={
                        pendingReleaseActive && pendingRelease === j.id
                      }
                      className="rounded border border-brand-600 bg-white px-2 py-0.5 text-xs font-medium text-brand-700 hover:bg-brand-50 disabled:opacity-50"
                      title={`Release held job ${j.id}`}
                    >
                      {pendingReleaseActive && pendingRelease === j.id
                        ? '…'
                        : 'Release'}
                    </button>
                  )}
                  <ConfirmButton
                    compact
                    onConfirm={() => onRemoveJob(j.id)}
                    pending={pendingJobActive && pendingJob === j.id}
                    title={`Remove job ${j.id}`}
                  />
                  <Link
                    href={`/jobs/${j.id}`}
                    className="inline-flex h-5 w-5 items-center justify-center rounded border border-gray-300 bg-white text-gray-500 hover:bg-gray-50 hover:text-gray-700"
                    title="Open job detail"
                    aria-label="Open job detail"
                  >
                    <PopOutIcon />
                  </Link>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// DisclosureCaret rotates 90° when the row is expanded.
function DisclosureCaret({ expanded }: { expanded: boolean }) {
  return (
    <span
      className={`inline-block transition-transform ${expanded ? 'rotate-90' : ''}`}
      aria-hidden
    >
      ▶
    </span>
  );
}

// Stable order so the breakdown reads consistently between renders.
const DISPLAY_STATUS_ORDER: DisplayStatus[] = [
  'running',
  'idle',
  'uploading',
  'transferring',
  'held',
  'suspended',
  'completed',
  'removed',
  'unknown',
];

const DISPLAY_STATUS_LABEL: Record<DisplayStatus, string> = {
  idle: 'Idle',
  running: 'Running',
  removed: 'Removed',
  completed: 'Completed',
  held: 'Held',
  transferring: 'Transferring Output',
  suspended: 'Suspended',
  uploading: 'Uploading Inputs',
  unknown: 'Unknown',
};

// StatusBreakdown summarizes "5 Running, 2 Uploading Inputs" in pill
// form. Counts come from groupIntoBatches keyed on DisplayStatus.
function StatusBreakdown({
  counts,
}: {
  counts: Record<DisplayStatus, number>;
}) {
  const entries = DISPLAY_STATUS_ORDER.filter((k) => (counts[k] ?? 0) > 0);
  if (entries.length === 0) return <span className="text-gray-400">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {entries.map((key) => (
        <StatusPill key={key} statusKey={key} count={counts[key]!} />
      ))}
    </div>
  );
}

function StatusPill({
  statusKey,
  count,
}: {
  statusKey: DisplayStatus;
  count: number;
}) {
  const label = DISPLAY_STATUS_LABEL[statusKey];
  return (
    <span
      className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium tabular-nums ${statusPillCls(statusKey)}`}
    >
      {count > 1 ? `${count} ` : ''}
      {label}
    </span>
  );
}

// JobStatusPill renders the per-job badge inside the expanded
// sub-table. Uses the per-job DisplayStatusInfo (which already
// carries the "Uploading Inputs" pseudo-label).
function JobStatusPill({ display }: { display: DisplayStatusInfo }) {
  return (
    <span
      className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${statusPillCls(display.key)}`}
    >
      {display.label}
    </span>
  );
}

// PopOutIcon: 14×14 square with arrow exiting top-right corner.
function PopOutIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M14 4h6v6" />
      <path d="M20 4l-9 9" />
      <path d="M19 13v5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h5" />
    </svg>
  );
}

function num(v: unknown): number | undefined {
  if (typeof v === 'number') return v;
  if (typeof v === 'string') {
    const n = Number(v);
    if (!Number.isNaN(n)) return n;
  }
  return undefined;
}

function str(v: unknown): string | undefined {
  if (typeof v === 'string' && v !== '') return v;
  if (v === undefined || v === null) return undefined;
  if (typeof v === 'string') return undefined;
  return String(v);
}
