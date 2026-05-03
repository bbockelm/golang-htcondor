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

import { useState } from 'react';
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

// HoldReasonCode is part of the projection so we can re-label "Held
// + spool" as "Uploading Inputs" client-side. See displayJobStatus
// in lib/api.ts.
const PROJECTION =
  'ClusterId,ProcId,JobStatus,HoldReason,HoldReasonCode,Owner,Cmd,Args,QDate,JobBatchName,Iwd';

export default function JobsPage() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['jobs', 'mine'],
    queryFn: () =>
      api.jobs.list({ projection: PROJECTION, limit: 1000, owned_by_me: true }),
    refetchInterval: 15_000,
  });

  return (
    <div className="space-y-4">
      <div className="flex items-baseline gap-3 flex-wrap">
        <h1 className="text-2xl font-bold text-gray-900">My Batches</h1>
        <span className="text-sm text-gray-500">
          One row per batch. Click a row to see the jobs in it.
        </span>
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
        <BatchTable jobs={data.jobs} onChange={() => refetch()} />
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

function BatchTable({
  jobs,
  onChange,
}: {
  jobs: ClassAd[];
  onChange: () => void;
}) {
  const batches = groupIntoBatches(jobs);
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

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

  const removeError = removeBatchMut.error ?? removeJobMut.error;

  return (
    <div className="space-y-2">
      {removeError && (
        <div className="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          Remove failed:{' '}
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
                onToggle={() => toggle(b.batchID)}
                onRemoveBatch={() => removeBatchMut.mutate(b.batchID)}
                onRemoveJob={(jobID) => removeJobMut.mutate(jobID)}
                pendingBatch={
                  removeBatchMut.isPending && removeBatchMut.variables === b.batchID
                }
                pendingJob={removeJobMut.variables}
                pendingJobActive={removeJobMut.isPending}
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
  onToggle,
  onRemoveBatch,
  onRemoveJob,
  pendingBatch,
  pendingJob,
  pendingJobActive,
}: {
  batch: Batch;
  expanded: boolean;
  onToggle: () => void;
  onRemoveBatch: () => void;
  onRemoveJob: (jobID: string) => void;
  pendingBatch: boolean;
  pendingJob: string | undefined;
  pendingJobActive: boolean;
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
              onRemoveJob={onRemoveJob}
              pendingJob={pendingJob}
              pendingJobActive={pendingJobActive}
            />
          </td>
        </tr>
      )}
    </>
  );
}

function JobsSubTable({
  jobs,
  onRemoveJob,
  pendingJob,
  pendingJobActive,
}: {
  jobs: BatchJob[];
  onRemoveJob: (id: string) => void;
  pendingJob: string | undefined;
  pendingJobActive: boolean;
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
            <tr key={j.id} className="hover:bg-white">
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
