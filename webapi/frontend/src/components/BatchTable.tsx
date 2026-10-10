'use client';

// The batch table shared by /jobs and /users/<owner>: one row per batch,
// expandable to the jobs inside it, sortable by column, with the
// submitting user shown when the listing spans more than one.

import { useCallback, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { api, ApiError, type DisplayStatus, type DisplayStatusInfo } from '@/lib/api';
import { statusPillCls } from '@/app/jobs/[id]/JobDetailClient';
import { ConfirmButton } from '@/components/ConfirmButton';
import {
  SortableHeader,
  useSortState,
  useSortedRows,
  type SortState,
} from '@/components/SortableTable';
import { BatchUsagePanel } from '@/components/BatchUsagePanel';
import { BatchProgressBar } from '@/components/BatchProgressBar';
import { UsageBar } from '@/components/UsageBar';
import {
  progressFraction,
  type BatchProgressResult,
} from '@/lib/batchProgress';
import {
  displayHoldReason,
  NO_REASON,
  summarizeHoldReasons,
  type HoldSummary,
} from '@/lib/holdReasons';
import type { BatchDetail } from '@/lib/batchView';
import {
  batchCpuReading,
  batchMemoryReading,
  jobCpuReading,
  jobMemoryReading,
  type JobUsage,
  type UsageReading,
} from '@/lib/runningUsage';
import {
  statusRank,
  summarizeBatchUsage,
  BATCH_USAGE_PROJECTION,
  DISPLAY_STATUS_LABEL,
  DISPLAY_STATUS_ORDER,
  batchKey,
  type Batch,
  type BatchJob,
  type BatchKey,
} from '@/lib/batches';

type BatchSortKey =
  | 'batch'
  | 'schedd'
  | 'owner'
  | 'jobs'
  | 'progress'
  | 'status'
  | 'submitted'
  | 'cmd'
  | 'reason'
  | 'memory'
  | 'cpu';

// Live usage for the 'usage' detail, keyed by BatchJob.id.
export interface RunningUsage {
  byJob: ReadonlyMap<string, JobUsage>;
  loading: boolean;
}

// Per-row values computed once per render of the table, for both the
// cells and the sort.
interface RowExtras {
  progress?: BatchProgressResult;
  hold?: HoldSummary;
  memory?: UsageReading;
  cpu?: UsageReading;
}

// Sorting reads a comparable value off the batch rather than the rendered
// cell: sorting "Submitted" by its formatted text would put April before
// January, and "Jobs" by its text would put 9 after 10.
function batchSortValue(
  b: Batch,
  key: BatchSortKey,
  x: RowExtras | undefined,
): string | number | undefined {
  switch (key) {
    case 'progress':
      return progressFraction(x?.progress);
    case 'reason':
      return x?.hold ? displayHoldReason(x.hold.top.example) : undefined;
    case 'memory':
      return x?.memory?.sortValue;
    case 'cpu':
      return x?.cpu?.sortValue;
    case 'batch':
      return b.name;
    case 'schedd':
      return b.schedd;
    case 'owner':
      return b.owner;
    case 'jobs':
      return b.jobCount;
    case 'status':
      return statusRank(b);
    case 'submitted':
      return b.submittedUnix;
    case 'cmd':
      return b.cmd;
  }
}

export function BatchTable({
  batches,
  resetKey,
  showOwner,
  expanded,
  setExpanded,
  highlighted,
  onChange,
  multiAP,
  progress,
  detail = 'command',
  usage,
}: {
  // Already grouped and filtered by the page: which jobs are in scope is
  // a page-level question (status chips, text filter, server constraint),
  // and the page needs the same answer for its summary panel.
  batches: Batch[];
  // Changing this snaps the visible window back to the first page —
  // pass whatever the user typed to narrow the list, so a new query
  // starts at its own first match rather than halfway down the old one.
  resetKey?: unknown;
  // Render the submitting user as a column. Off in the "Mine" view,
  // where every row would carry the same name.
  showOwner?: boolean;
  expanded: Set<BatchKey>;
  setExpanded: React.Dispatch<React.SetStateAction<Set<BatchKey>>>;
  highlighted: string | null; // "cluster.proc" of the chat-highlighted job
  onChange: () => void;
  // Multi-AP mode: show the access point column, and no actions -- the
  // server serves reads only.
  multiAP?: boolean;
  // How far along each batch is, keyed by Batch.groupKey. Computed by the
  // page from every job it loaded, not from `batches`, which may be
  // status-filtered (see batchProgress.ts). Omit to leave the column out.
  progress?: ReadonlyMap<string, BatchProgressResult>;
  // What the last column shows; see BatchDetail.
  detail?: BatchDetail;
  // Required for detail="usage".
  usage?: RunningUsage;
}) {
  const queryClient = useQueryClient();

  const extras = useMemo(() => {
    const m = new Map<BatchKey, RowExtras>();
    for (const b of batches) {
      const x: RowExtras = { progress: progress?.get(b.groupKey) };
      if (detail === 'hold') {
        x.hold = summarizeHoldReasons(
          b.jobs.filter((j) => j.display.key === 'held').map((j) => j.holdReason),
        );
      } else if (detail === 'usage' && usage) {
        const running = b.jobs.filter((j) => j.display.key === 'running');
        x.memory = batchMemoryReading(running, usage.byJob);
        x.cpu = batchCpuReading(running, usage.byJob);
      }
      m.set(batchKey(b), x);
    }
    return m;
  }, [batches, progress, detail, usage]);

  const sortValue = useCallback(
    (b: Batch, key: BatchSortKey) => batchSortValue(b, key, extras.get(batchKey(b))),
    [extras],
  );

  // Newest first by default, which is what the page used to do
  // unconditionally and is still the order people expect to land in.
  const [sort, setSort] = useSortState<BatchSortKey>('submitted', 'desc');
  const sorted = useSortedRows(batches, sort, sortValue);

  // Cap the initial render at 20 batches; the sentinel below the
  // table reveals the next 20 each time it scrolls into view.
  const {
    visible: visibleBatches,
    sentinelRef: batchSentinelRef,
    showAll: showAllBatches,
    hasMore: hasMoreBatches,
    total: totalBatches,
    shown: shownBatches,
  } = useInfiniteList(sorted, 20, resetKey);

  const toggle = (id: BatchKey) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  // Remove targets the batch's own constraint, not just its ClusterId: a
  // DAG batch spans many clusters, so removing it means matching the shared
  // JobBatchName (see groupIntoBatches). We key the mutation by the whole
  // Batch so the per-row pending state can compare on batchID.
  const removeBatchMut = useMutation({
    mutationFn: (b: Batch) => api.jobs.removeByConstraint(b.removeConstraint),
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

  // Multi-AP mode trades the Actions column for the Access point one. The
  // running view trades Submitted for its second bar: two bars and their
  // text do not fit beside it, and when a running batch was submitted is
  // the least of what that view is for.
  const showSubmitted = detail !== 'usage';
  const columns = 7 + (showOwner ? 1 : 0) + (progress ? 1 : 0);

  return (
    <div className="space-y-2">
      {removeError && (
        <div className="rounded-sm border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
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
              <BatchHeader label="Batch" sortKey="batch" sort={sort} onSort={setSort} />
              {/* The submitting user sits next to the batch name rather
                  than out past the command: on a pool-wide view it is the
                  first thing being scanned for. */}
              {multiAP && (
                <BatchHeader label="Access point" sortKey="schedd" sort={sort} onSort={setSort} />
              )}
              {showOwner && (
                <BatchHeader label="User" sortKey="owner" sort={sort} onSort={setSort} />
              )}
              <BatchHeader label="Jobs" sortKey="jobs" sort={sort} onSort={setSort} />
              {progress && (
                <BatchHeader label="Progress" sortKey="progress" sort={sort} onSort={setSort} />
              )}
              <BatchHeader label="Status" sortKey="status" sort={sort} onSort={setSort} />
              {showSubmitted && (
                <BatchHeader label="Submitted" sortKey="submitted" sort={sort} onSort={setSort} />
              )}
              {detail === 'hold' ? (
                <BatchHeader label="Hold reason" sortKey="reason" sort={sort} onSort={setSort} />
              ) : detail === 'usage' ? (
                <>
                  <BatchHeader label="Memory (peak)" sortKey="memory" sort={sort} onSort={setSort} />
                  <BatchHeader label="CPU (recent)" sortKey="cpu" sort={sort} onSort={setSort} />
                </>
              ) : (
                <BatchHeader label="Command" sortKey="cmd" sort={sort} onSort={setSort} />
              )}
              {!multiAP && <th className="px-3 py-2 w-1 text-right">Actions</th>}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {visibleBatches.map((b) => (
              <BatchRow
                key={batchKey(b)}
                batch={b}
                extras={extras.get(batchKey(b))}
                showProgress={!!progress}
                detail={detail}
                usage={usage}
                columns={columns}
                showOwner={showOwner}
                multiAP={multiAP}
                expanded={expanded.has(batchKey(b))}
                highlighted={highlighted}
                onToggle={() => toggle(batchKey(b))}
                onRemoveBatch={() => removeBatchMut.mutate(b)}
                onRemoveJob={(jobID) => removeJobMut.mutate(jobID)}
                onReleaseJob={(jobID) => releaseJobMut.mutate(jobID)}
                pendingBatch={
                  removeBatchMut.isPending &&
                  !!removeBatchMut.variables &&
                  batchKey(removeBatchMut.variables) === batchKey(b)
                }
                pendingJob={removeJobMut.variables}
                pendingJobActive={removeJobMut.isPending}
                pendingRelease={releaseJobMut.variables}
                pendingReleaseActive={releaseJobMut.isPending}
              />
            ))}
            {/* Sentinel + "showing N of M" footer. The sentinel <tr>
                triggers IntersectionObserver to grow the visible
                window; the "show all" link lets users skip the
                scroll. Rendered as a single full-width row so the
                table layout doesn't shift between paginated/full
                states. */}
            {totalBatches > 0 && (
              <tr ref={batchSentinelRef as unknown as React.Ref<HTMLTableRowElement>}>
                <td colSpan={columns} className="px-3 py-2 text-xs text-gray-500">
                  Showing {shownBatches.toLocaleString()} of{' '}
                  {totalBatches.toLocaleString()} batches
                  {hasMoreBatches && (
                    <>
                      {' '}— scroll to load more, or{' '}
                      <button
                        type="button"
                        onClick={showAllBatches}
                        className="text-brand-700 hover:underline"
                      >
                        show all
                      </button>
                    </>
                  )}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function BatchHeader({
  label,
  sortKey,
  sort,
  onSort,
}: {
  label: string;
  sortKey: BatchSortKey;
  sort: SortState<BatchSortKey>;
  onSort: (next: SortState<BatchSortKey>) => void;
}) {
  return (
    <SortableHeader
      label={label}
      sortKey={sortKey}
      sort={sort}
      onSort={onSort}
      className="text-left font-normal"
    />
  );
}

// UserPill is the clickable owner badge. It leads to that user's own
// page rather than filtering in place: "who is this and what else are
// they running" is a question about the user, not about this table.
export function UserPill({ owner }: { owner: string }) {
  return (
    <Link
      href={`/users/${encodeURIComponent(owner)}`}
      // The row underneath opens the batch; the pill is a different
      // destination and must not do both.
      onClick={(e) => e.stopPropagation()}
      title={`Everything ${owner} is running`}
      className="inline-block max-w-32 truncate rounded-full bg-indigo-100 px-2 py-0.5 text-xs font-medium text-indigo-800 hover:bg-indigo-200"
    >
      {owner}
    </Link>
  );
}

function BatchRow({
  batch,
  extras,
  showProgress,
  detail,
  usage,
  columns,
  showOwner,
  multiAP,
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
  extras: RowExtras | undefined;
  showProgress: boolean;
  detail: BatchDetail;
  usage: RunningUsage | undefined;
  columns: number;
  showOwner?: boolean;
  multiAP?: boolean;
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
          {/* A long batch name would otherwise wrap at every hyphen and
              squeeze the status pills into a column. */}
          <span
            className="inline-block max-w-44 truncate align-bottom text-gray-900"
            title={batch.name}
          >
            {batch.name}
          </span>
          {batch.isDag && (
            <span
              className="ml-2 rounded-sm bg-purple-100 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-purple-700"
              title="A DAG workflow — every node job and nested sub-DAG is folded into this one batch"
            >
              DAG
            </span>
          )}
          {batch.name !== String(batch.batchID) && (
            <span className="ml-2 text-gray-400">#{batch.batchID}</span>
          )}
        </td>
        {multiAP && (
          <td className="px-3 py-2 font-mono text-xs text-gray-700">{batch.schedd ?? '—'}</td>
        )}
        {showOwner && (
          <td className="px-3 py-2">
            {batch.owner ? <UserPill owner={batch.owner} /> : <span className="text-gray-400">—</span>}
          </td>
        )}
        <td className="px-3 py-2 text-gray-700 tabular-nums">
          {batch.jobCount}
        </td>
        {showProgress && (
          <td className="px-3 py-2">
            <BatchProgressBar progress={extras?.progress} />
          </td>
        )}
        <td className="px-3 py-2">
          <StatusBreakdown counts={batch.statusCounts} />
        </td>
        {detail !== 'usage' && (
          <td
            className="px-3 py-2 text-gray-500 text-xs whitespace-nowrap"
            title={batch.submittedUnix ? new Date(batch.submittedUnix * 1000).toLocaleString() : undefined}
          >
            {batch.submittedUnix ? formatSubmitted(batch.submittedUnix) : '—'}
          </td>
        )}
        {detail === 'hold' ? (
          <td className="px-3 py-2 text-gray-700">
            <HoldSummaryCell summary={extras?.hold} />
          </td>
        ) : detail === 'usage' ? (
          <>
            <td className="px-3 py-2">
              <UsageBar reading={extras?.memory} loading={usage?.loading} stacked />
            </td>
            <td className="px-3 py-2">
              <UsageBar reading={extras?.cpu} loading={usage?.loading} stacked />
            </td>
          </>
        ) : (
          <td className="px-3 py-2 text-gray-700">
            {batch.cmd ? (
              // The width is on a block inside the cell, not the cell: a
              // table cell grows to fit its content whatever its
              // max-width says, and a real command is an absolute path
              // plus arguments, long enough on its own to push the
              // Actions column off the page.
              <div
                className="max-w-56 truncate font-mono text-xs"
                title={batch.args ? `${batch.cmd} ${batch.args}` : batch.cmd}
              >
                {batch.cmd}
                {batch.args ? ' ' + batch.args : ''}
              </div>
            ) : (
              '—'
            )}
          </td>
        )}
        {!multiAP && (
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
        )}
      </tr>
      {expanded && (
        <tr>
          <td className="px-3 py-2 bg-gray-50" />
          <td colSpan={columns - 1} className="bg-gray-50 p-0">
            <BatchUsage batchID={batch.batchID} schedd={batch.schedd} constraint={batch.removeConstraint} />
            <JobsSubTable
              multiAP={multiAP}
              detail={detail}
              usage={usage}
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

// BatchUsage fetches the expanded batch's request and usage attributes.
//
// A separate, narrow query rather than more columns on the listing: the
// usage attributes are worth real bytes per job on a 30k queue, and they
// are only ever read for the one batch somebody opened. Same shape as
// the pool page's per-node slot query.
function BatchUsage({
  batchID,
  schedd,
  constraint,
}: {
  batchID: number;
  schedd?: string;
  constraint: string;
}) {
  const { data, isFetching, error } = useQuery({
    queryKey: ['batch-usage', batchID, schedd, constraint],
    queryFn: () =>
      api.jobs.list({
        // The batch's access point: its constraint names a cluster id,
        // which is unique only within one.
        schedd,
        // The batch's own constraint, so a DAG's usage covers every node
        // and sub-DAG, not just the representative (root DAGMan) cluster.
        constraint,
        projection: BATCH_USAGE_PROJECTION,
        limit: '*',
        // The constraint already names this batch's jobs, and the server
        // confines a session that may not see other people's jobs
        // whatever we ask for -- so this works for an admin looking at
        // somebody else's batch and for a user looking at their own.
        owned_by_me: false,
      }),
    // Usage moves while the row is open, and stops mattering when it
    // is closed.
    refetchInterval: 30_000,
    retry: false,
  });

  const usage = useMemo(
    () => summarizeBatchUsage(data?.jobs ?? []),
    [data],
  );

  if (error) {
    return (
      <div className="border-t border-gray-200 bg-white px-3 py-2 text-[11px] text-gray-500">
        Could not load this batch&apos;s resource usage:{' '}
        {error instanceof ApiError ? error.message : String(error)}
      </div>
    );
  }

  return <BatchUsagePanel usage={usage} loading={isFetching && !data} />;
}

function JobsSubTable({
  multiAP,
  detail,
  usage,
  jobs,
  highlighted,
  onRemoveJob,
  onReleaseJob,
  pendingJob,
  pendingJobActive,
  pendingRelease,
  pendingReleaseActive,
}: {
  multiAP?: boolean;
  detail: BatchDetail;
  usage: RunningUsage | undefined;
  jobs: BatchJob[];
  highlighted: string | null;
  onRemoveJob: (id: string) => void;
  onReleaseJob: (id: string) => void;
  pendingJob: string | undefined;
  pendingJobActive: boolean;
  pendingRelease: string | undefined;
  pendingReleaseActive: boolean;
}) {
  const router = useRouter();
  // Cap each expanded batch at 25 visible jobs initially; the
  // sentinel row at the bottom reveals 25 more on each scroll. This
  // sub-table mounts/unmounts as the user expands/collapses batches,
  // so a separate resetKey isn't needed — fresh mount = fresh count.
  const {
    visible: visibleJobs,
    sentinelRef: jobSentinelRef,
    showAll: showAllJobs,
    hasMore: hasMoreJobs,
    total: totalJobs,
    shown: shownJobs,
  } = useInfiniteList(jobs, 25);
  return (
    <div className="border-t border-gray-200">
      <table className="min-w-full text-xs">
        <thead className="bg-gray-100 text-left text-[10px] uppercase tracking-wide text-gray-500">
          <tr>
            <th className="px-3 py-1.5">Job</th>
            <th className="px-3 py-1.5">Status</th>
            {detail !== 'usage' && <th className="px-3 py-1.5">Submitted</th>}
            {detail === 'hold' ? (
              <th className="px-3 py-1.5">Hold reason</th>
            ) : detail === 'usage' ? (
              <>
                <th className="px-3 py-1.5">Memory (peak)</th>
                <th className="px-3 py-1.5">CPU (recent)</th>
              </>
            ) : (
              <th className="px-3 py-1.5">Command</th>
            )}
            {!multiAP && <th className="px-3 py-1.5 w-1 text-right">Actions</th>}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200">
          {visibleJobs.map((j) => (
            <tr
              key={j.id}
              // Clicking anywhere on the row that isn't already an
              // interactive element (the job-id link, the action
              // buttons, the open-icon link) navigates to the detail
              // page. The Actions <td> stops propagation; the job-id
              // <td> doesn't need to because the inner <Link> does
              // its own navigation and Next's router.push to the
              // same href is a no-op.
              onClick={() => router.push(`/jobs/${encodeURIComponent(j.id)}`)}
              className={
                'cursor-pointer ' +
                (j.id === highlighted
                  ? // animate-pulse-twice would be cute but we don't
                    // have a custom keyframe; a yellow flash via the
                    // standard pulse class for ~4 seconds (controlled
                    // by setHighlighted(null) on a timer in the
                    // parent) reads as "the assistant is pointing
                    // here right now".
                    'bg-yellow-100 animate-pulse'
                  : 'hover:bg-white')
              }>
              <td className="px-3 py-1.5 font-mono">
                <Link
                  href={`/jobs/${encodeURIComponent(j.id)}`}
                  className="text-brand-700 hover:underline"
                >
                  {j.id}
                </Link>
                {j.nodeName && (
                  <span
                    className="ml-2 text-gray-500"
                    title="DAG node name"
                  >
                    {j.nodeName}
                  </span>
                )}
              </td>
              <td className="px-3 py-1.5">
                <JobStatusPill display={j.display} />
              </td>
              {detail !== 'usage' && (
                <td
                  className="px-3 py-1.5 text-gray-500 whitespace-nowrap"
                  title={j.submittedUnix ? new Date(j.submittedUnix * 1000).toLocaleString() : undefined}
                >
                  {j.submittedUnix ? formatSubmitted(j.submittedUnix) : '—'}
                </td>
              )}
              {detail === 'hold' ? (
                <td className="px-3 py-1.5 text-gray-700">
                  <div className="max-w-sm truncate" title={j.holdReason}>
                    {j.holdReason ? (
                      displayHoldReason(j.holdReason)
                    ) : (
                      <span className="text-gray-400">{NO_REASON}</span>
                    )}
                  </div>
                </td>
              ) : detail === 'usage' ? (
                <>
                  <td className="px-3 py-1.5">
                    <JobUsageCell job={j} usage={usage} read={jobMemoryReading} />
                  </td>
                  <td className="px-3 py-1.5">
                    <JobUsageCell job={j} usage={usage} read={jobCpuReading} />
                  </td>
                </>
              ) : (
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
              )}
              {!multiAP && (
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
                        className="rounded-sm border border-brand-600 bg-white px-2 py-0.5 text-xs font-medium text-brand-700 hover:bg-brand-50 disabled:opacity-50"
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
                  </div>
                </td>
              )}
            </tr>
          ))}
          {/* Same sentinel + show-all pattern as the batch table.
              Lives inside the sub-table's <tbody> so it scrolls
              with the parent page (no inner scroll container) and
              the IntersectionObserver fires off the natural
              window scroll. */}
          {totalJobs > 0 && (
            <tr ref={jobSentinelRef as unknown as React.Ref<HTMLTableRowElement>}>
              <td colSpan={multiAP ? 4 : 5} className="px-3 py-1.5 text-[11px] text-gray-500">
                Showing {shownJobs.toLocaleString()} of {totalJobs.toLocaleString()} jobs
                {hasMoreJobs && (
                  <>
                    {' '}— scroll to load more, or{' '}
                    <button
                      type="button"
                      onClick={showAllJobs}
                      className="text-brand-700 hover:underline"
                    >
                      show all
                    </button>
                  </>
                )}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

// HoldSummaryCell is a batch's hold reasons in one line: a real message
// from the most common kind, how many jobs it covers, and how many other
// kinds there are. The message is truncated to the cell and whole in the
// tooltip.
function HoldSummaryCell({ summary }: { summary: HoldSummary | undefined }) {
  if (!summary) return <span className="text-gray-400">—</span>;
  const others = summary.otherReasons;
  return (
    <div className="flex items-baseline gap-1.5 whitespace-nowrap text-xs">
      {/* A width on the message, not the cell: a table cell grows to fit
          its content whatever its max-width says, and a hold message is
          longer than the rest of the row put together. */}
      <span className="max-w-[13rem] truncate" title={summary.top.example}>
        {displayHoldReason(summary.top.example)}
      </span>
      {summary.held > 1 && (
        <span
          className="shrink-0 tabular-nums text-gray-500"
          title={`${summary.top.count.toLocaleString()} of ${summary.held.toLocaleString()} held jobs`}
        >
          ×{summary.top.count.toLocaleString()}
        </span>
      )}
      {others > 0 && (
        <span className="shrink-0 text-gray-500">
          +{others.toLocaleString()} other reason{others === 1 ? '' : 's'}
        </span>
      )}
    </div>
  );
}

// JobUsageCell is one job's bar. A job the usage answer has not covered
// yet reads as loading while the answer is on its way, and otherwise as
// not reported -- never as a zero.
function JobUsageCell({
  job,
  usage,
  read,
}: {
  job: BatchJob;
  usage: RunningUsage | undefined;
  read: (u: JobUsage | undefined) => UsageReading;
}) {
  const u = usage?.byJob.get(job.id);
  if (!u && usage?.loading) return <UsageBar reading={undefined} loading />;
  return <UsageBar reading={read(u)} />;
}

// formatSubmitted is a submit time to the minute: seconds are noise in a
// queue listing, and dropping them is what lets the row fit beside the
// Progress and User columns. The cell's tooltip has the full time.
function formatSubmitted(unix: number): string {
  return new Date(unix * 1000).toLocaleString(undefined, {
    dateStyle: 'short',
    timeStyle: 'short',
  });
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
      className={`inline-flex whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium tabular-nums ${statusPillCls(statusKey)}`}
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

// useInfiniteList paginates a (possibly polling-refreshed) array via
// IntersectionObserver — when the returned `sentinelRef` element
// scrolls into view, the visible window grows by `pageSize`. Used by
// BatchTable and JobsSubTable to cap initial render at ~20-25 rows
// without giving up the "scroll to see more" affordance the user
// expects.
//
// Reset semantics: when `resetKey` changes (e.g., the user types a
// new filter, or expands a different batch), the visible window
// snaps back to `pageSize`. Polling refreshes that grow `items`
// in place leave the visible count alone — the user keeps seeing
// the rows they were reading.
//
// `showAll` is exposed for the "show remaining N" link below the
// table, since some users skip the scroll affordance.
export function useInfiniteList<T>(
  items: T[],
  pageSize: number,
  resetKey?: unknown,
): {
  visible: T[];
  sentinelRef: (el: Element | null) => void;
  showAll: () => void;
  hasMore: boolean;
  total: number;
  shown: number;
} {
  const [count, setCount] = useState(pageSize);

  // Snap back to one page when the caller signals a fresh context.
  // We deliberately do NOT key on `items` — a poll-driven array
  // identity change must not scroll the user back to the top mid-read.
  //
  // Compared during render rather than assigned from an effect, so the
  // list never paints one frame at the old length before snapping back.
  const resetSignal = `${pageSize}\u0000${String(resetKey)}`;
  const [prevResetSignal, setPrevResetSignal] = useState(resetSignal);
  if (prevResetSignal !== resetSignal) {
    setPrevResetSignal(resetSignal);
    setCount(pageSize);
  }

  // Clamp when the source list shrinks below the visible window
  // (e.g., the filter narrowed) — without this, hasMore would
  // briefly read false and the sentinel observer would stay
  // disconnected even after the user clears the filter.
  const total = items.length;
  const shown = Math.min(count, total);
  const hasMore = total > shown;

  // Callback ref so we can connect/disconnect the IntersectionObserver
  // when the sentinel mounts/unmounts (and re-mounts on rerender).
  // Using a closure-captured Observer keeps the wiring local; no
  // module-level state.
  const sentinelRef = useCallback(
    (el: Element | null) => {
      if (!el || !hasMore) return;
      const obs = new IntersectionObserver(
        (entries) => {
          for (const entry of entries) {
            if (entry.isIntersecting) {
              setCount((c) => c + pageSize);
            }
          }
        },
        // rootMargin pre-fetches the next page when the sentinel is
        // ~200px below the viewport — gives a continuous-scroll
        // feel rather than a noticeable pause when the user hits
        // the bottom.
        { rootMargin: '200px' },
      );
      obs.observe(el);
      // Disconnect on unmount via the ref-callback's cleanup form.
      return () => obs.disconnect();
    },
    [hasMore, pageSize],
  );

  const showAll = useCallback(() => setCount(total), [total]);

  // Slice once per render and return — slicing is cheap relative to
  // the rendering cost we're avoiding.
  const visible = items.slice(0, shown);

  return { visible, sentinelRef, showAll, hasMore, total, shown };
}
