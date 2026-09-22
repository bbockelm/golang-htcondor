'use client';

// The batch table shared by /jobs and /users/<owner>: one row per batch,
// expandable to the jobs inside it, sortable by column, with the
// submitting user shown when the listing spans more than one.

import { useCallback, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
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
import {
  statusRank,
  DISPLAY_STATUS_LABEL,
  DISPLAY_STATUS_ORDER,
  type Batch,
  type BatchJob,
} from '@/lib/batches';

type BatchSortKey = 'batch' | 'owner' | 'jobs' | 'status' | 'submitted' | 'cmd';

// Sorting reads a comparable value off the batch rather than the rendered
// cell: sorting "Submitted" by its formatted text would put April before
// January, and "Jobs" by its text would put 9 after 10.
function batchSortValue(b: Batch, key: BatchSortKey): string | number | undefined {
  switch (key) {
    case 'batch':
      return b.name;
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
  expanded: Set<number>;
  setExpanded: React.Dispatch<React.SetStateAction<Set<number>>>;
  highlighted: string | null; // "cluster.proc" of the chat-highlighted job
  onChange: () => void;
}) {
  const queryClient = useQueryClient();

  // Newest first by default, which is what the page used to do
  // unconditionally and is still the order people expect to land in.
  const [sort, setSort] = useSortState<BatchSortKey>('submitted', 'desc');
  const sorted = useSortedRows(batches, sort, batchSortValue);

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

  const columns = showOwner ? 8 : 7;

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
              {showOwner && (
                <BatchHeader label="User" sortKey="owner" sort={sort} onSort={setSort} />
              )}
              <BatchHeader label="Jobs" sortKey="jobs" sort={sort} onSort={setSort} />
              <BatchHeader label="Status" sortKey="status" sort={sort} onSort={setSort} />
              <BatchHeader label="Submitted" sortKey="submitted" sort={sort} onSort={setSort} />
              <BatchHeader label="Command" sortKey="cmd" sort={sort} onSort={setSort} />
              <th className="px-3 py-2 w-1 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {visibleBatches.map((b) => (
              <BatchRow
                key={b.batchID}
                batch={b}
                showOwner={showOwner}
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
      className="inline-flex max-w-[14rem] truncate rounded-full bg-indigo-100 px-2 py-0.5 text-xs font-medium text-indigo-800 hover:bg-indigo-200"
    >
      {owner}
    </Link>
  );
}

function BatchRow({
  batch,
  showOwner,
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
  showOwner?: boolean;
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
        {showOwner && (
          <td className="px-3 py-2">
            {batch.owner ? <UserPill owner={batch.owner} /> : <span className="text-gray-400">—</span>}
          </td>
        )}
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
          <td colSpan={showOwner ? 7 : 6} className="bg-gray-50 p-0">
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
            <th className="px-3 py-1.5">Submitted</th>
            <th className="px-3 py-1.5">Command</th>
            <th className="px-3 py-1.5 w-1 text-right">Actions</th>
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
              onClick={() => router.push(`/jobs/${j.id}`)}
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
            </tr>
          ))}
          {/* Same sentinel + show-all pattern as the batch table.
              Lives inside the sub-table's <tbody> so it scrolls
              with the parent page (no inner scroll container) and
              the IntersectionObserver fires off the natural
              window scroll. */}
          {totalJobs > 0 && (
            <tr ref={jobSentinelRef as unknown as React.Ref<HTMLTableRowElement>}>
              <td colSpan={5} className="px-3 py-1.5 text-[11px] text-gray-500">
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
