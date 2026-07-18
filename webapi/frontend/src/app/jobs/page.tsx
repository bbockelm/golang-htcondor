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
import { useRouter } from 'next/navigation';
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

  // Client-side tool dispatchers, keyed by tool name as advertised by
  // the server. The ChatPanel forwards each LLM-emitted tool_use to
  // hooks[toolName] and serializes whatever the handler returns as
  // the tool_result.
  //
  // === KEEP IN SYNC WITH jobsPageInstructions IN
  // httpserver/handlers_chat_tools.go ===
  // The server-side instructions tell the LLM which UI affordances
  // exist on this page. If you add or remove a hook here, update the
  // matching prose so the model doesn't hallucinate (or miss) tools.
  const chatHooks = useMemo<Record<string, (input: Record<string, unknown>) => unknown>>(
    () => ({
      set_filter: (input) => {
        const q = typeof input.query === 'string' ? input.query : '';
        setFilter(q);
        return { ok: true, applied_query: q };
      },
      expand_batch: (input) => {
        const cid = Number(input.cluster_id);
        if (!Number.isFinite(cid) || cid <= 0) {
          return { ok: false, error: 'cluster_id must be a positive integer' };
        }
        expandBatch(cid);
        return { ok: true, expanded_cluster_id: cid };
      },
      highlight_job: (input) => {
        const cid = Number(input.cluster_id);
        const pid = Number(input.proc_id);
        if (!Number.isFinite(cid) || !Number.isFinite(pid)) {
          return { ok: false, error: 'cluster_id and proc_id must be integers' };
        }
        highlightJob(cid, pid);
        return { ok: true, highlighted: `${cid}.${pid}` };
      },
    }),
    [expandBatch, highlightJob],
  );

  // Invalidate the jobs query when a chat-driven destructive tool
  // finishes server-side. Without this, the schedd has already
  // hold/released/removed the job but our table keeps showing the
  // stale row until the 15-second polling interval fires. The
  // ChatPanel calls onServerToolComplete exactly once per toolCallId
  // so it's safe to invalidate unconditionally for the names below.
  const jobsListQueryClient = useQueryClient();
  const handleServerToolComplete = useCallback(
    (toolName: string) => {
      if (
        toolName === 'remove_job' ||
        toolName === 'remove_jobs' ||
        toolName === 'hold_job' ||
        toolName === 'release_job'
      ) {
        jobsListQueryClient.invalidateQueries({ queryKey: ['jobs'] });
      }
    },
    [jobsListQueryClient],
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

      {/* Chat sits directly under the title, above the table. It's the
          primary affordance for "why is X held?" / "release my idle
          jobs" — the user shouldn't have to scroll past a long batch
          list to find it. Mirrors the placement on the job-detail
          page. */}
      <ChatPanel
        visible={chatVisible}
        page="jobs"
        hooks={chatHooks}
        headerLabel="Job assistant"
        togglerLabel="Ask about your jobs"
        pageHelp={`Ask things like "how many of my jobs are held?", "why is my last batch stuck?", or "release everything that's held with code 13".`}
        onServerToolComplete={handleServerToolComplete}
      />

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

      {/* Archive hint. Lives below the table because the typical
          path is "user looked here, didn't find it, then wonders
          where else to check." A subtle prompt at the bottom
          handles that. */}
      {data && (
        <p className="text-xs text-gray-500">
          Not seeing the job you&apos;re looking for? Check the{' '}
          <Link
            href="/archive"
            className="text-brand-700 hover:underline"
          >
            archive
          </Link>{' '}
          for completed and removed jobs.
        </p>
      )}
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
// `Show all` is exposed for the "show remaining N" link below the
// table, since some users skip the scroll affordance.
function useInfiniteList<T>(
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
  // We deliberately do NOT include `items` here — we don't want a
  // poll-driven array identity change to scroll the user back to
  // the top mid-read.
  useEffect(() => {
    setCount(pageSize);
  }, [pageSize, resetKey]);

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
  // Cap the initial render at 20 batches; the sentinel below the
  // table reveals the next 20 each time it scrolls into view. The
  // filter string drives the reset — typing a new query brings the
  // user back to the first page of matches instead of leaving them
  // halfway down a long list of mismatches.
  const {
    visible: visibleBatches,
    sentinelRef: batchSentinelRef,
    showAll: showAllBatches,
    hasMore: hasMoreBatches,
    total: totalBatches,
    shown: shownBatches,
  } = useInfiniteList(batches, 20, filter);

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
            {visibleBatches.map((b) => (
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
            {/* Sentinel + "showing N of M" footer. The sentinel <tr>
                triggers IntersectionObserver to grow the visible
                window; the "show all" link lets users skip the
                scroll. Rendered as a single full-width row so the
                table layout doesn't shift between paginated/full
                states. */}
            {totalBatches > 0 && (
              <tr ref={batchSentinelRef as unknown as React.Ref<HTMLTableRowElement>}>
                <td colSpan={7} className="px-3 py-2 text-xs text-gray-500">
                  Showing {shownBatches} of {totalBatches} batches
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
                Showing {shownJobs} of {totalJobs} jobs
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
