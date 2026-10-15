'use client';

// The jobs of one workflow, on the workflow's page: every job the
// analysis covered, one row each, with what it used against what it
// asked for. Sorted by the server and loaded a page at a time as the
// list scrolls, because a workflow can be tens of thousands of jobs.
//
// A range picked on one of the workflow's charts (a bin of the memory
// histogram, say) sorts the list by that measure and marks the jobs in
// the range, which is how "who are these 30 jobs at 6 GB?" gets answered.

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useInfiniteQuery } from '@tanstack/react-query';
import { api, ApiError } from '@/lib/api';
import { SortableHeader, type SortState } from '@/components/SortableTable';
import { UsageBar } from '@/components/UsageBar';
import { cpuTone, memoryTone, type UsageReading } from '@/lib/runningUsage';
import {
  formatCores,
  formatKiB,
  formatMiB,
  formatPercent,
  inFocus,
  jobArchiveHref,
  type JobFocus,
  type UtilJobRow,
  type UtilJobSort,
  type UtilJobsResponse,
} from '@/lib/utilization';
import { formatSeconds } from '@/lib/usage';

export interface JobsQuery {
  days: number;
  owned_by_me: boolean;
  schedd?: string;
  constraint?: string;
  owners?: string[];
  limit?: number;
}

const PAGE_SIZE = 100;
// How far the list will load on its own to find a job picked on a chart.
const MAX_SEARCH_PAGES = 20;

// --- Readings: one job's use against its request ---

const pct = (f: number) => `${Math.round(f * 100)}%`;

export function memoryReading(row: UtilJobRow): UsageReading | undefined {
  const used = row.memory_peak_mib;
  const req = row.request.memory_mib;
  if (used === null) return undefined;
  if (!req) return { tone: 'normal', text: formatMiB(used), title: `Peak memory ${formatMiB(used)}` };
  const f = used / req;
  const tone = memoryTone(f);
  return {
    fill: f,
    tone,
    text: `${formatMiB(used)} of ${formatMiB(req)}${tone === 'normal' ? '' : ` · ${pct(f)}`}`,
    title: `Peak memory ${formatMiB(used)} of ${formatMiB(req)} requested (${pct(f)})`,
  };
}

export function coresReading(row: UtilJobRow): UsageReading | undefined {
  const used = row.cores_used;
  const req = row.request.cpus;
  if (used === null) return undefined;
  if (!req) return { tone: 'normal', text: `${formatCores(used)} cores`, title: `${formatCores(used)} cores busy` };
  const f = used / req;
  const tone = cpuTone(f);
  return {
    fill: f,
    tone,
    text: `${formatCores(used)} of ${formatCores(req)}${tone === 'warn' ? ` · ${pct(f)}` : ''}`,
    title: `${formatCores(used)} of ${formatCores(req)} requested cores kept busy (${pct(f)})`,
  };
}

export function diskReading(row: UtilJobRow): UsageReading | undefined {
  const used = row.disk_used_kib;
  const req = row.request.disk_kib;
  if (used === null) return undefined;
  if (!req) return { tone: 'normal', text: formatKiB(used), title: `Disk ${formatKiB(used)}` };
  const f = used / req;
  // Over its request is where a job gets held; the same tones as memory.
  const tone = memoryTone(f);
  return {
    fill: f,
    tone,
    text: `${formatKiB(used)} of ${formatKiB(req)}${tone === 'normal' ? '' : ` · ${pct(f)}`}`,
    title: `Disk ${formatKiB(used)} of ${formatKiB(req)} requested (${pct(f)})`,
  };
}

export function gpuReading(row: UtilJobRow): UsageReading | undefined {
  const f = row.gpu_utilization;
  if (f === null) return undefined;
  const n = row.request.gpus ?? 1;
  return {
    fill: f,
    // A GPU kept busy a quarter of the time is the case worth spotting.
    tone: f < 0.25 ? 'muted' : 'normal',
    text: `${formatPercent(f)} busy${row.gpu_memory_peak_mib !== null ? ` · ${formatMiB(row.gpu_memory_peak_mib)}` : ''}`,
    title: `${n} GPU${n === 1 ? '' : 's'} kept busy ${formatPercent(f)} of the time`,
  };
}

// --- Outcome ---

export function OutcomeBadge({ row }: { row: UtilJobRow }) {
  let label: string;
  let cls: string;
  switch (row.outcome) {
    case 'ok':
      label = 'Succeeded';
      cls = 'bg-green-100 text-green-800';
      break;
    case 'memory_exceeded':
      label = 'Over memory';
      cls = 'bg-red-100 text-red-800';
      break;
    case 'removed':
      label = 'Removed';
      cls = 'bg-gray-100 text-gray-700';
      break;
    default:
      label = row.exit_by_signal
        ? 'Failed (signal)'
        : row.exit_code !== null
          ? `Failed (exit ${row.exit_code})`
          : 'Failed';
      cls = 'bg-red-100 text-red-800';
  }
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <span className={`inline-flex whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium ${cls}`}>
        {label}
      </span>
      {row.restarts > 0 && (
        <span className="whitespace-nowrap text-xs text-gray-500">
          restarted {row.restarts}×
        </span>
      )}
      {(row.held_for_memory || row.held_for_disk) && row.outcome !== 'memory_exceeded' && (
        <span className="whitespace-nowrap text-xs text-amber-800">
          held for {row.held_for_memory ? 'memory' : 'disk'}
        </span>
      )}
    </span>
  );
}

function when(t: number | null): string {
  if (!t) return '—';
  return new Date(t * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// --- The list ---

type Sort = SortState<UtilJobSort>;

export function WorkflowJobs({
  workflowKey,
  query,
  hasGpu,
  focus,
  onClearFocus,
}: {
  workflowKey: string;
  query: JobsQuery;
  hasGpu: boolean;
  focus: JobFocus | null;
  onClearFocus: () => void;
}) {
  const [sort, setSort] = useState<Sort>(
    focus ? { key: focus.sort, direction: 'desc' } : { key: 'completed', direction: 'desc' },
  );
  // A newly picked range sorts the list by its measure, largest first.
  // Compared during render so the list never paints a frame in the old
  // order with the new highlight.
  const [seenFocus, setSeenFocus] = useState<JobFocus | null>(focus);
  if (seenFocus !== focus) {
    setSeenFocus(focus);
    if (focus) setSort({ key: focus.sort, direction: 'desc' });
  }

  const { data, error, isLoading, fetchNextPage, hasNextPage, isFetchingNextPage } = useInfiniteQuery<
    UtilJobsResponse,
    Error
  >({
    queryKey: [
      'utilization-jobs',
      workflowKey,
      query.days,
      query.owned_by_me,
      query.schedd ?? '',
      query.constraint ?? '',
      (query.owners ?? []).join(','),
      query.limit ?? null,
      sort.key,
      sort.direction,
    ],
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      api.utilizationJobs({
        ...query,
        w: workflowKey,
        sort: sort.key,
        order: sort.direction,
        offset: pageParam as number,
        page_size: PAGE_SIZE,
      }),
    getNextPageParam: (last) => last.next_offset ?? undefined,
    staleTime: 60_000,
  });

  const rows = (data?.pages ?? []).flatMap((p) => p.jobs);
  const total = data?.pages[0]?.total;
  const marked = focus ? rows.filter((r) => inFocus(r, focus, true)).length : 0;

  // The list scrolls in its own bounded area, so the page has an end
  // however many jobs the workflow has: loading more as the page
  // scrolled made it grow forever. The next page loads as the end of
  // the AREA comes into view.
  const area = useRef<HTMLDivElement | null>(null);
  const sentinel = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const node = sentinel.current;
    if (!node || !hasNextPage) return;
    const obs = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting) && !isFetchingNextPage) void fetchNextPage();
      },
      { root: area.current, rootMargin: '300px 0px' },
    );
    obs.observe(node);
    return () => obs.disconnect();
  }, [hasNextPage, isFetchingNextPage, fetchNextPage]);

  // Bring the first job in a picked range into view once it has loaded,
  // once per pick.
  const firstIdx = focus ? rows.findIndex((r) => inFocus(r, focus, true)) : -1;
  const firstMarked = useRef<HTMLTableRowElement | null>(null);
  const scrolledFor = useRef<JobFocus | null>(null);
  useEffect(() => {
    if (focus && firstIdx >= 0 && scrolledFor.current !== focus && firstMarked.current) {
      scrollToRow(area.current, firstMarked.current);
      scrolledFor.current = focus;
    }
  }, [focus, firstIdx]);

  // A picked job that has not loaded yet: keep loading pages, sorted
  // near it by its own measure, up to a bound -- a workflow of 50,000
  // jobs should not be pulled in whole to find one.
  const pages = data?.pages.length ?? 0;
  const searching = !!focus?.job && firstIdx < 0 && !!hasNextPage && pages < MAX_SEARCH_PAGES;
  // Keyed on the page count too: a page can arrive without a render
  // ever seeing it in flight, and the search must go on regardless.
  useEffect(() => {
    if (searching && !isFetchingNextPage) void fetchNextPage();
  }, [searching, isFetchingNextPage, fetchNextPage, pages]);

  const notFound = error instanceof ApiError && error.status === 404;

  return (
    <section aria-labelledby="wf-jobs" className="space-y-2" data-testid="workflow-jobs">
      <div className="flex flex-wrap items-baseline gap-3">
        <h3 id="wf-jobs" className="text-sm font-semibold uppercase tracking-wide text-gray-500">
          Jobs
        </h3>
        {total !== undefined && (
          <span className="text-xs text-gray-500 tabular-nums">
            {rows.length.toLocaleString()} of {total.toLocaleString()} shown
          </span>
        )}
      </div>
      {focus && (
        <div
          className="flex flex-wrap items-center gap-2 rounded-sm border border-blue-200 bg-blue-50 px-3 py-1.5 text-sm text-blue-900"
          data-testid="job-focus"
        >
          {focus.job === undefined ? (
            <span>
              Marking jobs with {focus.label}
              {rows.length > 0 && ` — ${marked.toLocaleString()} among those shown`}.
            </span>
          ) : firstIdx >= 0 ? (
            <span>Job {focus.job}, marked below.</span>
          ) : searching ? (
            <span>Finding job {focus.job}…</span>
          ) : (
            <span>
              Job {focus.job} is further down the list.{' '}
              <Link href={jobArchiveHref({ id: focus.job })} className="font-medium underline">
                Open its record
              </Link>
            </span>
          )}
          <button type="button" onClick={onClearFocus} className="text-xs font-medium underline">
            clear
          </button>
        </div>
      )}
      {isLoading && <p className="text-sm text-gray-400">Loading jobs…</p>}
      {/* A 404 means this workflow has no jobs among the ones the
          current window and filters select -- usually because they were
          changed after the page loaded. Not an error: say what to do. */}
      {notFound && (
        <p className="text-sm text-gray-600">
          This workflow has no finished jobs in the selected window and filters. Widen the window or clear a filter
          to list them.
        </p>
      )}
      {error && !notFound && <p className="text-sm text-red-700">Could not load the jobs: {error.message}</p>}
      {(rows.length > 0 || hasNextPage) && (
        <div
          ref={area}
          // Scrollable by keyboard too.
          tabIndex={0}
          role="region"
          aria-label="Jobs of this workflow"
          className="max-h-[70vh] overflow-auto rounded-lg border border-gray-200 bg-white focus:outline-hidden focus-visible:ring-2 focus-visible:ring-brand-400"
          data-testid="workflow-jobs-scroll"
        >
          <table className="min-w-full text-sm">
            <thead className="sticky top-0 z-10 bg-gray-50 text-left text-xs text-gray-500 shadow-[0_1px_0_0_rgb(229_231_235)]">
              <tr>
                <th className="px-3 py-2 uppercase tracking-wide">Job</th>
                <th className="px-3 py-2 uppercase tracking-wide">Outcome</th>
                <SortableHeader label="Finished" sortKey="completed" sort={sort} onSort={setSort} />
                <SortableHeader label="Run time" sortKey="wall" sort={sort} onSort={setSort} className="text-right" />
                <SortableHeader label="Peak memory" sortKey="memory" sort={sort} onSort={setSort} />
                <SortableHeader label="CPU cores" sortKey="cores" sort={sort} onSort={setSort} />
                <SortableHeader label="Disk" sortKey="disk" sort={sort} onSort={setSort} />
                {hasGpu && <SortableHeader label="GPU" sortKey="gpu" sort={sort} onSort={setSort} />}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {rows.map((r, i) => {
                const mark = inFocus(r, focus, true);
                const isFirst = i === firstIdx;
                return (
                  <tr
                    key={`${r.schedd ?? ''}/${r.id}`}
                    ref={isFirst ? firstMarked : undefined}
                    // One picked job stands out more than a range of them.
                    className={
                      mark ? (focus?.job !== undefined ? 'bg-blue-100 outline-2 -outline-offset-2 outline-blue-500' : 'bg-blue-50') : undefined
                    }
                    data-marked={mark ? 'true' : undefined}
                  >
                    <td className="px-3 py-1.5 font-mono text-xs">
                      <Link href={jobArchiveHref(r)} className="text-brand-700 hover:underline">
                        {r.id}
                      </Link>
                      {r.schedd && <div className="text-[11px] text-gray-500">{r.schedd}</div>}
                    </td>
                    <td className="px-3 py-1.5">
                      <OutcomeBadge row={r} />
                    </td>
                    <td className="whitespace-nowrap px-3 py-1.5 text-xs text-gray-600 tabular-nums">
                      {when(r.completed)}
                    </td>
                    <td className="whitespace-nowrap px-3 py-1.5 text-right text-xs tabular-nums">
                      {formatSeconds(r.wall)}
                    </td>
                    <td className="px-3 py-1.5">
                      <UsageBar reading={memoryReading(r)} />
                    </td>
                    <td className="px-3 py-1.5">
                      <UsageBar reading={coresReading(r)} />
                    </td>
                    <td className="px-3 py-1.5">
                      <UsageBar reading={diskReading(r)} />
                    </td>
                    {hasGpu && (
                      <td className="px-3 py-1.5">
                        <UsageBar reading={gpuReading(r)} />
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
          {hasNextPage && (
            <div ref={sentinel} className="py-2 text-center text-xs text-gray-400">
              {isFetchingNextPage ? (
                'Loading more jobs…'
              ) : (
                <button type="button" onClick={() => void fetchNextPage()} className="underline">
                  Load more
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
}

// scrollToRow centres a row in the list's own scroll area, and brings the
// area into view only if none of it is on screen: the page is not moved
// to a row the list can show by itself.
function scrollToRow(area: HTMLElement | null, row: HTMLElement) {
  if (!area) return;
  const a = area.getBoundingClientRect();
  const r = row.getBoundingClientRect();
  const top = area.scrollTop + (r.top - a.top) - (area.clientHeight - r.height) / 2;
  area.scrollTo?.({ top: Math.max(0, top), behavior: 'smooth' });
  if (a.bottom <= 0 || a.top >= window.innerHeight) area.scrollIntoView?.({ block: 'nearest', behavior: 'smooth' });
}
