'use client';

// The archive view surfaces the schedd's history database — every
// job that's been completed or removed. Companion to /jobs (which
// shows what's currently in the queue): a user looking for "the run
// I started this morning" might find it here when the schedd has
// already evicted it from the live queue.
//
// Differences vs /jobs:
//   - Read-only: no remove / release / edit actions. History
//     entries are immutable.
//   - Flat per-job table (cluster.proc), not batch-grouped, since
//     "what's in flight" doesn't apply.
//   - Infinite scroll via keyset pagination on (ClusterId, ProcId).
//     Re-fetching with a bumped limit would re-scan records we
//     already have; bumping a `before_cluster`/`before_proc` cursor
//     instead asks the schedd for "strictly older than the last row
//     I displayed", which scales to hundreds of thousands of
//     archived jobs without the page blowing up.
//   - The chat panel is wired up the same way as /jobs, with a
//     dedicated server-side query_jobs_archive tool.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  api,
  type ClassAd,
  type HistoryListResponse,
} from '@/lib/api';
import { ChatPanel } from '@/components/ChatPanel';

// Default projection for the listing. Slightly wider than the server
// default so the UI can show submission/completion times and exit
// codes without a per-row round-trip.
const PROJECTION =
  'ClusterId,ProcId,Owner,QDate,JobStartDate,CompletionDate,RemoteWallClockTime,JobStatus,ExitCode,ExitBySignal,Cmd,Args,JobBatchName';

// Page size for each fetch. Small enough that an idle "load on
// scroll" doesn't pull more than a screenful at a time; large enough
// that the user doesn't see one fetch per scroll-tick.
const PAGE_SIZE = 100;

interface PageCursor {
  beforeCluster?: number;
  beforeProc?: number;
}

// PageData: what each useInfiniteQuery page returns. Carries the
// next cursor so getNextPageParam can read it without re-deriving
// from the ad list.
interface PageData {
  ads: ClassAd[];
  nextCursor: PageCursor | null;
}

export default function ArchivePage() {
  const [filter, setFilter] = useState('');

  const {
    data,
    isLoading,
    error,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery<PageData, Error>({
    queryKey: ['jobs', 'archive'],
    initialPageParam: { beforeCluster: undefined, beforeProc: undefined } as PageCursor,
    queryFn: async ({ pageParam }) => {
      const cursor = pageParam as PageCursor;
      const resp: HistoryListResponse = await api.jobs.archive({
        projection: PROJECTION,
        limit: PAGE_SIZE,
        before_cluster: cursor.beforeCluster,
        before_proc: cursor.beforeProc,
      });
      const ads = resp.ads ?? [];
      // The keyset cursor is the LAST ad in the page (oldest in
      // backwards-scan order). When the page came back short of
      // PAGE_SIZE we know we've hit the end of history and there's
      // no next cursor.
      let nextCursor: PageCursor | null = null;
      if (ads.length === PAGE_SIZE) {
        const last = ads[ads.length - 1];
        const c = num(last.ClusterId);
        const p = num(last.ProcId);
        if (c !== undefined) {
          nextCursor = { beforeCluster: c, beforeProc: p ?? 0 };
        }
      }
      return { ads, nextCursor };
    },
    getNextPageParam: (lastPage) => lastPage.nextCursor ?? undefined,
    // Archive doesn't churn — completed jobs stay completed. A long
    // staleTime keeps refocus from re-querying the schedd.
    staleTime: 30_000,
  });

  // Flatten pages into a single ad list for filtering / rendering.
  const ads = useMemo(
    () => (data?.pages ?? []).flatMap((p) => p.ads),
    [data],
  );
  const filteredAds = useMemo(() => filterAds(ads, filter), [ads, filter]);

  // Chat hooks — same shape as /jobs.
  const chatHooks = useMemo<
    Record<string, (input: Record<string, unknown>) => unknown>
  >(
    () => ({
      set_filter: (input) => {
        const q = typeof input.query === 'string' ? input.query : '';
        setFilter(q);
        return { ok: true, applied_query: q };
      },
    }),
    [],
  );

  const handleServerToolComplete = useCallback((toolName: string) => {
    // Read-only archive page — nothing to invalidate today.
    void toolName;
  }, []);

  const { data: chatInfo } = useQuery({
    queryKey: ['chat-info'],
    queryFn: api.chat.info,
    staleTime: Infinity,
    retry: false,
  });
  const chatVisible = !!chatInfo?.enabled;

  // Sentinel ref for the IntersectionObserver. When the empty
  // "loader" div at the bottom of the table scrolls into view we
  // pull the next page. Using IO instead of scroll-event handlers
  // avoids the rAF-throttled bookkeeping and Just Works with
  // virtualised parents (and the fact that our app shell is itself
  // the scroll container).
  const sentinelRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const node = sentinelRef.current;
    if (!node) return;
    if (!hasNextPage) return;
    const obs = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting && hasNextPage && !isFetchingNextPage) {
            void fetchNextPage();
          }
        }
      },
      // 200px rootMargin so the next page kicks off slightly BEFORE
      // the user actually scrolls to the very bottom — keeps the
      // table feeling continuous instead of pause-then-load.
      { rootMargin: '200px 0px' },
    );
    obs.observe(node);
    return () => obs.disconnect();
  }, [hasNextPage, isFetchingNextPage, fetchNextPage]);

  return (
    <div className="space-y-4">
      <div className="flex items-baseline gap-3 flex-wrap">
        <h1 className="text-2xl font-bold text-gray-900">Archive</h1>
        <span className="text-sm text-gray-500">
          Completed and removed jobs from the schedd&apos;s history.
        </span>
        <Link
          href="/jobs"
          className="ml-auto text-sm text-brand-700 hover:underline"
        >
          ← Back to live jobs
        </Link>
      </div>

      <ChatPanel
        visible={chatVisible}
        page="archive"
        hooks={chatHooks}
        headerLabel="Archive assistant"
        togglerLabel="Ask about your job history"
        pageHelp={`Ask things like "show my failed jobs from yesterday", "how long did the training-run batch take?", or "find that python job I ran on Tuesday".`}
        onServerToolComplete={handleServerToolComplete}
      />

      <FilterBar value={filter} onChange={setFilter} />

      {isLoading && <p className="text-gray-400">Loading history…</p>}

      {error && (
        <p className="text-red-600 text-sm">
          Could not load archive: {error.message}
        </p>
      )}

      {!isLoading && ads.length === 0 && (
        <p className="text-gray-500 text-sm">
          No history records. New jobs land here once they complete or
          are removed.
        </p>
      )}

      {ads.length > 0 && (
        <>
          <ArchiveTable ads={filteredAds} />
          <div className="flex items-center justify-between gap-3 text-xs text-gray-500">
            <span>
              Showing {filteredAds.length}
              {filter ? ` of ${ads.length}` : ''} record
              {filteredAds.length === 1 ? '' : 's'}
              {!hasNextPage && ' (end of history)'}
            </span>
            {isFetchingNextPage && <span>Loading more…</span>}
          </div>
          {/* Infinite-scroll sentinel. The IntersectionObserver in
              the effect above watches this element; when it scrolls
              into view (within 200px of viewport bottom) the next
              page kicks off. Hidden but still occupies a layout
              slot below the table so the observer has something to
              fire on. */}
          {hasNextPage && (
            <div ref={sentinelRef} aria-hidden className="h-px" />
          )}
        </>
      )}
    </div>
  );
}

// FilterBar — substring filter input. Mirrors the affordance on
// /jobs so users see the same shape across the two pages.
function FilterBar({
  value,
  onChange,
}: {
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="flex items-center gap-2">
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Filter by id, owner, batch name, command, or status…"
        className="min-w-0 flex-1 max-w-md rounded border border-gray-300 bg-white px-2 py-1 text-sm focus:border-brand-400 focus:outline-none focus:ring-1 focus:ring-brand-400"
      />
      {value && (
        <button
          type="button"
          onClick={() => onChange('')}
          className="text-xs text-gray-500 hover:text-gray-800"
        >
          clear
        </button>
      )}
    </div>
  );
}

// filterAds runs a multi-token AND substring match against a flat
// haystack built from each ad's user-visible fields. Mirrors the
// /jobs filter behavior so the user sees consistent semantics.
//
// Note: the filter is CLIENT-side, applied to the records we've
// already fetched. Records still on disk in the schedd's history
// but never paged in won't match — the user has to scroll to fetch
// more, or use the chat assistant for server-side constraint
// queries.
function filterAds(ads: ClassAd[], query: string): ClassAd[] {
  const q = query.trim().toLowerCase();
  if (q === '') return ads;
  const tokens = q.split(/\s+/);
  return ads.filter((ad) => {
    const haystack = [
      String(num(ad.ClusterId) ?? ''),
      String(num(ad.ProcId) ?? ''),
      str(ad.Owner) ?? '',
      str(ad.JobBatchName) ?? '',
      str(ad.Cmd) ?? '',
      str(ad.Args) ?? '',
      historyStatus(ad).label.toLowerCase(),
    ]
      .join(' ')
      .toLowerCase();
    return tokens.every((t) => haystack.includes(t));
  });
}

function ArchiveTable({ ads }: { ads: ClassAd[] }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
      <table className="min-w-full text-sm">
        <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
          <tr>
            <th className="px-3 py-2">Job</th>
            <th className="px-3 py-2">Status</th>
            <th className="px-3 py-2">Owner</th>
            <th className="px-3 py-2">Batch</th>
            <th className="px-3 py-2">Submitted</th>
            <th className="px-3 py-2">Completed</th>
            <th className="px-3 py-2">Runtime</th>
            <th className="px-3 py-2">Command</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {ads.length === 0 ? (
            <tr>
              <td
                colSpan={8}
                className="px-3 py-4 text-center text-xs text-gray-500"
              >
                No matches.
              </td>
            </tr>
          ) : (
            ads.map((ad) => <ArchiveRow key={archiveKey(ad)} ad={ad} />)
          )}
        </tbody>
      </table>
    </div>
  );
}

function ArchiveRow({ ad }: { ad: ClassAd }) {
  const router = useRouter();
  const cluster = num(ad.ClusterId);
  const proc = num(ad.ProcId);
  const id = `${cluster ?? '?'}.${proc ?? 0}`;
  const status = historyStatus(ad);
  const owner = str(ad.Owner);
  const batch = str(ad.JobBatchName);
  const qdate = num(ad.QDate);
  const completion = num(ad.CompletionDate);
  const runtime = num(ad.RemoteWallClockTime);
  const cmd = str(ad.Cmd);
  const args = str(ad.Args);

  // Whole row navigates to /archive/{id}. Mirrors the live /jobs
  // expanded-batch row pattern: clicking anywhere outside a nested
  // link opens the detail page.
  const navigable = cluster !== undefined;
  const href = `/archive/${id}`;

  return (
    <tr
      className={`hover:bg-gray-50 ${navigable ? 'cursor-pointer' : ''}`}
      onClick={navigable ? () => router.push(href) : undefined}
    >
      <td className="px-3 py-2 font-mono text-xs">
        {cluster !== undefined ? (
          <Link
            href={href}
            className="text-brand-700 hover:underline"
            // Stop the row's onClick from firing twice — Next's
            // <Link> handles the navigation, and bubbling up to the
            // <tr> would push the same URL a second time.
            onClick={(e) => e.stopPropagation()}
          >
            {id}
          </Link>
        ) : (
          id
        )}
      </td>
      <td className="px-3 py-2">
        <span
          className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${status.cls}`}
        >
          {status.label}
        </span>
      </td>
      <td className="px-3 py-2 text-gray-700 text-xs whitespace-nowrap">
        {owner ?? '—'}
      </td>
      <td className="px-3 py-2 text-gray-700 text-xs">{batch ?? '—'}</td>
      <td className="px-3 py-2 text-gray-500 text-xs whitespace-nowrap">
        {qdate ? new Date(qdate * 1000).toLocaleString() : '—'}
      </td>
      <td className="px-3 py-2 text-gray-500 text-xs whitespace-nowrap">
        {completion ? new Date(completion * 1000).toLocaleString() : '—'}
      </td>
      <td className="px-3 py-2 text-gray-700 text-xs whitespace-nowrap">
        {humanRuntime(runtime)}
      </td>
      <td className="px-3 py-2 text-gray-700 max-w-md truncate">
        {cmd ? (
          <span className="font-mono text-xs">
            {cmd}
            {args ? ' ' + args : ''}
          </span>
        ) : (
          '—'
        )}
      </td>
    </tr>
  );
}

interface HistoryStatus {
  label: string;
  cls: string;
}

// historyStatus collapses the (JobStatus, ExitCode, ExitBySignal)
// tuple of a history entry into a single user-readable label.
// History only ever shows terminal-state jobs (Completed=4 or
// Removed=3), so this is much narrower than displayJobStatus.
function historyStatus(ad: ClassAd): HistoryStatus {
  const status = num(ad.JobStatus);
  const exitCode = num(ad.ExitCode);
  const bySignal =
    ad.ExitBySignal === true || ad.ExitBySignal === 'true';
  if (status === 3) {
    return { label: 'Removed', cls: 'bg-rose-100 text-rose-800' };
  }
  if (status === 4) {
    if (bySignal) {
      return { label: 'Killed', cls: 'bg-amber-100 text-amber-800' };
    }
    if (exitCode !== undefined && exitCode !== 0) {
      return {
        label: `Failed (${exitCode})`,
        cls: 'bg-rose-100 text-rose-800',
      };
    }
    return { label: 'Completed', cls: 'bg-emerald-100 text-emerald-800' };
  }
  return { label: 'Unknown', cls: 'bg-gray-100 text-gray-700' };
}

// humanRuntime formats a wall-clock-seconds count as a short
// readable string. RemoteWallClockTime is the schedd's
// authoritative measurement.
function humanRuntime(secs: number | undefined): string {
  if (secs === undefined || secs <= 0) return '—';
  const s = Math.floor(secs);
  if (s < 60) return `${s}s`;
  if (s < 3600) {
    const m = Math.floor(s / 60);
    const rs = s % 60;
    return rs > 0 ? `${m}m ${rs}s` : `${m}m`;
  }
  if (s < 86400) {
    const h = Math.floor(s / 3600);
    const rm = Math.floor((s % 3600) / 60);
    return rm > 0 ? `${h}h ${rm}m` : `${h}h`;
  }
  const d = Math.floor(s / 86400);
  const rh = Math.floor((s % 86400) / 3600);
  return rh > 0 ? `${d}d ${rh}h` : `${d}d`;
}

// archiveKey: composite (cluster, proc, completion) so React's diff
// is stable across reorders, AND a job that ran twice (epoch
// re-entry) shows two rows with distinct keys.
function archiveKey(ad: ClassAd): string {
  return `${num(ad.ClusterId) ?? '?'}.${num(ad.ProcId) ?? '?'}@${num(ad.CompletionDate) ?? 0}`;
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
