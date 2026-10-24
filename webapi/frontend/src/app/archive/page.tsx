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
//
// Filtering works on two levels, and the difference matters here more
// than it does on /jobs: text, status and user narrow the records this
// page has already paged in, while a ClassAd expression goes to the
// schedd and searches all of history. History is far too big to load,
// so the expression is the only one that can find something nobody has
// scrolled to.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  api,
  ApiError,
  jobIdOf,
  scheddOf,
  type ClassAd,
  type HistoryListResponse,
  type JobListResponse,
  type Sources,
} from '@/lib/api';
import { useMultiAP } from '@/lib/multiap';
import { ScheddFilter } from '@/components/ScheddFilter';
import { SourcesBanner } from '@/components/SourcesBanner';
import { ChatPanel } from '@/components/ChatPanel';
import { ScopeToggle, useScope } from '@/components/ScopeToggle';
import { FilterControls, type FilterMode } from '@/components/FilterControls';
import { StatusStrip } from '@/components/StatusStrip';
import { LISTING_PAGE_SIZE } from '@/lib/paging';
import {
  archiveStatus,
  archiveStatusCls,
  countArchiveStatuses,
  filterAdsByArchiveStatus,
  filterAdsByOwner,
  filterAdsByText,
  ownersOf,
  ARCHIVE_STATUS_LABEL,
  ARCHIVE_STATUS_ORDER,
  type ArchiveStatus,
} from '@/lib/archive';

// Default projection for the listing. Slightly wider than the server
// default so the UI can show submission/completion times and exit
// codes without a per-row round-trip.
const PROJECTION =
  'ClusterId,ProcId,Owner,QDate,JobStartDate,CompletionDate,RemoteWallClockTime,JobStatus,ExitCode,ExitBySignal,Cmd,Args,JobBatchName';

// Page size for each fetch.
//
// Was a hundred, chosen so an idle "load on scroll" would not pull more
// than a screenful at a time. That reasoning holds for a small archive
// and inverts for a real one: on an access point with tens of thousands
// of records, finding anything means scrolling, and scrolling meant a
// round trip per screenful.
const PAGE_SIZE = LISTING_PAGE_SIZE;

interface PageCursor {
  beforeCluster?: number;
  beforeProc?: number;
  // Multi-AP mode: the server's page token. A cluster.proc keyset does
  // not identify a position across access points.
  pageToken?: string;
}

// PageData: what each useInfiniteQuery page returns. Carries the
// next cursor so getNextPageParam can read it without re-deriving
// from the ad list.
interface PageData {
  ads: ClassAd[];
  nextCursor: PageCursor | null;
  sources?: Sources;
}

export default function ArchivePage() {
  const [filter, setFilter] = useState('');
  const [mode, setMode] = useState<FilterMode>('text');
  const [exprInput, setExprInput] = useState('');
  const [appliedExpr, setAppliedExpr] = useState('');
  const [statuses, setStatuses] = useState<Set<ArchiveStatus>>(new Set());
  const [owner, setOwner] = useState('');

  const toggleStatus = useCallback((key: ArchiveStatus) => {
    setStatuses((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);
  const clearStatuses = useCallback(() => setStatuses(new Set()), []);

  // Same Mine/Everyone selector as the dashboard and /jobs, sharing one
  // stored choice (lib/scope.ts). Only admins see it: the server
  // confines a non-admin browser session to its own records whatever we
  // send, so the toggle would be inert for them.
  const { data: session } = useQuery({
    queryKey: ['session'],
    queryFn: api.auth.me,
  });
  const isAdmin = !!session?.is_admin;
  const multiAP = useMultiAP();
  const [scope] = useScope();
  const ownedByMe = scope === 'mine';

  // A server-side constraint handed over in the URL, the same way /jobs
  // takes one. It is how the dashboard drills into finished work: those
  // jobs are gone from the queue, so the archive is the only page that
  // can answer.
  const searchParams = useSearchParams();
  const urlConstraint = searchParams.get('constraint') ?? undefined;
  const why = searchParams.get('why') ?? undefined;
  const [schedd, setSchedd] = useState(searchParams.get('schedd') ?? '');
  // Finished jobs that have not left the queue are not history records
  // and are not in the table below. Off by default: this page answers
  // "what did I run", and most of the time nothing is waiting.
  const [showWaiting, setShowWaiting] = useState(false);

  // The drill-in constraint and a user expression both narrow; ANDing
  // them keeps the banner's promise true while the user refines inside
  // it.
  const exprConstraint = mode === 'expr' ? appliedExpr.trim() : '';
  const constraint =
    [urlConstraint, exprConstraint]
      .filter((c): c is string => !!c)
      .map((c) => `(${c})`)
      .join(' && ') || undefined;

  const {
    data,
    isLoading,
    error,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery<PageData, Error>({
    queryKey: ['jobs', 'archive', scope, constraint, multiAP, schedd],
    initialPageParam: { beforeCluster: undefined, beforeProc: undefined } as PageCursor,
    queryFn: async ({ pageParam }) => {
      const cursor = pageParam as PageCursor;
      if (multiAP) {
        const resp: HistoryListResponse = await api.jobs.archive({
          constraint,
          projection: PROJECTION,
          limit: PAGE_SIZE,
          page_token: cursor.pageToken,
          schedd: schedd || undefined,
        });
        return {
          ads: resp.ads ?? [],
          nextCursor: resp.next_page_token ? { pageToken: resp.next_page_token } : null,
          sources: resp.sources,
        };
      }
      const resp: HistoryListResponse = await api.jobs.archive({
        constraint,
        projection: PROJECTION,
        limit: PAGE_SIZE,
        before_cluster: cursor.beforeCluster,
        before_proc: cursor.beforeProc,
        owned_by_me: ownedByMe,
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
  // Counts for the strip come from everything loaded, before the
  // status filter: while looking at the failures you still want to see
  // how many completed, and the chip is how you get back to them.
  const statusCounts = useMemo(() => countArchiveStatuses(ads), [ads]);
  const owners = useMemo(() => ownersOf(ads, owner), [ads, owner]);

  const textFilter = mode === 'text' ? filter : '';
  const filteredAds = useMemo(
    () =>
      filterAdsByText(
        filterAdsByOwner(filterAdsByArchiveStatus(ads, statuses), owner),
        textFilter,
      ),
    [ads, statuses, owner, textFilter],
  );

  // Whether anything is hiding loaded records, which changes what the
  // count under the table means.
  const narrowed = !!textFilter || statuses.size > 0 || !!owner;

  // A rejected expression is a typo, not an outage; reported next to
  // the input rather than as "could not load archive".
  const exprError =
    mode === 'expr' && appliedExpr && error instanceof ApiError
      ? error.message
      : null;

  // Chat hooks — same shape as /jobs.
  const chatHooks = useMemo<
    Record<string, (input: Record<string, unknown>) => unknown>
  >(
    () => ({
      set_filter: (input) => {
        const q = typeof input.query === 'string' ? input.query : '';
        setFilter(q);
        // The text box is only applied in text mode, so a set_filter
        // that landed while the user was writing an expression would
        // otherwise do nothing visible.
        setMode('text');
        return { ok: true, applied_query: q };
      },
      set_constraint: (input) => {
        // The expression the user would type into the filter's
        // expression box and Apply; the server evaluates it.
        const c = typeof input.constraint === 'string' ? input.constraint.trim() : '';
        setExprInput(c);
        setAppliedExpr(c);
        setMode(c ? 'expr' : 'text');
        return { ok: true, applied_constraint: c };
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
        <h1 className="text-2xl font-bold text-gray-900">
          {ownedByMe ? 'My Archive' : 'All Archive'}
        </h1>
        <span className="text-sm text-gray-500">
          Completed and removed jobs from the schedd&apos;s history.
        </span>
        {isAdmin && !multiAP && <ScopeToggle />}
        {multiAP && <ScheddFilter value={schedd} onChange={setSchedd} />}
        <Link
          href="/jobs"
          className="ml-auto text-sm text-brand-700 hover:underline"
        >
          ← Back to live jobs
        </Link>
      </div>

      <SourcesBanner sources={data?.pages[data.pages.length - 1]?.sources} />

      <ChatPanel
        visible={chatVisible}
        page="archive"
        scope={ownedByMe ? 'mine' : 'everyone'}
        hooks={chatHooks}
        headerLabel="Archive assistant"
        togglerLabel={ownedByMe ? 'Ask about your job history' : 'Ask about job history'}
        pageHelp={
          ownedByMe
            ? `Ask things like "show my failed jobs from yesterday", "how long did the training-run batch take?", or "find that python job I ran on Tuesday".`
            : `Ask things like "show failed jobs from yesterday", "how long did the training-run batch take?", or "who ran the most jobs this week?".`
        }
        onServerToolComplete={handleServerToolComplete}
      />

      <WaitingToArchive
        show={showWaiting}
        onShow={setShowWaiting}
        ownedByMe={ownedByMe}
        schedd={schedd || undefined}
      />

      {urlConstraint && (
        <div className="mb-3 flex items-baseline gap-3 rounded border border-brand-200 bg-brand-50 px-3 py-2 text-sm">
          <span className="text-gray-700">Showing {why ?? 'a filtered set of jobs'}</span>
          <Link href="/archive" className="ml-auto text-xs text-brand-700 underline">
            show all history
          </Link>
        </div>
      )}

      <FilterControls
        mode={mode}
        input={mode === 'text' ? filter : exprInput}
        onMode={setMode}
        onInput={mode === 'text' ? setFilter : setExprInput}
        onApplyExpr={() => setAppliedExpr(exprInput.trim())}
        textPlaceholder="Filter by id, owner, batch name, command, or status…"
        exprPlaceholder={'ClassAd, e.g. ExitCode != 0 && QDate > 1757000000'}
      />
      {exprError && (
        <p className="rounded-sm border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {exprError}
        </p>
      )}

      {ads.length > 0 && (
        <div className="flex flex-wrap items-center gap-3">
          <StatusStrip
            chips={ARCHIVE_STATUS_ORDER.filter(
              (k) => (statusCounts[k] ?? 0) > 0 || statuses.has(k),
            ).map((key) => ({
              key,
              label: ARCHIVE_STATUS_LABEL[key],
              cls: archiveStatusCls(key),
              count: statusCounts[key] ?? 0,
            }))}
            selected={statuses}
            onToggle={toggleStatus}
            onClear={clearStatuses}
            total={ads.length}
            label="Filter by outcome"
            noun="records"
          />
          {/* Only worth a control when there is more than one user to
              choose between — in the Mine view there never is. */}
          {(owners.length > 1 || owner) && (
            <label className="flex items-center gap-1.5 text-xs text-gray-500">
              User:
              <select
                value={owner}
                onChange={(e) => setOwner(e.target.value)}
                className="rounded-sm border border-gray-300 bg-white px-2 py-1 text-xs text-gray-800"
              >
                <option value="">All users</option>
                {owners.map((o) => (
                  <option key={o} value={o}>
                    {o}
                  </option>
                ))}
              </select>
            </label>
          )}
        </div>
      )}

      {isLoading && <p className="text-gray-400">Loading history…</p>}

      {error && !exprError && (
        <p className="text-red-600 text-sm">
          Could not load archive: {error.message}
        </p>
      )}

      {!isLoading && !error && ads.length === 0 && (
        <p className="text-gray-500 text-sm">
          {constraint
            ? 'No history records match this query.'
            : 'No history records. New jobs land here once they complete or are removed.'}
        </p>
      )}

      {ads.length > 0 && (
        <>
          <ArchiveTable ads={filteredAds} onOwner={setOwner} multiAP={multiAP} />
          <div className="flex items-center justify-between gap-3 text-xs text-gray-500">
            <span>
              Showing {filteredAds.length.toLocaleString()}
              {narrowed ? ` of ${ads.length.toLocaleString()}` : ''} record
              {/* The noun agrees with the number it follows: "1 of 3
                  records", not "1 of 3 record". */}
              {(narrowed ? ads.length : filteredAds.length) === 1 ? '' : 's'}
              {narrowed && ' loaded so far'}
              {!hasNextPage && ' (end of history)'}
            </span>
            {isFetchingNextPage && <span>Loading more…</span>}
          </div>
          {/* The distinction that matters on this page: these three
              filters only see what has been paged in. Someone hunting a
              failure from last month will not find it by scrolling. */}
          {narrowed && hasNextPage && (
            <p className="text-xs text-gray-400">
              Text, outcome and user filters apply to the records loaded so
              far; scroll to load more, or switch to a ClassAd expression to
              search all of history.
            </p>
          )}
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

function ArchiveTable({
  ads,
  onOwner,
  multiAP,
}: {
  ads: ClassAd[];
  onOwner: (owner: string) => void;
  multiAP?: boolean;
}) {
  return (
    <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
      <table className="min-w-full text-sm">
        <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
          <tr>
            <th className="px-3 py-2">Job</th>
            {multiAP && <th className="px-3 py-2">Access point</th>}
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
                colSpan={multiAP ? 9 : 8}
                className="px-3 py-4 text-center text-xs text-gray-500"
              >
                No matches.
              </td>
            </tr>
          ) : (
            ads.map((ad) => (
              <ArchiveRow key={archiveKey(ad)} ad={ad} onOwner={onOwner} multiAP={multiAP} />
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

function ArchiveRow({
  ad,
  onOwner,
  multiAP,
}: {
  ad: ClassAd;
  onOwner: (owner: string) => void;
  multiAP?: boolean;
}) {
  const router = useRouter();
  const cluster = num(ad.ClusterId);
  const proc = num(ad.ProcId);
  // Multi-AP rows carry the complete id the server rendered.
  const id = jobIdOf(ad) ?? `${cluster ?? '?'}.${proc ?? 0}`;
  const status = archiveStatus(ad);
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
  const href = `/archive/${encodeURIComponent(id)}`;

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
      {multiAP && (
        <td className="px-3 py-2 font-mono text-xs text-gray-700">{scheddOf(ad) ?? '—'}</td>
      )}
      <td className="px-3 py-2">
        <span
          className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${status.cls}`}
        >
          {status.label}
        </span>
      </td>
      <td className="px-3 py-2 text-xs whitespace-nowrap">
        {owner ? (
          <button
            type="button"
            // Narrows in place rather than opening the user's page:
            // /users/<owner> is the live queue, and this row is history.
            onClick={(e) => {
              e.stopPropagation();
              onOwner(owner);
            }}
            title={`Show only ${owner}'s records`}
            className="rounded-full bg-indigo-100 px-2 py-0.5 font-medium text-indigo-800 hover:bg-indigo-200"
          >
            {owner}
          </button>
        ) : (
          <span className="text-gray-700">—</span>
        )}
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
  const base = `${num(ad.ClusterId) ?? '?'}.${num(ad.ProcId) ?? '?'}@${num(ad.CompletionDate) ?? 0}`;
  const schedd = scheddOf(ad);
  return schedd ? `${schedd}\u0000${base}` : base;
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


// WaitingToArchive lists the finished jobs that are still in the queue.
//
// They are the one thing a reader of this page can be looking for and
// not find: a job submitted here is kept after it finishes so its
// output can still be fetched, and until it is archived there is no
// history record of it to list. Opt-in, because it is a second query
// and on most visits the answer is empty.
function WaitingToArchive({
  show,
  onShow,
  ownedByMe,
  schedd,
}: {
  show: boolean;
  onShow: (v: boolean) => void;
  ownedByMe: boolean;
  schedd?: string;
}) {
  const { data, isLoading, error } = useQuery<JobListResponse, Error>({
    queryKey: ['jobs', 'waiting-to-archive', ownedByMe, schedd],
    queryFn: () =>
      api.jobs.list({
        constraint: 'JobStatus == 4',
        owned_by_me: ownedByMe,
        schedd,
        // Narrow on purpose: this is a sidebar to the page, not the
        // page. Everything it shows is one click from its job page.
        projection: 'ClusterId,ProcId,Owner,Cmd,Args,CompletionDate,ExitCode',
        limit: 200,
      }),
    enabled: show,
  });
  const jobs = data?.jobs ?? [];

  return (
    <div className="rounded border border-gray-200 bg-gray-50 px-3 py-2">
      <label className="flex items-center gap-2 text-sm text-gray-700">
        <input
          type="checkbox"
          checked={show}
          onChange={(e) => onShow(e.target.checked)}
          className="h-4 w-4 rounded-sm border-gray-300"
        />
        Also show finished jobs still in the queue
      </label>
      {show && (
        <>
          <p className="mt-1.5 text-xs text-gray-500">
            A job submitted through this interface is kept after it finishes so
            its output can still be fetched, and it has no history record until
            it is archived. These are those jobs; archiving one from its job
            page moves it into the table below.
          </p>
          {isLoading && <p className="mt-2 text-xs text-gray-400">Loading…</p>}
          {error && (
            <p className="mt-2 text-xs text-red-700">
              Could not read the queue: {error.message}
            </p>
          )}
          {!isLoading && !error && jobs.length === 0 && (
            <p className="mt-2 text-xs text-gray-500">
              None — every finished job is in the history below.
            </p>
          )}
          {jobs.length > 0 && (
            <table className="mt-2 w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wide text-gray-500">
                  <th className="px-2 py-1 font-medium">Job</th>
                  {!ownedByMe && <th className="px-2 py-1 font-medium">User</th>}
                  <th className="px-2 py-1 font-medium">Finished</th>
                  <th className="px-2 py-1 font-medium">Command</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {jobs.map((ad) => {
                  const id = waitingJobID(ad);
                  const finished = numAttr(ad.CompletionDate);
                  const cmd = typeof ad.Cmd === 'string' ? ad.Cmd : undefined;
                  const args = typeof ad.Args === 'string' ? ad.Args : undefined;
                  const owner = typeof ad.Owner === 'string' ? ad.Owner : undefined;
                  return (
                    <tr key={id ?? JSON.stringify(ad)}>
                      <td className="px-2 py-1 font-mono text-xs">
                        {id ? (
                          <Link href={`/jobs/${id}`} className="text-brand-700 hover:underline">
                            {id}
                          </Link>
                        ) : (
                          '—'
                        )}
                      </td>
                      {!ownedByMe && (
                        <td className="px-2 py-1 text-xs text-gray-700">{owner ?? '—'}</td>
                      )}
                      <td className="px-2 py-1 whitespace-nowrap text-xs text-gray-500">
                        {finished ? new Date(finished * 1000).toLocaleString() : '—'}
                      </td>
                      <td className="max-w-md truncate px-2 py-1 text-xs text-gray-700">
                        {cmd ? (
                          <span className="font-mono">
                            {cmd}
                            {args ? ' ' + args : ''}
                          </span>
                        ) : (
                          '—'
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
          {data?.has_more && (
            <p className="mt-1.5 text-xs text-gray-500">
              Showing the first {jobs.length.toLocaleString()}; more are waiting.
            </p>
          )}
        </>
      )}
    </div>
  );
}

// waitingJobID: the queue's own job_id when it sent one, else built
// from the ad. The archive's jobIdOf only knows the first form.
function waitingJobID(ad: ClassAd): string | undefined {
  const given = jobIdOf(ad);
  if (given) return given;
  const cluster = numAttr(ad.ClusterId);
  const proc = numAttr(ad.ProcId);
  if (cluster === undefined || proc === undefined) return undefined;
  return `${cluster}.${proc}`;
}

// numAttr reads a ClassAd attribute that should be a number, whichever
// of the two shapes the API used for it.
function numAttr(v: unknown): number | undefined {
  if (typeof v === 'number') return v;
  if (typeof v === 'string' && v.trim() !== '' && !Number.isNaN(Number(v))) {
    return Number(v);
  }
  return undefined;
}
