'use client';

// HTCondor is batch-oriented: a single submission produces one batch
// that may contain many jobs. This page mirrors that — one row per
// batch, with an aggregated jobs count + status breakdown + oldest
// submission time.
//
// Click anywhere on a batch row (except the action buttons) to expand
// it inline and see the individual jobs in that batch.
//
// Three filters stack, and they narrow different things:
//   - the status strip and the text box run in the browser, over the
//     job ads already fetched;
//   - a ClassAd expression goes to the server as a query constraint,
//     which is the only one that can reach jobs this page has not
//     loaded.
// The summary panel totals whatever survives all three, so it always
// describes the table underneath it.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  useInfiniteQuery,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import {
  api,
  ApiError,
  type DisplayStatus,
  type JobListResponse,
} from '@/lib/api';
import { ChatPanel } from '@/components/ChatPanel';
import { ScopeToggle, useScope } from '@/components/ScopeToggle';
import { FilterControls, type FilterMode } from '@/components/FilterControls';
import { JobStatusStrip } from '@/components/JobStatusStrip';
import { JobsSummaryPanel } from '@/components/JobsSummaryPanel';
import { BatchTable } from '@/components/BatchTable';
import { MAX_AUTO_PAGES, useAutoLoadAll, useLoadAllJobs } from '@/lib/loadAll';
import {
  applyBatchFilter,
  filterAdsByStatus,
  groupIntoBatches,
  num,
  summarizeJobs,
  BATCH_PROJECTION,
} from '@/lib/batches';

// How many job ads to pull per request. The queue can be far larger than
// this -- an access point with 30k queued jobs is ordinary -- so the
// number is a page size, not a ceiling, and the response's has_more tells
// us when we are looking at a fraction of the queue.
const PAGE_SIZE = 1000;

// Auto-refresh cadence. Slower once the whole queue has been pulled in:
// re-fetching every loaded page every 15s is cheap for one page and
// decidedly not for thirty.
const REFRESH_MS = 15_000;
const REFRESH_MS_FULL = 60_000;

export default function JobsPage() {
  const searchParams = useSearchParams();
  // Admin browser sessions can opt into a pool-wide view; non-admin
  // sessions can't (the server enforces it). We default admins to
  // "show only mine" too — admin views are explicit, not surprising.
  const { data: session } = useQuery({
    queryKey: ['session'],
    queryFn: api.auth.me,
  });
  const isAdmin = !!session?.is_admin;

  // Shared with the dashboard and /archive; see lib/scope.ts.
  const [scope] = useScope();
  const ownedByMe = scope === 'mine';

  // A server-side constraint handed over in the URL, which is how the
  // dashboard's panels drill in: clicking a hold reason lands here
  // showing exactly those jobs. `why` is the human sentence to put on
  // the banner, because a raw ClassAd expression is not one.
  const urlConstraint = searchParams.get('constraint') ?? undefined;
  const why = searchParams.get('why') ?? undefined;

  // Filter mode. Text is the default: it is instant, forgiving, and
  // covers "where is my training run". The expression mode is the
  // precise tool and the only one that can narrow the server-side
  // query, which is what a queue too big to load whole needs.
  const [mode, setMode] = useState<FilterMode>('text');
  // Two inputs, not one: switching modes should not throw away what the
  // user typed in the other, and only the active one is applied.
  const [filter, setFilter] = useState('');
  const [exprInput, setExprInput] = useState('');
  const [appliedExpr, setAppliedExpr] = useState('');
  const textFilter = mode === 'text' ? filter : '';
  const exprConstraint = mode === 'expr' ? appliedExpr.trim() : '';

  // A drill-in constraint from the URL and a user expression both
  // narrow; ANDing them keeps the banner's promise ("showing jobs held
  // for X") true while the user refines inside it.
  const constraint =
    [urlConstraint, exprConstraint]
      .filter((c): c is string => !!c)
      .map((c) => `(${c})`)
      .join(' && ') || undefined;

  // Status chips. An empty set means "every status" — see JobStatusStrip.
  const [statuses, setStatuses] = useState<Set<DisplayStatus>>(new Set());
  const toggleStatus = useCallback((key: DisplayStatus) => {
    setStatuses((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);
  const clearStatuses = useCallback(() => setStatuses(new Set()), []);

  // "Load everything" is opt-in: the default keeps a bounded first page
  // so opening /jobs on a 30k-job queue is not a multi-second download,
  // and the banner below offers the rest. Asking for it is remembered
  // (lib/loadAll.ts) -- a poll cycle that dropped back to the first
  // page would otherwise re-ask a question the user has answered.
  const [loadAll, setLoadAll] = useLoadAllJobs();

  const {
    data: pages,
    isLoading,
    isFetching,
    error,
    refetch,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery<JobListResponse, Error>({
    queryKey: ['jobs', scope, loadAll, constraint],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) =>
      api.jobs.list({
        constraint,
        projection: BATCH_PROJECTION,
        // "*" is the server's unlimited sentinel. Only ever sent because
        // the user asked for it after being told the answer was cut off.
        limit: loadAll ? '*' : PAGE_SIZE,
        page_token: pageParam as string | undefined,
        owned_by_me: ownedByMe,
      }),
    // A token is only ever present when an htcondordb mirror served the
    // query; a live schedd cannot be paged through.
    getNextPageParam: (last) => last.next_page_token ?? undefined,
    refetchInterval: loadAll ? REFRESH_MS_FULL : REFRESH_MS,
    // A rejected expression is not worth retrying -- it will be rejected
    // three more times and the user waits out the backoff before seeing
    // their typo. Everything else keeps the default resilience.
    retry: exprConstraint ? false : 3,
  });

  // A rejected expression is a typo, not an outage. Reported next to the
  // input that caused it rather than as "could not load jobs", which
  // would read as the server being down.
  const exprError =
    mode === 'expr' && appliedExpr && error instanceof ApiError
      ? error.message
      : null;

  // The paginated (htcondordb mirror) path: the mirror clamps a single
  // request's limit, which is why it pages at all, so limit="*" does not
  // pull everything -- the only way to get the whole answer is to follow
  // every page token. The walk runs off the preference rather than a
  // button press, so it resumes after a refetch instead of stopping at
  // whatever page the poll left behind.
  const pageCount = pages?.pages.length ?? 0;
  useAutoLoadAll({
    enabled: loadAll,
    hasNextPage: !!hasNextPage,
    isFetching,
    pageCount,
    fetchNextPage,
  });

  // Flatten the loaded pages, and read the truncation state off the
  // LAST one -- earlier pages always report has_more.
  const jobs = useMemo(
    () => (pages?.pages ?? []).flatMap((p) => p.jobs ?? []),
    [pages],
  );
  const lastPage = pages?.pages[pages.pages.length - 1];
  const data = pages ? { jobs } : undefined;

  // Counts for the strip come from the jobs BEFORE the status filter:
  // while looking at the running jobs you still want to see that eleven
  // are held, and the chip is how you get to them.
  const statusCounts = useMemo(() => summarizeJobs(jobs).counts, [jobs]);

  const statusFiltered = useMemo(
    () => filterAdsByStatus(jobs, statuses),
    [jobs, statuses],
  );

  const batches = useMemo(
    () => applyBatchFilter(groupIntoBatches(statusFiltered), textFilter),
    [statusFiltered, textFilter],
  );

  // The summary totals exactly the jobs the table is showing. The text
  // filter matches whole batches, so the ads it keeps are the ones whose
  // cluster survived it.
  const summary = useMemo(() => {
    if (!textFilter) return summarizeJobs(statusFiltered);
    const clusters = new Set(batches.map((b) => b.batchID));
    return summarizeJobs(
      statusFiltered.filter((j) => {
        const c = num(j.ClusterId);
        return c !== undefined && clusters.has(c);
      }),
    );
  }, [statusFiltered, textFilter, batches]);

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
  // table view: expanded-batch set and a brief highlight on a
  // specific job row. (The filter is lifted for the same reason.)
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
        // The text box is only applied in text mode, so a set_filter
        // that landed while the user was writing an expression would
        // otherwise do nothing visible.
        setMode('text');
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
        {isAdmin && <ScopeToggle />}
        <Link
          href="/submit"
          className="ml-auto rounded-sm bg-brand-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-700"
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

      {error && !exprError && (
        <p className="text-red-600 text-sm">
          Could not load jobs: {(error as Error).message}
        </p>
      )}

      {data && data.jobs.length === 0 && !constraint && (
        <p className="text-gray-500 text-sm">
          No batches in the queue.{' '}
          <Link href="/submit" className="text-brand-700 hover:underline">
            Submit one
          </Link>{' '}
          to get started.
        </p>
      )}

      {/* A narrowed query that matched nothing. Distinct from the empty
          queue above: the jobs may well be there, just not these. */}
      {data && data.jobs.length === 0 && constraint && (
        <p className="text-gray-500 text-sm">
          No jobs in the queue match this query.
        </p>
      )}

      {lastPage && (
        <TruncationNotice
          shown={jobs.length}
          page={lastPage}
          canPage={!!hasNextPage}
          fetchingMore={isFetchingNextPage}
          loadAll={loadAll}
          capped={pageCount >= MAX_AUTO_PAGES}
          onLoadMore={() => fetchNextPage()}
          onSetLoadAll={setLoadAll}
        />
      )}

      {urlConstraint && (
        <div className="flex items-baseline gap-3 rounded border border-brand-200 bg-brand-50 px-3 py-2 text-sm">
          <span className="text-gray-700">
            Showing {why ?? 'a filtered set of jobs'}
          </span>
          {/* Without a way out, a narrowed list looks like a broken
              jobs page: the counts do not match anything and the
              jobs someone expected are simply absent. */}
          <Link href="/jobs" className="ml-auto text-xs text-brand-700 underline">
            show all jobs
          </Link>
        </div>
      )}

      <FilterControls
        mode={mode}
        input={mode === 'text' ? filter : exprInput}
        onMode={setMode}
        onInput={mode === 'text' ? setFilter : setExprInput}
        onApplyExpr={() => setAppliedExpr(exprInput.trim())}
        textPlaceholder="Filter batches (name, cluster id, user, status…)"
        exprPlaceholder={'ClassAd, e.g. JobStatus == 5 && RequestCpus > 4'}
      />
      {exprError && (
        <p className="rounded-sm border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {exprError}
        </p>
      )}

      {data && data.jobs.length > 0 && (
        <>
          <JobStatusStrip
            counts={statusCounts}
            selected={statuses}
            onToggle={toggleStatus}
            onClear={clearStatuses}
            total={jobs.length}
          />

          <JobsSummaryPanel summary={summary} showOwners={!ownedByMe} />

          {batches.length === 0 ? (
            <p className="text-sm text-gray-500">
              No batches match this filter.{' '}
              <button
                type="button"
                onClick={() => {
                  setFilter('');
                  clearStatuses();
                }}
                className="text-brand-700 hover:underline"
              >
                Clear it
              </button>{' '}
              to see the rest.
            </p>
          ) : (
            <BatchTable
              batches={batches}
              resetKey={`${textFilter}\u0000${[...statuses].sort().join(',')}`}
              showOwner={!ownedByMe}
              expanded={expanded}
              setExpanded={setExpanded}
              highlighted={highlighted}
              onChange={() => refetch()}
            />
          )}
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

// TruncationNotice is the answer to "am I looking at all my jobs?".
//
// The server reports has_more, and when it cannot paginate it even
// explains why. Rendering a truncated list as though it were the whole
// queue is not a cosmetic problem on an access point with 30k queued
// jobs: it is the UI asserting something false.
//
// Two ways to get the rest, depending on which backend answered:
//   - An htcondordb mirror gives a cursor, so the page walks it.
//   - A live schedd has no cursor to resume from, so the only option is
//     to pull the whole answer in one request.
// Either way the choice is remembered, so this notice's job once it has
// been made is to report what is loaded and offer the way back.
function TruncationNotice({
  shown,
  page,
  canPage,
  fetchingMore,
  loadAll,
  capped,
  onLoadMore,
  onSetLoadAll,
}: {
  shown: number;
  page: JobListResponse;
  canPage: boolean;
  fetchingMore: boolean;
  loadAll: boolean;
  // The cursor walk hit its backstop. Reported rather than silently
  // stopping, which would look exactly like "this is the whole queue".
  capped: boolean;
  onLoadMore: () => void;
  onSetLoadAll: (next: boolean) => void;
}) {
  // A partial-result error is worth showing even when nothing was
  // truncated: the ads that arrived are valid, but the answer is short
  // for a reason the user should see.
  if (page.error) {
    return (
      <p className="rounded-sm border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900">
        Showing {shown.toLocaleString()} job{shown === 1 ? '' : 's'}; the query
        did not finish: {page.error}
      </p>
    );
  }

  if (loadAll) {
    if (capped) {
      return (
        <div className="rounded-sm border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900">
          Stopped after {shown.toLocaleString()} jobs — that is as far as this
          page will page automatically. Narrow the query to see the rest.{' '}
          <StopLoadingAll onSetLoadAll={onSetLoadAll} />
        </div>
      );
    }
    if (canPage || page.has_more) {
      return (
        <p className="text-xs text-gray-500">
          Loading the whole queue — {shown.toLocaleString()} job
          {shown === 1 ? '' : 's'} so far.{' '}
          <StopLoadingAll onSetLoadAll={onSetLoadAll} />
        </p>
      );
    }
    return (
      <p className="text-xs text-gray-500">
        Showing all {shown.toLocaleString()} matching jobs, and will keep
        doing so. <StopLoadingAll onSetLoadAll={onSetLoadAll} />
      </p>
    );
  }

  if (!page.has_more) return null;

  return (
    <div className="rounded-sm border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900">
      <span>
        Showing the first <strong>{shown.toLocaleString()}</strong> jobs.
      </span>{' '}
      {canPage && (
        <>
          <button
            type="button"
            onClick={onLoadMore}
            disabled={fetchingMore}
            className="font-medium underline hover:text-amber-950 disabled:opacity-50"
          >
            {fetchingMore ? 'Loading…' : 'Load more'}
          </button>{' '}
        </>
      )}
      {/* The server's own explanation of why there is no cursor. Better
          than paraphrasing it here, because the reason differs by
          backend and version. */}
      {!canPage && page.pagination_unavailable && (
        <span className="text-amber-800">{page.pagination_unavailable} </span>
      )}
      <button
        type="button"
        onClick={() => onSetLoadAll(true)}
        disabled={fetchingMore}
        className="font-medium underline hover:text-amber-950 disabled:opacity-50"
      >
        Load them all
      </button>
      <span className="text-amber-800">
        {' '}
        — may take several seconds on a big queue, and stays on until you
        turn it off.
      </span>
    </div>
  );
}

// StopLoadingAll is the way back to the bounded default. It exists
// because the preference outlives the page view: without a visible way
// off, a user who once asked for a 200k-job queue would pay for it on
// every visit with no idea why the page had become slow.
function StopLoadingAll({
  onSetLoadAll,
}: {
  onSetLoadAll: (next: boolean) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onSetLoadAll(false)}
      className="underline hover:text-gray-800"
    >
      Stop loading everything
    </button>
  );
}
