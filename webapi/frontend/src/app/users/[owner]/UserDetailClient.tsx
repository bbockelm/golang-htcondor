'use client';

// /users/<owner> is the page behind the user pills on /jobs: everything
// one person has in the queue, with the same batch table and the same
// summary the pool-wide listing uses.
//
// It exists because "who is filling the pool" is a question an operator
// answers by picking a name out of a list and then wanting only that
// name. Doing that through the shared listing would mean either a text
// filter that also matches batch names and commands, or hand-writing a
// ClassAd expression.

import { useCallback, useMemo, useState } from 'react';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { api, ApiError, type DisplayStatus, type JobListResponse } from '@/lib/api';
import { useResolvedParams } from '@/lib/useResolvedParams';
import { JobStatusStrip } from '@/components/JobStatusStrip';
import { JobsSummaryPanel } from '@/components/JobsSummaryPanel';
import { BatchTable } from '@/components/BatchTable';
import {
  applyBatchFilter,
  filterAdsByStatus,
  groupIntoBatches,
  num,
  summarizeJobs,
  BATCH_PROJECTION,
} from '@/lib/batches';

const PAGE_SIZE = 1000;
const REFRESH_MS = 15_000;

export default function UserDetailClient() {
  const { owner } = useResolvedParams<{ owner: string }>('/users/[owner]');
  const decoded = decodeURIComponent(owner ?? '');

  const { data: session } = useQuery({
    queryKey: ['session'],
    queryFn: api.auth.me,
  });

  // Whether this session can see anybody's jobs but its own. The server
  // decides that regardless of what we ask for; knowing it here is what
  // lets an empty page say "you can only see your own jobs" instead of
  // "this user has nothing queued", which are very different claims.
  const isAdmin = !!session?.is_admin;
  const isSelf = sameUser(decoded, session?.username);
  const maySee = isAdmin || isSelf;

  const [filter, setFilter] = useState('');
  const [statuses, setStatuses] = useState<Set<DisplayStatus>>(new Set());
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  const toggleStatus = useCallback((key: DisplayStatus) => {
    setStatuses((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);
  const clearStatuses = useCallback(() => setStatuses(new Set()), []);

  // Owner is matched server-side. Quoting through JSON.stringify rather
  // than by hand: a name with a quote in it would otherwise end the
  // string literal and change the expression's meaning.
  const constraint = `Owner == ${JSON.stringify(decoded)}`;

  const {
    data: pages,
    isLoading,
    error,
    refetch,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery<JobListResponse, Error>({
    queryKey: ['jobs', 'user', decoded],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) =>
      api.jobs.list({
        constraint,
        projection: BATCH_PROJECTION,
        limit: PAGE_SIZE,
        page_token: pageParam as string | undefined,
        // Asking for the pool-wide listing and letting the constraint do
        // the narrowing. A non-admin session is confined by the server,
        // which is why `maySee` gates the explanation below rather than
        // the request.
        owned_by_me: false,
      }),
    getNextPageParam: (last) => last.next_page_token ?? undefined,
    refetchInterval: REFRESH_MS,
    // The placeholder page the static export prerenders has no owner to
    // query for.
    enabled: !!decoded && decoded !== '_',
    retry: false,
  });

  const jobs = useMemo(
    () => (pages?.pages ?? []).flatMap((p) => p.jobs ?? []),
    [pages],
  );
  const lastPage = pages?.pages[pages.pages.length - 1];

  const statusCounts = useMemo(() => summarizeJobs(jobs).counts, [jobs]);
  const statusFiltered = useMemo(
    () => filterAdsByStatus(jobs, statuses),
    [jobs, statuses],
  );
  const batches = useMemo(
    () => applyBatchFilter(groupIntoBatches(statusFiltered), filter),
    [statusFiltered, filter],
  );
  const summary = useMemo(() => {
    if (!filter) return summarizeJobs(statusFiltered);
    const clusters = new Set(batches.map((b) => b.batchID));
    return summarizeJobs(
      statusFiltered.filter((j) => {
        const c = num(j.ClusterId);
        return c !== undefined && clusters.has(c);
      }),
    );
  }, [statusFiltered, filter, batches]);

  return (
    <div className="space-y-4">
      <div className="flex items-baseline gap-3 flex-wrap">
        <h1 className="text-2xl font-bold text-gray-900">{decoded || 'User'}</h1>
        <span className="text-sm text-gray-500">
          Everything this user has in the queue right now.
        </span>
        <Link href="/jobs" className="ml-auto text-sm text-brand-700 hover:underline">
          ← All batches
        </Link>
      </div>

      {isLoading && <p className="text-gray-400">Loading…</p>}

      {error && (
        <p className="text-sm text-red-600">
          Could not load this user&apos;s jobs:{' '}
          {error instanceof ApiError ? error.message : String(error)}
        </p>
      )}

      {lastPage?.has_more && (
        <div className="rounded-sm border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900">
          Showing the first <strong>{jobs.length.toLocaleString()}</strong> jobs.{' '}
          {hasNextPage ? (
            <button
              type="button"
              onClick={() => fetchNextPage()}
              disabled={isFetchingNextPage}
              className="font-medium underline hover:text-amber-950 disabled:opacity-50"
            >
              {isFetchingNextPage ? 'Loading…' : 'Load more'}
            </button>
          ) : (
            <span className="text-amber-800">
              {lastPage.pagination_unavailable ??
                'The rest cannot be paged through from here.'}
            </span>
          )}
        </div>
      )}

      {pages && jobs.length === 0 && !error && (
        <p className="text-sm text-gray-500">
          {maySee
            ? `${decoded} has nothing in the queue.`
            : // Not "no jobs": this session is only ever shown its own,
              // so an empty answer here says nothing about that user.
              'You can only see your own jobs, so this page cannot show you what this user is running.'}{' '}
          <Link href="/archive" className="text-brand-700 hover:underline">
            Check the archive
          </Link>{' '}
          for jobs that have already finished.
        </p>
      )}

      {jobs.length > 0 && (
        <>
          <JobStatusStrip
            counts={statusCounts}
            selected={statuses}
            onToggle={toggleStatus}
            onClear={clearStatuses}
            total={jobs.length}
          />

          <JobsSummaryPanel summary={summary} />

          <div className="flex items-center gap-2 text-xs">
            <span className="text-gray-500">Filter:</span>
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="batch name, cluster id, status…"
              className="min-w-0 flex-1 max-w-sm rounded-sm border border-gray-300 bg-white px-2 py-1 text-sm focus:border-brand-400 focus:outline-hidden focus:ring-1 focus:ring-brand-400"
            />
            {filter && (
              <button
                type="button"
                onClick={() => setFilter('')}
                className="text-gray-500 hover:text-gray-800"
              >
                clear
              </button>
            )}
          </div>

          {batches.length === 0 ? (
            <p className="text-sm text-gray-500">No batches match this filter.</p>
          ) : (
            <BatchTable
              batches={batches}
              resetKey={`${filter}\u0000${[...statuses].sort().join(',')}`}
              expanded={expanded}
              setExpanded={setExpanded}
              highlighted={null}
              onChange={() => refetch()}
            />
          )}
        </>
      )}

      {jobs.length > 0 && (
        <p className="text-xs text-gray-500">
          Looking for what this user has already run? The{' '}
          <Link
            href={`/archive?constraint=${encodeURIComponent(constraint)}&why=${encodeURIComponent(
              `jobs submitted by ${decoded}`,
            )}`}
            className="text-brand-700 hover:underline"
          >
            archive
          </Link>{' '}
          holds their completed and removed jobs.
        </p>
      )}
    </div>
  );
}

// sameUser compares a queue Owner with the session's identity. The queue
// stores a bare account name; a session identity may be fully qualified
// (user@domain), so compare on the local part.
function sameUser(owner: string, username: string | undefined): boolean {
  if (!owner || !username) return false;
  const local = (s: string) => s.split('@')[0].toLowerCase();
  return local(owner) === local(username);
}
