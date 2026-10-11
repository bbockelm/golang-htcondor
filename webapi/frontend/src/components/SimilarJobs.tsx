'use client';

// The finished jobs a job's runtime estimate draws on, and the other
// groups it could be compared with. A job's page shows how long it will
// probably take; this shows what that is based on, so the user can judge
// it -- and go from one job back to the group it belongs to.
//
// One group at a time, from the most specific (same command) to the
// broadest (every recent job on the access point). The broadest spans
// other users, so it shows only its spread, never their jobs.

import { useState } from 'react';
import Link from 'next/link';
import { useInfiniteQuery } from '@tanstack/react-query';
import { api, ApiError } from '@/lib/api';
import { approxDuration } from '@/lib/duration';
import type { EstimateLevel, SimilarJobsResponse } from '@/lib/similar';

const PAGE_SIZE = 50;

// RuntimeSpread draws a group's runtimes on an axis from zero: whiskers
// from the 10th to 90th percentile, a box over the middle half, a tick at
// the median, and a mark for this job. The sentence under it says the
// same in words.
export function RuntimeSpread({
  runtimes,
  mark,
}: {
  runtimes: NonNullable<SimilarJobsResponse['runtimes']>;
  mark?: { seconds: number; label: string };
}) {
  const max = Math.max(runtimes.p90, mark?.seconds ?? 0) * 1.15 || 1;
  const at = (s: number) => `${Math.min(100, (s / max) * 100).toFixed(2)}%`;
  return (
    <div data-testid="runtime-spread">
      <div className="relative h-8" aria-hidden="true">
        <div className="absolute inset-x-0 top-4 h-px bg-gray-300" />
        <div
          className="absolute top-[15px] h-0.5 bg-[#2a78d6]"
          style={{ left: at(runtimes.p10), width: `calc(${at(runtimes.p90)} - ${at(runtimes.p10)})` }}
        />
        <div
          className="absolute top-2.5 h-3 rounded-sm bg-[#86b6ef]"
          style={{ left: at(runtimes.p25), width: `max(3px, calc(${at(runtimes.p75)} - ${at(runtimes.p25)}))` }}
        />
        <div className="absolute top-1.5 h-5 w-0.5 bg-[#184f95]" style={{ left: at(runtimes.p50) }} />
        {mark && (
          <div
            className="absolute top-0 h-8 w-[3px] -translate-x-1/2 rounded-sm bg-gray-900"
            style={{ left: at(mark.seconds) }}
            data-testid="spread-mark"
          />
        )}
      </div>
      <div className="flex justify-between text-xs text-gray-500 tabular-nums">
        <span>0</span>
        <span>{approxDuration(max)}</span>
      </div>
      <p className="mt-1 text-sm text-gray-700">
        Half of these {runtimes.count.toLocaleString()} jobs took {approxDuration(runtimes.p25)} to{' '}
        {approxDuration(runtimes.p75)} (typically {approxDuration(runtimes.p50)}); 9 in 10 finished within{' '}
        {approxDuration(runtimes.p90)}.
        {mark && (
          <>
            {' '}
            <span className="font-medium text-gray-900">
              {mark.label}: {approxDuration(mark.seconds)}.
            </span>
          </>
        )}
      </p>
    </div>
  );
}

function when(t: number): string {
  return new Date(t * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}

export function SimilarJobs({
  jobID,
  mark,
}: {
  jobID: string;
  // This job on the group's spread: how long it has run, its estimate, or
  // for a finished job how long it took.
  mark?: { seconds: number; label: string };
}) {
  // Undefined until the user picks: the server answers with the group
  // the estimate used.
  const [level, setLevel] = useState<EstimateLevel | undefined>(undefined);
  const q = useInfiniteQuery<SimilarJobsResponse, Error>({
    queryKey: ['similar-jobs', jobID, level ?? 'default'],
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      api.jobs.similar(jobID, { level, offset: pageParam as number, page_size: PAGE_SIZE }),
    getNextPageParam: (last) => last.next_offset ?? undefined,
    staleTime: 60_000,
    // Not retried: a 4xx will not change, and 501 means the feature is off.
    retry: (n, e) => !(e instanceof ApiError && (e.status < 500 || e.status === 501)) && n < 1,
  });

  if (q.error instanceof ApiError && q.error.status === 501) {
    return <p className="text-sm text-gray-500">Similar jobs are not available on this server.</p>;
  }
  if (q.error) return <p className="text-sm text-red-700">Could not load similar jobs: {q.error.message}</p>;
  const first = q.data?.pages[0];
  if (!first) return <p className="text-sm text-gray-400">Loading similar jobs…</p>;
  const jobs = q.data!.pages.flatMap((p) => p.jobs);
  const current = first.level;

  return (
    <div className="space-y-3" data-testid="similar-jobs">
      <div role="radiogroup" aria-label="Compare with" className="flex flex-wrap gap-1.5">
        {first.levels
          .filter((l) => l.applies)
          .map((l) => (
            <button
              key={l.level}
              type="button"
              role="radio"
              aria-checked={l.level === current}
              onClick={() => setLevel(l.level)}
              className={`rounded-full border px-2.5 py-1 text-xs ${
                l.level === current
                  ? 'border-brand-600 bg-brand-50 text-brand-800'
                  : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50'
              }`}
              data-level={l.level}
            >
              {l.description}
              {l.count !== undefined && l.count !== null && (
                <>
                  {' '}
                  <span className="tabular-nums text-gray-500">· {l.count.toLocaleString()}</span>
                </>
              )}
              {l.level === first.estimate_level && (
                <>
                  {' '}
                  <span className="text-gray-500">(used for the estimate)</span>
                </>
              )}
            </button>
          ))}
      </div>
      <div className={q.isFetching && !q.isFetchingNextPage ? 'opacity-60' : undefined}>
        <p className="text-sm text-gray-600">
          <span className="font-medium text-gray-900">{first.description.charAt(0).toUpperCase() + first.description.slice(1)}</span>
          {': '}finished in the last {Math.round(first.window.days)} days
          {first.total > 0 && !first.aggregate_only ? `, ${first.total.toLocaleString()} found` : ''}.
        </p>
        {first.runtimes ? (
          <div className="mt-2">
            <RuntimeSpread runtimes={first.runtimes} mark={mark} />
          </div>
        ) : (
          <p className="mt-2 text-sm text-gray-500">Run times for this group are not available yet.</p>
        )}
        {first.aggregate_only ? (
          <p className="mt-2 text-sm text-gray-600" data-testid="aggregate-only">
            This group includes other people&apos;s jobs, so only how long they took is shown, not the jobs.
          </p>
        ) : jobs.length === 0 ? (
          <p className="mt-2 text-sm text-gray-500">No finished jobs in this group.</p>
        ) : (
          <div className="mt-2 overflow-x-auto rounded-sm border border-gray-200">
            <table className="min-w-full text-sm">
              <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
                <tr>
                  <th className="px-3 py-1.5 font-medium">Job</th>
                  <th className="px-3 py-1.5 font-medium">Finished</th>
                  <th className="px-3 py-1.5 text-right font-medium">Run time</th>
                  <th className="px-3 py-1.5 font-medium">Outcome</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {jobs.map((j) => (
                  <tr key={j.id}>
                    <td className="px-3 py-1.5 font-mono text-xs">
                      <Link href={`/archive/${encodeURIComponent(j.id)}`} className="text-brand-700 hover:underline">
                        {j.id}
                      </Link>
                    </td>
                    <td className="whitespace-nowrap px-3 py-1.5 text-xs text-gray-600 tabular-nums">{when(j.completed)}</td>
                    <td className="whitespace-nowrap px-3 py-1.5 text-right text-xs tabular-nums">
                      {approxDuration(j.runtime)}
                    </td>
                    <td className="px-3 py-1.5">
                      <span className="inline-flex rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800">
                        {j.exit_code === 0 ? 'Completed' : `Exit ${j.exit_code}`}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {q.hasNextPage && (
          <button
            type="button"
            onClick={() => void q.fetchNextPage()}
            disabled={q.isFetchingNextPage}
            className="mt-2 text-sm text-brand-700 hover:underline disabled:opacity-50"
          >
            {q.isFetchingNextPage ? 'Loading…' : `Show more (${jobs.length.toLocaleString()} of ${first.total.toLocaleString()})`}
          </button>
        )}
      </div>
    </div>
  );
}

// SimilarJobsSection is the collapsible section the page's Related row
// and the run time card both open.
export function SimilarJobsSection({
  jobID,
  open,
  onToggle,
  mark,
}: {
  jobID: string;
  open: boolean;
  onToggle: () => void;
  mark?: { seconds: number; label: string };
}) {
  return (
    <section
      id="similar-jobs"
      aria-labelledby="similar-jobs-title"
      className="scroll-mt-4 rounded-sm border border-gray-200 bg-white p-4"
    >
      <div className="flex items-center justify-between gap-2">
        <h2 id="similar-jobs-title" className="text-xs font-semibold uppercase tracking-wide text-gray-500">
          Similar jobs
        </h2>
        <button type="button" onClick={onToggle} aria-expanded={open} className="text-sm text-brand-700 hover:underline">
          {open ? 'Hide' : 'Show'}
        </button>
      </div>
      {open && (
        <div className="mt-3">
          <SimilarJobs jobID={jobID} mark={mark} />
        </div>
      )}
    </section>
  );
}
