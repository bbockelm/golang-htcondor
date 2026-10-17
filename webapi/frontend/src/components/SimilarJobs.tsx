'use client';

// The finished jobs a job's runtime estimate draws on, and the other
// groups it could be compared with. A job's page shows how long it will
// probably take; this shows what that is based on, so the user can judge
// it -- and go from one job back to the group it belongs to.
//
// One group at a time, from the most specific (same command) to the
// broadest (all the owner's jobs of the kind). Every group is the
// owner's own jobs.

import { useState } from 'react';
import Link from 'next/link';
import { useInfiniteQuery } from '@tanstack/react-query';
import { api, ApiError } from '@/lib/api';
import { approxDuration } from '@/lib/duration';
import type { EstimateLevel, Quantiles, SimilarJobsResponse } from '@/lib/similar';
import { formatMiB } from '@/lib/utilization';

const PAGE_SIZE = 50;

// Spread draws a group's values on an axis from zero: whiskers from the
// 10th to 90th percentile, a box over the middle half, a tick at the
// median, a mark for this job, and any labelled reference lines (a
// request, say). The sentence under it says the same in words; words
// supplies its verbs ("took" ... "finished within") and format its
// figures.
export function Spread({
  q,
  format,
  words,
  mark,
  refs = [],
  testID,
  markTestID,
}: {
  q: Quantiles;
  format: (v: number) => string;
  words: { range: string; under: string };
  mark?: { value: number; label: string };
  refs?: { value: number; label: string }[];
  testID: string;
  markTestID: string;
}) {
  const max = Math.max(q.p90, mark?.value ?? 0, ...refs.map((r) => r.value)) * 1.15 || 1;
  const at = (v: number) => `${Math.min(100, (v / max) * 100).toFixed(2)}%`;
  return (
    <div data-testid={testID}>
      <div className="relative h-8" aria-hidden="true">
        <div className="absolute inset-x-0 top-4 h-px bg-gray-300" />
        <div
          className="absolute top-[15px] h-0.5 bg-[#2a78d6]"
          style={{ left: at(q.p10), width: `calc(${at(q.p90)} - ${at(q.p10)})` }}
        />
        <div
          className="absolute top-2.5 h-3 rounded-sm bg-[#86b6ef]"
          style={{ left: at(q.p25), width: `max(3px, calc(${at(q.p75)} - ${at(q.p25)}))` }}
        />
        <div className="absolute top-1.5 h-5 w-0.5 bg-[#184f95]" style={{ left: at(q.p50) }} />
        {refs.map((r) => (
          <div
            key={r.label}
            className="absolute top-0 h-8 border-l border-dashed border-gray-500"
            style={{ left: at(r.value) }}
            data-testid={`${testID}-ref`}
          />
        ))}
        {mark && (
          <div
            className="absolute top-0 h-8 w-[3px] -translate-x-1/2 rounded-sm bg-gray-900"
            style={{ left: at(mark.value) }}
            data-testid={markTestID}
          />
        )}
      </div>
      <div className="relative flex justify-between text-xs text-gray-500 tabular-nums">
        <span>0</span>
        {refs.map((r) => (
          <span
            key={r.label}
            className="absolute -translate-x-1/2 whitespace-nowrap bg-white px-0.5"
            style={{ left: at(r.value) }}
          >
            {r.label}
          </span>
        ))}
        <span>{format(max)}</span>
      </div>
      <p className="mt-1 text-sm text-gray-700">
        Half of these {q.count.toLocaleString()} jobs {words.range} {format(q.p25)} to {format(q.p75)} (typically{' '}
        {format(q.p50)}); 9 in 10 {words.under} {format(q.p90)}.
        {mark && (
          <>
            {' '}
            <span className="font-medium text-gray-900">
              {mark.label}: {format(mark.value)}.
            </span>
          </>
        )}
        {refs.map((r) => (
          <span key={r.label}>
            {' '}
            {r.label}: {format(r.value)}.
          </span>
        ))}
      </p>
    </div>
  );
}

// RuntimeSpread is a group's runtimes, and this job's, as a Spread.
export function RuntimeSpread({
  runtimes,
  mark,
}: {
  runtimes: Quantiles;
  mark?: { seconds: number; label: string };
}) {
  return (
    <Spread
      q={runtimes}
      format={approxDuration}
      words={{ range: 'took', under: 'finished within' }}
      mark={mark && { value: mark.seconds, label: mark.label }}
      testID="runtime-spread"
      markTestID="spread-mark"
    />
  );
}

// MemorySpread is the same group's peak memory, with this job's peak and
// its request.
export function MemorySpread({
  memory,
  mark,
  requestedMiB,
}: {
  memory: Quantiles;
  mark?: { mib: number; label: string };
  requestedMiB?: number;
}) {
  return (
    <Spread
      q={memory}
      format={formatMiB}
      words={{ range: 'peaked at', under: 'stayed under' }}
      mark={mark && { value: mark.mib, label: mark.label }}
      refs={requestedMiB ? [{ value: requestedMiB, label: 'Requested' }] : []}
      testID="memory-spread"
      markTestID="memory-spread-mark"
    />
  );
}

function when(t: number): string {
  return new Date(t * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}

// This job's memory on the group's memory spread: its peak (so far), and
// what it requested.
export interface MemoryMarks {
  mark?: { mib: number; label: string };
  requestedMiB?: number;
}

export function SimilarJobs({
  jobID,
  mark,
  memory,
}: {
  jobID: string;
  // This job on the group's spread: how long it has run, its estimate, or
  // for a finished job how long it took.
  mark?: { seconds: number; label: string };
  memory?: MemoryMarks;
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
          {first.total > 0 ? `, ${first.total.toLocaleString()} found` : ''}.
        </p>
        {first.runtimes ? (
          <div className="mt-2">
            {first.memory && <h3 className="text-xs font-medium text-gray-500">Run time</h3>}
            <RuntimeSpread runtimes={first.runtimes} mark={mark} />
          </div>
        ) : (
          <p className="mt-2 text-sm text-gray-500">Run times for this group are not available yet.</p>
        )}
        {first.memory && (
          <div className="mt-3">
            <h3 className="text-xs font-medium text-gray-500">Peak memory</h3>
            <MemorySpread memory={first.memory} mark={memory?.mark} requestedMiB={memory?.requestedMiB} />
          </div>
        )}
        {jobs.length === 0 ? (
          <p className="mt-2 text-sm text-gray-500">No finished jobs in this group.</p>
        ) : (
          <div className="mt-2 overflow-x-auto rounded-sm border border-gray-200">
            <table className="min-w-full text-sm">
              <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
                <tr>
                  <th className="px-3 py-1.5 font-medium">Job</th>
                  <th className="px-3 py-1.5 font-medium">Finished</th>
                  <th className="px-3 py-1.5 text-right font-medium">Run time</th>
                  <th className="px-3 py-1.5 text-right font-medium">Peak memory</th>
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
                    <td className="whitespace-nowrap px-3 py-1.5 text-right text-xs tabular-nums">
                      {j.peak_memory_mib == null ? <span className="text-gray-400">—</span> : formatMiB(j.peak_memory_mib)}
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
  memory,
}: {
  jobID: string;
  open: boolean;
  onToggle: () => void;
  mark?: { seconds: number; label: string };
  memory?: MemoryMarks;
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
          <SimilarJobs jobID={jobID} mark={mark} memory={memory} />
        </div>
      )}
    </section>
  );
}
