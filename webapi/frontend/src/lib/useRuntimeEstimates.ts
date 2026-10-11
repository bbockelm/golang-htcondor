'use client';

// useRuntimeEstimates fetches the runtime estimates for a listing's
// waiting and running jobs in one request (POST
// /api/v1/jobs/runtime-estimates), and answers again only when the set
// of jobs or their states change -- which happens when the listing
// refreshes -- or after a minute. So it never asks more often than the
// listing does, and a quiet queue is asked once a minute.

import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';

import { api, MAX_RUNTIME_ESTIMATE_IDS, type JobRuntimeEstimate } from '@/lib/api';

// A job to ask about.
export interface EstimateRequestJob {
  id: string;
  status: 'idle' | 'running' | 'other';
}

export interface RuntimeEstimatesState {
  // Undefined until the server has answered; false when it does not run
  // estimates (or cannot yet).
  available: boolean | undefined;
  byId: ReadonlyMap<string, JobRuntimeEstimate>;
  // The ids that were asked about: a job outside it has no answer
  // because nobody asked, not because there is no history.
  requested: ReadonlySet<string>;
  // When the answer was fetched, unix seconds: a running job's remaining
  // time was measured then.
  fetchedAt: number;
}

// requestIds picks the ids to ask about, at most limit: every running
// job first, since a batch's finish time needs all of them, then the
// waiting ones in order. A waiting job's figure is the same for its
// cluster's siblings, so a batch past the limit still gets its typical
// run from the ones asked about.
export function requestIds(jobs: readonly EstimateRequestJob[], limit = MAX_RUNTIME_ESTIMATE_IDS): string[] {
  const running = jobs.filter((j) => j.status === 'running').map((j) => j.id);
  const idle = jobs.filter((j) => j.status === 'idle').map((j) => j.id);
  return [...running, ...idle].slice(0, limit);
}

// fnv1a is a short, stable digest of the request, for the query key: the
// ids and states of a few thousand jobs are too long to key a cache by.
function fnv1a(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(36);
}

const EMPTY_MAP: ReadonlyMap<string, JobRuntimeEstimate> = new Map();

export function useRuntimeEstimates(
  jobs: readonly EstimateRequestJob[],
  enabled: boolean,
): RuntimeEstimatesState {
  const { ids, key, statusOf } = useMemo(() => {
    const ids = requestIds(jobs);
    const statusOf = new Map(jobs.map((j) => [j.id, j.status]));
    const sig = ids.map((id) => `${id}:${statusOf.get(id)}`).join(',');
    return { ids, key: `${ids.length}-${fnv1a(sig)}`, statusOf };
  }, [jobs]);

  const { data } = useQuery({
    queryKey: ['runtime-estimates', key],
    enabled: enabled && ids.length > 0,
    queryFn: async () => ({
      resp: await api.jobs.runtimeEstimates(ids),
      fetchedAt: Math.floor(Date.now() / 1000),
      ids,
    }),
    // Keep showing the last answer while the next set's is on its way,
    // so the column does not blank on every refresh.
    placeholderData: keepPreviousData,
    staleTime: 30_000,
    refetchInterval: 60_000,
    // No estimates is a fine answer; a failed request is not worth
    // retrying before the next refresh.
    retry: false,
  });

  return useMemo(() => {
    if (!data) {
      return { available: undefined, byId: EMPTY_MAP, requested: new Set<string>(), fetchedAt: 0 };
    }
    // An answer for a job whose state has changed since is stale -- a
    // waiting job's figure says nothing about the run it has started --
    // so it is dropped until the next answer.
    const byId = new Map<string, JobRuntimeEstimate>();
    for (const [id, e] of Object.entries(data.resp.estimates ?? {})) {
      const st = statusOf.get(id);
      const wasRunning = e.elapsed_seconds !== undefined;
      if (st === 'running' ? wasRunning : st === 'idle' && !wasRunning) byId.set(id, e);
    }
    return {
      available: data.resp.available,
      byId,
      requested: new Set(data.ids),
      fetchedAt: data.fetchedAt,
    };
  }, [data, statusOf]);
}
