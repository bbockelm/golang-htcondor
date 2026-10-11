// Exact progress for batches the listing only shows part of.
//
// A listing cut off at its first page, or narrowed by a ClassAd
// expression, holds some of a batch's queued jobs and not others, and a
// job missing from it is indistinguishable from one that finished. Rather
// than show no progress for exactly the big queues where it matters most,
// the page asks again for just those batches' clusters: every queued job
// of each, without the user's expression, and only the handful of
// attributes the count needs. That answer is complete for the clusters it
// names, so progress computed from it is exact.

import type { ClassAd, JobListResponse } from '@/lib/api';
import {
  PROGRESS_WHY,
  progressByBatch,
  type BatchProgressResult,
} from '@/lib/batchProgress';
import type { Batch } from '@/lib/batches';

// What progressByBatch reads for a plain batch: the group key (Owner,
// JobBatchName), the status (HoldReasonCode separates a spooling hold),
// and the two cluster attributes the arithmetic is built on.
export const EXACT_COUNTS_PROJECTION =
  'ClusterId,ProcId,JobStatus,HoldReasonCode,Owner,JobBatchName,TotalSubmitProcs,JobMaterializeNextProcId';

// Cluster ids per request. member() over a list is evaluated against
// every job ad, so the list is kept short enough that one request stays
// cheap however many clusters are on screen.
export const EXACT_COUNTS_CHUNK = 500;

// A bound on the page walk per chunk, like the listing's own.
const MAX_PAGES_PER_CHUNK = 100;

export type ExactCounts =
  | { status: 'loading' }
  | { status: 'failed' }
  // `clusters` is what was asked for: a batch is only counted from this
  // answer if every one of its clusters is in it.
  | { status: 'ready'; clusters: ReadonlySet<number>; ads: ClassAd[] };

// clustersNeedingCounts lists the clusters of the shown batches whose
// progress the listing could not settle. DAG batches are not among them:
// their count comes from the root job's own ad.
export function clustersNeedingCounts(
  batches: Batch[],
  progress: ReadonlyMap<string, BatchProgressResult>,
): number[] {
  const ids = new Set<number>();
  for (const b of batches) {
    const p = progress.get(b.groupKey);
    if (p && !p.known && p.why === PROGRESS_WHY.partial) {
      for (const c of b.clusterIds) ids.add(c);
    }
  }
  return [...ids].sort((a, b) => a - b);
}

// clusterConstraints splits the ids into member() constraints of at most
// `chunk` ids each.
export function clusterConstraints(ids: number[], chunk = EXACT_COUNTS_CHUNK): string[] {
  const out: string[] = [];
  for (let i = 0; i < ids.length; i += chunk) {
    out.push(`member(ClusterId, {${ids.slice(i, i + chunk).join(', ')}})`);
  }
  return out;
}

type ListFn = (params: {
  constraint: string;
  projection: string;
  limit: '*';
  page_token?: string;
  owned_by_me: boolean;
  schedd?: string;
}) => Promise<JobListResponse>;

// fetchExactCounts fetches every queued job of the given clusters. Each
// chunk follows its page tokens to the end: a paginated answer is clamped
// per request even when asked for everything. An answer that ends early
// -- an error in the response, or a walk that hit its bound -- is a
// failure, never a smaller count.
export async function fetchExactCounts(
  ids: number[],
  list: ListFn,
  opts: { ownedByMe: boolean; schedd?: string },
): Promise<ClassAd[]> {
  const ads: ClassAd[] = [];
  for (const constraint of clusterConstraints(ids)) {
    let token: string | undefined;
    let pages = 0;
    for (;;) {
      const page = await list({
        constraint,
        projection: EXACT_COUNTS_PROJECTION,
        limit: '*',
        page_token: token,
        owned_by_me: opts.ownedByMe,
        schedd: opts.schedd,
      });
      if (page.error) throw new Error(page.error);
      ads.push(...(page.jobs ?? []));
      token = page.next_page_token ?? undefined;
      if (!token) {
        // More matched, and there is no way to ask for the rest.
        if (page.has_more) throw new Error('incomplete answer');
        break;
      }
      if (++pages >= MAX_PAGES_PER_CHUNK) throw new Error('too many pages');
    }
  }
  return ads;
}

// withExactCounts replaces the listing's "only some of this batch is
// listed" with the exact count where the second answer covers the batch,
// and with "counting" or "could not be counted" where it does not yet.
// Every other batch keeps what the listing said.
export function withExactCounts(
  progress: ReadonlyMap<string, BatchProgressResult>,
  batches: Batch[],
  exact: ExactCounts,
): Map<string, BatchProgressResult> {
  const out = new Map(progress);
  const exactProgress = exact.status === 'ready' ? progressByBatch(exact.ads, true) : undefined;
  for (const b of batches) {
    const p = progress.get(b.groupKey);
    if (!p || p.known || p.why !== PROGRESS_WHY.partial) continue;
    if (exact.status === 'failed') {
      out.set(b.groupKey, { known: false, why: PROGRESS_WHY.countFailed });
      continue;
    }
    // An answer for a different set of clusters -- the one before the
    // listing changed -- says nothing about a cluster it did not ask for.
    const covered =
      exact.status === 'ready' && b.clusterIds.every((c) => exact.clusters.has(c));
    const e = covered ? exactProgress?.get(b.groupKey) : undefined;
    out.set(b.groupKey, e ?? { known: false, why: PROGRESS_WHY.counting });
  }
  return out;
}
