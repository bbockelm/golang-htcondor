import { describe, expect, it, vi } from 'vitest';
import type { ClassAd, JobListResponse } from '@/lib/api';
import { PROGRESS_WHY, type BatchProgress } from './batchProgress';
import { batchView } from './batchView';
import {
  clusterConstraints,
  clustersNeedingCounts,
  EXACT_COUNTS_PROJECTION,
  fetchExactCounts,
  withExactCounts,
} from './exactCounts';

// The whole queue for cluster 7: 100 submitted, 12 still queued.
const queued7: ClassAd[] = [2, 2, 2, 2, 2, 1, 1, 1, 1, 5, 5, 5].map((s, i) => ({
  ClusterId: 7, ProcId: i, JobStatus: s, Owner: 'alice', TotalSubmitProcs: 100,
}));

// What a cut-off listing holds of it: two of the twelve.
const listed7 = queued7.slice(0, 2);

// A DAG whose count the listing already settles.
const dag: ClassAd[] = [
  {
    ClusterId: 50, ProcId: 0, JobStatus: 2, Owner: 'alice', Cmd: 'condor_dagman',
    JobBatchName: 'w.dag+50', DAG_NodesTotal: 4, DAG_NodesDone: 1,
  },
];

function partialView() {
  return batchView([...listed7, ...dag], new Set(), '', false);
}

describe('clustersNeedingCounts', () => {
  it('asks for the plain batches the listing could not settle, not the DAGs', () => {
    const v = partialView();
    expect(clustersNeedingCounts(v.batches, v.progress)).toEqual([7]);
  });

  it('asks for nothing when the listing is whole', () => {
    const v = batchView(queued7, new Set(), '', true);
    expect(clustersNeedingCounts(v.batches, v.progress)).toEqual([]);
  });
});

describe('clusterConstraints', () => {
  it('chunks the ids into member() lists', () => {
    const ids = Array.from({ length: 1201 }, (_, i) => i + 1);
    const cs = clusterConstraints(ids);
    expect(cs).toHaveLength(3);
    expect(cs[0].startsWith('member(ClusterId, {1, 2, ')).toBe(true);
    expect(cs[2]).toBe(`member(ClusterId, {${ids.slice(1000).join(', ')}})`);
  });
});

describe('fetchExactCounts', () => {
  it('walks every page of every chunk, without the user\'s expression', async () => {
    const pages: Record<string, JobListResponse> = {
      first: { jobs: queued7.slice(0, 6), next_page_token: 't2' },
      t2: { jobs: queued7.slice(6), has_more: false },
    };
    const list = vi.fn(async (p: { page_token?: string; constraint: string }) =>
      /\{7[,}]/.test(p.constraint) ? pages[p.page_token ?? 'first'] : { jobs: [] },
    );
    const ids = [7, ...Array.from({ length: 500 }, (_, i) => 1000 + i)];
    const ads = await fetchExactCounts(ids, list, { ownedByMe: true, schedd: 'ap1' });
    expect(ads).toHaveLength(12);
    // Two chunks of at most 500, the first one walked over two pages.
    expect(list).toHaveBeenCalledTimes(3);
    for (const [p] of list.mock.calls) {
      expect(p.constraint).toMatch(/^member\(ClusterId, \{[\d, ]+\}\)$/);
      expect(p).toMatchObject({ projection: EXACT_COUNTS_PROJECTION, limit: '*', owned_by_me: true, schedd: 'ap1' });
    }
  });

  it('fails rather than return a short answer', async () => {
    const truncated = async () => ({ jobs: queued7.slice(0, 2), has_more: true });
    await expect(fetchExactCounts([7], truncated, { ownedByMe: true })).rejects.toThrow();
    const errored = async () => ({ jobs: queued7.slice(0, 2), error: 'schedd went away' });
    await expect(fetchExactCounts([7], errored, { ownedByMe: true })).rejects.toThrow();
  });
});

describe('withExactCounts', () => {
  it('counts the batch from the exact answer, never the partial listing', () => {
    const v = partialView();
    const key = v.batches.find((b) => b.batchID === 7)!.groupKey;
    const p = withExactCounts(v.progress, v.batches, {
      status: 'ready', clusters: new Set([7]), ads: queued7,
    }).get(key) as BatchProgress;
    // 88, from all twelve queued jobs -- not 98 from the two listed.
    expect(p.known).toBe(true);
    expect(p.done).toBe(88);
  });

  it('shows "counting" while the answer is on its way', () => {
    const v = partialView();
    const key = v.batches.find((b) => b.batchID === 7)!.groupKey;
    const m = withExactCounts(v.progress, v.batches, { status: 'loading' });
    expect(m.get(key)).toEqual({ known: false, why: PROGRESS_WHY.counting });
  });

  it('says so when the count failed', () => {
    const v = partialView();
    const key = v.batches.find((b) => b.batchID === 7)!.groupKey;
    const m = withExactCounts(v.progress, v.batches, { status: 'failed' });
    expect(m.get(key)).toEqual({ known: false, why: PROGRESS_WHY.countFailed });
  });

  it('does not use an answer that did not ask for all of the batch\'s clusters', () => {
    // A named batch over clusters 7 and 8; the answer on hand is from
    // before cluster 8 was on screen.
    const named = [
      ...listed7.map((a) => ({ ...a, JobBatchName: 'sweep' })),
      { ClusterId: 8, ProcId: 0, JobStatus: 1, Owner: 'alice', JobBatchName: 'sweep', TotalSubmitProcs: 5 },
    ];
    const v = batchView(named, new Set(), '', false);
    const m = withExactCounts(v.progress, v.batches, {
      status: 'ready', clusters: new Set([7]), ads: queued7.map((a) => ({ ...a, JobBatchName: 'sweep' })),
    });
    expect(m.get(v.batches[0].groupKey)).toEqual({ known: false, why: PROGRESS_WHY.counting });
  });

  it('leaves the DAG\'s own count alone', () => {
    const v = partialView();
    const dagKey = v.batches.find((b) => b.isDag)!.groupKey;
    const m = withExactCounts(v.progress, v.batches, { status: 'failed' });
    expect((m.get(dagKey) as BatchProgress).done).toBe(1);
  });
});
