import { describe, expect, it } from 'vitest';
import type { ClassAd, DisplayStatus } from '@/lib/api';
import {
  PROGRESS_WHY,
  progressByBatch,
  progressFraction,
  progressSentence,
  type BatchProgress,
  type BatchProgressResult,
} from './batchProgress';
import { batchView } from './batchView';
import { groupIntoBatches } from './batches';

// n jobs of one cluster with the given statuses, all carrying the
// cluster's TotalSubmitProcs the way the schedd hands them back.
function cluster(
  id: number,
  total: number | undefined,
  statuses: number[],
  extra: ClassAd = {},
): ClassAd[] {
  return statuses.map((s, i) => ({
    ClusterId: id,
    ProcId: i,
    JobStatus: s,
    Owner: 'alice',
    ...(total !== undefined ? { TotalSubmitProcs: total } : {}),
    ...extra,
  }));
}

function known(p: BatchProgressResult | undefined): BatchProgress {
  expect(p?.known).toBe(true);
  return p as BatchProgress;
}

function only(m: Map<string, BatchProgressResult>): BatchProgressResult {
  expect(m.size).toBe(1);
  return [...m.values()][0];
}

function part(p: BatchProgress, name: string): number {
  return p.parts.find((x) => x.part === name)?.count ?? 0;
}

describe('progressByBatch for plain clusters', () => {
  it('counts the jobs that have left the queue as done', () => {
    // 100 submitted; 12 still here: 5 running, 4 idle, 3 held.
    const ads = cluster(7, 100, [2, 2, 2, 2, 2, 1, 1, 1, 1, 5, 5, 5]);
    const p = known(only(progressByBatch(ads, true)));
    expect(p.unit).toBe('jobs');
    expect(p.total).toBe(100);
    expect(p.done).toBe(88);
    expect(part(p, 'running')).toBe(5);
    expect(part(p, 'idle')).toBe(4);
    expect(part(p, 'held')).toBe(3);
    expect(progressSentence(p).split('\n')[0]).toBe('88 of 100 jobs done');
  });

  it('counts completed and removed jobs still in the queue as done', () => {
    const ads = cluster(7, 4, [4, 3, 2, 1]);
    expect(known(only(progressByBatch(ads, true))).done).toBe(2);
  });

  it('sums the clusters of a named batch', () => {
    const ads = [
      ...cluster(7, 10, [2], { JobBatchName: 'sweep' }),
      ...cluster(8, 20, [1, 1], { JobBatchName: 'sweep' }),
    ];
    const p = known(only(progressByBatch(ads, true)));
    expect(p.total).toBe(30);
    expect(p.done).toBe(27);
  });

  it('has no number when any cluster of the batch lacks a total', () => {
    const ads = [
      ...cluster(7, 10, [2], { JobBatchName: 'sweep' }),
      ...cluster(8, undefined, [1], { JobBatchName: 'sweep' }),
    ];
    // Summing the one cluster that has a total would claim 9 of 10 done
    // for a batch that is at least eleven jobs.
    expect(only(progressByBatch(ads, true))).toEqual({
      known: false,
      why: PROGRESS_WHY.noTotal,
    });
  });

  it('has no number when the listing does not hold every queued job', () => {
    // A cut-off listing: the missing jobs would be counted as finished.
    const ads = cluster(7, 100, [2]);
    expect(only(progressByBatch(ads, false))).toEqual({
      known: false,
      why: PROGRESS_WHY.partial,
    });
  });

  it('does not count jobs a factory has not queued yet as done', () => {
    // max_materialize: 1000 jobs, the factory has queued procs 0..9, and
    // those ten are all still here. None is done.
    const ads = cluster(7, 1000, [2, 2, 2, 2, 2, 1, 1, 1, 1, 1], {
      JobMaterializeNextProcId: 10,
    });
    const p = known(only(progressByBatch(ads, true)));
    expect(p.done).toBe(0);
    expect(p.total).toBe(1000);
    expect(p.notQueued).toBe(990);
    // Not yet queued is waiting to run.
    expect(part(p, 'idle')).toBe(995);
    expect(progressSentence(p)).toContain('990 not yet in the queue');
  });

  it('counts a factory\'s queued-then-finished jobs as done', () => {
    // 40 queued so far, 10 still here: 30 finished.
    const ads = cluster(7, 1000, Array(10).fill(2), { JobMaterializeNextProcId: 40 });
    expect(known(only(progressByBatch(ads, true))).done).toBe(30);
  });

  it('reads the attributes whatever their capitalization', () => {
    const ads: ClassAd[] = [{ ClusterId: 7, ProcId: 0, JobStatus: 2, totalsubmitprocs: 3 }];
    expect(known(only(progressByBatch(ads, true))).done).toBe(2);
  });

  it('keeps the spooling hold out of "held"', () => {
    const ads = cluster(7, 2, [5], { HoldReasonCode: 16 });
    const p = known(only(progressByBatch(ads, true)));
    expect(part(p, 'held')).toBe(0);
    expect(part(p, 'other')).toBe(1);
  });
});

describe('progressByBatch for DAGs', () => {
  // The root DAGMan job, a nested sub-DAG's DAGMan job (itself one node
  // of the root, publishing its own counts), and two node jobs.
  function dag(root: ClassAd = {}): ClassAd[] {
    return [
      {
        ClusterId: 100, ProcId: 0, JobStatus: 2, Owner: 'carol', Cmd: '/usr/bin/condor_dagman',
        JobBatchName: 'foo.dag+100',
        DAG_NodesTotal: 40, DAG_NodesDone: 17, DAG_NodesFailed: 3, DAG_NodesQueued: 5,
        // Two thousand finished node jobs would make a job count
        // meaningless; the node count is the one to trust.
        TotalSubmitProcs: 1,
        ...root,
      },
      {
        ClusterId: 250, ProcId: 0, JobStatus: 2, Owner: 'carol', Cmd: '/usr/bin/condor_dagman',
        JobBatchName: 'foo.dag+100', DAGManJobId: 100,
        // Already counted as one node of the root: adding these would
        // count the sub-DAG's nodes twice.
        DAG_NodesTotal: 8, DAG_NodesDone: 2, DAG_NodesFailed: 0, DAG_NodesQueued: 1,
      },
      { ClusterId: 201, ProcId: 0, JobStatus: 2, Owner: 'carol', JobBatchName: 'foo.dag+100', DAGManJobId: 100, TotalSubmitProcs: 1 },
      { ClusterId: 202, ProcId: 0, JobStatus: 1, Owner: 'carol', JobBatchName: 'foo.dag+100', DAGManJobId: 250, TotalSubmitProcs: 1 },
    ];
  }

  it('reads nodes from the root DAGMan job', () => {
    const p = known(only(progressByBatch(dag(), true)));
    expect(p.unit).toBe('nodes');
    expect(p.total).toBe(40);
    expect(p.done).toBe(17);
    expect(p.failed).toBe(3);
    expect(part(p, 'queued')).toBe(5);
    expect(part(p, 'other')).toBe(15);
    expect(progressSentence(p).split('\n')[0]).toBe('17 of 40 nodes done, 3 failed');
  });

  it('lands the root job in the same batch as its nodes', () => {
    const ads = dag();
    const [batch] = groupIntoBatches(ads);
    expect(batch.isDag).toBe(true);
    expect(progressByBatch(ads, true).get(batch.groupKey)?.known).toBe(true);
  });

  it('still counts a DAG when the listing is partial', () => {
    // The count lives in the root's own ad, not in how many node jobs
    // were loaded.
    expect(known(only(progressByBatch(dag(), false))).done).toBe(17);
  });

  it('says so when DAGMan has not published yet', () => {
    const ads = dag({ DAG_NodesTotal: undefined, DAG_NodesDone: undefined });
    for (const a of ads) for (const k of Object.keys(a)) if (a[k] === undefined) delete a[k];
    expect(only(progressByBatch(ads, true))).toEqual({
      known: false,
      why: PROGRESS_WHY.dagNotReporting,
    });
  });

  it('has no number when the root job is not loaded', () => {
    const ads = dag().slice(1);
    // The sub-DAG's counts are not the workflow's.
    expect(only(progressByBatch(ads, true))).toEqual({
      known: false,
      why: PROGRESS_WHY.dagMissing,
    });
  });

  it('works for a DAG submitted under its own batch name', () => {
    // -batch-name drops the +N suffix; the root is still the DAGMan job
    // that is not itself a node.
    const ads = dag().map((a) => ({ ...a, JobBatchName: 'nightly' }));
    expect(groupIntoBatches(ads)[0].isDag).toBe(false);
    expect(known(only(progressByBatch(ads, true))).unit).toBe('nodes');
  });
});

describe('progress under a status filter', () => {
  // 10 submitted: 3 finished and gone, 5 running, 2 held.
  const ads = cluster(7, 10, [2, 2, 2, 2, 2, 5, 5]);

  it('is computed from every loaded job, not the filtered ones', () => {
    const view = batchView(ads, new Set<DisplayStatus>(['held']), '', true);
    expect(view.batches).toHaveLength(1);
    // The row shows the two held jobs...
    expect(view.batches[0].jobCount).toBe(2);
    // ...but the batch is 3 of 10 done, not the 8 of 10 that counting the
    // two survivors would give.
    const p = known(view.progress.get(view.batches[0].groupKey));
    expect(p.done).toBe(3);
    expect(part(p, 'running')).toBe(5);
  });

  it('joins a multi-cluster batch by its group, not its id', () => {
    // Under the Held chip only cluster 8 survives, so the row's id is 8
    // where the whole batch's is 7.
    const named = [
      ...cluster(7, 5, [2, 2], { JobBatchName: 'sweep' }),
      ...cluster(8, 5, [5], { JobBatchName: 'sweep' }),
    ];
    const view = batchView(named, new Set<DisplayStatus>(['held']), '', true);
    expect(view.batches[0].batchID).toBe(8);
    expect(known(view.progress.get(view.batches[0].groupKey)).done).toBe(7);
  });

  it('keeps access points apart', () => {
    const multi = [
      ...cluster(7, 4, [2], { schedd: 'ap1' }),
      ...cluster(7, 9, [2], { schedd: 'ap2' }),
    ];
    const view = batchView(multi, new Set(), '', true);
    const done = view.batches
      .map((b) => [b.schedd, known(view.progress.get(b.groupKey)).done])
      .sort();
    expect(done).toEqual([['ap1', 3], ['ap2', 8]]);
  });
});

describe('progressFraction', () => {
  it('sorts unknown batches as missing', () => {
    expect(progressFraction({ known: false, why: 'x' })).toBeUndefined();
    expect(progressFraction(undefined)).toBeUndefined();
  });
});
