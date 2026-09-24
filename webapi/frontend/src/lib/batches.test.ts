import { describe, expect, it } from 'vitest';
import type { ClassAd } from '@/lib/api';
import {
  applyBatchFilter,
  filterAdsByStatus,
  groupIntoBatches,
  statusRank,
  summarizeBatchUsage,
  summarizeJobs,
} from './batches';

// A queue with two users: one running a two-job batch, one with an idle
// job and a held one. Enough shape that the aggregations have something
// to get wrong.
function queue(): ClassAd[] {
  return [
    {
      ClusterId: 10,
      ProcId: 0,
      JobStatus: 2,
      Owner: 'alice',
      Cmd: '/bin/train',
      QDate: 1000,
      JobBatchName: 'training',
      RequestCpus: 4,
      RequestMemory: 2048,
      RequestGpus: 1,
    },
    {
      ClusterId: 10,
      ProcId: 1,
      JobStatus: 2,
      Owner: 'alice',
      Cmd: '/bin/train',
      QDate: 900,
      JobBatchName: 'training',
      RequestCpus: 4,
      RequestMemory: 2048,
      RequestGpus: 1,
    },
    {
      ClusterId: 11,
      ProcId: 0,
      JobStatus: 1,
      Owner: 'bob',
      Cmd: '/bin/sim',
      QDate: 2000,
      RequestCpus: 2,
      RequestMemory: 1024,
    },
    {
      ClusterId: 12,
      ProcId: 0,
      JobStatus: 5,
      HoldReason: 'nope',
      Owner: 'bob',
      Cmd: '/bin/sim',
      QDate: 3000,
      RequestCpus: 8,
      RequestMemory: 4096,
    },
  ];
}

// A whole DAG workflow as it appears in the queue: the root DAGMan job
// (ClusterId 100, Cmd condor_dagman) plus three node jobs spread across
// three clusters. Two of the nodes sit under nested sub-DAGs, so their
// DAGManJobId differs (250, 251) from the root's cluster — but every job
// shares ONE JobBatchName, "foo.dag+100", whose trailing +100 is the root
// DAGMan cluster.
function nestedDag(): ClassAd[] {
  return [
    {
      ClusterId: 100, ProcId: 0, JobStatus: 2, Owner: 'carol',
      Cmd: 'condor_dagman', QDate: 500, JobBatchName: 'foo.dag+100',
    },
    {
      ClusterId: 201, ProcId: 0, JobStatus: 2, Owner: 'carol',
      Cmd: '/bin/node', QDate: 600, JobBatchName: 'foo.dag+100',
      DAGManJobId: 100, DAGNodeName: 'A',
    },
    {
      ClusterId: 305, ProcId: 0, JobStatus: 1, Owner: 'carol',
      Cmd: '/bin/node', QDate: 700, JobBatchName: 'foo.dag+100',
      DAGManJobId: 250, DAGNodeName: 'B',
    },
    {
      ClusterId: 402, ProcId: 0, JobStatus: 1, Owner: 'carol',
      Cmd: '/bin/node', QDate: 800, JobBatchName: 'foo.dag+100',
      DAGManJobId: 251, DAGNodeName: 'C',
    },
  ];
}

describe('groupIntoBatches', () => {
  it('carries the submitting user onto the batch', () => {
    const [newest] = groupIntoBatches(queue());
    // Sorted newest-cluster-first, so batch 12 leads.
    expect(newest.batchID).toBe(12);
    expect(newest.owner).toBe('bob');
  });

  it('dates a batch by its OLDEST job, not the first one seen', () => {
    const training = groupIntoBatches(queue()).find((b) => b.batchID === 10)!;
    // Proc 0 (QDate 1000) is seen first but proc 1 (QDate 900) is older.
    // Reporting 1000 would say the batch was submitted after part of it.
    expect(training.submittedUnix).toBe(900);
    expect(training.jobCount).toBe(2);
    expect(training.statusCounts.running).toBe(2);
  });

  it('folds an entire DAG tree (nodes + nested sub-DAGs) into one batch', () => {
    const batches = groupIntoBatches(nestedDag());
    // All four jobs, despite three different clusters and differing
    // DAGManJobId, collapse to a single row.
    expect(batches).toHaveLength(1);
    const [dag] = batches;
    // Representative id is the root DAGMan cluster from the +N suffix.
    expect(dag.batchID).toBe(100);
    // Display name has the +<root> stripped.
    expect(dag.name).toBe('foo.dag');
    expect(dag.isDag).toBe(true);
    expect(dag.jobCount).toBe(4);
    expect(dag.statusCounts.running).toBe(2);
    expect(dag.statusCounts.idle).toBe(2);
    // Every member cluster is tracked so the summary panel can total the
    // batch's jobs even when a text filter is active.
    expect([...dag.clusterIds].sort((a, b) => a - b)).toEqual([100, 201, 305, 402]);
    // Jobs keep their real cluster.proc ids, sorted by cluster then proc.
    expect(dag.jobs.map((j) => j.id)).toEqual(['100.0', '201.0', '305.0', '402.0']);
  });

  it('removes a whole DAG by its shared batch name, not one cluster', () => {
    const [dag] = groupIntoBatches(nestedDag());
    // Matching the shared JobBatchName takes down every node and every
    // nested sub-DAG; ClusterId == 100 is a belt-and-suspenders for the
    // root DAGMan job.
    expect(dag.removeConstraint).toBe(
      'JobBatchName == "foo.dag+100" || ClusterId == 100',
    );
  });

  it('groups a simple (non-nested) DAG by its root DAGMan cluster', () => {
    // bar.dag+55 with DAGManJobId 55 == the dagman cluster == the +N.
    const jobs: ClassAd[] = [
      {
        ClusterId: 55, ProcId: 0, JobStatus: 2, Owner: 'dan',
        Cmd: 'condor_dagman', QDate: 10, JobBatchName: 'bar.dag+55',
      },
      {
        ClusterId: 56, ProcId: 0, JobStatus: 1, Owner: 'dan',
        Cmd: '/bin/x', QDate: 20, JobBatchName: 'bar.dag+55',
        DAGManJobId: 55, DAGNodeName: 'only',
      },
    ];
    const batches = groupIntoBatches(jobs);
    expect(batches).toHaveLength(1);
    expect(batches[0].batchID).toBe(55);
    expect(batches[0].name).toBe('bar.dag');
    expect(batches[0].isDag).toBe(true);
    expect(batches[0].jobCount).toBe(2);
  });

  it('keeps two unnamed clusters as two separate batches', () => {
    const jobs: ClassAd[] = [
      { ClusterId: 1, ProcId: 0, JobStatus: 1, Owner: 'e' },
      { ClusterId: 2, ProcId: 0, JobStatus: 1, Owner: 'e' },
    ];
    const batches = groupIntoBatches(jobs);
    expect(batches.map((b) => b.batchID).sort((a, b) => a - b)).toEqual([1, 2]);
    expect(batches.every((b) => !b.isDag)).toBe(true);
    // Unnamed removal stays cluster-scoped, exactly as before.
    expect(batches.find((b) => b.batchID === 1)!.removeConstraint).toBe(
      'ClusterId == 1',
    );
  });

  it('removes a plain named (non-DAG) batch by name and owner', () => {
    // One batch name spanning two clusters, no DAG suffix.
    const jobs: ClassAd[] = [
      {
        ClusterId: 31, ProcId: 0, JobStatus: 1, Owner: 'fred',
        JobBatchName: 'nightly', Cmd: '/bin/r',
      },
      {
        ClusterId: 30, ProcId: 0, JobStatus: 1, Owner: 'fred',
        JobBatchName: 'nightly', Cmd: '/bin/r',
      },
    ];
    const batches = groupIntoBatches(jobs);
    expect(batches).toHaveLength(1);
    // Representative id is the smallest cluster in the group.
    expect(batches[0].batchID).toBe(30);
    expect(batches[0].isDag).toBe(false);
    expect(batches[0].name).toBe('nightly');
    expect(batches[0].removeConstraint).toBe(
      'JobBatchName == "nightly" && Owner == "fred"',
    );
  });

  it('scopes a shared batch name per owner so users are not merged', () => {
    const jobs: ClassAd[] = [
      { ClusterId: 40, ProcId: 0, JobStatus: 1, Owner: 'g', JobBatchName: 'run' },
      { ClusterId: 41, ProcId: 0, JobStatus: 1, Owner: 'h', JobBatchName: 'run' },
    ];
    expect(groupIntoBatches(jobs)).toHaveLength(2);
  });

  it('escapes quotes in the batch name for the remove constraint', () => {
    const jobs: ClassAd[] = [
      {
        ClusterId: 60, ProcId: 0, JobStatus: 1, Owner: 'i',
        JobBatchName: 'weird"name',
      },
    ];
    const [b] = groupIntoBatches(jobs);
    expect(b.removeConstraint).toBe('JobBatchName == "weird\\"name" && Owner == "i"');
  });
});

describe('applyBatchFilter', () => {
  it('matches on the submitting user', () => {
    const batches = groupIntoBatches(queue());
    const mine = applyBatchFilter(batches, 'bob');
    expect(mine.map((b) => b.batchID).sort()).toEqual([11, 12]);
  });

  it('requires every token to match somewhere', () => {
    const batches = groupIntoBatches(queue());
    // "held" is a status name and "bob" an owner: both true only of 12.
    expect(applyBatchFilter(batches, 'bob held').map((b) => b.batchID)).toEqual([12]);
    expect(applyBatchFilter(batches, 'alice held')).toHaveLength(0);
  });
});

describe('filterAdsByStatus', () => {
  it('treats an empty selection as no filter rather than as nothing', () => {
    // The status strip has no way to express "show nothing", and a user
    // who deselects their last chip means "show me everything again".
    expect(filterAdsByStatus(queue(), new Set())).toHaveLength(4);
  });

  it('keeps only the selected statuses', () => {
    const running = filterAdsByStatus(queue(), new Set(['running'] as const));
    expect(running).toHaveLength(2);
    expect(new Set(running.map((j) => j.ClusterId))).toEqual(new Set([10]));

    const either = filterAdsByStatus(queue(), new Set(['idle', 'held'] as const));
    expect(either.map((j) => j.ClusterId).sort()).toEqual([11, 12]);
  });

  it('follows the display status, so a spooling hold is not "held"', () => {
    const spooling: ClassAd[] = [
      { ClusterId: 1, ProcId: 0, JobStatus: 5, HoldReasonCode: 16 },
    ];
    expect(filterAdsByStatus(spooling, new Set(['held'] as const))).toHaveLength(0);
    expect(filterAdsByStatus(spooling, new Set(['uploading'] as const))).toHaveLength(1);
  });
});

describe('summarizeJobs', () => {
  it('splits resources into what is in use and what is waiting', () => {
    const s = summarizeJobs(queue());
    expect(s.jobs).toBe(4);
    expect(s.batches).toBe(3);
    expect(s.owners).toBe(2);

    // Running: two jobs at 4 CPUs / 2 GiB / 1 GPU each.
    expect(s.running.cpus).toBe(8);
    expect(s.running.memoryMB).toBe(4096);
    expect(s.running.gpus).toBe(2);

    // Idle: one job. The HELD job is neither holding resources nor
    // waiting for them, so it must not appear in either column --
    // counting it as idle demand would overstate the queue by 8 CPUs.
    expect(s.idle.cpus).toBe(2);
    expect(s.idle.memoryMB).toBe(1024);
  });

  it('counts jobs whose request is still an expression instead of ignoring them', () => {
    const s = summarizeJobs([
      { ClusterId: 1, ProcId: 0, JobStatus: 1, RequestCpus: 1, RequestMemory: 'ifthenelse(x, 1, 2)' },
    ]);
    // The total is short by one job, and says so. Silently reporting
    // "1 CPU, 0 GiB" would look like a job that asked for no memory.
    expect(s.idle.unresolved).toBe(1);
    expect(s.idle.memoryMB).toBe(0);
  });

  it('counts output transfer and suspension as in use', () => {
    const s = summarizeJobs([
      { ClusterId: 1, ProcId: 0, JobStatus: 6, RequestCpus: 3, RequestMemory: 512 },
      { ClusterId: 2, ProcId: 0, JobStatus: 7, RequestCpus: 5, RequestMemory: 512 },
    ]);
    // Both still occupy a slot on an execute node.
    expect(s.running.cpus).toBe(8);
    expect(s.idle.cpus).toBe(0);
  });
});

describe('statusRank', () => {
  it('orders a mixed batch by its most active status', () => {
    const batches = groupIntoBatches(queue());
    const running = batches.find((b) => b.batchID === 10)!;
    const idle = batches.find((b) => b.batchID === 11)!;
    const held = batches.find((b) => b.batchID === 12)!;
    expect(statusRank(running)).toBeLessThan(statusRank(idle));
    expect(statusRank(idle)).toBeLessThan(statusRank(held));
  });
});

describe('summarizeBatchUsage', () => {
  // One batch: two running jobs reporting usage, one idle, one held.
  const batch: ClassAd[] = [
    {
      ClusterId: 7, ProcId: 0, JobStatus: 2,
      RequestCpus: 4, RequestMemory: 4096, RequestDisk: 1048576, RequestGpus: 1,
      CPUsUsage: 3.5, MemoryUsage: 1024, DiskUsage: 262144,
    },
    {
      ClusterId: 7, ProcId: 1, JobStatus: 2,
      RequestCpus: 4, RequestMemory: 4096, RequestDisk: 1048576, RequestGpus: 1,
      CPUsUsage: 0.5, ResidentSetSize: 524288, DiskUsage: 262144,
    },
    {
      ClusterId: 7, ProcId: 2, JobStatus: 1,
      RequestCpus: 4, RequestMemory: 4096, RequestDisk: 1048576, RequestGpus: 1,
    },
    { ClusterId: 7, ProcId: 3, JobStatus: 5, RequestCpus: 4, RequestMemory: 4096 },
  ];
  const row = (u: ReturnType<typeof summarizeBatchUsage>, label: string) =>
    u.rows.find((r) => r.label === label)!;

  it('compares usage against what the RUNNING jobs were given', () => {
    const u = summarizeBatchUsage(batch);
    expect(u.running).toBe(2);
    expect(u.idle).toBe(1);
    // Two running jobs at 4 CPUs. Totalling the idle and held jobs in
    // here would make the batch look like it was wasting most of an
    // allocation the pool never gave it.
    expect(row(u, 'CPUs').allocated).toBe(8);
    expect(row(u, 'CPUs').used).toBe(4);
    expect(row(u, 'CPUs').waiting).toBe(4);
  });

  it('falls back to ResidentSetSize when MemoryUsage is not a number', () => {
    // MemoryUsage is an expression in the job ad more often than not;
    // only ResidentSetSize (KiB) is reliably a literal.
    const u = summarizeBatchUsage(batch);
    // 1024 MiB reported directly + 524288 KiB = 512 MiB.
    expect(row(u, 'Memory').used).toBe(1536);
  });

  it('leaves a measurement missing rather than counting it as zero', () => {
    const justStarted = summarizeBatchUsage([
      { ClusterId: 8, ProcId: 0, JobStatus: 2, RequestCpus: 2, RequestMemory: 2048 },
    ]);
    expect(justStarted.running).toBe(1);
    // A batch that started ten seconds ago has reported nothing. Zero
    // would render as "using none of its allocation", which is a claim
    // about the job rather than about the absence of a report.
    expect(justStarted.reporting).toBe(0);
    expect(row(justStarted, 'CPUs').used).toBeUndefined();
    expect(row(justStarted, 'CPUs').allocated).toBe(2);
  });

  it('offers a GPU row only when something asked for one', () => {
    expect(summarizeBatchUsage(batch).rows.map((r) => r.label)).toContain('GPUs');
    const noGpu = summarizeBatchUsage([
      { ClusterId: 9, ProcId: 0, JobStatus: 2, RequestCpus: 1, RequestMemory: 1024 },
    ]);
    expect(noGpu.rows.map((r) => r.label)).not.toContain('GPUs');
  });

  it('counts output transfer as still holding the allocation', () => {
    const u = summarizeBatchUsage([
      { ClusterId: 9, ProcId: 0, JobStatus: 6, RequestCpus: 3, RequestMemory: 1024, CPUsUsage: 0.1 },
    ]);
    expect(u.running).toBe(1);
    expect(row(u, 'CPUs').allocated).toBe(3);
  });
});
