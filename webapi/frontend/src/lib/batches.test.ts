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
