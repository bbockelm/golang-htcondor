import { describe, expect, it } from 'vitest';
import type { ClassAd } from '@/lib/api';
import type { BatchJob } from '@/lib/batches';
import type { MetricsResponse } from '@/lib/metrics';
import {
  batchCpuReading,
  batchMemoryReading,
  jobCpuReading,
  jobMemoryReading,
  jobUsageByJob,
  recentCpuByJob,
  recentCpuConstraint,
  type JobUsage,
} from './runningUsage';

function metrics(rows: string[][]): MetricsResponse {
  return {
    enabled: true,
    table: 'job_metrics',
    columns: [
      { name: 'ClusterId', kind: 'group' },
      { name: 'ProcId', kind: 'group' },
      { name: 'avg_CpuUtil', kind: 'metric', func: 'avg', attr: 'CpuUtil' },
    ],
    rows,
  };
}

function job(id: string): BatchJob {
  const [c, p] = id.split('.').map(Number);
  return { id, cluster: c, jobIdx: p, display: { key: 'running', label: 'Running' } };
}

describe('recentCpuByJob', () => {
  it('is undefined when samples are not kept', () => {
    expect(recentCpuByJob({ enabled: false, table: 'job_metrics' })).toBeUndefined();
  });

  it('skips a job whose window has no rate rather than reading zero', () => {
    const m = recentCpuByJob(metrics([['7', '0', '0.9'], ['7', '1', '']]))!;
    expect(m.get('7.0')).toBe(0.9);
    expect(m.has('7.1')).toBe(false);
  });
});

describe('jobUsageByJob', () => {
  const ads: ClassAd[] = [
    { ClusterId: 7, ProcId: 0, RequestMemory: 2048, RequestCpus: 1, MemoryUsage: 1229, CpusUsage: 0.95 },
    { ClusterId: 7, ProcId: 1, RequestMemory: 2048, RequestCpus: 1, ResidentSetSize: 524288, CpusUsage: 0.9 },
    { ClusterId: 7, ProcId: 2, RequestMemory: 2048, RequestCpus: 1 },
  ];

  it('prefers the last hour of samples, and falls back to the ad', () => {
    const u = jobUsageByJob(ads, new Map([['7.0', 0.2]]));
    expect(u.get('7.0')).toMatchObject({ cpuUsed: 0.2, cpuSource: 'recent' });
    // No recent sample for 7.1: since-start, and labelled so.
    expect(u.get('7.1')).toMatchObject({ cpuUsed: 0.9, cpuSource: 'since-start' });
    expect(jobCpuReading(u.get('7.0')).title).toContain('last hour');
    expect(jobCpuReading(u.get('7.1')).title).toContain('since the job started');
  });

  it('uses the ad when samples are not kept at all', () => {
    const u = jobUsageByJob(ads, undefined);
    expect(u.get('7.0')).toMatchObject({ cpuUsed: 0.95, cpuSource: 'since-start' });
  });

  it('reads memory from MemoryUsage, else ResidentSetSize in KiB', () => {
    const u = jobUsageByJob(ads, undefined);
    expect(u.get('7.0')?.memUsedMiB).toBe(1229);
    expect(u.get('7.1')?.memUsedMiB).toBe(512);
    expect(u.get('7.2')?.memUsedMiB).toBeUndefined();
  });

  it('does not join samples onto another access point\'s job', () => {
    const multi: ClassAd[] = [
      { ClusterId: 7, ProcId: 0, CpusUsage: 0.5, RequestCpus: 1, schedd: 'ap1', job_id: '7.0@ap1' },
    ];
    const u = jobUsageByJob(multi, new Map([['7.0', 0.1]]));
    expect(u.get('7.0@ap1')).toMatchObject({ cpuUsed: 0.5, cpuSource: 'since-start' });
  });
});

describe('job readings', () => {
  it('says "not reported yet" for a job with no measurement, never 0', () => {
    const r = jobMemoryReading({ memReqMiB: 2048 });
    expect(r.tone).toBe('none');
    expect(r.text).toBe('not reported yet');
    expect(r.fill).toBeUndefined();
    expect(jobCpuReading({ cpuReq: 1 }).text).toBe('not reported yet');
  });

  it('flags memory near the request, and over it', () => {
    expect(jobMemoryReading({ memUsedMiB: 1229, memReqMiB: 2048 })).toMatchObject({
      tone: 'normal',
      text: '1.2 / 2.0 GB',
    });
    expect(jobMemoryReading({ memUsedMiB: 1900, memReqMiB: 2048 }).tone).toBe('warn');
    const over = jobMemoryReading({ memUsedMiB: 2400, memReqMiB: 2048 });
    expect(over.tone).toBe('critical');
    expect(over.text).toBe('2.3 / 2.0 GB · 117%');
  });

  it('flags CPU over-use and mutes idle cores', () => {
    const base: JobUsage = { cpuReq: 1, cpuSource: 'recent' };
    expect(jobCpuReading({ ...base, cpuUsed: 0.9 })).toMatchObject({ tone: 'normal', text: '0.9 / 1 core' });
    expect(jobCpuReading({ ...base, cpuUsed: 1.5 }).tone).toBe('warn');
    expect(jobCpuReading({ ...base, cpuUsed: 0.1 }).tone).toBe('muted');
  });
});

describe('batch readings', () => {
  const jobs = ['7.0', '7.1', '7.2', '7.3'].map(job);

  it('draws the median job as the fill and the largest as the tick', () => {
    const usage = new Map<string, JobUsage>([
      ['7.0', { memUsedMiB: 1024, memReqMiB: 2048 }],
      ['7.1', { memUsedMiB: 1126, memReqMiB: 2048 }],
      ['7.2', { memUsedMiB: 1946, memReqMiB: 2048 }],
      // 7.3 has not reported: left out, not counted as zero.
    ]);
    const r = batchMemoryReading(jobs, usage);
    expect(r.fill).toBeCloseTo(1126 / 2048);
    expect(r.tick).toBeCloseTo(1946 / 2048);
    expect(r.text).toBe('median 1.1 · max 1.9 of 2.0 GB');
    // The median job is fine; the largest is close to being held, and
    // its tick says so without painting the whole batch.
    expect(r.tone).toBe('normal');
    expect(r.tickTone).toBe('warn');
    expect(r.title).toContain('1 job has not reported yet');
  });

  it('falls back to percentages when the jobs asked for different amounts', () => {
    const usage = new Map<string, JobUsage>([
      ['7.0', { memUsedMiB: 1024, memReqMiB: 2048 }],
      ['7.1', { memUsedMiB: 1024, memReqMiB: 4096 }],
    ]);
    expect(batchMemoryReading(jobs, usage).text).toBe('median 38% · max 50% of request');
  });

  it('is "not reported yet" when no job has reported', () => {
    expect(batchMemoryReading(jobs, new Map()).text).toBe('not reported yet');
    expect(batchCpuReading(jobs, new Map()).tone).toBe('none');
  });

  it('averages CPU and names a mixed source', () => {
    const usage = new Map<string, JobUsage>([
      ['7.0', { cpuUsed: 0.8, cpuReq: 1, cpuSource: 'recent' }],
      ['7.1', { cpuUsed: 1.0, cpuReq: 1, cpuSource: 'since-start' }],
    ]);
    const r = batchCpuReading(jobs, usage);
    expect(r.text).toBe('mean 0.9 of 1 core');
    expect(r.fill).toBeCloseTo(0.9);
    expect(r.tick).toBeCloseTo(1.0);
    expect(r.title).toContain('last hour for 1 job, since it started for 1 job');
  });
});

describe('recentCpuConstraint', () => {
  it('spans the clusters on screen', () => {
    expect(recentCpuConstraint([{ ClusterId: 9 }, { ClusterId: 3 }, { ClusterId: 5 }])).toBe(
      'ClusterId >= 3 && ClusterId <= 9',
    );
    expect(recentCpuConstraint([{ ClusterId: 4 }])).toBe('ClusterId == 4');
    expect(recentCpuConstraint([])).toBeUndefined();
  });
});
