import { describe, expect, it } from 'vitest';
import { EXPR_REQUEST_MEMORY, exprRequestJob } from './jobRequests.fixture';
import {
  buildJobMetrics,
  formatMetric,
  jobMetricsSelector,
  RATE_SAMPLE_GUARD,
  type MetricsResponse,
} from './metrics';

// Columns exactly as the server returns for the job page's query.
const COLUMNS = [
  { name: 'RunInstanceID', kind: 'group' as const },
  { name: 'SampleTime', kind: 'group' as const, bucket_seconds: 900 },
  { name: 'max_MemoryUsage', kind: 'metric' as const },
  { name: 'avg_CpuUtil', kind: 'metric' as const },
  { name: 'max_DiskUsage', kind: 'metric' as const },
  { name: 'avg_GpuUtil', kind: 'metric' as const },
  { name: 'max_RequestMemory', kind: 'metric' as const },
  { name: 'max_RequestCpus', kind: 'metric' as const },
  { name: 'max_RequestDisk', kind: 'metric' as const },
  { name: 'max_RequestGpus', kind: 'metric' as const },
];

// row: [run, t, mem, cpu, disk, gpu, reqMem, reqCpu, reqDisk, reqGpu]
function resp(rows: (string | number)[][]): MetricsResponse {
  return {
    enabled: true,
    table: 'job_metrics',
    time_attr: 'SampleTime',
    bucket_seconds: 900,
    columns: COLUMNS,
    rows: rows.map((r) => r.map(String)),
  };
}

function memRows(n: number, run = 0): (string | number)[][] {
  return Array.from({ length: n }, (_, i) => [
    run, 1000 + i * 900, 2048 + i * 100, 1.5, 0, 0, 4096, 2, 0, 0,
  ]);
}

// One run's worth of memory samples at a request of its own: the shape a
// job on a retry ladder leaves, a run per rung.
function rungRows(run: number, reqMem: number, n = 4): (string | number)[][] {
  const t0 = 1000 + run * 10_000;
  return Array.from({ length: n }, (_, i) => [
    run, t0 + i * 900, reqMem / 2 + i * 100, 1.5, 0, 0, reqMem, 2, 0, 0,
  ]);
}

describe('buildJobMetrics', () => {
  it('returns nothing when the feature is disabled', () => {
    expect(buildJobMetrics({ enabled: false, table: 'job_metrics' })).toEqual([]);
  });

  it('needs more than three points to graph', () => {
    expect(buildJobMetrics(resp(memRows(3)))).toEqual([]); // exactly 3 -> no
    const four = buildJobMetrics(resp(memRows(4)));
    expect(four.map((s) => s.key)).toContain('memory');
  });

  it('plots memory with the requested reference and says how to read it', () => {
    const mem = buildJobMetrics(resp(memRows(5))).find((s) => s.key === 'memory')!;
    expect(mem.requested).toBe(4096);
    expect(mem.pointCount).toBe(5);
    expect(mem.executions).toHaveLength(1);
    expect(mem.executions[0].points[0].value).toBe(2048);
    expect(mem.note).toBe('Each point is the most memory the run had used by then.');
  });

  it('omits disk and GPU when the job never used them', () => {
    const keys = buildJobMetrics(resp(memRows(5))).map((s) => s.key);
    expect(keys).toContain('cpu');
    expect(keys).not.toContain('disk');
    expect(keys).not.toContain('gpu');
  });

  it('groups points by run attempt, sorted, one series each', () => {
    const rows = [...memRows(4, 0), ...memRows(4, 1)];
    const mem = buildJobMetrics(resp(rows)).find((s) => s.key === 'memory')!;
    expect(mem.executions.map((e) => e.run)).toEqual([0, 1]);
    const ts = mem.executions[0].points.map((p) => p.t);
    expect(ts).toEqual([...ts].sort((a, b) => a - b));
  });

  it('shows GPU as a note (util vs a device count cannot share the axis)', () => {
    const rows = Array.from({ length: 5 }, (_, i) => [
      0, 1000 + i * 900, 2048, 1.5, 0, 0.8, 4096, 2, 0, 2,
    ]);
    const gpu = buildJobMetrics(resp(rows)).find((s) => s.key === 'gpu')!;
    expect(gpu.requested).toBeUndefined();
    expect(gpu.requestedNote).toBe('Requested 2 GPUs');
  });
});

describe('buildJobMetrics with the job ad', () => {
  // The resource table and the graph's "requested" line read one number:
  // the request as evaluated in the job's ad. The samples are the fallback.
  it('draws the requested line at the evaluated request from the ad, and keeps its rule', () => {
    const mem = buildJobMetrics(resp(memRows(5)), exprRequestJob).find((s) => s.key === 'memory')!;
    expect(mem.requested).toBe(10987);
    expect(mem.requestedExpr).toBe(EXPR_REQUEST_MEMORY);
    const cpu = buildJobMetrics(resp(memRows(5)), exprRequestJob).find((s) => s.key === 'cpu')!;
    expect(cpu.requested).toBe(1);
    expect(cpu.requestedExpr).toBeUndefined();
  });

  it('falls back to the sampled request when the ad does not carry one', () => {
    const mem = buildJobMetrics(resp(memRows(5)), {}).find((s) => s.key === 'memory')!;
    expect(mem.requested).toBe(4096);
  });
});

describe('formatMetric', () => {
  it('promotes MB and KB to human scale', () => {
    expect(formatMetric(512, 'MB')).toBe('512 MB');
    expect(formatMetric(4096, 'MB')).toBe('4 GB');
    expect(formatMetric(2 * 1024 * 1024, 'KB')).toBe('2 GB');
    expect(formatMetric(1.5, 'cores')).toBe('1.5 cores');
    expect(formatMetric(1, 'cores')).toBe('1 core');
    expect(formatMetric(10987, 'MB')).toBe('10.7 GB');
  });
});

describe('jobMetricsSelector', () => {
  it('names a single-AP job by its numbers', () => {
    expect(jobMetricsSelector('12.3', false)).toEqual({
      constraint: `ClusterId == 12 && ProcId == 3 && ${RATE_SAMPLE_GUARD}`,
    });
    expect(jobMetricsSelector('12345.0@1790000000', false)?.constraint).toContain('ClusterId == 12345 && ProcId == 0');
    expect(jobMetricsSelector('x.y', false)).toBeUndefined();
  });

  it('passes a multi-AP job id whole, with no cluster or proc clause', () => {
    // The numbers repeat across access points; the server confines the
    // samples to the one the id names.
    const sel = jobMetricsSelector('12.3@ap2.example.org', true);
    expect(sel).toEqual({ constraint: RATE_SAMPLE_GUARD, job_id: '12.3@ap2.example.org' });
    expect(sel?.constraint).not.toMatch(/ClusterId|ProcId/);
    expect(jobMetricsSelector('', true)).toBeUndefined();
  });
});

// The reported case (12428255.40559): a job with
// retry_request_memory = { 2048, ... 65536 } drew one dashed line at the
// rung it finished on, so the runs it was killed on looked like runs that
// had memory to spare.
describe('a request that moved between runs', () => {
  const climbed = () =>
    buildJobMetrics(
      resp([...rungRows(0, 2048), ...rungRows(1, 4096), ...rungRows(2, 8192)]),
      { RequestMemory: 8192 },
    ).find((s) => s.key === 'memory')!;

  it('gives each run the request that run had', () => {
    const mem = climbed();
    expect(mem.executions.map((e) => e.request)).toEqual([2048, 4096, 8192]);
  });

  it('draws no single line across the chart', () => {
    expect(climbed().requested).toBeUndefined();
  });

  it('says in the caption where the request started and ended', () => {
    expect(climbed().requestedNote).toBe('Requested 2 GB → 8 GB');
  });

  it('captions from the samples it drew, not from the ad', () => {
    // The ad is the request the job holds now. Where that is past the
    // last run the samples caught, the caption would name a step the
    // chart does not draw.
    const mem = buildJobMetrics(
      resp([...rungRows(0, 2048), ...rungRows(1, 4096), ...rungRows(2, 8192)]),
      { RequestMemory: 16384 },
    ).find((s) => s.key === 'memory')!;
    expect(mem.requestedNote).toBe('Requested 2 GB → 8 GB');
  });

  it('leaves a job whose request never moved exactly as it was', () => {
    const mem = buildJobMetrics(resp([...memRows(4, 0), ...memRows(4, 1)]), {
      RequestMemory: 4096,
    }).find((s) => s.key === 'memory')!;
    expect(mem.requested).toBe(4096);
    expect(mem.requestedNote).toBeUndefined();
    expect(mem.executions.map((e) => e.request)).toEqual([undefined, undefined]);
  });

  it('does not read a run the samples say nothing about as a change', () => {
    // reqMem 0 is the sampler having nothing to report, not a job that
    // asked for nothing. One step drawn from it would invent a drop to
    // the axis.
    const mem = buildJobMetrics(
      resp([...rungRows(0, 2048), ...rungRows(1, 0), ...rungRows(2, 8192)]),
      { RequestMemory: 8192 },
    ).find((s) => s.key === 'memory')!;
    expect(mem.requested).toBe(8192);
    expect(mem.executions.every((e) => e.request === undefined)).toBe(true);
  });

  it('keeps one line for a single run, whatever it asked for', () => {
    const mem = buildJobMetrics(resp(rungRows(0, 2048, 5)), { RequestMemory: 2048 }).find(
      (s) => s.key === 'memory',
    )!;
    expect(mem.requested).toBe(2048);
    expect(mem.executions[0].request).toBeUndefined();
  });
});
