import { describe, expect, it } from 'vitest';
import { buildJobMetrics, formatMetric, type MetricsResponse } from './metrics';

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

describe('buildJobMetrics', () => {
  it('returns nothing when the feature is disabled', () => {
    expect(buildJobMetrics({ enabled: false, table: 'job_metrics' })).toEqual([]);
  });

  it('needs more than three points to graph', () => {
    expect(buildJobMetrics(resp(memRows(3)))).toEqual([]); // exactly 3 -> no
    const four = buildJobMetrics(resp(memRows(4)));
    expect(four.map((s) => s.key)).toContain('memory');
  });

  it('plots memory with the requested reference and its HWM caveat', () => {
    const mem = buildJobMetrics(resp(memRows(5))).find((s) => s.key === 'memory')!;
    expect(mem.requested).toBe(4096);
    expect(mem.pointCount).toBe(5);
    expect(mem.executions).toHaveLength(1);
    expect(mem.executions[0].points[0].value).toBe(2048);
    expect(mem.note).toMatch(/high-water/i);
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

describe('formatMetric', () => {
  it('promotes MB and KB to human scale', () => {
    expect(formatMetric(512, 'MB')).toBe('512 MB');
    expect(formatMetric(4096, 'MB')).toBe('4 GB');
    expect(formatMetric(2 * 1024 * 1024, 'KB')).toBe('2 GB');
    expect(formatMetric(1.5, 'cores')).toBe('1.5 cores');
  });
});
