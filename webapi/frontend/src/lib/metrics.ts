// Shape and transform for the job-metrics graphs on the job page.
//
// The server (GET /api/v1/metrics/job_metrics) returns a generic
// column/row aggregate. This turns one job's aggregate into a small set of
// per-metric series -- one line per run attempt (RunInstanceID) -- plus the
// requested amount to draw as a reference line. It also decides which
// metrics are worth a chart: a metric graphs only when it has more than
// three points (the sampler's floor is one point every ~15 min), and
// disk/GPU appear only when the job actually used them.

export interface MetricsColumn {
  name: string;
  kind: 'group' | 'metric';
  func?: string;
  attr?: string;
  bucket_seconds?: number;
}

export interface MetricsResponse {
  enabled: boolean;
  table: string;
  time_attr?: string;
  bucket_seconds?: number;
  columns?: MetricsColumn[];
  rows?: string[][];
  truncated?: boolean;
}

// The query the job page issues. Kept beside the defs that read it back so
// the aggregate column names cannot drift from what we parse.
export const JOB_METRICS_GROUP_BY = 'RunInstanceID';
export const JOB_METRICS_BUCKET_SECONDS = 900; // 15 min: the sampler's floor
export const JOB_METRICS_AGG =
  'max:MemoryUsage,avg:CpuUtil,max:DiskUsage,avg:GpuUtil,' +
  'max:RequestMemory,max:RequestCpus,max:RequestDisk,max:RequestGpus';

export interface SeriesPoint {
  t: number; // unix seconds (bucket start)
  value: number;
}
export interface ExecutionSeries {
  run: number; // RunInstanceID
  points: SeriesPoint[];
}
export interface MetricSeries {
  key: string;
  label: string;
  unit: string;
  executions: ExecutionSeries[];
  // Requested amount as a reference line, in the same unit as the series.
  // Undefined when there is no sensible same-unit request (GPU: util vs a
  // count), in which case requestedNote carries it as text instead.
  requested?: number;
  requestedNote?: string;
  pointCount: number;
  // Caveat shown under the chart (e.g. the memory HWM ratchet).
  note?: string;
}

interface JobMetricDef {
  key: string;
  label: string;
  unit: string;
  valueCol: string;
  requestCol?: string;
  // Whether the request is the same unit as the value (so it can be a line).
  requestIsLine: boolean;
  // Require actual usage (> 0) before charting -- for disk/GPU, which are
  // absent or zero on most jobs.
  requireData: boolean;
  note?: string;
}

const JOB_METRIC_DEFS: JobMetricDef[] = [
  {
    key: 'memory',
    label: 'Memory',
    unit: 'MB',
    valueCol: 'max_MemoryUsage',
    requestCol: 'max_RequestMemory',
    requestIsLine: true,
    requireData: false,
    note: 'MemoryUsage is a high-water mark, not a live reading — the curve only rises, so it shows the peak a run ever needed rather than a working-set trace.',
  },
  {
    key: 'cpu',
    label: 'CPU',
    unit: 'cores',
    valueCol: 'avg_CpuUtil',
    requestCol: 'max_RequestCpus',
    requestIsLine: true,
    requireData: false,
  },
  {
    key: 'disk',
    label: 'Disk',
    unit: 'KB',
    valueCol: 'max_DiskUsage',
    requestCol: 'max_RequestDisk',
    requestIsLine: true,
    requireData: true,
    note: 'DiskUsage is a high-water mark for the current execution.',
  },
  {
    key: 'gpu',
    label: 'GPU utilization',
    unit: 'GPU',
    valueCol: 'avg_GpuUtil',
    requestCol: 'max_RequestGpus',
    // GpuUtil is a utilization fraction; RequestGpus is a device count, so
    // it cannot share the axis. Shown as a note instead of a line.
    requestIsLine: false,
    requireData: true,
    note: 'Per-interval GPU utilization, de-averaged from the pool’s lifetime average.',
  },
];

const MIN_POINTS = 3; // "more than 3 points"

function toNum(v: string | undefined): number | undefined {
  if (v === undefined || v === '') return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

// buildJobMetrics turns the server response into the charts the page should
// draw. Returns [] when the feature is off or nothing clears the gate.
export function buildJobMetrics(resp: MetricsResponse | undefined): MetricSeries[] {
  if (!resp || !resp.enabled || !resp.columns || !resp.rows) return [];

  const idx = new Map<string, number>();
  resp.columns.forEach((c, i) => idx.set(c.name, i));
  const runIdx = idx.get(JOB_METRICS_GROUP_BY);
  // The time bucket column is the group column named after the time attr.
  const timeIdx = resp.time_attr ? idx.get(resp.time_attr) : undefined;
  if (runIdx === undefined || timeIdx === undefined) return [];

  const out: MetricSeries[] = [];
  for (const def of JOB_METRIC_DEFS) {
    const valIdx = idx.get(def.valueCol);
    if (valIdx === undefined) continue;
    const reqIdx = def.requestCol ? idx.get(def.requestCol) : undefined;

    // Collect points per run, and the requested value (constant per job, so
    // take the max seen).
    const byRun = new Map<number, SeriesPoint[]>();
    let pointCount = 0;
    let maxValue = 0;
    let requested: number | undefined;
    for (const row of resp.rows) {
      const t = toNum(row[timeIdx]);
      const value = toNum(row[valIdx]);
      const run = toNum(row[runIdx]) ?? 0;
      if (reqIdx !== undefined) {
        const rq = toNum(row[reqIdx]);
        if (rq !== undefined && (requested === undefined || rq > requested)) {
          requested = rq;
        }
      }
      if (t === undefined || value === undefined) continue;
      const arr = byRun.get(run) ?? [];
      arr.push({ t, value });
      byRun.set(run, arr);
      pointCount++;
      if (value > maxValue) maxValue = value;
    }

    if (pointCount <= MIN_POINTS) continue;
    if (def.requireData && maxValue <= 0) continue;

    const executions: ExecutionSeries[] = [...byRun.entries()]
      .map(([run, points]) => ({
        run,
        points: points.sort((a, b) => a.t - b.t),
      }))
      .sort((a, b) => a.run - b.run);

    const series: MetricSeries = {
      key: def.key,
      label: def.label,
      unit: def.unit,
      executions,
      pointCount,
      note: def.note,
    };
    if (requested !== undefined && requested > 0) {
      if (def.requestIsLine) series.requested = requested;
      else series.requestedNote = `Requested ${requested} GPU${requested === 1 ? '' : 's'}`;
    }
    out.push(series);
  }
  return out;
}

// The categorical hues for run attempts, in fixed order (validated for CVD
// on a light surface by the dataviz palette). More than this many runs on
// one job is vanishingly rare; index past the end falls back to the last.
export const RUN_COLORS = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#4a3aa7'];

export function runColor(i: number): string {
  return RUN_COLORS[Math.min(i, RUN_COLORS.length - 1)];
}

// formatMetric renders a value in the metric's unit, promoting bytes-ish
// units to human scale. Memory is MB, disk is KB.
export function formatMetric(value: number, unit: string): string {
  switch (unit) {
    case 'MB':
      return value >= 1024
        ? `${(value / 1024).toLocaleString(undefined, { maximumFractionDigits: 1 })} GB`
        : `${value.toLocaleString(undefined, { maximumFractionDigits: 0 })} MB`;
    case 'KB':
      if (value >= 1024 * 1024)
        return `${(value / 1024 / 1024).toLocaleString(undefined, { maximumFractionDigits: 1 })} GB`;
      if (value >= 1024)
        return `${(value / 1024).toLocaleString(undefined, { maximumFractionDigits: 1 })} MB`;
      return `${value.toLocaleString(undefined, { maximumFractionDigits: 0 })} KB`;
    case 'cores':
      return `${value.toLocaleString(undefined, { maximumFractionDigits: 2 })} cores`;
    case 'GPU':
      return value.toLocaleString(undefined, { maximumFractionDigits: 2 });
    default:
      return value.toLocaleString();
  }
}
