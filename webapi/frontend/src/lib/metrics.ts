// Shape and transform for the job-metrics graphs on the job page.
//
// The server (GET /api/v1/metrics/job_metrics) returns a generic
// column/row aggregate. This turns one job's aggregate into a small set of
// per-metric series -- one line per run attempt (RunInstanceID) -- plus the
// requested amount to draw as a reference line. It also decides which
// metrics are worth a chart: a metric graphs only when it has more than
// three points (the sampler's floor is one point every ~15 min), and
// disk/GPU appear only when the job actually used them.

import type { ClassAd } from './api';
import { jobRequest, type RequestAttr } from './jobRequests';
import { formatKiB, formatMiB } from './utilization';

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

// Derived rates (CpuUtil, GpuUtil) are a counter's change divided by the
// sample's SampleInterval, in seconds. Samples were once recorded with an
// interval of about a second -- an ingest clock read just after the
// previous sample rather than the starter's -- and a second's worth of
// counter over one second reads as hundreds of cores on a one-core job.
// Those rows are append-only and still in the store, and the chart
// averages server-side per bucket, so a client can no longer pick them
// out: the query has to leave them out. A sampler's real intervals are
// minutes long. A run's first sample has no interval and no rates, and
// stays (its memory and disk readings are good). The cost: a short-interval
// sample's memory and disk readings go too, which a later sample's
// high-water mark covers.
export const RATE_MIN_SAMPLE_INTERVAL = 60;
export const RATE_SAMPLE_GUARD = `(SampleInterval is undefined || SampleInterval >= ${RATE_MIN_SAMPLE_INTERVAL})`;

// jobMetricsConstraint selects one job's samples for the charts.
export function jobMetricsConstraint(cluster: number, proc: number): string {
  return `ClusterId == ${cluster} && ProcId == ${proc} && ${RATE_SAMPLE_GUARD}`;
}

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
  // The request's expression, when the job wrote it as one.
  requestedExpr?: string;
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
  // The job attribute the request comes from, read from the ad when the
  // page has it (see buildJobMetrics).
  requestAttr: RequestAttr;
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
    requestAttr: 'RequestMemory',
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
    requestAttr: 'RequestCpus',
    requestIsLine: true,
    requireData: false,
  },
  {
    key: 'disk',
    label: 'Disk',
    unit: 'KB',
    valueCol: 'max_DiskUsage',
    requestCol: 'max_RequestDisk',
    requestAttr: 'RequestDisk',
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
    requestAttr: 'RequestGPUs',
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
//
// job, when given, is where the "requested" reference comes from: the value
// each Request* evaluates to in the job's ad, the same number the resource
// table shows. The samples' own max:Request* columns are the fallback for an
// ad that does not carry the request.
export function buildJobMetrics(resp: MetricsResponse | undefined, job?: ClassAd): MetricSeries[] {
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
    const fromAd = jobRequest(job, def.requestAttr);
    if (fromAd.value !== undefined) requested = fromAd.value;
    if (fromAd.expr) series.requestedExpr = fromAd.expr;
    if (requested !== undefined && requested > 0) {
      if (def.requestIsLine) series.requested = requested;
      else series.requestedNote = `Requested ${requested} GPU${requested === 1 ? '' : 's'}`;
    }
    out.push(series);
  }
  return out;
}

// The categorical hues for run attempts, in fixed order (validated for CVD
// on a light surface by the dataviz palette).
export const RUN_COLORS = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#4a3aa7'];

// runColor cycles through the palette, so neighbouring runs always differ.
// A job can run dozens of times (a restart on every eviction); clamping to
// the last hue painted every run past the sixth the same colour. Runs a
// palette apart share a hue, so the chart names the run in each tooltip.
export function runColor(i: number): string {
  const n = RUN_COLORS.length;
  return RUN_COLORS[((i % n) + n) % n];
}

// formatMetric renders a value in the metric's unit. Memory (MiB) and disk
// (KiB) go through formatMiB/formatKiB, the formatter the resource table
// and the rest of the app use, so a request reads the same in the table,
// the caption and a tooltip.
export function formatMetric(value: number, unit: string): string {
  switch (unit) {
    case 'MB':
      return formatMiB(value);
    case 'KB':
      return formatKiB(value);
    case 'cores':
      return `${value.toLocaleString(undefined, { maximumFractionDigits: 2 })} ${value === 1 ? 'core' : 'cores'}`;
    case 'GPU':
      return value.toLocaleString(undefined, { maximumFractionDigits: 2 });
    default:
      return value.toLocaleString();
  }
}
