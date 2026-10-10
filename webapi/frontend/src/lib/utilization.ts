// Shape and display helpers for the Utilization page
// (GET /api/v1/utilization): how much of what a user's finished jobs
// reserved they actually used, per workflow, and what to change.
//
// Units are HTCondor's own and are named in every field: memory MiB, disk
// KiB, time seconds unless the name says `_hours`. Everything here that
// turns them into text uses HTCondor's submit-file convention, where
// "GB" is 1024 MiB -- so a figure on the page and a `request_memory = 2 GB`
// line in a suggestion mean the same amount.

export type UtilResource = 'cpu' | 'memory' | 'disk' | 'gpu';

export interface UtilizationResponse {
  since: number; // unix seconds, inclusive lower bound actually used
  until: number; // unix seconds
  days: number;
  jobs_considered: number; // finished jobs that fed the analysis
  truncated: boolean; // hit the server cap; analysis covers the most recent jobs_considered
  overall: UtilOverall;
  workflows: UtilWorkflow[]; // default order: wall_hours desc
}

export interface UtilOverall {
  jobs: number;
  wall_hours: number; // Σ RemoteWallClockTime / 3600
  badput_hours: number; // wall spent on runs that did not count: failed exits + evicted/restarted runs
  resources: UtilResourceSummary[]; // cpu, memory, disk always; gpu only if any job requested GPUs
}

// Time-weighted: "of what you reserved, how much did you use".
export interface UtilResourceSummary {
  resource: UtilResource;
  allocated_hours: number; // Σ request_i · wall_hours_i   (core-h, MiB-h, KiB-h, GPU-h)
  used_hours: number | null; // Σ used_i · wall_hours_i over jobs where usage was measured; null if none
  allocated_hours_measured: number; // Σ request_i · wall_hours_i over ONLY the jobs where usage was measured
  jobs_measured: number;
}

export interface UtilDistribution {
  n: number;
  min: number;
  p10: number;
  p25: number;
  p50: number;
  p75: number;
  p90: number;
  p95: number;
  p99: number;
  max: number;
  histogram: { lo: number; hi: number; count: number }[]; // 12–30 bins, contiguous, lo inclusive
}

export interface UtilRequest {
  typical: number; // the most common requested value (mode)
  min: number;
  max: number;
  distinct: number; // number of distinct requested values
}

export interface UtilBatchPoint {
  id: number; // ClusterId (DAG: root DAGMan cluster)
  submitted: number; // min QDate
  jobs: number;
  memory_request_mib: number | null; // typical
  memory_p95_mib: number | null;
  cpu_request: number | null; // typical
  cpu_cores_p50: number | null;
  wall_p50: number | null; // seconds
}

export interface UtilSample {
  memory_mib: number | null;
  wall: number; // seconds
  cores: number | null;
  disk_kib: number | null;
  outcome: 'ok' | 'failed' | 'removed' | 'memory_exceeded';
}

export interface UtilMemoryCurvePoint {
  request_mib: number; // a candidate request_memory
  retry_mib: number | null; // the retry_request_memory paired with it (null = no retry needed at this request)
  reserved_mib_hours: number; // expected Σ reserved MiB-h, retries included
  retry_fraction: number; // fraction of jobs that would exceed request_mib and rerun
  is_current: boolean; // the workflow's typical current request
  is_recommended: boolean;
}

export interface UtilAdvice {
  id: string;
  resource: UtilResource | 'runtime';
  severity: 'info' | 'suggest' | 'warn';
  title: string;
  detail: string;
  submit: string[];
  saves: { unit: 'core_hours' | 'gib_hours' | 'gpu_hours'; amount: number } | null;
  confidence: 'low' | 'medium' | 'high';
}

export interface UtilWorkflow {
  key: string; // stable opaque id (used in the URL ?w=)
  name: string;
  executable: string;
  owner?: string; // set in pool-wide scope
  schedd?: string; // multi-AP
  is_dag: boolean;
  jobs: number;
  succeeded: number;
  failed: number;
  removed: number;
  wall_hours: number;
  wall: UtilDistribution | null; // seconds
  short_jobs: number;
  restarts: { jobs: number; lost_hours: number };
  holds: { memory: number; disk: number };
  resources: UtilResourceSummary[];
  memory: { request: UtilRequest | null; peak_mib: UtilDistribution | null };
  cpu: {
    request: UtilRequest | null;
    cores_used: UtilDistribution | null;
    efficiency: UtilDistribution | null;
  };
  disk: { request: UtilRequest | null; used_kib: UtilDistribution | null };
  gpu: { request: UtilRequest | null; utilization: UtilDistribution | null } | null;
  memory_curve: UtilMemoryCurvePoint[];
  advice: UtilAdvice[];
  batches: UtilBatchPoint[];
  samples: UtilSample[];
}

export type UtilDays = 1 | 7 | 30;
export const UTIL_DAYS: UtilDays[] = [1, 7, 30];
export const DEFAULT_UTIL_DAYS: UtilDays = 7;

// parseDays reads the window from the URL. Anything the server would
// reject falls back to the default rather than producing an error page
// for a hand-edited link.
export function parseDays(raw: string | null | undefined): UtilDays {
  const n = Number(raw);
  return (UTIL_DAYS as number[]).includes(n) ? (n as UtilDays) : DEFAULT_UTIL_DAYS;
}

export function daysLabel(days: number): string {
  return days === 1 ? 'Last day' : `${days} days`;
}

export function windowPhrase(days: number): string {
  return days === 1 ? 'the last day' : `the last ${days} days`;
}

// --- Number formatting ---

// fixed renders at most `digits` decimals with thousands separators and
// no trailing zeros, so whole numbers read as whole ("4", not "4.0").
function fixed(v: number, digits: number): string {
  return v.toLocaleString('en-US', {
    maximumFractionDigits: digits,
    minimumFractionDigits: 0,
  });
}

// digitsFor keeps about two significant figures on small values and none
// past the decimal point on large ones: "0.42", "3.4", "27", "1,204".
function digitsFor(v: number): number {
  const a = Math.abs(v);
  if (a === 0) return 0;
  if (a < 1) return 2;
  if (a < 10) return 1;
  return 0;
}

/** formatMiB renders a MiB quantity in the scale a reader expects. */
export function formatMiB(mib: number): string {
  if (!Number.isFinite(mib)) return '—';
  const a = Math.abs(mib);
  if (a >= 1024 * 1024) return `${fixed(mib / (1024 * 1024), digitsFor(mib / (1024 * 1024)))} TB`;
  if (a >= 1024) return `${fixed(mib / 1024, digitsFor(mib / 1024))} GB`;
  if (a >= 1 || a === 0) return `${fixed(mib, 0)} MB`;
  return `${fixed(mib * 1024, 0)} KB`;
}

/** formatKiB renders a KiB quantity (disk) through the same scale. */
export function formatKiB(kib: number): string {
  if (!Number.isFinite(kib)) return '—';
  return formatMiB(kib / 1024);
}

/** formatCores renders a core count, fractional when measured. */
export function formatCores(n: number): string {
  if (!Number.isFinite(n)) return '—';
  return fixed(n, digitsFor(n));
}

/** formatNumber is the general figure: two significant-ish digits. */
export function formatNumber(n: number): string {
  if (!Number.isFinite(n)) return '—';
  return fixed(n, digitsFor(n));
}

/**
 * formatPercent renders a fraction as a percentage. A small non-zero
 * share says "<1%" rather than rounding to a 0% that reads as "none".
 */
export function formatPercent(f: number | null | undefined): string {
  if (f === null || f === undefined || !Number.isFinite(f)) return '—';
  if (f > 0 && f < 0.005) return '<1%';
  return `${Math.round(f * 100)}%`;
}

/** formatHours renders a wall-clock figure in hours. */
export function formatHours(h: number): string {
  if (!Number.isFinite(h)) return '—';
  return `${fixed(h, digitsFor(h))} h`;
}

// RESOURCE_LABEL names each resource the way the page talks about it.
export const RESOURCE_LABEL: Record<UtilResource, string> = {
  cpu: 'CPU',
  memory: 'Memory',
  disk: 'Disk',
  gpu: 'GPU',
};

/**
 * resourceHours converts a time-weighted figure from its wire unit
 * (core-h, MiB-h, KiB-h, GPU-h) to the unit the page shows, and names it.
 * Memory and disk become GB-hours: a MiB-hour count in the millions is
 * not a number anyone can picture.
 */
export function resourceHours(
  resource: UtilResource,
  wire: number,
): { value: number; unit: string } {
  switch (resource) {
    case 'cpu':
      return { value: wire, unit: 'core-hours' };
    case 'memory':
      return { value: wire / 1024, unit: 'GB-hours' };
    case 'disk':
      return { value: wire / (1024 * 1024), unit: 'GB-hours' };
    case 'gpu':
      return { value: wire, unit: 'GPU-hours' };
  }
}

export function formatResourceHours(resource: UtilResource, wire: number): string {
  const { value, unit } = resourceHours(resource, wire);
  return `${formatNumber(value)} ${unit}`;
}

/** formatResourceAmount renders a per-job value (a request or a use). */
export function formatResourceAmount(resource: UtilResource, v: number): string {
  switch (resource) {
    case 'cpu':
      return `${formatCores(v)} ${v === 1 ? 'core' : 'cores'}`;
    case 'memory':
      return formatMiB(v);
    case 'disk':
      return formatKiB(v);
    case 'gpu':
      return `${formatCores(v)} GPU${v === 1 ? '' : 's'}`;
  }
}

/** formatSaves renders an advice's projected saving. */
export function formatSaves(saves: UtilAdvice['saves']): string | null {
  if (!saves || !(saves.amount > 0)) return null;
  const unit =
    saves.unit === 'core_hours' ? 'core-hours' : saves.unit === 'gib_hours' ? 'GB-hours of memory' : 'GPU-hours';
  return `${formatNumber(saves.amount)} ${unit}`;
}

// --- The figures the page leads with ---

/**
 * usedFraction is "of what you reserved, how much did you use".
 *
 * The denominator is allocated_hours_measured, not allocated_hours: jobs
 * whose usage was never measured contribute a reservation but no use, and
 * dividing by everything would report them as idle when nothing is known
 * about them at all.
 */
export function usedFraction(s: UtilResourceSummary): number | null {
  if (s.used_hours === null || !(s.allocated_hours_measured > 0)) return null;
  return s.used_hours / s.allocated_hours_measured;
}

/** idleHours is the reserved-but-unused amount, in the wire unit. */
export function idleHours(s: UtilResourceSummary): number | null {
  if (s.used_hours === null) return null;
  return s.allocated_hours_measured - s.used_hours;
}

// The order the page lists resources in, whatever order they arrive in.
export const RESOURCE_ORDER: UtilResource[] = ['cpu', 'memory', 'disk', 'gpu'];

export function sortResources(rs: UtilResourceSummary[]): UtilResourceSummary[] {
  return [...rs].sort(
    (a, b) => RESOURCE_ORDER.indexOf(a.resource) - RESOURCE_ORDER.indexOf(b.resource),
  );
}

// --- Advice ---

const SEVERITY_RANK: Record<UtilAdvice['severity'], number> = { warn: 0, suggest: 1, info: 2 };
const CONFIDENCE_RANK: Record<UtilAdvice['confidence'], number> = { high: 0, medium: 1, low: 2 };

export interface RankedAdvice {
  advice: UtilAdvice;
  workflow: UtilWorkflow;
}

/**
 * compareAdvice orders advice by severity, then by how much it saves,
 * then by how sure it is. Savings in different units are compared by
 * amount: there is no fair exchange rate between a core-hour and a
 * GB-hour, and within a severity the bigger number is usually the bigger
 * waste anyway.
 */
export function compareAdvice(a: UtilAdvice, b: UtilAdvice): number {
  const s = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
  if (s !== 0) return s;
  const as = a.saves?.amount ?? -1;
  const bs = b.saves?.amount ?? -1;
  if (as !== bs) return bs - as;
  return CONFIDENCE_RANK[a.confidence] - CONFIDENCE_RANK[b.confidence];
}

/**
 * rankAdvice gathers the suggestions worth acting on across every
 * workflow, most valuable first. Informational notes ("memory request
 * fits") stay on their workflow's page: at the top they would crowd out
 * the changes that save something.
 */
export function rankAdvice(workflows: UtilWorkflow[]): RankedAdvice[] {
  const out: RankedAdvice[] = [];
  for (const w of workflows) {
    for (const a of w.advice) {
      if (a.severity === 'info') continue;
      out.push({ advice: a, workflow: w });
    }
  }
  return out.sort((x, y) => compareAdvice(x.advice, y.advice));
}

// --- The range strip ---

export interface StripGeometry {
  // Every position is a fraction of the track, 0 at zero usage.
  request: number | null;
  p10: number;
  p25: number;
  p75: number;
  p90: number;
  max: number;
  // The largest job used more than the typical request.
  over: boolean;
  trackMax: number;
}

/**
 * stripGeometry lays out one resource's range strip: the track spans
 * zero to the larger of the request and the largest use, so a request
 * far above every job and a job far above its request both stay on it.
 */
export function stripGeometry(
  request: UtilRequest | null,
  dist: UtilDistribution | null,
): StripGeometry | null {
  if (!dist || dist.n === 0) return null;
  const req = request?.typical ?? null;
  const trackMax = Math.max(dist.max, req ?? 0);
  if (!(trackMax > 0)) return null;
  const at = (v: number) => Math.min(1, Math.max(0, v / trackMax));
  return {
    request: req === null ? null : at(req),
    p10: at(dist.p10),
    p25: at(dist.p25),
    p75: at(dist.p75),
    p90: at(dist.p90),
    max: at(dist.max),
    over: req !== null && dist.max > req,
    trackMax,
  };
}

/** workflowUse picks the request and distribution for one resource. */
export function workflowUse(
  w: UtilWorkflow,
  r: Exclude<UtilResource, 'gpu'>,
): { request: UtilRequest | null; dist: UtilDistribution | null } {
  switch (r) {
    case 'memory':
      return { request: w.memory.request, dist: w.memory.peak_mib };
    case 'cpu':
      return { request: w.cpu.request, dist: w.cpu.cores_used };
    case 'disk':
      return { request: w.disk.request, dist: w.disk.used_kib };
  }
}

/** fitRatio orders workflows by how well a resource fits: median / request. */
export function fitRatio(w: UtilWorkflow, r: Exclude<UtilResource, 'gpu'>): number | undefined {
  const { request, dist } = workflowUse(w, r);
  if (!request || !dist || !(request.typical > 0)) return undefined;
  return dist.p50 / request.typical;
}
