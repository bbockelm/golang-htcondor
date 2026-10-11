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
  workflows: UtilWorkflowSummary[]; // every workflow, wall_hours desc
  // Advice from every workflow, ranked by the server: severity, then
  // GPU-hour savings ahead of any other, then larger savings; at most 500.
  suggestions: UtilSuggestion[];
  limit: number; // the limit actually applied
  max_limit: number; // the server's ceiling, so the page can offer "analyze more"
  // Owners present in the analyzed jobs, by wall_hours desc; only when the
  // scope can see other users.
  owners?: UtilOwner[];
}

export interface UtilOwner {
  owner: string;
  jobs: number;
  wall_hours: number;
}

export interface UtilGpu {
  request: UtilRequest | null;
  jobs: number; // jobs that requested >= 1 GPU
  measured: number; // of those, jobs with a utilization measurement
  utilization: UtilDistribution | null; // fraction of requested GPUs kept busy
  memory_peak_mib: UtilDistribution | null; // peak GPU memory per job
  device_memory_mib: number | null; // typical memory of the GPUs the jobs ran on, when known
  cores_used_while_gpu: UtilDistribution | null; // CPU cores used by GPU jobs
}

export interface UtilOverall {
  jobs: number;
  wall_hours: number; // Σ RemoteWallClockTime / 3600
  badput_hours: number; // wall spent on runs that did not count: failed exits + evicted/restarted runs
  resources: UtilResourceSummary[]; // cpu, memory, disk always; gpu only if any job requested GPUs
  // All workflows together: Σ occupancy_current / Σ occupancy_suggested
  // (unchanged workflows count in both sums).
  throughput_gain: number | null;
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
  // The request is a formula over the job's own usage (e.g. memory that
  // grows after a hold); typical/min/max are then the STARTING request.
  adaptive?: boolean;
  expression?: string; // the typical formula as written, when adaptive
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
  gpu_request: number | null; // typical request_gpus of the batch's GPU jobs; null when none requested GPUs
  gpu_util_p50: number | null; // median fraction of requested GPUs kept busy; null when unmeasured
}

export interface UtilSample {
  memory_mib: number | null;
  wall: number; // seconds
  cores: number | null;
  disk_kib: number | null;
  outcome: 'ok' | 'failed' | 'removed' | 'memory_exceeded';
  job: string; // "cluster.proc", the same form as UtilJobRow.id
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
  // POST /api/v1/utilization/apply can apply this advice to waiting jobs.
  applies?: boolean;
  // The edit it makes, when it applies.
  change?: { attribute: 'RequestMemory' | 'RequestCpus' | 'RequestDisk' | 'RequestGPUs'; value: number };
}

export interface UtilSavings {
  unit: 'core_hours' | 'gib_hours' | 'gpu_hours';
  amount: number;
}

export type UtilAdaptiveResource = 'memory' | 'cpus' | 'disk' | 'gpus';

// UtilWorkflowSummary is a workflow as the list carries it: enough for a
// table row, with the histograms, samples and advice text left to the
// workflow's own endpoint (an access point can have ten thousand).
export interface UtilWorkflowSummary {
  key: string;
  name: string;
  executable: string; // the program, not necessarily basename(Cmd)
  owner?: string;
  schedd?: string;
  is_dag: boolean;
  jobs: number;
  succeeded: number;
  failed: number;
  removed: number;
  wall_hours: number;
  holds?: { memory: number; disk: number }; // omitted when both are 0
  request: {
    // Typical requests (the STARTING value when adaptive).
    memory_mib: number | null;
    cpus: number | null;
    disk_kib: number | null;
    gpus: number | null; // null when no job requested GPUs
    adaptive?: UtilAdaptiveResource[]; // which of them are formulas
  };
  used: {
    // used_hours / allocated_hours_measured, a fraction; null if unmeasured
    cpu: number | null;
    memory: number | null;
    disk: number | null;
    gpu: number | null;
  };
  gpu_hours?: number; // GPU-hours reserved, when any job requested GPUs
  gain?: number; // throughput.gain, when there is an estimate
  slots_limited?: boolean; // throughput.slots_limited, when there is an estimate
  advice: { id: string; severity: UtilAdvice['severity']; saves: UtilSavings | null }[];
}

export interface UtilSuggestion {
  key: string; // workflow key
  name: string;
  executable: string;
  owner?: string;
  id: string;
  resource: UtilResource | 'runtime';
  severity: UtilAdvice['severity'];
  title: string;
  saves: UtilSavings | null;
  confidence: UtilAdvice['confidence'];
}

export interface UtilWorkflowDetail {
  since: number;
  until: number;
  days: number;
  truncated: boolean;
  limit: number;
  workflow: UtilWorkflow;
  // The caller's idle queue jobs of this workflow right now; null in
  // multi-AP mode or when the queue could not be read.
  waiting_jobs: number | null;
  // The request attributes that EVERY waiting job writes as a formula,
  // which an apply leaves alone on all of them; omitted when none.
  waiting_adaptive?: UtilAdaptiveResource[];
}

export interface UtilApplyRequest {
  w: string;
  advice: string[]; // advice ids, never values: the server applies its own
  days?: number;
  owned_by_me?: boolean;
  constraint?: string;
  owners?: string; // comma-separated
  limit?: number;
  schedd?: string;
}

export interface UtilApplyResponse {
  edited: number;
  set: { RequestMemory?: number; RequestCpus?: number; RequestDisk?: number; RequestGPUs?: number };
  declined: { advice: string; reason: string }[];
  skipped: { job: string; reason: string }[];
  failed: { job: string; reason: string }[];
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
  gpu: UtilGpu | null; // null when no job requested GPUs
  memory_curve: UtilMemoryCurvePoint[];
  advice: UtilAdvice[];
  batches: UtilBatchPoint[];
  samples: UtilSample[];
  // null: no advice changes the request, n < 20, or no pool data (multi-AP)
  throughput: UtilThroughput | null;
}

export interface UtilShape {
  cpus: number;
  memory_mib: number;
  disk_kib: number;
  gpus: number;
}

export interface UtilThroughput {
  current: UtilShape; // the workflow's typical request
  suggested: UtilShape; // the same with every request-changing advice applied (memory, cpus, disk)
  retry_memory_mib: number | null; // the suggested retry_request_memory, if any
  // How many copies of each shape the execute machines in the pool could hold at once.
  fit_current: number;
  fit_suggested: number;
  // Up-to estimate of how many more of these jobs could run at once:
  // pool occupancy per unit of work, current / suggested, reruns included.
  gain: number;
  limited_by: 'cpu' | 'memory' | 'disk' | 'gpu'; // the resource that caps the CURRENT shape on most machines
  wait_p50: number; // seconds, median wait from submission to first start
  slots_limited: boolean; // wait_p50 >= 900
  // The most recent batch with >= 20 jobs, to turn the gain into time.
  last_batch: {
    id: number;
    jobs: number;
    elapsed: number; // seconds, first QDate -> last CompletionDate
    estimated: number; // seconds, max(longest job wall, elapsed / gain)
  } | null;
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
  // One decimal up to 100 GB: a suggested 13.5 GB must not read as 14.
  if (a >= 1024) return `${fixed(mib / 1024, a < 100 * 1024 ? 1 : 0)} GB`;
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
  // GPUs lead whenever any job reserved one: they are the most expensive
  // thing a job can ask for, and the scarcest.
  const order = gpuReserved(rs) ? (['gpu', 'cpu', 'memory', 'disk'] as UtilResource[]) : RESOURCE_ORDER;
  return [...rs].sort((a, b) => order.indexOf(a.resource) - order.indexOf(b.resource));
}

/** gpuReserved says whether any job in the summary reserved a GPU. */
export function gpuReserved(rs: UtilResourceSummary[]): boolean {
  return rs.some((r) => r.resource === 'gpu' && r.allocated_hours > 0);
}

// --- Advice ---

const SEVERITY_RANK: Record<UtilAdvice['severity'], number> = { warn: 0, suggest: 1, info: 2 };
const CONFIDENCE_RANK: Record<UtilAdvice['confidence'], number> = { high: 0, medium: 1, low: 2 };

export interface RankedAdvice {
  advice: UtilAdvice;
  workflow: UtilWorkflow;
}

/**
 * compareAdvice orders advice by severity, then GPU-hour savings ahead
 * of any other, then by how much it saves, then by how sure it is. Core-
 * and GB-hour savings are compared by amount: there is no fair exchange
 * rate between them, and within a severity the bigger number is usually
 * the bigger waste anyway.
 */
export function compareAdvice(a: UtilAdvice, b: UtilAdvice): number {
  const s = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
  if (s !== 0) return s;
  // A GPU-hour outranks a core-hour or a GB-hour: it is the scarcest
  // and most expensive thing in the pool.
  const ag = a.saves?.unit === 'gpu_hours' ? 0 : 1;
  const bg = b.saves?.unit === 'gpu_hours' ? 0 : 1;
  if (ag !== bg) return ag - bg;
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

// --- Throughput ---

// THROUGHPUT_SHOWN is the smallest gain worth a headline: below it the
// estimate is inside its own error and "1.0x as many" says nothing.
export const THROUGHPUT_SHOWN = 1.1;

/** formatGain renders a multiplier to one decimal: "2.1×". */
export function formatGain(g: number): string {
  return `${g.toLocaleString('en-US', { maximumFractionDigits: 1, minimumFractionDigits: 1 })}×`;
}

/**
 * formatDuration renders an elapsed time at the precision a reader plans
 * with: minutes under an hour and a half, hours under two days (one
 * decimal below ten), days beyond.
 */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return '—';
  const min = seconds / 60;
  if (min < 90) {
    const m = Math.max(1, Math.round(min));
    return `${m} min`;
  }
  const h = seconds / 3600;
  if (h < 48) return `${fixed(h, h < 10 ? 1 : 0)} h`;
  const d = h / 24;
  return `${fixed(d, d < 10 ? 1 : 0)} days`;
}

// waitPhrase says how soon jobs started: "within a minute", "within 4 minutes".
function waitPhrase(seconds: number): string {
  if (seconds < 60) return 'within a minute';
  const m = Math.round(seconds / 60);
  return `within ${m} minute${m === 1 ? '' : 's'}`;
}

// raisedNoun names what a gain below one comes from: the request that
// went up between the current shape and the suggested one.
function raisedNoun(t: UtilThroughput): string {
  if (t.suggested.cpus > t.current.cpus) return 'cores';
  if (t.suggested.memory_mib > t.current.memory_mib) return 'memory';
  if (t.suggested.disk_kib > t.current.disk_kib) return 'disk';
  return 'resources';
}

export interface ThroughputStatement {
  kind: 'gain' | 'loss' | 'unlimited';
  // The one line for a suggestion card and the lead of a workflow's page.
  line: string;
  // Only for a gain with a recent batch to measure it against.
  batch?: string;
}

/**
 * throughputStatement turns a workflow's throughput estimate into what
 * to tell the user, or null when there is nothing worth saying.
 *
 * The multiplier is only claimed when slots limited the workflow: jobs
 * that started within minutes would not have finished sooner with a
 * smaller request, and promising "2x faster" to them would be false.
 */
export function throughputStatement(t: UtilThroughput | null | undefined): ThroughputStatement | null {
  if (!t) return null;
  const loss = t.gain < 0.95;
  if (!t.slots_limited) {
    const wait = waitPhrase(t.wait_p50);
    return {
      kind: 'unlimited',
      line: loss
        ? `Your jobs started ${wait}, so requesting the ${raisedNoun(t)} they use should cost little waiting.`
        : `Your jobs started ${wait}, so this mainly frees the pool for others.`,
    };
  }
  if (loss) {
    const noun = raisedNoun(t);
    return {
      kind: 'loss',
      line: `Requesting the ${noun} your jobs use means fewer run at once (${formatGain(t.gain)}), but each job stops competing for ${noun} it didn't ask for.`,
    };
  }
  if (t.gain < THROUGHPUT_SHOWN) return null;
  const out: ThroughputStatement = {
    kind: 'gain',
    line: `Up to ${formatGain(t.gain)} as many of these jobs could run at once.`,
  };
  const b = t.last_batch;
  if (b && b.estimated < b.elapsed) {
    out.batch =
      `Your last batch of ${b.jobs.toLocaleString('en-US')} jobs took ${formatDuration(b.elapsed)} ` +
      `from submission to the last result; with these settings, about ${formatDuration(b.estimated)}.`;
  }
  return out;
}

/**
 * throughputColumn is the workflows table's figure: the multiplier when
 * it may be claimed, nothing otherwise.
 */
export function throughputColumn(w: UtilWorkflow): number | undefined {
  const t = w.throughput;
  if (!t || !t.slots_limited) return undefined;
  if (t.gain >= 0.95 && t.gain < THROUGHPUT_SHOWN) return undefined;
  return t.gain;
}

/**
 * throughputAdviceId picks the one suggestion card that carries the
 * workflow's throughput line. The estimate is for every change together,
 * so repeating it on each card would credit the disk suggestion with what
 * the memory one does. A gain goes on the change to the resource that
 * caps how many jobs fit now; a loss on the change that raises a request.
 */
export function throughputAdviceId(w: UtilWorkflow): string | null {
  const t = w.throughput;
  if (!t) return null;
  const cards = w.advice.filter(changesRequest);
  if (cards.length === 0) return null;
  const byResource = (r: string) => cards.find((a) => a.resource === r);
  if (t.gain < 0.95) {
    const raised =
      t.suggested.cpus > t.current.cpus
        ? 'cpu'
        : t.suggested.memory_mib > t.current.memory_mib
          ? 'memory'
          : t.suggested.disk_kib > t.current.disk_kib
            ? 'disk'
            : null;
    return (raised && byResource(raised)?.id) || cards[0].id;
  }
  return byResource(t.limited_by)?.id ?? cards[0].id;
}

/** changesRequest says whether an advice card is one the estimate covers. */
export function changesRequest(a: UtilAdvice): boolean {
  return (a.resource === 'memory' || a.resource === 'cpu' || a.resource === 'disk') && a.submit.length > 0;
}

// --- Filters, owners, more jobs ---

/**
 * filterWorkflows narrows the workflows the page already has by a typed
 * substring: name, executable, owner or access point, ignoring case.
 */
export function filterWorkflows<T extends Pick<UtilWorkflowSummary, 'name' | 'executable' | 'owner' | 'schedd'>>(
  ws: T[],
  text: string,
): T[] {
  const q = text.trim().toLowerCase();
  if (!q) return ws;
  return ws.filter((w) =>
    [w.name, w.executable, w.owner, w.schedd].some((f) => f !== undefined && f.toLowerCase().includes(q)),
  );
}

/** parseOwners reads the comma-separated owner list from the URL. */
export function parseOwners(raw: string | null | undefined): string[] {
  if (!raw) return [];
  return [...new Set(raw.split(',').map((o) => o.trim()).filter(Boolean))];
}

/** parseLimit reads the job limit from the URL; nothing usable is no limit. */
export function parseLimit(raw: string | null | undefined): number | undefined {
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : undefined;
}

export interface MoreOption {
  limit: number;
  label: string;
}

/**
 * moreOptions offers bigger analyses after a truncated one: five times
 * the current limit when that is short of the ceiling, and the ceiling.
 */
export function moreOptions(limit: number, max: number): MoreOption[] {
  if (!(max > limit)) return [];
  const out: MoreOption[] = [];
  const next = limit * 5;
  if (next < max) out.push({ limit: next, label: `Analyze up to ${next.toLocaleString('en-US')} jobs` });
  out.push({
    limit: max,
    label: out.length ? `all, up to ${max.toLocaleString('en-US')}` : `Analyze all, up to ${max.toLocaleString('en-US')} jobs`,
  });
  return out;
}

/**
 * splitSingles separates workflows of exactly one job, which the table
 * folds into a single row: on a busy pool there can be hundreds of
 * one-off test runs, each a row with nothing to compare.
 */
export function splitSingles<T extends { jobs: number }>(ws: T[]): { multi: T[]; singles: T[] } {
  const multi: T[] = [];
  const singles: T[] = [];
  for (const w of ws) (w.jobs === 1 ? singles : multi).push(w);
  // One single is not worth a group row of its own.
  if (singles.length < 2) return { multi: ws, singles: [] };
  return { multi, singles };
}

// --- Jobs in a workflow (GET /api/v1/utilization/jobs) ---

export type UtilJobSort =
  | 'completed'
  | 'submitted'
  | 'wall'
  | 'memory'
  | 'cores'
  | 'efficiency'
  | 'disk'
  | 'gpu';

export interface UtilJobsResponse {
  key: string; // the workflow key asked for
  total: number; // jobs in this workflow within the analysed set
  offset: number; // offset of jobs[0]
  next_offset: number | null; // pass as `offset` for the next page; null at the end
  sort: UtilJobSort;
  order: 'asc' | 'desc';
  truncated: boolean; // the analysis read hit `limit`
  jobs: UtilJobRow[];
}

export interface UtilJobRow {
  id: string; // "cluster.proc"
  cluster: number;
  proc: number;
  schedd?: string; // multi-AP only
  owner: string;
  submitted: number | null; // unix seconds (QDate)
  started: number | null; // unix seconds, first start (JobStartDate)
  completed: number | null; // unix seconds: CompletionDate, or when a removed job left the queue
  outcome: 'ok' | 'failed' | 'removed' | 'memory_exceeded';
  exit_code: number | null;
  exit_by_signal: boolean;
  wall: number; // seconds, all runs (RemoteWallClockTime)
  request: {
    memory_mib: number | null;
    cpus: number | null;
    disk_kib: number | null;
    gpus: number | null; // null when the job requested none
  };
  memory_peak_mib: number | null;
  cores_used: number | null; // CPU seconds / wall seconds; null under 60 s of wall or unmeasured
  cpu_efficiency: number | null; // cores_used / request.cpus, a fraction
  disk_used_kib: number | null;
  gpu_utilization: number | null; // fraction of the requested GPUs kept busy
  gpu_memory_peak_mib: number | null;
  restarts: number; // max(0, NumJobStarts - 1)
  held_for_memory: boolean;
  held_for_disk: boolean;
}

/**
 * JobFocus is a range picked on one of the workflow's charts -- a bin of
 * the peak-memory histogram, say -- that the job list highlights.
 */
export interface JobFocus {
  sort: Extract<UtilJobSort, 'memory' | 'cores' | 'disk' | 'gpu'>;
  lo: number; // inclusive
  hi: number; // exclusive, except for the last bin
  label: string; // "peak memory 1.5–1.8 GB"
  // One job picked (a point of the scatter): only it is marked, and the
  // range is its own value, so the list sorts it among its neighbours.
  job?: string;
}

/** jobFocusValue is a job's value on the axis a focus was picked from. */
export function jobFocusValue(row: UtilJobRow, sort: JobFocus['sort']): number | null {
  switch (sort) {
    case 'memory':
      return row.memory_peak_mib;
    case 'cores':
      return row.cores_used;
    case 'disk':
      return row.disk_used_kib;
    case 'gpu':
      return row.gpu_utilization;
  }
}

/** inFocus says whether a job falls in a picked range. */
export function inFocus(row: UtilJobRow, focus: JobFocus | null, closed = false): boolean {
  if (!focus) return false;
  if (focus.job !== undefined) return row.id === focus.job;
  const v = jobFocusValue(row, focus.sort);
  if (v === null) return false;
  return v >= focus.lo && (closed ? v <= focus.hi : v < focus.hi);
}

/** jobArchiveHref links a finished job to its record. */
export function jobArchiveHref(row: Pick<UtilJobRow, 'id' | 'schedd'>): string {
  const id = row.schedd ? `${row.id}@${row.schedd}` : row.id;
  return `/archive/${encodeURIComponent(id)}`;
}

// --- Summaries ---

/** summaryGain is the table's throughput figure for a summary row. */
export function summaryGain(w: UtilWorkflowSummary): number | undefined {
  if (w.gain === undefined || w.slots_limited !== true) return undefined;
  if (w.gain >= 0.95 && w.gain < THROUGHPUT_SHOWN) return undefined;
  return w.gain;
}

/** actionableCount is how many of a summary's suggestions change something. */
export function actionableCount(w: Pick<UtilWorkflowSummary, 'advice'>): number {
  return w.advice.filter((a) => a.severity !== 'info').length;
}

// --- Requests that grow ---

const ADAPTIVE_GROWS: Record<UtilAdaptiveResource, string> = {
  memory: 'grows after a memory hold',
  cpus: 'grows with the job',
  disk: 'grows after a disk hold',
  gpus: 'grows with the job',
};

/**
 * requestPhrase says what a request is: "2 GB", or for one written as a
 * formula, "starts at 2 GB, grows after a memory hold". The starting value
 * alone would read as the request, which it is only until the first hold.
 */
export function requestPhrase(resource: UtilAdaptiveResource, value: string, adaptive: boolean | undefined): string {
  return adaptive ? `starts at ${value}, ${ADAPTIVE_GROWS[resource]}` : value;
}

/** requestMarkerLabel is the short form for a chart's "requested" line. */
export function requestMarkerLabel(value: string, adaptive: boolean | undefined): string {
  return adaptive ? `requested ${value}, grows` : `requested ${value}`;
}

// --- Applying advice to waiting jobs ---

export interface ApplyChange {
  advice: UtilAdvice;
  attr: 'request_memory' | 'request_cpus' | 'request_disk' | 'request_gpus';
  from: string; // the typical request now, as the page shows it
  to: string; // the value from the advice's submit line
  adaptive: boolean; // the waiting jobs' request is a formula, which an edit leaves alone
}

const ATTR_RE = /^\s*(request_(memory|cpus|disk|gpus))\s*=\s*(.+?)\s*$/i;

const CHANGE_KIND: Record<
  NonNullable<UtilAdvice['change']>['attribute'],
  (v: number) => { kind: 'memory' | 'cpus' | 'disk' | 'gpus'; to: string }
> = {
  RequestMemory: (v) => ({ kind: 'memory', to: formatMiB(v) }),
  RequestCpus: (v) => ({ kind: 'cpus', to: formatCores(v) }),
  RequestDisk: (v) => ({ kind: 'disk', to: formatKiB(v) }),
  RequestGPUs: (v) => ({ kind: 'gpus', to: formatCores(v) }),
};

/**
 * applyPlan lists what applying a workflow's advice would change on its
 * waiting jobs -- attribute, from, to -- and the request-changing advice
 * that cannot be applied, so the confirm step can say exactly what will
 * and will not happen. The values shown come from the advice; the server
 * writes its own, by advice id.
 */
export function applyPlan(
  w: UtilWorkflow,
  // The attributes the server reports as formulas on EVERY waiting job,
  // which an apply skips on all of them. Absent means none: where only
  // some waiting jobs have a formula the change still applies to the
  // rest, and the others come back as skipped.
  waitingAdaptive: UtilAdaptiveResource[] = [],
): { changes: ApplyChange[]; blocked: UtilAdvice[] } {
  const changes: ApplyChange[] = [];
  const blocked: UtilAdvice[] = [];
  for (const a of w.advice) {
    const lines = a.submit.map((l) => l.match(ATTR_RE)).filter((m): m is RegExpMatchArray => m !== null);
    if (lines.length === 0) continue;
    if (!a.applies) {
      blocked.push(a);
      continue;
    }
    // The server's own edit, when it says what it is; the submit lines
    // otherwise.
    const edits: { kind: 'memory' | 'cpus' | 'disk' | 'gpus'; to: string }[] = a.change
      ? [CHANGE_KIND[a.change.attribute](a.change.value)]
      : lines.map((m) => ({ kind: m[2].toLowerCase() as 'memory' | 'cpus' | 'disk' | 'gpus', to: m[3] }));
    for (const { kind, to } of edits) {
      const req =
        kind === 'memory' ? w.memory.request : kind === 'cpus' ? w.cpu.request : kind === 'disk' ? w.disk.request : w.gpu?.request ?? null;
      const now = !req
        ? '—'
        : kind === 'memory'
          ? formatMiB(req.typical)
          : kind === 'disk'
            ? formatKiB(req.typical)
            : formatCores(req.typical);
      changes.push({
        advice: a,
        attr: `request_${kind}`,
        from: requestPhrase(kind, now, req?.adaptive),
        to,
        adaptive: waitingAdaptive.includes(kind),
      });
    }
  }
  return { changes, blocked };
}

/** describeSet renders the values the server wrote. */
export function describeSet(set: UtilApplyResponse['set']): string[] {
  const out: string[] = [];
  if (set.RequestMemory !== undefined) out.push(`memory ${formatMiB(set.RequestMemory)}`);
  if (set.RequestCpus !== undefined) out.push(`${formatCores(set.RequestCpus)} ${set.RequestCpus === 1 ? 'CPU' : 'CPUs'}`);
  if (set.RequestDisk !== undefined) out.push(`disk ${formatKiB(set.RequestDisk)}`);
  if (set.RequestGPUs !== undefined) out.push(`${set.RequestGPUs} ${set.RequestGPUs === 1 ? 'GPU' : 'GPUs'}`);
  return out;
}

// --- The list as it arrives ---

/**
 * The list leaves out fields that hold their usual value -- for a million
 * jobs it is the difference between 5 MB and 56. These are the wire
 * forms; normalizeUtilization fills the defaults back in once, so nothing
 * downstream has to know.
 */
export type UtilWorkflowSummaryWire = Omit<
  UtilWorkflowSummary,
  'name' | 'is_dag' | 'failed' | 'removed' | 'request' | 'used' | 'advice'
> & {
  name?: string; // omitted when it equals executable
  is_dag?: boolean;
  failed?: number;
  removed?: number;
  request: Omit<UtilWorkflowSummary['request'], 'gpus'> & { gpus?: number | null };
  used: Omit<UtilWorkflowSummary['used'], 'gpu'> & { gpu?: number | null };
  advice: { id: string; severity: UtilAdvice['severity']; saves?: UtilSavings | null }[];
};

export type UtilizationResponseWire = Omit<UtilizationResponse, 'workflows'> & {
  workflows: UtilWorkflowSummaryWire[];
};

export function normalizeSummary(w: UtilWorkflowSummaryWire): UtilWorkflowSummary {
  return {
    ...w,
    name: w.name ?? w.executable,
    is_dag: w.is_dag ?? false,
    failed: w.failed ?? 0,
    removed: w.removed ?? 0,
    request: { ...w.request, gpus: w.request.gpus ?? null },
    used: { ...w.used, gpu: w.used.gpu ?? null },
    advice: w.advice.map((a) => ({ ...a, saves: a.saves ?? null })),
  };
}

export function normalizeUtilization(r: UtilizationResponseWire): UtilizationResponse {
  return { ...r, workflows: r.workflows.map(normalizeSummary), suggestions: r.suggestions ?? [] };
}

/**
 * applicableIds are the advice an apply can act on: those with at least
 * one change the waiting jobs will take. A change to a request that is a
 * formula on those jobs is not one -- the server leaves it alone -- so
 * offering it would promise an edit that will not happen.
 */
export function applicableIds(changes: ApplyChange[]): string[] {
  return [...new Set(changes.filter((c) => !c.adaptive).map((c) => c.advice.id))];
}
