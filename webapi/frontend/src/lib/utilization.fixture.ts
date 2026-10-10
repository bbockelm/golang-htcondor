import type {
  UtilAdvice,
  UtilBatchPoint,
  UtilDistribution,
  UtilMemoryCurvePoint,
  UtilRequest,
  UtilResourceSummary,
  UtilSample,
  UtilWorkflow,
  UtilizationResponse,
} from './utilization';

// A realistic /api/v1/utilization answer for the component tests and the
// smoke suite, built from simulated jobs rather than typed in by hand.
//
// Generated, not literal, because the response is full of figures that
// must agree with each other -- a histogram that sums to the job count,
// percentiles inside it, a memory curve whose minimum is the
// recommendation, a summary that is the sum of its workflows. A literal
// fixture that got one of those wrong would test the page against data
// no server sends. The generator is seeded, so every run is identical.
//
// Only type imports above: the dev mock server loads this file directly
// with Node's type stripping, which cannot resolve the `@/` alias.

const MIB_PER_GIB = 1024;
const KIB_PER_GIB = 1024 * 1024;

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function gaussian(r: () => number): number {
  const u = Math.max(r(), 1e-9);
  const v = r();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}

function lognormal(r: () => number, median: number, sigma: number): number {
  return median * Math.exp(sigma * gaussian(r));
}

function quantile(sorted: number[], q: number): number {
  if (sorted.length === 0) return 0;
  const i = (sorted.length - 1) * q;
  const lo = Math.floor(i);
  const hi = Math.ceil(i);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (i - lo);
}

export function distribution(values: number[], bins = 20): UtilDistribution | null {
  if (values.length === 0) return null;
  const s = [...values].sort((a, b) => a - b);
  const min = s[0];
  const max = s[s.length - 1];
  const lo0 = 0;
  const width = (max > lo0 ? max - lo0 : 1) / bins;
  const histogram = Array.from({ length: bins }, (_, i) => ({
    lo: lo0 + i * width,
    hi: lo0 + (i + 1) * width,
    count: 0,
  }));
  for (const v of s) {
    const i = Math.min(bins - 1, Math.floor((v - lo0) / width));
    histogram[i].count++;
  }
  return {
    n: s.length,
    min,
    p10: quantile(s, 0.1),
    p25: quantile(s, 0.25),
    p50: quantile(s, 0.5),
    p75: quantile(s, 0.75),
    p90: quantile(s, 0.9),
    p95: quantile(s, 0.95),
    p99: quantile(s, 0.99),
    max,
    histogram,
  };
}

function requestOf(values: number[]): UtilRequest | null {
  if (values.length === 0) return null;
  const counts = new Map<number, number>();
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1);
  let typical = values[0];
  let best = -1;
  for (const [v, c] of counts) {
    if (c > best) {
      best = c;
      typical = v;
    }
  }
  return {
    typical,
    min: Math.min(...values),
    max: Math.max(...values),
    distinct: counts.size,
  };
}

interface SimJob {
  cluster: number;
  qdate: number;
  wall: number; // seconds
  reqMem: number; // MiB
  reqCpu: number;
  reqDisk: number; // KiB
  reqGpu: number;
  mem: number | null;
  cores: number | null;
  disk: number | null;
  gpuUtil: number | null;
  outcome: UtilSample['outcome'];
  restartLost: number; // seconds of wall lost to earlier, evicted runs
}

interface WorkflowSpec {
  key: string;
  name: string;
  executable: string;
  owner: string;
  is_dag: boolean;
  seed: number;
  jobs: number;
  batches: number;
  clusterBase: number;
  // Per-batch requests, so a workflow can show a change over time.
  reqMem: (batch: number) => number;
  reqCpu: (batch: number) => number;
  reqDisk: number;
  reqGpu?: number;
  memMedian: number;
  memSigma: number;
  coresMedian: number;
  diskMedian: number;
  wallMedian: number;
  wallSigma: number;
  pFailed: number;
  pRemoved: number;
  pRestart: number;
  gpuMedian?: number;
  advice: (ctx: AdviceContext) => UtilAdvice[];
}

interface AdviceContext {
  n: number;
  memory: UtilDistribution | null;
  cores: UtilDistribution | null;
  disk: UtilDistribution | null;
  curve: UtilMemoryCurvePoint[];
  reqMem: UtilRequest | null;
  reqCpu: UtilRequest | null;
  reqDisk: UtilRequest | null;
  wallHours: number;
  confidence: UtilAdvice['confidence'];
}

const NOW = 1_760_100_000; // fixed: the fixture must not move under the tests
const DAY = 86400;

function gb(mib: number): string {
  const g = mib / MIB_PER_GIB;
  return `${g >= 10 ? Math.round(g) : Math.round(g * 10) / 10} GB`;
}

// submitMem writes a request the way a person would: whole GB when it is
// one, MB otherwise.
function submitMem(mib: number): string {
  return mib % MIB_PER_GIB === 0 ? `${mib / MIB_PER_GIB} GB` : `${mib} MB`;
}

function simulate(spec: WorkflowSpec): SimJob[] {
  const r = mulberry32(spec.seed);
  const jobs: SimJob[] = [];
  const perBatch = Math.ceil(spec.jobs / spec.batches);
  for (let i = 0; i < spec.jobs; i++) {
    const batch = Math.floor(i / perBatch);
    const reqMem = spec.reqMem(batch);
    const reqCpu = spec.reqCpu(batch);
    const mem = Math.round(lognormal(r, spec.memMedian, spec.memSigma));
    const wall = Math.max(30, Math.round(lognormal(r, spec.wallMedian, spec.wallSigma)));
    const measured = r() > 0.03;
    let outcome: UtilSample['outcome'] = 'ok';
    // A job over its memory request is put on hold; say so rather than
    // calling it a plain failure.
    if (mem > reqMem * 1.05) outcome = 'memory_exceeded';
    else if (r() < spec.pRemoved) outcome = 'removed';
    else if (r() < spec.pFailed) outcome = 'failed';
    jobs.push({
      cluster: spec.clusterBase + batch * 7,
      qdate: NOW - (spec.batches - batch) * (6.5 * DAY / spec.batches) - r() * 3600,
      wall,
      reqMem,
      reqCpu,
      reqDisk: spec.reqDisk,
      reqGpu: spec.reqGpu ?? 0,
      mem: measured ? mem : null,
      cores: measured
        ? Math.min(reqCpu * 1.1, Math.max(0.05, lognormal(r, spec.coresMedian * Math.min(1, reqCpu / spec.reqCpu(0)), 0.18)))
        : null,
      disk: measured ? Math.round(lognormal(r, spec.diskMedian, 0.35)) : null,
      gpuUtil: spec.reqGpu ? Math.min(1, Math.max(0.01, lognormal(r, spec.gpuMedian ?? 0.5, 0.5))) : null,
      outcome,
      restartLost: r() < spec.pRestart ? Math.round(wall * (0.2 + r() * 0.6)) : 0,
    });
  }
  return jobs;
}

// Candidate requests: quarter-GB steps where jobs usually sit, coarser
// above, the way people actually write request_memory.
const GRID_GIB = [
  ...Array.from({ length: 16 }, (_, i) => 0.25 * (i + 1)),
  4.5, 5, 5.5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 64,
];

function memoryCurve(jobs: SimJob[], current: number): UtilMemoryCurvePoint[] {
  const peaks = jobs.filter((j) => j.mem !== null) as (SimJob & { mem: number })[];
  if (peaks.length < 20) return [];
  const max = Math.max(...peaks.map((j) => j.mem));
  const lowest = quantile(peaks.map((j) => j.mem).sort((a, b) => a - b), 0.1);
  const top = Math.max(current, max) * 1.15;
  const grid = GRID_GIB.map((g) => g * MIB_PER_GIB);
  const retryFor = grid.find((g) => g >= max) ?? max;
  const cands = grid.filter((g) => g >= lowest && g <= top);
  if (!cands.includes(current)) cands.push(current);
  cands.sort((a, b) => a - b);
  const pts = cands.map((req) => {
    let reserved = 0;
    let over = 0;
    for (const j of peaks) {
      const h = j.wall / 3600;
      reserved += req * h;
      if (j.mem > req) {
        over++;
        // The first attempt is lost and the job reruns at the retry size.
        reserved += retryFor * h;
      }
    }
    return {
      request_mib: req,
      retry_mib: over > 0 ? retryFor : null,
      reserved_mib_hours: reserved,
      retry_fraction: over / peaks.length,
      is_current: req === current,
      is_recommended: false,
    };
  });
  let best = 0;
  for (let i = 1; i < pts.length; i++) {
    if (pts[i].reserved_mib_hours < pts[best].reserved_mib_hours) best = i;
  }
  pts[best].is_recommended = true;
  return pts;
}

function summaries(jobs: SimJob[], withGpu: boolean): UtilResourceSummary[] {
  const sum = (
    resource: UtilResourceSummary['resource'],
    req: (j: SimJob) => number,
    used: (j: SimJob) => number | null,
  ): UtilResourceSummary => {
    let allocated = 0;
    let measured = 0;
    let usedH = 0;
    let n = 0;
    for (const j of jobs) {
      const h = j.wall / 3600;
      allocated += req(j) * h;
      const u = used(j);
      if (u !== null) {
        measured += req(j) * h;
        usedH += u * h;
        n++;
      }
    }
    return {
      resource,
      allocated_hours: allocated,
      used_hours: n > 0 ? usedH : null,
      allocated_hours_measured: measured,
      jobs_measured: n,
    };
  };
  const out = [
    sum('cpu', (j) => j.reqCpu, (j) => j.cores),
    sum('memory', (j) => j.reqMem, (j) => j.mem),
    sum('disk', (j) => j.reqDisk, (j) => j.disk),
  ];
  if (withGpu) {
    out.push(sum('gpu', (j) => j.reqGpu, (j) => (j.gpuUtil === null ? null : j.gpuUtil * j.reqGpu)));
  }
  return out;
}

function nonNull(vs: (number | null)[]): number[] {
  return vs.filter((v): v is number => v !== null);
}

function buildWorkflow(spec: WorkflowSpec): UtilWorkflow {
  const jobs = simulate(spec);
  const memory = distribution(nonNull(jobs.map((j) => j.mem)));
  const cores = distribution(nonNull(jobs.map((j) => j.cores)));
  const disk = distribution(nonNull(jobs.map((j) => j.disk)));
  const wall = distribution(jobs.map((j) => j.wall));
  const reqMem = requestOf(jobs.map((j) => j.reqMem));
  const reqCpu = requestOf(jobs.map((j) => j.reqCpu));
  const reqDisk = requestOf(jobs.map((j) => j.reqDisk));
  const curve = memoryCurve(jobs, reqMem?.typical ?? 0);
  const efficiency = distribution(nonNull(jobs.map((j) => (j.cores === null ? null : j.cores / j.reqCpu))));
  const wallHours = jobs.reduce((a, j) => a + j.wall, 0) / 3600;

  const byCluster = new Map<number, SimJob[]>();
  for (const j of jobs) {
    const list = byCluster.get(j.cluster) ?? [];
    list.push(j);
    byCluster.set(j.cluster, list);
  }
  const batches: UtilBatchPoint[] = [...byCluster.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([id, js]) => {
      const m = distribution(nonNull(js.map((j) => j.mem)));
      const c = distribution(nonNull(js.map((j) => j.cores)));
      const w = distribution(js.map((j) => j.wall));
      return {
        id,
        submitted: Math.round(Math.min(...js.map((j) => j.qdate))),
        jobs: js.length,
        memory_request_mib: requestOf(js.map((j) => j.reqMem))?.typical ?? null,
        memory_p95_mib: m ? Math.round(m.p95) : null,
        cpu_request: requestOf(js.map((j) => j.reqCpu))?.typical ?? null,
        cpu_cores_p50: c ? c.p50 : null,
        wall_p50: w ? Math.round(w.p50) : null,
      };
    });

  const step = Math.max(1, Math.floor(jobs.length / 400));
  const samples: UtilSample[] = jobs
    .filter((_, i) => i % step === 0)
    .slice(0, 400)
    .map((j) => ({
      memory_mib: j.mem,
      wall: j.wall,
      cores: j.cores === null ? null : Math.round(j.cores * 100) / 100,
      disk_kib: j.disk,
      outcome: j.outcome,
    }));

  const n = jobs.length;
  const restarted = jobs.filter((j) => j.restartLost > 0);
  return {
    key: spec.key,
    name: spec.name,
    executable: spec.executable,
    owner: spec.owner,
    is_dag: spec.is_dag,
    jobs: n,
    succeeded: jobs.filter((j) => j.outcome === 'ok').length,
    failed: jobs.filter((j) => j.outcome === 'failed' || j.outcome === 'memory_exceeded').length,
    removed: jobs.filter((j) => j.outcome === 'removed').length,
    wall_hours: wallHours,
    wall,
    short_jobs: jobs.filter((j) => j.wall < 600 && j.outcome === 'ok').length,
    restarts: {
      jobs: restarted.length,
      lost_hours: restarted.reduce((a, j) => a + j.restartLost, 0) / 3600,
    },
    holds: { memory: jobs.filter((j) => j.outcome === 'memory_exceeded').length, disk: 0 },
    resources: summaries(jobs, !!spec.reqGpu),
    memory: { request: reqMem, peak_mib: memory },
    cpu: { request: reqCpu, cores_used: cores, efficiency },
    disk: { request: reqDisk, used_kib: disk },
    gpu: spec.reqGpu
      ? {
          request: requestOf(jobs.map((j) => j.reqGpu)),
          utilization: distribution(nonNull(jobs.map((j) => j.gpuUtil))),
        }
      : null,
    memory_curve: curve,
    advice: spec.advice({
      n,
      memory,
      cores,
      disk,
      curve,
      reqMem,
      reqCpu,
      reqDisk,
      wallHours,
      confidence: n < 50 ? 'low' : n < 200 ? 'medium' : 'high',
    }),
    batches: batches.slice(-50),
    samples,
  };
}

function curveSaves(ctx: AdviceContext): number {
  const cur = ctx.curve.find((p) => p.is_current);
  const rec = ctx.curve.find((p) => p.is_recommended);
  if (!cur || !rec) return 0;
  return Math.max(0, (cur.reserved_mib_hours - rec.reserved_mib_hours) / MIB_PER_GIB);
}

const SPECS: WorkflowSpec[] = [
  {
    key: 'wf-blast',
    name: 'blast-search',
    executable: 'run_blast.sh',
    owner: 'alice',
    is_dag: false,
    seed: 11,
    jobs: 1204,
    batches: 14,
    clusterBase: 81200,
    // Asked for 8 GB until the last few submissions, then 4 GB: the
    // over-time chart should show the change.
    reqMem: (b) => (b < 10 ? 8 * MIB_PER_GIB : 4 * MIB_PER_GIB),
    reqCpu: () => 1,
    reqDisk: 10 * KIB_PER_GIB,
    memMedian: 1300,
    memSigma: 0.22,
    coresMedian: 0.96,
    diskMedian: 1.8 * KIB_PER_GIB,
    wallMedian: 2400,
    wallSigma: 0.5,
    pFailed: 0.01,
    pRemoved: 0.005,
    pRestart: 0.02,
    advice: (ctx) => {
      const rec = ctx.curve.find((p) => p.is_recommended);
      const recMib = rec?.request_mib ?? 2048;
      const retry = ctx.curve.find((p) => p.is_recommended)?.retry_mib ?? null;
      return [
        {
          id: retry ? 'memory-retry' : 'memory-lower',
          resource: 'memory',
          severity: 'suggest',
          title: retry
            ? `Request ${gb(recMib)} of memory and retry at ${gb(retry)}`
            : `Request ${gb(recMib)} of memory`,
          detail: `95% of ${ctx.n.toLocaleString('en-US')} jobs peaked under ${gb(ctx.memory?.p95 ?? 0)}; the largest peaked at ${gb(ctx.memory?.max ?? 0)}. Most asked for ${gb(ctx.reqMem?.typical ?? 0)}.`,
          submit: retry
            ? [`request_memory = ${submitMem(recMib)}`, `retry_request_memory = ${submitMem(retry)}`]
            : [`request_memory = ${submitMem(recMib)}`],
          saves: { unit: 'gib_hours', amount: curveSaves(ctx) },
          confidence: ctx.confidence,
        },
        {
          id: 'disk-lower',
          resource: 'disk',
          severity: 'suggest',
          title: 'Request 3 GB of disk',
          detail: `Jobs asked for ${gb((ctx.reqDisk?.typical ?? 0) / 1024)} of disk; 99% used under ${gb((ctx.disk?.p99 ?? 0) / 1024)}.`,
          submit: ['request_disk = 3 GB'],
          saves: null,
          confidence: ctx.confidence,
        },
      ];
    },
  },
  {
    key: 'wf-train',
    name: 'train-resnet',
    executable: 'train.py',
    owner: 'alice',
    is_dag: false,
    seed: 23,
    jobs: 64,
    batches: 6,
    clusterBase: 81240,
    reqMem: () => 32 * MIB_PER_GIB,
    reqCpu: () => 8,
    reqDisk: 40 * KIB_PER_GIB,
    reqGpu: 1,
    gpuMedian: 0.34,
    memMedian: 11.5 * MIB_PER_GIB,
    memSigma: 0.12,
    coresMedian: 2.1,
    diskMedian: 22 * KIB_PER_GIB,
    wallMedian: 6 * 3600,
    wallSigma: 0.35,
    pFailed: 0.03,
    pRemoved: 0.02,
    pRestart: 0.12,
    advice: (ctx) => [
      {
        id: 'cpus-lower',
        resource: 'cpu',
        severity: 'suggest',
        title: 'Request 3 CPUs',
        detail: `These jobs asked for ${ctx.reqCpu?.typical ?? 0} CPUs and kept a median of ${(ctx.cores?.p50 ?? 0).toFixed(1)} busy; 90% used fewer than ${(ctx.cores?.p90 ?? 0).toFixed(1)}.`,
        submit: ['request_cpus = 3'],
        saves: { unit: 'core_hours', amount: ctx.wallHours * 5 },
        confidence: ctx.confidence,
      },
      {
        id: 'gpu-idle',
        resource: 'gpu',
        severity: 'warn',
        title: 'The GPU sat idle most of the time',
        detail: 'Half of these jobs kept their GPU busy less than 35% of the time. Feeding it data faster, or fitting two runs on one GPU, would use it better.',
        submit: [],
        saves: { unit: 'gpu_hours', amount: ctx.wallHours * 0.6 },
        confidence: ctx.confidence,
      },
      {
        id: 'restarts',
        resource: 'runtime',
        severity: 'suggest',
        title: 'Save checkpoints so restarts resume',
        detail: '8 jobs were interrupted and started over, losing about 20 hours of run time.',
        submit: ['checkpoint_exit_code = 85'],
        saves: null,
        confidence: 'low',
      },
    ],
  },
  {
    key: 'wf-assemble',
    name: 'genome-assembly',
    executable: 'assemble.sh',
    owner: 'bob',
    is_dag: true,
    seed: 37,
    jobs: 310,
    batches: 9,
    clusterBase: 80900,
    reqMem: () => 2 * MIB_PER_GIB,
    reqCpu: () => 4,
    reqDisk: 8 * KIB_PER_GIB,
    memMedian: 1750,
    memSigma: 0.2,
    coresMedian: 3.7,
    diskMedian: 6.5 * KIB_PER_GIB,
    wallMedian: 1.5 * 3600,
    wallSigma: 0.4,
    pFailed: 0.02,
    pRemoved: 0.01,
    pRestart: 0.03,
    advice: (ctx) => {
      const rec = ctx.curve.find((p) => p.is_recommended);
      const over = ctx.curve.find((p) => p.is_current)?.retry_fraction ?? 0;
      return [
        {
          id: 'memory-raise',
          resource: 'memory',
          severity: 'warn',
          title: `Request ${gb(rec?.request_mib ?? 3072)} of memory`,
          detail: `${Math.round(over * 100)}% of ${ctx.n} jobs went over their ${gb(ctx.reqMem?.typical ?? 0)} request and were held; the largest peaked at ${gb(ctx.memory?.max ?? 0)}.`,
          submit: rec?.retry_mib
            ? [`request_memory = ${submitMem(rec.request_mib)}`, `retry_request_memory = ${submitMem(rec.retry_mib)}`]
            : [`request_memory = ${submitMem(rec?.request_mib ?? 3072)}`],
          saves: { unit: 'gib_hours', amount: curveSaves(ctx) },
          confidence: ctx.confidence,
        },
        {
          id: 'disk-raise',
          resource: 'disk',
          severity: 'suggest',
          title: 'Request 10 GB of disk',
          detail: 'One in ten jobs came within 5% of its 8 GB disk request.',
          submit: ['request_disk = 10 GB'],
          saves: null,
          confidence: ctx.confidence,
        },
      ];
    },
  },
  {
    key: 'wf-post',
    name: 'summarize',
    executable: 'summarize.py',
    owner: 'alice',
    is_dag: false,
    seed: 41,
    jobs: 18,
    batches: 3,
    clusterBase: 81300,
    reqMem: () => 1024,
    reqCpu: () => 1,
    reqDisk: 1 * KIB_PER_GIB,
    memMedian: 600,
    memSigma: 0.15,
    coresMedian: 0.8,
    diskMedian: 0.2 * KIB_PER_GIB,
    wallMedian: 140,
    wallSigma: 0.5,
    pFailed: 0.05,
    pRemoved: 0,
    pRestart: 0,
    advice: () => [
      {
        id: 'short-jobs',
        resource: 'runtime',
        severity: 'suggest',
        title: 'Bundle these jobs into fewer, longer ones',
        detail: 'Most of these jobs ran for under 5 minutes, so starting each one took a large share of its time.',
        submit: [],
        saves: null,
        confidence: 'low',
      },
      {
        id: 'memory-ok',
        resource: 'memory',
        severity: 'info',
        title: 'Memory request fits',
        detail: 'Every job peaked between 45% and 80% of its 1 GB request.',
        submit: [],
        saves: null,
        confidence: 'low',
      },
    ],
  },
];

function combine(ws: UtilWorkflow[]): UtilResourceSummary[] {
  const by = new Map<string, UtilResourceSummary>();
  for (const w of ws) {
    for (const r of w.resources) {
      const acc = by.get(r.resource);
      if (!acc) {
        by.set(r.resource, { ...r });
        continue;
      }
      acc.allocated_hours += r.allocated_hours;
      acc.allocated_hours_measured += r.allocated_hours_measured;
      acc.jobs_measured += r.jobs_measured;
      acc.used_hours =
        acc.used_hours === null && r.used_hours === null
          ? null
          : (acc.used_hours ?? 0) + (r.used_hours ?? 0);
    }
  }
  return [...by.values()];
}

export function buildUtilizationFixture(): UtilizationResponse {
  const workflows = SPECS.map(buildWorkflow).sort((a, b) => b.wall_hours - a.wall_hours);
  const jobs = workflows.reduce((a, w) => a + w.jobs, 0);
  const wallHours = workflows.reduce((a, w) => a + w.wall_hours, 0);
  // Failed runs' whole wall time plus the part of restarted runs that was
  // thrown away. Approximate per workflow: failures at median wall.
  const badput = workflows.reduce(
    (a, w) => a + w.restarts.lost_hours + (w.failed * (w.wall?.p50 ?? 0)) / 3600,
    0,
  );
  return {
    since: NOW - 7 * DAY,
    until: NOW,
    days: 7,
    jobs_considered: jobs,
    truncated: false,
    overall: {
      jobs,
      wall_hours: wallHours,
      badput_hours: badput,
      resources: combine(workflows),
    },
    workflows,
  };
}

export const utilizationFixture: UtilizationResponse = buildUtilizationFixture();
