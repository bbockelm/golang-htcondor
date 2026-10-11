import type {
  UtilAdvice,
  UtilBatchPoint,
  UtilDistribution,
  UtilMemoryCurvePoint,
  UtilRequest,
  UtilResourceSummary,
  UtilSample,
  UtilWorkflow,
  UtilShape,
  UtilThroughput,
  UtilizationResponse,
  UtilWorkflowSummary,
  UtilSuggestion,
  UtilWorkflowDetail,
  UtilJobRow,
  UtilJobSort,
  UtilJobsResponse,
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
  gpuMem: number | null; // MiB, peak GPU memory
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
  gpuMemMedian?: number; // MiB
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
      // One GPU job in ten has no utilization measurement.
      gpuUtil:
        spec.reqGpu && r() > 0.1 ? Math.min(1, Math.max(0.01, lognormal(r, spec.gpuMedian ?? 0.5, 0.5))) : null,
      gpuMem: spec.reqGpu ? Math.round(lognormal(r, spec.gpuMemMedian ?? 4096, 0.2)) : null,
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
        gpu_request: js.some((j) => j.reqGpu > 0) ? requestOf(js.map((j) => j.reqGpu))!.typical : null,
        gpu_util_p50: distribution(nonNull(js.map((j) => j.gpuUtil)))?.p50 ?? null,
      };
    });

  const step = Math.max(1, Math.floor(jobs.length / 400));
  // Job ids the way jobRows numbers them: procs count up within a cluster.
  const procs = new Map<number, number>();
  const ids = jobs.map((j) => {
    const proc = procs.get(j.cluster) ?? 0;
    procs.set(j.cluster, proc + 1);
    return `${j.cluster}.${proc}`;
  });
  const samples: UtilSample[] = jobs
    .map((j, i) => ({ j, id: ids[i] }))
    .filter((_, i) => i % step === 0)
    .slice(0, 400)
    .map(({ j, id }) => ({
      memory_mib: j.mem,
      wall: j.wall,
      cores: j.cores === null ? null : Math.round(j.cores * 100) / 100,
      disk_kib: j.disk,
      outcome: j.outcome,
      job: id,
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
          jobs: jobs.filter((j) => j.reqGpu > 0).length,
          measured: jobs.filter((j) => j.gpuUtil !== null).length,
          utilization: distribution(nonNull(jobs.map((j) => j.gpuUtil))),
          memory_peak_mib: distribution(nonNull(jobs.map((j) => j.gpuMem))),
          device_memory_mib: 40 * MIB_PER_GIB, // an A100 40GB
          cores_used_while_gpu: cores,
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
    throughput: null, // filled in by withThroughput
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
    gpuMemMedian: 2.9 * MIB_PER_GIB,
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
        id: 'gpu-memory-small',
        resource: 'gpu',
        severity: 'suggest',
        title: 'Your jobs fit GPUs with 8 GB of memory',
        detail: 'The largest of 64 jobs used 4.1 GB of GPU memory; they all ran on 40 GB GPUs.',
        submit: ['gpus_minimum_memory = 8192'],
        saves: null,
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
  // One-off runs: a debugging job, an environment check, a probe. The
  // table folds these into one row.
  ...(['debug-run', 'check-env', 'probe-node'] as const).map(
    (name, i): WorkflowSpec => ({
      key: `wf-single-${i}`,
      name,
      executable: `${name}.sh`,
      owner: ['carol', 'dave', 'alice'][i],
      is_dag: false,
      seed: 101 + i,
      jobs: 1,
      batches: 1,
      clusterBase: 81400 + i * 3,
      reqMem: () => 2048,
      reqCpu: () => 1,
      reqDisk: 1 * KIB_PER_GIB,
      memMedian: 300 + i * 200,
      memSigma: 0.1,
      coresMedian: 0.6,
      diskMedian: 0.1 * KIB_PER_GIB,
      wallMedian: 300 + i * 900,
      wallSigma: 0.2,
      pFailed: 0,
      pRemoved: 0,
      pRestart: 0,
      advice: () => [],
    }),
  ),
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

// --- Throughput ---
//
// A pool of two machine types, and for each workflow the shape its advice
// leads to, how long its jobs waited, and how long its last batch took.
// The arithmetic follows the contract: copies of a shape per machine,
// gain = fit ratio with reruns charged against the suggestion.

const CPU_MACHINE: UtilShape = { cpus: 32, memory_mib: 128 * MIB_PER_GIB, disk_kib: 500 * KIB_PER_GIB, gpus: 0 };
const GPU_MACHINE: UtilShape = { cpus: 64, memory_mib: 512 * MIB_PER_GIB, disk_kib: 2000 * KIB_PER_GIB, gpus: 4 };

interface ThroughputSpec {
  suggested: (w: UtilWorkflow) => Partial<UtilShape>;
  waitP50: number; // seconds
  lastBatchHours: number;
}

const THROUGHPUT: Record<string, ThroughputSpec> = {
  'wf-blast': {
    suggested: (w) => ({ memory_mib: w.memory_curve.find((p) => p.is_recommended)?.request_mib, disk_kib: 3 * KIB_PER_GIB }),
    waitP50: 2.5 * 3600,
    lastBatchHours: 14,
  },
  // Started within minutes: the estimate frees the pool, it does not
  // speed these jobs up.
  'wf-train': { suggested: () => ({ cpus: 3 }), waitP50: 4 * 60, lastBatchHours: 9 },
  // Raising memory: fewer run at once.
  'wf-assemble': {
    suggested: (w) => ({ memory_mib: w.memory_curve.find((p) => p.is_recommended)?.request_mib, disk_kib: 10 * KIB_PER_GIB }),
    waitP50: 40 * 60,
    lastBatchHours: 6,
  },
};

function fit(shape: UtilShape, m: UtilShape): { n: number; by: UtilThroughput['limited_by'] } {
  const caps: [UtilThroughput['limited_by'], number][] = [
    ['cpu', m.cpus / shape.cpus],
    ['memory', m.memory_mib / shape.memory_mib],
    ['disk', m.disk_kib / shape.disk_kib],
  ];
  if (shape.gpus > 0) caps.push(['gpu', m.gpus / shape.gpus]);
  caps.sort((a, b) => a[1] - b[1]);
  return { n: Math.floor(caps[0][1]), by: caps[0][0] };
}

function withThroughput(w: UtilWorkflow): UtilWorkflow {
  const spec = THROUGHPUT[w.key];
  if (!spec || !w.memory.request || !w.cpu.request || !w.disk.request) return w;
  const current: UtilShape = {
    cpus: w.cpu.request.typical,
    memory_mib: w.memory.request.typical,
    disk_kib: w.disk.request.typical,
    gpus: w.gpu?.request?.typical ?? 0,
  };
  const over = spec.suggested(w);
  const suggested: UtilShape = {
    cpus: over.cpus ?? current.cpus,
    memory_mib: over.memory_mib ?? current.memory_mib,
    disk_kib: over.disk_kib ?? current.disk_kib,
    gpus: current.gpus,
  };
  const machine = current.gpus > 0 ? GPU_MACHINE : CPU_MACHINE;
  const fc = fit(current, machine);
  const fs = fit(suggested, machine);
  const at = w.memory_curve.find((p) => p.request_mib === suggested.memory_mib);
  const reruns = at?.retry_fraction ?? 0;
  const gain = fs.n / fc.n / (1 + reruns);
  const batch = [...w.batches].reverse().find((b) => b.jobs >= 20);
  const elapsed = spec.lastBatchHours * 3600;
  return {
    ...w,
    throughput: {
      current,
      suggested,
      retry_memory_mib: at?.retry_mib ?? null,
      fit_current: fc.n,
      fit_suggested: fs.n,
      gain,
      limited_by: fc.by,
      wait_p50: spec.waitP50,
      slots_limited: spec.waitP50 >= 900,
      last_batch: batch
        ? { id: batch.id, jobs: batch.jobs, elapsed, estimated: Math.max(w.wall?.max ?? 0, elapsed / gain) }
        : null,
    },
  };
}

// throughputGain is the pool-wide figure: occupancy per unit of work,
// summed, before over after. Workflows with no estimate count the same
// on both sides.
function throughputGain(ws: UtilWorkflow[]): number | null {
  let before = 0;
  let after = 0;
  for (const w of ws) {
    const t = w.throughput;
    const occ = t ? w.wall_hours / t.fit_current : w.wall_hours / 32;
    before += occ;
    after += t ? occ / t.gain : occ;
  }
  return after > 0 ? before / after : null;
}

// changeOf turns an advice's first request line into the edit the server
// would make: "request_memory = 1792 MB" -> RequestMemory 1792 (MiB).
function changeOf(submit: string[]): UtilAdvice['change'] {
  for (const l of submit) {
    const m = l.match(/^request_(memory|cpus|disk)\s*=\s*([\d.]+)\s*(GB|MB)?/i);
    if (!m) continue;
    const n = Number(m[2]);
    const mib = m[3]?.toUpperCase() === 'GB' ? n * MIB_PER_GIB : n;
    if (m[1] === 'memory') return { attribute: 'RequestMemory', value: mib };
    if (m[1] === 'disk') return { attribute: 'RequestDisk', value: mib * 1024 };
    return { attribute: 'RequestCpus', value: n };
  }
  return undefined;
}

// Advice a queued job can take: a change to a plain request. A GPU
// memory requirement lives in the job's requirements, not a request.
function withApplies(w: UtilWorkflow): UtilWorkflow {
  return {
    ...w,
    advice: w.advice.map((a) => {
      const applies = ['memory', 'cpu', 'disk'].includes(a.resource) && a.submit.some((l) => /^request_/.test(l));
      return applies ? { ...a, applies, change: changeOf(a.submit) } : { ...a, applies };
    }),
  };
}

// genome-assembly asks for memory with a formula that grows after a
// hold, the way real workflows do: the summary and the charts must say
// "starts at", not report the starting value as the request.
function withAdaptive(w: UtilWorkflow): UtilWorkflow {
  if (w.key !== 'wf-assemble' || !w.memory.request) return w;
  return {
    ...w,
    memory: {
      ...w.memory,
      request: {
        ...w.memory.request,
        adaptive: true,
        expression: 'ifThenElse(MemoryUsage isnt undefined, max({2048, 3 * MemoryUsage / 2}), 2048)',
      },
    },
  };
}

/** fullWorkflows are the fixture's workflows with every detail. */
export const fullWorkflows: UtilWorkflow[] = SPECS.map(buildWorkflow)
  .map(withThroughput)
  .map(withApplies)
  .map(withAdaptive)
  .sort((a, b) => b.wall_hours - a.wall_hours);

function usedOf(w: UtilWorkflow, r: 'cpu' | 'memory' | 'disk' | 'gpu'): number | null {
  const s = w.resources.find((x) => x.resource === r);
  if (!s || s.used_hours === null || !(s.allocated_hours_measured > 0)) return null;
  return s.used_hours / s.allocated_hours_measured;
}

/** summarize is a workflow as the list carries it. */
export function summarize(w: UtilWorkflow): UtilWorkflowSummary {
  const adaptive = (
    [
      ['memory', w.memory.request],
      ['cpus', w.cpu.request],
      ['disk', w.disk.request],
      ['gpus', w.gpu?.request ?? null],
    ] as const
  )
    .filter(([, r]) => r?.adaptive)
    .map(([k]) => k);
  return {
    key: w.key,
    name: w.name,
    executable: w.executable,
    owner: w.owner,
    schedd: w.schedd,
    is_dag: w.is_dag,
    jobs: w.jobs,
    succeeded: w.succeeded,
    failed: w.failed,
    removed: w.removed,
    wall_hours: w.wall_hours,
    ...(w.holds.memory || w.holds.disk ? { holds: w.holds } : {}),
    request: {
      memory_mib: w.memory.request?.typical ?? null,
      cpus: w.cpu.request?.typical ?? null,
      disk_kib: w.disk.request?.typical ?? null,
      gpus: w.gpu?.request?.typical ?? null,
      ...(adaptive.length ? { adaptive: [...adaptive] } : {}),
    },
    used: { cpu: usedOf(w, 'cpu'), memory: usedOf(w, 'memory'), disk: usedOf(w, 'disk'), gpu: usedOf(w, 'gpu') },
    ...(w.gpu ? { gpu_hours: w.resources.find((r) => r.resource === 'gpu')?.allocated_hours } : {}),
    ...(w.throughput ? { gain: w.throughput.gain, slots_limited: w.throughput.slots_limited } : {}),
    advice: w.advice.map((a) => ({ id: a.id, severity: a.severity, saves: a.saves })),
  };
}

// The server's ranking: severity, then GPU-hour savings first, then
// larger savings.
function rankSuggestions(ws: UtilWorkflow[]): UtilSuggestion[] {
  const sev: Record<UtilAdvice['severity'], number> = { warn: 0, suggest: 1, info: 2 };
  const out: UtilSuggestion[] = [];
  for (const w of ws) {
    for (const a of w.advice) {
      if (a.severity === 'info') continue;
      out.push({
        key: w.key,
        name: w.name,
        executable: w.executable,
        owner: w.owner,
        id: a.id,
        resource: a.resource,
        severity: a.severity,
        title: a.title,
        saves: a.saves,
        confidence: a.confidence,
      });
    }
  }
  return out.sort(
    (x, y) =>
      sev[x.severity] - sev[y.severity] ||
      (x.saves?.unit === 'gpu_hours' ? 0 : 1) - (y.saves?.unit === 'gpu_hours' ? 0 : 1) ||
      (y.saves?.amount ?? -1) - (x.saves?.amount ?? -1),
  );
}

// Queued jobs per workflow, for the apply flow.
const WAITING: Record<string, number> = { 'wf-blast': 120, 'wf-assemble': 40 };

/** utilizationWorkflowFixture answers GET /api/v1/utilization/workflow. */
export function utilizationWorkflowFixture(key: string): UtilWorkflowDetail | null {
  const w = fullWorkflows.find((x) => x.key === key);
  if (!w) return null;
  return {
    since: NOW - 7 * DAY,
    until: NOW,
    days: 7,
    truncated: false,
    limit: 50_000,
    workflow: w,
    waiting_jobs: WAITING[key] ?? 0,
    // genome-assembly's queued jobs ask for memory with the same formula.
    ...(key === 'wf-assemble' ? { waiting_adaptive: ['memory' as const] } : {}),
  };
}

export function buildUtilizationFixture(): UtilizationResponse {
  const workflows = fullWorkflows;
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
      throughput_gain: throughputGain(workflows),
    },
    workflows: workflows.map(summarize),
    suggestions: rankSuggestions(workflows),
    limit: 50_000,
    max_limit: 1_000_000,
    owners: ownersOf(workflows),
  };
}

// ownersOf is the owner list a pool-wide answer carries, by run time.
export function ownersOf(ws: Pick<UtilWorkflowSummary, 'owner' | 'jobs' | 'wall_hours'>[]): NonNullable<UtilizationResponse['owners']> {
  const by = new Map<string, { owner: string; jobs: number; wall_hours: number }>();
  for (const w of ws) {
    if (!w.owner) continue;
    const o = by.get(w.owner) ?? { owner: w.owner, jobs: 0, wall_hours: 0 };
    o.jobs += w.jobs;
    o.wall_hours += w.wall_hours;
    by.set(w.owner, o);
  }
  return [...by.values()].sort((a, b) => b.wall_hours - a.wall_hours);
}

export const utilizationFixture: UtilizationResponse = buildUtilizationFixture();

// --- Jobs in a workflow ---

// jobRows re-runs a workflow's simulation (it is seeded, so these are the
// same jobs its figures came from) and lists them the way the jobs
// endpoint does.
export function jobRows(key: string): UtilJobRow[] | null {
  const spec = SPECS.find((sp) => sp.key === key);
  if (!spec) return null;
  const procs = new Map<number, number>();
  return simulate(spec).map((j) => {
    const proc = procs.get(j.cluster) ?? 0;
    procs.set(j.cluster, proc + 1);
    const submitted = Math.round(j.qdate);
    const started = submitted + 120;
    return {
      id: `${j.cluster}.${proc}`,
      cluster: j.cluster,
      proc,
      owner: spec.owner,
      submitted,
      started,
      completed: started + j.wall + j.restartLost,
      outcome: j.outcome,
      exit_code: j.outcome === 'failed' ? 1 : j.outcome === 'ok' ? 0 : null,
      exit_by_signal: false,
      wall: j.wall + j.restartLost,
      request: {
        memory_mib: j.reqMem,
        cpus: j.reqCpu,
        disk_kib: j.reqDisk,
        gpus: j.reqGpu > 0 ? j.reqGpu : null,
      },
      memory_peak_mib: j.mem,
      cores_used: j.cores === null || j.wall < 60 ? null : Math.round(j.cores * 100) / 100,
      cpu_efficiency: j.cores === null || j.wall < 60 ? null : j.cores / j.reqCpu,
      disk_used_kib: j.disk,
      gpu_utilization: j.gpuUtil,
      gpu_memory_peak_mib: j.gpuMem,
      restarts: j.restartLost > 0 ? 1 : 0,
      held_for_memory: j.outcome === 'memory_exceeded',
      held_for_disk: false,
    };
  });
}

const SORT_VALUE: Record<UtilJobSort, (r: UtilJobRow) => number | null> = {
  completed: (r) => r.completed,
  submitted: (r) => r.submitted,
  wall: (r) => r.wall,
  memory: (r) => r.memory_peak_mib,
  cores: (r) => r.cores_used,
  efficiency: (r) => r.cpu_efficiency,
  disk: (r) => r.disk_used_kib,
  gpu: (r) => r.gpu_utilization,
};

/** utilizationJobsFixture answers GET /api/v1/utilization/jobs. */
export function utilizationJobsFixture(
  key: string,
  opts: { sort?: UtilJobSort; order?: 'asc' | 'desc'; offset?: number; page_size?: number } = {},
): UtilJobsResponse | null {
  const rows = jobRows(key);
  if (!rows) return null;
  const sort = opts.sort ?? 'completed';
  const order = opts.order ?? 'desc';
  const v = SORT_VALUE[sort];
  // Nulls last in either order; ties on (cluster, proc) ascending.
  rows.sort((a, b) => {
    const av = v(a);
    const bv = v(b);
    if (av === null || bv === null) {
      if (av === bv) return a.cluster - b.cluster || a.proc - b.proc;
      return av === null ? 1 : -1;
    }
    if (av !== bv) return order === 'asc' ? av - bv : bv - av;
    return a.cluster - b.cluster || a.proc - b.proc;
  });
  const offset = opts.offset ?? 0;
  const size = Math.min(opts.page_size ?? 100, 500);
  const page = rows.slice(offset, offset + size);
  return {
    key,
    total: rows.length,
    offset,
    next_offset: offset + size < rows.length ? offset + size : null,
    sort,
    order,
    truncated: false,
    jobs: page,
  };
}
