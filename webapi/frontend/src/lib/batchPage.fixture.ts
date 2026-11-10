// Batch page responses for the component tests, the smoke suite and the
// local mock server: a batch with jobs in the queue and finished ones, a
// batch that has finished, a DAG, and one just submitted.

import type { DisplayStatus } from './api';
import type { BatchJobRow, BatchJobSort, BatchJobsResponse, BatchResponse, FinishedStats } from './batchPage';

const NO_FINISHED: FinishedStats = {
  jobs: 0,
  truncated: false,
  limit: 100_000,
  succeeded: 0,
  failed: 0,
  removed: 0,
  outcomes: [],
  wall_hours: 0,
  badput_hours: 0,
  core_hours: 0,
};

/** A batch part-way through: running, waiting, held, finished and failed jobs. */
export function liveBatchFixture(now: number): BatchResponse {
  return {
    kind: 'named',
    id: 300,
    name: 'blast-run',
    owner: 'alice',
    constraint: 'JobBatchName == "blast-run" && Owner == "alice"',
    remove_constraint: 'JobBatchName == "blast-run" && Owner == "alice"',
    clusters: [300, 301],
    submitted: now - 6 * 3600,
    first_start: now - 5.5 * 3600,
    last_completion: now - 600,
    progress: {
      known: true,
      unit: 'jobs',
      total: 100,
      done: 55,
      failed: 0,
      parts: [
        { part: 'done', count: 55 },
        { part: 'running', count: 12 },
        { part: 'idle', count: 30 },
        { part: 'held', count: 3 },
      ],
      notQueued: 0,
    },
    live: { running: 12, idle: 30, held: 3 },
    live_jobs: 45,
    live_truncated: false,
    finished: {
      jobs: 55,
      truncated: false,
      limit: 100_000,
      succeeded: 50,
      failed: 4,
      removed: 1,
      outcomes: [
        { outcome: 'exit', code: 0, count: 50 },
        { outcome: 'exit', code: 1, count: 3 },
        { outcome: 'signal', code: 9, count: 1 },
        { outcome: 'removed', count: 1 },
      ],
      runtime: { count: 54, p10: 1800, p50: 2700, p90: 4200, max: 6900, mean: 2900 },
      wall_hours: 52.4,
      badput_hours: 6.1,
      core_hours: 209.6,
      memory: { count: 54, request_p50: 4096, peak_p50: 1200, peak_p95: 2900, peak_max: 3500 },
    },
    hold_reasons: [
      {
        kind: 'held',
        template: 'Error from slot1_*: Job has gone over cgroup memory limit of * megabytes.',
        count: 3,
        codes: [{ code: 34, subcode: 0, label: 'Memory limit exceeded', count: 3 }],
        examples: [
          { id: '301.4', message: 'Error from slot1_3@e101: Job has gone over cgroup memory limit of 4096 megabytes.' },
          { id: '301.9', message: 'Error from slot1_7@e204: Job has gone over cgroup memory limit of 4096 megabytes.' },
        ],
      },
      {
        kind: 'was_held',
        template: 'Transfer input files failure at execution point * : *',
        count: 2,
        codes: [{ code: 13, subcode: 0, label: 'Input transfer failed', count: 2 }],
        examples: [{ id: '300.12', message: 'Transfer input files failure at execution point slot1@e9: reading db.tar' }],
      },
    ],
    workflows: [
      { key: 'wf-blast', name: 'blastn', executable: 'run_blast.sh', jobs: 100, finished_jobs: 55 },
    ],
    has_history: true,
    fetched_at: now,
  };
}

/** A batch every job of which has finished: nothing left in the queue. */
export function finishedBatchFixture(now: number): BatchResponse {
  return {
    kind: 'cluster',
    id: 410,
    name: '410',
    owner: 'alice',
    constraint: 'ClusterId == 410',
    remove_constraint: 'ClusterId == 410',
    clusters: [410],
    submitted: now - 3 * 86400,
    first_start: now - 3 * 86400 + 120,
    last_completion: now - 2 * 86400,
    progress: {
      known: true,
      unit: 'jobs',
      total: 20,
      done: 20,
      failed: 0,
      parts: [{ part: 'done', count: 20 }],
      notQueued: 0,
    },
    live: {},
    live_jobs: 0,
    live_truncated: false,
    finished: {
      jobs: 20,
      truncated: false,
      limit: 100_000,
      succeeded: 20,
      failed: 0,
      removed: 0,
      outcomes: [{ outcome: 'exit', code: 0, count: 20 }],
      runtime: { count: 20, p10: 540, p50: 600, p90: 660, max: 700, mean: 600 },
      wall_hours: 3.3,
      badput_hours: 0,
      core_hours: 3.3,
    },
    hold_reasons: [],
    workflows: [{ key: 'wf-sim', name: 'simulate', executable: 'sim', jobs: 20, finished_jobs: 20 }],
    has_history: true,
    fetched_at: now,
  };
}

/** A DAG mid-run: its DAGMan job, two node jobs running and one waiting. */
export function dagBatchFixture(now: number): BatchResponse {
  return {
    kind: 'dag',
    id: 500,
    name: 'assembly.dag',
    owner: 'alice',
    constraint: 'JobBatchName == "assembly.dag+500"',
    remove_constraint: 'JobBatchName == "assembly.dag+500" || ClusterId == 500',
    clusters: [500, 501, 502, 503, 504, 505, 506],
    dagman_job_id: '500.0',
    submitted: now - 2 * 3600,
    first_start: now - 2 * 3600 + 60,
    last_completion: now - 1200,
    progress: {
      known: true,
      unit: 'nodes',
      total: 8,
      done: 3,
      failed: 0,
      parts: [
        { part: 'done', count: 3 },
        { part: 'queued', count: 3 },
        { part: 'other', count: 2 },
      ],
      notQueued: 0,
    },
    live: { running: 3, idle: 1 },
    live_jobs: 4,
    live_truncated: false,
    finished: {
      ...NO_FINISHED,
      jobs: 3,
      succeeded: 3,
      outcomes: [{ outcome: 'exit', code: 0, count: 3 }],
      runtime: { count: 3, p10: 900, p50: 1100, p90: 1300, max: 1300, mean: 1100 },
      wall_hours: 0.9,
      core_hours: 1.8,
    },
    hold_reasons: [],
    dag: {
      attributes: {
        DAG_NodesTotal: 8,
        DAG_NodesDone: 3,
        DAG_NodesQueued: 3,
        DAG_NodesUnready: 2,
        DAG_NodesFailed: 0,
        DAG_Status: 0,
        DAG_InRecovery: 0,
      },
      status: 2,
      source: 'queue',
    },
    workflows: [],
    has_history: true,
    fetched_at: now,
  };
}

/** A batch just submitted: every job waiting, none finished. */
export function newBatchFixture(now: number): BatchResponse {
  return {
    kind: 'cluster',
    id: 620,
    name: '620',
    owner: 'alice',
    constraint: 'ClusterId == 620',
    remove_constraint: 'ClusterId == 620',
    clusters: [620],
    submitted: now - 120,
    progress: { known: false, why: 'noTotal' },
    live: { idle: 5 },
    live_jobs: 5,
    live_truncated: false,
    finished: NO_FINISHED,
    hold_reasons: [],
    workflows: [],
    has_history: false,
    fetched_at: now,
  };
}

export const BATCH_FIXTURES: Record<number, (now: number) => BatchResponse> = {
  300: liveBatchFixture,
  410: finishedBatchFixture,
  500: dagBatchFixture,
  620: newBatchFixture,
};

// The rows behind a fixture: its queue by state, then its finished jobs.
function rowsFor(b: BatchResponse, now: number): BatchJobRow[] {
  const rows: BatchJobRow[] = [];
  const cluster = b.clusters[b.clusters.length - 1];
  let proc = 0;
  if (b.kind === 'dag' && b.dagman_job_id) {
    rows.push({
      id: b.dagman_job_id,
      cluster: b.id,
      proc: 0,
      source: 'queue',
      status: 'running',
      dagman: true,
      submitted: b.submitted,
      started: b.submitted,
    });
  }
  const order: DisplayStatus[] = ['running', 'idle', 'held'];
  let node = 0;
  for (const s of order) {
    let n = b.live[s] ?? 0;
    if (b.kind === 'dag' && s === 'running') n -= 1; // the DAGMan job above
    for (let i = 0; i < n; i++) {
      const c = b.kind === 'dag' ? b.clusters[1 + (node % (b.clusters.length - 1))] : cluster;
      const p = b.kind === 'dag' ? 0 : proc++;
      rows.push({
        id: `${c}.${p}`,
        cluster: c,
        proc: p,
        source: 'queue',
        status: s,
        node: b.kind === 'dag' ? `node_${String.fromCharCode(65 + node++)}` : undefined,
        submitted: (b.submitted ?? now) + 10,
        started: s === 'running' ? now - 1200 - i * 300 : undefined,
        request_memory_mib: 4096,
        request_cpus: 4,
        hold_reason:
          s === 'held' ? `Error from slot1_${i}@e101: Job has gone over cgroup memory limit of 4096 megabytes.` : undefined,
        hold_code: s === 'held' ? 34 : undefined,
      });
    }
  }
  const f = b.finished;
  const endings: { outcome: BatchJobRow['outcome']; exit_code?: number; exit_signal?: number }[] = [];
  for (const o of f.outcomes) {
    for (let i = 0; i < o.count; i++) {
      if (o.outcome === 'removed') endings.push({ outcome: 'removed' });
      else if (o.outcome === 'signal') endings.push({ outcome: 'failed', exit_signal: o.code });
      else endings.push({ outcome: o.code === 0 ? 'succeeded' : 'failed', exit_code: o.code });
    }
  }
  endings.forEach((e, i) => {
    // A DAG's finished nodes are clusters of their own, after the live ones.
    const c = b.kind === 'dag' ? b.clusters[node + 1 + i] : b.clusters[0];
    const p = b.kind === 'dag' ? 0 : 1000 + i;
    const runtime = (f.runtime?.p50 ?? 600) + ((i * 37) % 11) * 60;
    rows.push({
      id: `${c}.${p}`,
      cluster: c,
      proc: p,
      source: 'history',
      status: e.outcome === 'removed' ? 'removed' : 'completed',
      node: b.kind === 'dag' ? `done_${i + 1}` : undefined,
      outcome: e.outcome,
      exit_code: e.exit_code,
      exit_signal: e.exit_signal,
      submitted: b.submitted,
      started: (b.last_completion ?? now) - i * 400 - runtime,
      finished: (b.last_completion ?? now) - i * 400,
      runtime_seconds: runtime,
      request_memory_mib: 4096,
      peak_memory_mib: 900 + ((i * 53) % 9) * 100,
      request_cpus: 4,
      cores_used: 3.6,
    });
  });
  return rows;
}

const DESC_DEFAULT = new Set<BatchJobSort>(['submitted', 'started', 'finished', 'runtime', 'peak_memory']);

/** batchJobsFixture answers GET /api/v1/batches/{id}/jobs over a fixture. */
export function batchJobsFixture(
  b: BatchResponse,
  now: number,
  q: { status?: string[]; sort?: BatchJobSort; order?: 'asc' | 'desc'; offset?: number; page_size?: number },
): BatchJobsResponse {
  let rows = rowsFor(b, now);
  const want = new Set(q.status ?? []);
  if (want.size > 0) {
    rows = rows.filter(
      (r) =>
        want.has(r.status) || (want.has('live') && r.source === 'queue') || (want.has('finished') && r.source === 'history'),
    );
  }
  const sort = q.sort ?? 'default';
  if (sort !== 'default') {
    const key = (r: BatchJobRow): number | string | undefined =>
      ({
        id: r.cluster * 1e6 + r.proc,
        status: r.status,
        submitted: r.submitted,
        started: r.started,
        finished: r.finished,
        runtime: r.runtime_seconds,
        exit: r.exit_code ?? r.exit_signal,
        peak_memory: r.peak_memory_mib,
        default: 0,
      })[sort];
    const desc = (q.order ?? (DESC_DEFAULT.has(sort) ? 'desc' : 'asc')) === 'desc';
    rows = [...rows].sort((a, z) => {
      const ka = key(a);
      const kz = key(z);
      if (ka === undefined && kz === undefined) return 0;
      if (ka === undefined) return 1;
      if (kz === undefined) return -1;
      const c = ka < kz ? -1 : ka > kz ? 1 : 0;
      return desc ? -c : c;
    });
  }
  const offset = q.offset ?? 0;
  const size = Math.min(q.page_size ?? 100, 500);
  const page = rows.slice(offset, offset + size);
  return {
    id: b.id,
    total: rows.length,
    offset,
    next_offset: offset + size < rows.length ? offset + size : null,
    live_truncated: false,
    history_truncated: false,
    jobs: page,
  };
}
