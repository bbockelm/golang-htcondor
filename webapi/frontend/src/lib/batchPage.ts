// One batch or DAG, as /batches/<id> shows it: GET /api/v1/batches/{id}
// and GET /api/v1/batches/{id}/jobs (see BATCH_CONTRACT.md). A batch is
// exactly one row of the /jobs page, so the identity rules and the
// progress shape are the ones in lib/batches.ts and lib/batchProgress.ts.

import type { DisplayStatus } from './api';
import { PROGRESS_WHY, type BatchProgressResult } from './batchProgress';
import type { DagNodeCounts } from './batches';

export interface BatchResponse {
  kind: 'dag' | 'named' | 'cluster';
  id: number; // canonical batch id
  name: string;
  owner?: string;
  constraint: string; // selects the batch's jobs, queue and archive
  remove_constraint: string; // what /jobs's "Remove batch" uses
  clusters: number[];
  dagman_job_id?: string; // DAG only: the root DAGMan job

  submitted?: number;
  first_start?: number;
  last_completion?: number;

  // The server sends `why` as a PROGRESS_WHY key, like the client's.
  progress: BatchProgressResult;

  live: Partial<Record<DisplayStatus, number>>;
  live_jobs: number;
  live_truncated: boolean;

  finished: FinishedStats;
  hold_reasons: BatchHoldReason[];
  dag?: DagInfo;
  workflows: BatchWorkflow[];
  has_history: boolean;

  fetched_at: number;
}

export interface FinishedStats {
  jobs: number;
  truncated: boolean;
  limit: number;
  succeeded: number;
  failed: number;
  removed: number;
  outcomes: { outcome: 'exit' | 'signal' | 'removed'; code?: number; count: number }[];
  runtime?: { count: number; p10: number; p50: number; p90: number; max: number; mean: number };
  wall_hours: number;
  badput_hours: number;
  core_hours: number;
  memory?: { count: number; request_p50: number; peak_p50: number; peak_p95: number; peak_max: number };
}

export interface BatchHoldReason {
  kind: 'held' | 'was_held';
  template: string;
  count: number;
  codes: { code: number; subcode: number; label?: string; count: number }[];
  examples: { id: string; message: string }[];
}

export interface DagInfo {
  attributes: Record<string, number | string | boolean>;
  status: number | null;
  source: 'queue' | 'history';
}

export interface BatchWorkflow {
  key: string;
  name: string;
  executable: string;
  jobs: number;
  finished_jobs: number;
}

export type BatchJobSort =
  | 'default'
  | 'id'
  | 'status'
  | 'submitted'
  | 'started'
  | 'finished'
  | 'runtime'
  | 'exit'
  | 'peak_memory';

export interface BatchJobsResponse {
  id: number;
  total: number;
  offset: number;
  next_offset: number | null;
  live_truncated: boolean;
  history_truncated: boolean;
  jobs: BatchJobRow[];
}

export interface BatchJobRow {
  id: string;
  cluster: number;
  proc: number;
  source: 'queue' | 'history';
  status: DisplayStatus;
  node?: string;
  dagman?: boolean;
  outcome?: 'succeeded' | 'failed' | 'removed';
  exit_code?: number;
  exit_signal?: number;
  submitted?: number;
  started?: number;
  finished?: number;
  runtime_seconds?: number;
  request_memory_mib?: number;
  peak_memory_mib?: number;
  request_cpus?: number;
  cores_used?: number;
  hold_reason?: string;
  hold_code?: number;
}

// --- Helpers ---

/** dagNodes reads a DAG's node counts from its DAGMan job's attributes. */
export function dagNodes(dag: DagInfo | undefined): DagNodeCounts | undefined {
  const a = dag?.attributes;
  const n = (k: string) => (typeof a?.[k] === 'number' ? (a[k] as number) : undefined);
  const total = n('DAG_NodesTotal');
  if (total === undefined) return undefined;
  return { total, done: n('DAG_NodesDone') ?? 0, failed: n('DAG_NodesFailed') ?? 0, queued: n('DAG_NodesQueued') ?? 0 };
}

/** dagNodeBreakdown is every DAG_Nodes* count the DAG reported, labelled. */
export function dagNodeBreakdown(dag: DagInfo | undefined): { label: string; count: number }[] {
  const a = dag?.attributes ?? {};
  const rows: [string, string][] = [
    ['DAG_NodesDone', 'done'],
    ['DAG_NodesQueued', 'in the queue'],
    ['DAG_NodesReady', 'ready to submit'],
    ['DAG_NodesUnready', 'waiting on parents'],
    ['DAG_NodesPrerun', 'running a PRE script'],
    ['DAG_NodesPostrun', 'running a POST script'],
    ['DAG_NodesHoldrun', 'held'],
    ['DAG_NodesFutile', 'will not run'],
    ['DAG_NodesFailed', 'failed'],
  ];
  return rows
    .filter(([k]) => typeof a[k] === 'number' && (a[k] as number) > 0)
    .map(([k, label]) => ({ label, count: a[k] as number }));
}

/** outcomeLabel names one way finished jobs ended. */
export function outcomeLabel(o: FinishedStats['outcomes'][number]): string {
  if (o.outcome === 'removed') return 'removed';
  if (o.outcome === 'signal') return `killed by signal ${o.code ?? '?'}`;
  return o.code === 0 ? 'exit code 0' : `exit code ${o.code ?? '?'}`;
}

/** batchHrefFor is a batch's page. */
export function batchPageHref(id: number | string): string {
  return `/batches/${encodeURIComponent(String(id))}`;
}

/** liveCount is how many of the batch's jobs are in a display state now. */
export function liveCount(b: Pick<BatchResponse, 'live'>, s: DisplayStatus): number {
  return b.live[s] ?? 0;
}

/**
 * progressForDisplay turns the server's progress into the client's: the
 * server names why a count is unknown by PROGRESS_WHY key, the client's
 * BatchProgressResult carries the sentence.
 */
export function progressForDisplay(p: BatchProgressResult): BatchProgressResult {
  if (p.known) return p;
  const text = (PROGRESS_WHY as Record<string, string>)[p.why];
  return text ? { known: false, why: text } : p;
}
