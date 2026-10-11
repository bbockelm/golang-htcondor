// How far along each batch is: "88 of 100 jobs done".
//
// The queue cannot answer that by counting, because a finished job leaves
// the queue. What it can answer is how many jobs a batch STARTED with and
// how many of them are still there, and the difference is the ones that
// finished. Both halves come from attributes HTCondor already keeps:
//
//   - Every cluster's ad carries TotalSubmitProcs, the number of jobs the
//     submit produced, and every job in the cluster inherits it. A batch
//     that spans several clusters (one name, several submits) sums them.
//
//   - A cluster submitted with max_materialize is a job factory: its jobs
//     enter the queue a few at a time, so most of TotalSubmitProcs may not
//     exist yet. Counting those as finished would report a 1000-job batch
//     with 10 jobs in the queue as 990 done. The factory records the next
//     proc id it will create in JobMaterializeNextProcId; ids below it have
//     been queued, ids at or above it have not, so only the former can have
//     finished. (The schedd sets TotalSubmitProcs on a factory cluster when
//     it materializes the first job, and only once the item list has been
//     read in full -- a `queue from` a still-growing source never gets one,
//     and that batch has no progress to show.)
//
//   - A DAG is counted in nodes, not jobs: its root DAGMan job publishes
//     DAG_NodesTotal/Done/Failed/Queued in its own ad, which is both more
//     accurate (a node can be several jobs, or a PRE script and no job at
//     all) and independent of how many node jobs this page loaded.
//
// The trap this file exists to avoid: computing progress from the jobs a
// status filter left. Selecting "Held" drops every running and idle job
// from the batch, and the arithmetic above would then call them finished.
// Progress is computed from every loaded ad and joined to the filtered
// rows by batch group key.

import type { ClassAd } from '@/lib/api';
import { displayJobStatus } from '@/lib/api';
import { attr, batchGroupKey, num, str } from '@/lib/batches';

export type ProgressPart = 'done' | 'running' | 'idle' | 'held' | 'queued' | 'failed' | 'other';

export interface BatchProgress {
  known: true;
  unit: 'jobs' | 'nodes';
  total: number;
  done: number;
  // DAGs only: nodes that failed. Not part of `done`.
  failed: number;
  // The bar's segments, in drawing order. They sum to `total`.
  parts: { part: ProgressPart; count: number }[];
  // Jobs of a max_materialize batch that have not entered the queue yet.
  // They are counted in the `idle` part; this is for the sentence.
  notQueued: number;
}

export interface UnknownProgress {
  known: false;
  // Why there is no number, for the cell's tooltip.
  why: string;
}

export type BatchProgressResult = BatchProgress | UnknownProgress;

// Text the cell shows when progress is unknown. Facts about the batch or
// the view, not about where the numbers come from.
export const PROGRESS_WHY = {
  partial:
    'Only some of this batch’s jobs are listed here, so how many are done is unknown.',
  noTotal: 'How many jobs this batch was submitted with is not recorded.',
  dagNotReporting: 'This workflow has not reported its progress yet.',
  dagMissing: 'This workflow’s progress is not available.',
  mixed: 'This batch mixes a workflow with other jobs, so it has no single progress count.',
  counting: 'Counting this batch’s jobs…',
  countFailed: 'How many of this batch’s jobs are done could not be counted.',
} as const;

function attrNum(ad: ClassAd, name: string): number | undefined {
  return num(attr(ad, name));
}

// isDagManJob mirrors the server's test (mcpserver/handlers_dag.go):
// DAG_NodesTotal is conclusive once DAGMan has started, and before that
// the command is the only sign.
function isDagManJob(ad: ClassAd): boolean {
  if (attrNum(ad, 'DAG_NodesTotal') !== undefined) return true;
  const cmd = str(ad.Cmd)?.trim();
  return cmd === 'condor_dagman' || !!cmd?.endsWith('/condor_dagman');
}

// isDagNode: a job DAGMan submitted, including a nested sub-DAG's DAGMan.
function isDagNode(ad: ClassAd): boolean {
  return attr(ad, 'DAGManJobId') !== undefined && attr(ad, 'DAGManJobId') !== null;
}

// progressByBatch computes progress for every batch in `ads`, keyed by
// batchGroupKey.
//
// `complete` says whether `ads` is every queued job of every batch it
// touches. When it is not -- the listing was cut off, or a server-side
// constraint chose some jobs and not others -- a job missing from the
// list is indistinguishable from a job that finished, so plain batches
// report no number rather than an inflated one. A DAG's count lives in
// its root job's ad and survives either.
export function progressByBatch(
  ads: ClassAd[],
  complete: boolean,
): Map<string, BatchProgressResult> {
  const groups = new Map<string, ClassAd[]>();
  for (const ad of ads) {
    const key = batchGroupKey(ad);
    if (key === undefined) continue;
    const g = groups.get(key);
    if (g) g.push(ad);
    else groups.set(key, [ad]);
  }
  const out = new Map<string, BatchProgressResult>();
  for (const [key, group] of groups) {
    out.set(key, progressOf(group, complete));
  }
  return out;
}

function progressOf(ads: ClassAd[], complete: boolean): BatchProgressResult {
  const roots = ads.filter((a) => isDagManJob(a) && !isDagNode(a));
  const dagAds = ads.filter((a) => isDagNode(a) || isDagManJob(a));
  if (dagAds.length > 0) {
    // A plain job sharing the workflow's batch name: nodes and jobs are
    // different units, and adding them would mean nothing.
    if (dagAds.length !== ads.length) return { known: false, why: PROGRESS_WHY.mixed };
    if (roots.length === 0) return { known: false, why: PROGRESS_WHY.dagMissing };
    return dagProgress(roots);
  }
  if (!complete) return { known: false, why: PROGRESS_WHY.partial };
  return jobProgress(ads);
}

// dagProgress sums the root DAGMan jobs' own counts. There is normally one
// root; two appear when two workflows were submitted under one batch name,
// and nodes add up across them.
function dagProgress(roots: ClassAd[]): BatchProgressResult {
  let total = 0;
  let done = 0;
  let failed = 0;
  let queued = 0;
  for (const r of roots) {
    const t = attrNum(r, 'DAG_NodesTotal');
    if (t === undefined) return { known: false, why: PROGRESS_WHY.dagNotReporting };
    total += t;
    done += attrNum(r, 'DAG_NodesDone') ?? 0;
    failed += attrNum(r, 'DAG_NodesFailed') ?? 0;
    queued += attrNum(r, 'DAG_NodesQueued') ?? 0;
  }
  // Everything else -- ready, waiting on a parent, in a PRE or POST
  // script, futile -- is "not done and not in the queue".
  const other = Math.max(0, total - done - failed - queued);
  return {
    known: true,
    unit: 'nodes',
    total,
    done,
    failed,
    // Finished first, as in the job bar.
    parts: [
      { part: 'done', count: done },
      { part: 'queued', count: queued },
      { part: 'failed', count: failed },
      { part: 'other', count: other },
    ],
    notQueued: 0,
  };
}

interface ClusterAcc {
  totalProcs?: number;
  nextProcId?: number;
  running: number;
  idle: number;
  held: number;
  other: number;
}

function jobProgress(ads: ClassAd[]): BatchProgressResult {
  const clusters = new Map<number, ClusterAcc>();
  for (const ad of ads) {
    const cluster = num(ad.ClusterId);
    if (cluster === undefined) continue;
    let c = clusters.get(cluster);
    if (!c) {
      c = { running: 0, idle: 0, held: 0, other: 0 };
      clusters.set(cluster, c);
    }
    // Cluster attributes: the same on every job of the cluster, so any
    // job that carries them will do.
    c.totalProcs ??= attrNum(ad, 'TotalSubmitProcs');
    c.nextProcId ??= attrNum(ad, 'JobMaterializeNextProcId');

    const display = displayJobStatus({
      status: ad.JobStatus as number | string | null | undefined,
      holdReasonCode: ad.HoldReasonCode as number | string | null | undefined,
    });
    switch (display.key) {
      // Completed and removed jobs that have not left the queue yet are
      // finished all the same.
      case 'completed':
      case 'removed':
        break;
      case 'running':
        c.running++;
        break;
      case 'idle':
        c.idle++;
        break;
      case 'held':
        c.held++;
        break;
      default:
        // Transferring output, suspended, uploading inputs.
        c.other++;
    }
  }

  let total = 0;
  let done = 0;
  let notQueued = 0;
  let running = 0;
  let idle = 0;
  let held = 0;
  let other = 0;
  for (const c of clusters.values()) {
    // One cluster without a total and the batch has none: a sum over the
    // clusters that have one is a partial number dressed as a whole one.
    if (c.totalProcs === undefined) return { known: false, why: PROGRESS_WHY.noTotal };
    const queuedSoFar =
      c.nextProcId !== undefined ? Math.min(c.nextProcId, c.totalProcs) : c.totalProcs;
    const active = c.running + c.idle + c.held + c.other;
    total += c.totalProcs;
    done += Math.max(0, queuedSoFar - active);
    notQueued += c.totalProcs - queuedSoFar;
    running += c.running;
    idle += c.idle;
    held += c.held;
    other += c.other;
  }
  return {
    known: true,
    unit: 'jobs',
    total,
    done,
    failed: 0,
    parts: [
      { part: 'done', count: done },
      { part: 'running', count: running },
      // Not yet queued is still waiting to run, which is what idle means
      // to the person who submitted it.
      { part: 'idle', count: idle + notQueued },
      { part: 'held', count: held },
      { part: 'other', count: other },
    ],
    notQueued,
  };
}

// progressFraction is the sort key: how much of the batch is done.
export function progressFraction(p: BatchProgressResult | undefined): number | undefined {
  if (!p || !p.known || p.total <= 0) return undefined;
  return p.done / p.total;
}

const PART_WORDS: Record<ProgressPart, string> = {
  done: 'done',
  running: 'running',
  idle: 'waiting',
  held: 'held',
  queued: 'in the queue',
  failed: 'failed',
  other: 'other',
};

// progressSentence is the plain-language reading of the bar, for its
// tooltip: "88 of 100 jobs done" / "17 of 40 nodes done, 3 failed", and
// then the rest of the breakdown.
export function progressSentence(p: BatchProgress): string {
  const unit = p.total === 1 ? p.unit.slice(0, -1) : p.unit;
  let head = `${p.done.toLocaleString()} of ${p.total.toLocaleString()} ${unit} done`;
  if (p.failed > 0) head += `, ${p.failed.toLocaleString()} failed`;
  const rest = p.parts
    .filter((x) => x.part !== 'done' && x.part !== 'failed' && x.count > 0)
    .map((x) => {
      let s = `${x.count.toLocaleString()} ${PART_WORDS[x.part]}`;
      if (x.part === 'idle' && p.notQueued > 0) {
        s += ` (${p.notQueued.toLocaleString()} not yet in the queue)`;
      }
      return s;
    });
  return rest.length > 0 ? `${head}\n${rest.join(' · ')}` : head;
}
