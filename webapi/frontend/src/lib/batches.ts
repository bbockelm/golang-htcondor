// The batch model behind /jobs and /users/<owner>.
//
// HTCondor is batch-oriented: a submission produces one cluster that may
// hold many jobs, and the listing pages render one row per batch with the
// jobs inside it. Both pages ask the same questions of the same job ads --
// group them, filter them, total their resources -- so the answers live
// here rather than in either page.

import {
  displayJobStatus,
  jobIdOf,
  scheddOf,
  type ClassAd,
  type DisplayStatus,
  type DisplayStatusInfo,
} from '@/lib/api';

// Attributes every batch listing needs. QDate has to be asked for
// explicitly: the schedd does not backfill it, and the submit path sets it
// at submit time (see submit.go). The Request* attributes drive the
// resource totals in the summary panel. DAGManJobId/DAGNodeName mark a job
// as a DAG node so a whole workflow folds into one batch (see
// groupIntoBatches). The last six are what the Progress column counts
// with (see batchProgress.ts): finished jobs leave the queue, so "how many
// are done" has to be worked out from how many there were to begin with.
export const BATCH_PROJECTION =
  'ClusterId,ProcId,JobStatus,HoldReason,HoldReasonCode,Owner,Cmd,Args,QDate,JobBatchName,DAGManJobId,DAGNodeName,Iwd,RequestCpus,RequestMemory,RequestGpus,' +
  'TotalSubmitProcs,JobMaterializeNextProcId,DAG_NodesTotal,DAG_NodesDone,DAG_NodesFailed,DAG_NodesQueued,' +
  // How long each job has been running or waiting (see jobTiming).
  'JobCurrentStartExecutingDate,JobCurrentStartDate,EnteredCurrentStatus';

// Batch is what we render: one batch's worth of jobs aggregated.
export interface Batch {
  // Representative cluster used for the row's identity, its URL, the
  // expanded-set and the "#id" badge. For a DAG this is the ROOT DAGMan
  // cluster (the `+N` in JobBatchName), which is stable across the whole
  // workflow; for anything else it is the group's (smallest) ClusterId.
  batchID: number;
  // The access point the batch is on, in multi-AP mode. Cluster ids are
  // per access point, so two access points' cluster 12 are two batches.
  schedd?: string;
  // Display name: for a DAG the dag file name with the `+<root>` suffix
  // stripped, else JobBatchName if set, else the batch id.
  name: string;
  // Submitting user. Only shown in the pool-wide ("Everyone") view — in
  // the "Mine" view every row would carry the same value.
  owner?: string;
  // Representative command (the first job's Cmd we found). All jobs
  // in a batch nearly always share the same Cmd; we don't bother
  // showing multiple even when they differ.
  cmd?: string;
  args?: string;
  // QDate of the oldest job (= when the batch was submitted).
  submittedUnix?: number;
  // The grouping key (see batchGroupKey). Unlike batchID it does not
  // depend on which of the batch's jobs survived a filter -- a named batch
  // spanning clusters 10 and 11 is batch 11 when only 11's jobs are held --
  // so it is what joins a filtered row to anything computed over the whole
  // queue.
  groupKey: string;
  // Per-status counts — keyed by DisplayStatus so spool-held shows
  // up as "Uploading Inputs" instead of being lumped under "Held".
  statusCounts: Record<DisplayStatus, number>;
  jobCount: number;
  // The individual jobs, kept around so the row can expand inline.
  jobs: BatchJob[];
  // True when this batch is a DAG workflow (JobBatchName ends in `+N`).
  isDag: boolean;
  // The DAG's node counts, summed over its root DAGMan jobs, when this
  // batch has a root DAGMan job that has reported them; see dagNodeCounts.
  dagNodes?: DagNodeCounts;
  // Every ClusterId represented in this batch. A DAG spans many clusters
  // (one per node job, plus nested sub-DAGMan jobs); the consumers that
  // re-filter ads by "does this ad belong to a surviving batch" key on
  // this rather than on batchID alone.
  clusterIds: number[];
  // ClassAd constraint that selects exactly this batch's jobs, used by
  // the "Remove batch" action (and to fetch the expanded row's usage).
  // For a DAG this matches the shared JobBatchName so removing the row
  // takes down every node and sub-DAG, not just the representative
  // cluster.
  removeConstraint: string;
  // ClassAd constraint naming this batch's jobs wherever they are -- in
  // the queue or long finished -- for links that look at the batch over
  // time. Like removeConstraint, except a DAG is matched by its batch
  // name alone: the root cluster id adds nothing once every job of the
  // tree carries the name.
  selectConstraint: string;
}

export interface BatchJob {
  // Display id used in URLs: "3.0", or in multi-AP mode the server's
  // job_id ("3.0@ap1.example.org").
  id: string;
  schedd?: string;
  cluster: number; // ClusterId
  jobIdx: number; // ProcId
  display: DisplayStatusInfo;
  cmd?: string;
  args?: string;
  submittedUnix?: number;
  // DAG node name, when this job is a node of a DAG workflow.
  nodeName?: string;
  // A DAG's workflow manager (a DAGMan job, root or nested): it runs as
  // long as the DAG does and is not one of its nodes.
  dagman?: boolean;
  // Submitted by DAGMan (DAGManJobId set): a node job, or a nested
  // sub-DAG's DAGMan job.
  dagNode?: boolean;
  holdReason?: string;
  // When the job's current run, or current wait, began.
  timing?: JobTiming;
}

// The trailing `+<rootDagmanCluster>` HTCondor appends to a DAG's
// JobBatchName. Its presence is what marks a batch as a DAG, and the
// captured number is the root DAGMan cluster — constant across the whole
// tree even when nested sub-DAGs carry different DAGManJobId values.
const DAG_SUFFIX = /\+(\d+)\s*$/;

// isDagManJob mirrors the server's test (mcpserver/handlers_dag.go):
// DAG_NodesTotal is conclusive once DAGMan has started, and before that
// the command is the only sign.
export function isDagManJob(ad: ClassAd): boolean {
  if (num(attr(ad, 'DAG_NodesTotal')) !== undefined) return true;
  const cmd = str(ad.Cmd)?.trim();
  return cmd === 'condor_dagman' || !!cmd?.endsWith('/condor_dagman');
}

// isDagNode: a job DAGMan submitted, including a nested sub-DAG's DAGMan.
export function isDagNode(ad: ClassAd): boolean {
  return attr(ad, 'DAGManJobId') !== undefined && attr(ad, 'DAGManJobId') !== null;
}

// A DAG's node counts, as its root DAGMan job publishes them.
export interface DagNodeCounts {
  total: number;
  done: number;
  failed: number;
  queued: number;
}

// dagNodeCounts sums the root DAGMan jobs' own counts, or is undefined
// when there is no root or one has not reported yet. There is normally
// one root; two appear when two workflows were submitted under one batch
// name, and nodes add up across them.
export function dagNodeCounts(roots: readonly ClassAd[]): DagNodeCounts | undefined {
  if (roots.length === 0) return undefined;
  const c: DagNodeCounts = { total: 0, done: 0, failed: 0, queued: 0 };
  for (const r of roots) {
    const t = num(attr(r, 'DAG_NodesTotal'));
    if (t === undefined) return undefined;
    c.total += t;
    c.done += num(attr(r, 'DAG_NodesDone')) ?? 0;
    c.failed += num(attr(r, 'DAG_NodesFailed')) ?? 0;
    c.queued += num(attr(r, 'DAG_NodesQueued')) ?? 0;
  }
  return c;
}

// Escape a string for use as a ClassAd string literal inside a constraint.
function escapeClassAdString(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

// One group's running accumulator before we finalize it into a Batch.
interface BatchAcc {
  schedd?: string;
  batchName?: string;
  owner?: string;
  cmd?: string;
  args?: string;
  submittedUnix?: number;
  statusCounts: Record<DisplayStatus, number>;
  jobCount: number;
  jobs: BatchJob[];
  clusters: Set<number>;
  minCluster: number;
  // Root DAGMan jobs' ads, for the node counts.
  dagRoots: ClassAd[];
  // A DAG's owner is its root DAGMan job's, when that job is listed.
  rootOwner?: string;
}

// batchGroupKey is the key groupIntoBatches folds a job ad under, or
// undefined for an ad with no ClusterId (which belongs to no batch).
//
// A DAG (JobBatchName ending in `+N`) folds together by its JobBatchName
// alone: every node job and every nested sub-DAG shares it, and N, the
// root DAGMan cluster, names one workflow on its access point. Owner is
// left out on purpose: an access point whose schedd is not root runs
// DAGMan's node jobs as its own user, and keying on Owner split such a
// DAG into two rows.
//
// Any other named submission folds together by
// `${Owner}\u0000${JobBatchName}`, matching `condor_q -batch`; scoping by
// Owner keeps two users who reused a batch name apart in the pool-wide
// view. Unnamed submissions fall back to per-cluster grouping.
// Batches never span access points: a cluster id, and a batch name, is
// only unique within one.
export function batchGroupKey(j: ClassAd): string | undefined {
  const cluster = num(j.ClusterId);
  if (cluster === undefined) return undefined;
  const batchName = str(j.JobBatchName);
  const base = !batchName
    ? `cluster\u0000${cluster}`
    : DAG_SUFFIX.test(batchName)
      ? `dag\u0000${batchName}`
      : `${str(j.Owner) ?? ''}\u0000${batchName}`;
  const schedd = scheddOf(j);
  return schedd ? `${schedd}\u0001${base}` : base;
}

export function groupIntoBatches(jobs: ClassAd[]): Batch[] {
  const map = new Map<string, BatchAcc>();
  for (const j of jobs) {
    const key = batchGroupKey(j);
    if (key === undefined) continue;
    const cluster = num(j.ClusterId)!;
    const proc = num(j.ProcId);
    const owner = str(j.Owner);
    const batchName = str(j.JobBatchName);
    const schedd = scheddOf(j);

    let a = map.get(key);
    if (!a) {
      a = {
        schedd,
        batchName,
        owner,
        cmd: str(j.Cmd),
        args: str(j.Args),
        submittedUnix: num(j.QDate),
        statusCounts: {} as Record<DisplayStatus, number>,
        jobCount: 0,
        jobs: [],
        clusters: new Set<number>(),
        minCluster: cluster,
        dagRoots: [],
      };
      map.set(key, a);
    }

    a.jobCount++;
    a.clusters.add(cluster);
    if (cluster < a.minCluster) a.minCluster = cluster;
    const display = displayJobStatus({
      status: j.JobStatus as number | string | null | undefined,
      holdReasonCode: j.HoldReasonCode as number | string | null | undefined,
    });
    a.statusCounts[display.key] = (a.statusCounts[display.key] ?? 0) + 1;
    const q = num(j.QDate);
    if (q !== undefined && (a.submittedUnix === undefined || q < a.submittedUnix)) {
      a.submittedUnix = q;
    }
    if (!a.owner) a.owner = owner;
    if (!a.cmd) a.cmd = str(j.Cmd);
    if (!a.args) a.args = str(j.Args);

    const dagman = isDagManJob(j);
    const dagNode = isDagNode(j);
    if (dagman && !dagNode) {
      a.dagRoots.push(j);
      const root = batchName ? DAG_SUFFIX.exec(batchName) : null;
      if (root && Number(root[1]) === cluster && owner) a.rootOwner = owner;
    }
    a.jobs.push({
      id: jobIdOf(j) ?? `${cluster}.${proc ?? 0}`,
      schedd,
      cluster,
      jobIdx: proc ?? 0,
      display,
      cmd: str(j.Cmd),
      args: str(j.Args),
      submittedUnix: q,
      nodeName: str(j.DAGNodeName),
      dagman: dagman || undefined,
      dagNode: dagNode || undefined,
      holdReason: str(j.HoldReason),
      timing: jobTiming(j),
    });
  }

  const batches: Batch[] = [];
  for (const [groupKey, a] of map) {
    // Stable order within the batch: by cluster, then proc. A DAG spans
    // many clusters, so job index alone is not enough.
    a.jobs.sort((x, y) => x.cluster - y.cluster || x.jobIdx - y.jobIdx);

    let batchID: number;
    let name: string;
    let isDag = false;
    let removeConstraint: string;
    let selectConstraint: string;

    const dag = a.batchName ? DAG_SUFFIX.exec(a.batchName) : null;
    if (a.batchName && dag) {
      // DAG: the `+N` is the root DAGMan cluster. Use it as the row id and
      // strip it from the display name. Remove by the shared batch name so
      // the whole tree (nodes + nested sub-DAGs) goes, plus the root
      // cluster for good measure.
      isDag = true;
      batchID = Number(dag[1]);
      name = a.batchName.replace(DAG_SUFFIX, '');
      removeConstraint = `JobBatchName == "${escapeClassAdString(a.batchName)}" || ClusterId == ${batchID}`;
      selectConstraint = `JobBatchName == "${escapeClassAdString(a.batchName)}"`;
    } else if (a.batchName) {
      // Plain named batch (not a DAG): may span several clusters under one
      // name, so remove by name + owner rather than by a single cluster.
      batchID = a.minCluster;
      name = a.batchName;
      removeConstraint = a.owner
        ? `JobBatchName == "${escapeClassAdString(a.batchName)}" && Owner == "${escapeClassAdString(a.owner)}"`
        : `JobBatchName == "${escapeClassAdString(a.batchName)}"`;
      selectConstraint = removeConstraint;
    } else {
      // Unnamed submission: one cluster, one batch, as before.
      batchID = a.minCluster;
      name = String(batchID);
      removeConstraint = `ClusterId == ${batchID}`;
      selectConstraint = removeConstraint;
    }

    batches.push({
      batchID,
      schedd: a.schedd,
      name,
      owner: isDag ? (a.rootOwner ?? a.owner) : a.owner,
      cmd: a.cmd,
      args: a.args,
      submittedUnix: a.submittedUnix,
      groupKey,
      statusCounts: a.statusCounts,
      jobCount: a.jobCount,
      jobs: a.jobs,
      isDag,
      dagNodes: dagNodeCounts(a.dagRoots),
      clusterIds: Array.from(a.clusters),
      removeConstraint,
      selectConstraint,
    });
  }

  // Newest batch first. The table's own sort takes over from here; this
  // only fixes the order the sort starts from.
  return batches.sort((a, b) => b.batchID - a.batchID);
}

// BatchKey identifies a batch row: its cluster id, or in multi-AP mode
// the access point and cluster id together.
export type BatchKey = number | string;

export function batchKey(b: Batch): BatchKey {
  return b.schedd ? `${b.schedd}\u0000${b.batchID}` : b.batchID;
}

// batchPagePath is a batch's own page, /batches/<id>. The server
// resolves any of a batch's clusters to it, but it serves a single access
// point only: a batch read in multi-AP mode (schedd set) has no page.
export function batchPagePath(b: Pick<Batch, 'batchID' | 'schedd'>): string | undefined {
  if (b.schedd) return undefined;
  return `/batches/${b.batchID}`;
}

// batchIDOfJob is the id of the batch a job belongs to, as
// groupIntoBatches would give it where the job's whole batch is in
// view: a DAG's root DAGMan cluster, from the JobBatchName suffix, for
// every job of the DAG; otherwise the job's own cluster, which the batch
// page resolves to its batch.
export function batchIDOfJob(ad: ClassAd): number | undefined {
  const dag = str(ad.JobBatchName)?.match(DAG_SUFFIX);
  if (dag) return Number(dag[1]);
  return num(ad.ClusterId);
}

// adsInBatches keeps the ads whose cluster one of batches covers, for a
// summary that totals exactly what a filtered table shows. A batch can
// span many clusters (a DAG folds a whole tree into one row), so every
// cluster it covers counts, not just its representative id; and in
// multi-AP mode a cluster is matched together with its access point,
// because two access points each have a cluster 12.
export function adsInBatches(ads: ClassAd[], batches: Batch[]): ClassAd[] {
  const key = (schedd: string | undefined, cluster: number) =>
    schedd ? `${schedd}\u0000${cluster}` : String(cluster);
  const clusters = new Set(batches.flatMap((b) => b.clusterIds.map((c) => key(b.schedd, c))));
  return ads.filter((j) => {
    const c = num(j.ClusterId);
    return c !== undefined && clusters.has(key(scheddOf(j), c));
  });
}

// applyBatchFilter does the user-facing substring filter. Both the
// filter input and the chat's `set_filter` tool drive this. We match
// against a flat string built per batch — every field a user might
// reference in the input box: name, cluster id, owner, command line,
// and the display-status names of the jobs inside.
//
// Empty query returns the input unchanged. Multi-token queries
// (whitespace-separated) require ALL tokens to match SOMEWHERE in the
// haystack — feels natural for "held training-run" type inputs.
export function applyBatchFilter(batches: Batch[], query: string): Batch[] {
  const q = query.trim().toLowerCase();
  if (q === '') return batches;
  const tokens = q.split(/\s+/);
  return batches.filter((b) => {
    const haystack = [
      b.name,
      String(b.batchID),
      b.schedd ?? '',
      b.owner ?? '',
      b.cmd ?? '',
      b.args ?? '',
      // The status names the user actually reads in the row, e.g.
      // "running", "held", "uploading inputs". Lower-cased so the
      // substring compare against the lower-cased query is direct.
      Object.entries(b.statusCounts)
        .filter(([, n]) => n > 0)
        .map(([k]) => k)
        .join(' '),
    ]
      .join(' ')
      .toLowerCase();
    return tokens.every((t) => haystack.includes(t));
  });
}

// filterAdsByStatus narrows the job ads to the selected display statuses.
//
// It runs BEFORE grouping, deliberately: selecting "Running" should leave
// a batch's row reporting the running jobs in it, not the whole batch with
// its original breakdown. An empty selection means "no filter" rather than
// "nothing" — the status strip has no way to express the empty set and it
// is not a state a user would ask for.
export function filterAdsByStatus(ads: ClassAd[], selected: Set<DisplayStatus>): ClassAd[] {
  if (selected.size === 0) return ads;
  return ads.filter((j) =>
    selected.has(
      displayJobStatus({
        status: j.JobStatus as number | string | null | undefined,
        holdReasonCode: j.HoldReasonCode as number | string | null | undefined,
      }).key,
    ),
  );
}

// Stable order so status breakdowns and the status strip read
// consistently between renders.
export const DISPLAY_STATUS_ORDER: DisplayStatus[] = [
  'running',
  'idle',
  'uploading',
  'transferring',
  'held',
  'suspended',
  'completed',
  'removed',
  'unknown',
];

export const DISPLAY_STATUS_LABEL: Record<DisplayStatus, string> = {
  idle: 'Idle',
  running: 'Running',
  removed: 'Removed',
  completed: 'Completed',
  held: 'Held',
  transferring: 'Transferring Output',
  suspended: 'Suspended',
  uploading: 'Uploading Inputs',
  unknown: 'Unknown',
};

// statusRank orders a batch by the most "active" status it contains, for
// the sortable Status column. Sorting a multi-valued cell needs a single
// number, and the one that makes the column useful is the one that groups
// the running batches together and the held ones together.
export function statusRank(b: Batch): number {
  for (let i = 0; i < DISPLAY_STATUS_ORDER.length; i++) {
    if ((b.statusCounts[DISPLAY_STATUS_ORDER[i]] ?? 0) > 0) return i;
  }
  return DISPLAY_STATUS_ORDER.length;
}

// Resource totals over a set of jobs, in HTCondor's own units:
// RequestMemory is MB, and CPUs/GPUs are counts.
export interface ResourceTotals {
  cpus: number;
  memoryMB: number;
  gpus: number;
  // Jobs whose request we could not total because the attribute is an
  // unevaluated expression rather than a literal (RequestMemory is
  // routinely `ifthenelse(...)` until the job matches). Surfaced so a
  // partial total is never presented as a complete one.
  unresolved: number;
}

export interface JobsSummary {
  jobs: number;
  batches: number;
  owners: number;
  counts: Record<DisplayStatus, number>;
  // Resources the running jobs hold right now.
  running: ResourceTotals;
  // Resources the idle jobs are waiting for — the queue's pending demand.
  idle: ResourceTotals;
}

// summarizeJobs totals the jobs currently on screen: how many, in what
// state, and what they are consuming.
//
// "Consuming" is the requested allocation, not measured usage: the job ads
// a listing pulls carry Request*, and the startd's measured usage is not
// in them. For a running job the requested figure is what the pool handed
// out, which is the number an operator is looking for.
export function summarizeJobs(ads: ClassAd[]): JobsSummary {
  const counts = {} as Record<DisplayStatus, number>;
  const running = emptyTotals();
  const idle = emptyTotals();
  const clusters = new Set<number>();
  const owners = new Set<string>();

  for (const j of ads) {
    const display = displayJobStatus({
      status: j.JobStatus as number | string | null | undefined,
      holdReasonCode: j.HoldReasonCode as number | string | null | undefined,
    });
    counts[display.key] = (counts[display.key] ?? 0) + 1;

    const cluster = num(j.ClusterId);
    if (cluster !== undefined) clusters.add(cluster);
    const owner = str(j.Owner);
    if (owner) owners.add(owner);

    // Transferring output still occupies the slot, so it counts as in
    // use. Held and completed jobs hold nothing and are waiting for
    // nothing, so they land in neither bucket.
    if (display.key === 'running' || display.key === 'transferring' || display.key === 'suspended') {
      addRequest(running, j);
    } else if (display.key === 'idle') {
      addRequest(idle, j);
    }
  }

  return {
    jobs: ads.length,
    batches: clusters.size,
    owners: owners.size,
    counts,
    running,
    idle,
  };
}

function emptyTotals(): ResourceTotals {
  return { cpus: 0, memoryMB: 0, gpus: 0, unresolved: 0 };
}

function addRequest(into: ResourceTotals, j: ClassAd) {
  const cpus = num(j.RequestCpus);
  const mem = num(j.RequestMemory);
  const gpus = num(j.RequestGpus);
  // A job whose CPU or memory request is still an expression contributes
  // nothing to the total; count it so the panel can say the total is short
  // rather than quietly under-reporting.
  if (cpus === undefined || mem === undefined) into.unresolved++;
  into.cpus += cpus ?? 0;
  into.memoryMB += mem ?? 0;
  into.gpus += gpus ?? 0;
}

// attr reads a job attribute case-insensitively. ClassAd attribute names
// are, and a JSON object's keys are not: the schedd spells DAG_NodesTotal
// the way DAGMan published it, which need not be the way it is written
// here.
// --- How long a job has been in its current state ---
//
// For the listings and the job page: how long a running job's current
// run has been going, and how long an idle job has been waiting.

export interface JobTiming {
  kind: 'running' | 'waiting';
  // Unix seconds the state began.
  since: number;
}

// jobTiming reads the start of the current state off a job ad.
//
// Running counts from when the executable began (after input transfer),
// falling back to when the job was matched and started its run. Waiting
// counts from when the job last became idle -- an evicted job goes back
// to waiting, and its wait starts again -- falling back to submission.
export function jobTiming(ad: ClassAd): JobTiming | undefined {
  const status = num(ad.JobStatus);
  if (status === 2) {
    const since =
      num(attr(ad, 'JobCurrentStartExecutingDate')) ?? num(attr(ad, 'JobCurrentStartDate'));
    return since !== undefined && since > 0 ? { kind: 'running', since } : undefined;
  }
  if (status === 1) {
    const since = num(attr(ad, 'EnteredCurrentStatus')) ?? num(ad.QDate);
    return since !== undefined && since > 0 ? { kind: 'waiting', since } : undefined;
  }
  return undefined;
}

// --- Cores a job is using ---
//
// CpusUsage cannot be trusted while a job runs. On a cgroup v2 execute
// node the starter computes its CPU share as a fraction of one core and
// then publishes it divided by 100 as though it were a percentage
// (proc_family_direct_cgroup_v2.cpp, vanilla_proc.cpp), so a job keeping
// one core busy reports 0.01. Only when the job exits is CpusUsage
// recomputed from its CPU time, correctly.
//
// So for a running job the cores come from the cumulative counters: CPU
// seconds this run (RemoteUserCpu + RemoteSysCpu, which the shadow zeroes
// at the start of each run) over the wall time they cover. That wall time
// ends at StatsLastUpdateTimeStarter -- the starter's clock when it built
// the update that carried those counters, copied into the job ad from the
// same update -- not "now": the counters are only refreshed every few
// minutes, and dividing by the time since would understate a busy job.

// What coresUsed reads, for the projections that feed it.
export const CPU_COUNTER_ATTRS =
  'RemoteUserCpu,RemoteSysCpu,StatsLastUpdateTimeStarter,JobCurrentStartExecutingDate';

// Below this, the interval is too short to divide by: a few seconds of
// counter granularity (whole CPU-seconds) would swing the answer wildly.
const MIN_CPU_INTERVAL_SECONDS = 60;

// coresUsed is the number of cores a job is using, or undefined when its
// ad cannot say yet.
export function coresUsed(ad: ClassAd): number | undefined {
  const status = num(ad.JobStatus);
  // Running and suspended jobs have not exited: their CpusUsage is the
  // broken in-flight figure, never read here.
  if (status === 2 || status === 7) {
    const user = num(attr(ad, 'RemoteUserCpu'));
    const sys = num(attr(ad, 'RemoteSysCpu'));
    const sampled = num(attr(ad, 'StatsLastUpdateTimeStarter'));
    const started = num(attr(ad, 'JobCurrentStartExecutingDate'));
    if (user === undefined || sys === undefined || sampled === undefined || started === undefined) {
      return undefined;
    }
    // A sample time from before this run started belongs to the previous
    // run, whose counters the shadow has already zeroed.
    const interval = sampled - started;
    if (!(interval >= MIN_CPU_INTERVAL_SECONDS)) return undefined;
    return (user + sys) / interval;
  }
  return num(attr(ad, 'CpusUsage'));
}

export function attr(ad: ClassAd, name: string): unknown {
  if (name in ad) return ad[name];
  const lc = name.toLowerCase();
  for (const k of Object.keys(ad)) {
    if (k.toLowerCase() === lc) return ad[k];
  }
  return undefined;
}

export function num(v: unknown): number | undefined {
  if (typeof v === 'number') return v;
  if (typeof v === 'string') {
    const n = Number(v);
    if (!Number.isNaN(n)) return n;
  }
  return undefined;
}

export function str(v: unknown): string | undefined {
  if (typeof v === 'string' && v !== '') return v;
  if (v === undefined || v === null) return undefined;
  if (typeof v === 'string') return undefined;
  return String(v);
}

// --- Per-batch usage, for the panel inside an expanded batch row ---

// What the expanded row asks for on demand. Deliberately not part of
// BATCH_PROJECTION: these attributes are worth a column of bytes per job
// on a queue of 30k, and they are only ever read for the one batch
// somebody opened.
export const BATCH_USAGE_PROJECTION =
  'ClusterId,ProcId,JobStatus,HoldReasonCode,RequestCpus,RequestMemory,RequestDisk,RequestGpus,CpusUsage,MemoryUsage,ResidentSetSize,DiskUsage,' +
  CPU_COUNTER_ATTRS;

// How a row's numbers should be read. The lib keeps HTCondor's own
// units -- MiB for memory, KiB for disk -- and the panel formats them.
export type ResourceUnit = 'count' | 'mib' | 'kib';

export interface BatchUsageRow {
  label: string;
  unit: ResourceUnit;
  // Requested by the jobs that are running: what the pool handed this
  // batch. undefined when no running job carried a literal request.
  allocated?: number;
  // Measured by the execute nodes. undefined where nothing reports it
  // (GPUs), or where no running job has reported yet.
  used?: number;
  // Requested by the idle jobs: what the batch is still waiting for.
  waiting?: number;
}

export interface BatchUsage {
  running: number;
  idle: number;
  // Running jobs that have reported any measurement at all. A batch
  // that just started matches "running > 0, reporting == 0", which is
  // why the panel can say "not reported yet" instead of showing zero
  // usage as though the jobs were idling.
  reporting: number;
  rows: BatchUsageRow[];
}

// summarizeBatchUsage totals one batch's requests against what the
// execute nodes measured.
//
// Requests are split by state on purpose. Comparing usage against the
// WHOLE batch's request would make a batch with two running jobs and a
// hundred queued ones look like it was wasting 98% of its allocation,
// when the pool has handed it nothing for those hundred.
//
// Usage attributes only exist for jobs that are running, and only after
// the starter's first report -- so every one of them is optional, and a
// missing value stays missing rather than being counted as a zero.
export function summarizeBatchUsage(ads: ClassAd[]): BatchUsage {
  const alloc = { cpus: 0, mem: 0, disk: 0, gpus: 0 };
  const wait = { cpus: 0, mem: 0, disk: 0, gpus: 0 };
  const used = { cpus: 0, mem: 0, disk: 0 };
  const seen = { alloc: false, wait: false, cpus: false, mem: false, disk: false };
  let running = 0;
  let idle = 0;
  let reporting = 0;

  for (const j of ads) {
    const display = displayJobStatus({
      status: j.JobStatus as number | string | null | undefined,
      holdReasonCode: j.HoldReasonCode as number | string | null | undefined,
    });
    // Output transfer and suspension still hold the slot, so they are
    // counted as running here just as they are in the queue summary.
    const isRunning =
      display.key === 'running' ||
      display.key === 'transferring' ||
      display.key === 'suspended';
    const isIdle = display.key === 'idle';
    if (!isRunning && !isIdle) continue;

    const req = {
      cpus: num(j.RequestCpus),
      mem: num(j.RequestMemory),
      disk: num(j.RequestDisk),
      gpus: num(j.RequestGpus),
    };
    const into = isRunning ? alloc : wait;
    for (const k of ['cpus', 'mem', 'disk', 'gpus'] as const) {
      const v = req[k];
      if (v === undefined) continue;
      into[k] += v;
      if (isRunning) seen.alloc = true;
      else seen.wait = true;
    }

    if (isRunning) {
      running++;
      const cpus = coresUsed(j);
      // MemoryUsage is an expression in the job ad more often than not,
      // so ResidentSetSize -- which the starter writes as a literal in
      // KiB -- is the one that can be trusted to be a number.
      const rss = num(attr(j, 'ResidentSetSize'));
      const mem = num(attr(j, 'MemoryUsage')) ?? (rss !== undefined ? rss / 1024 : undefined);
      const disk = num(attr(j, 'DiskUsage'));
      let any = false;
      if (cpus !== undefined) {
        used.cpus += cpus;
        seen.cpus = true;
        any = true;
      }
      if (mem !== undefined) {
        used.mem += mem;
        seen.mem = true;
        any = true;
      }
      if (disk !== undefined) {
        used.disk += disk;
        seen.disk = true;
        any = true;
      }
      if (any) reporting++;
    } else {
      idle++;
    }
  }

  const rows: BatchUsageRow[] = [
    {
      label: 'CPUs',
      unit: 'count',
      allocated: seen.alloc ? alloc.cpus : undefined,
      used: seen.cpus ? used.cpus : undefined,
      waiting: seen.wait ? wait.cpus : undefined,
    },
    {
      label: 'Memory',
      unit: 'mib',
      allocated: seen.alloc ? alloc.mem : undefined,
      used: seen.mem ? used.mem : undefined,
      waiting: seen.wait ? wait.mem : undefined,
    },
    {
      label: 'Disk',
      unit: 'kib',
      allocated: seen.alloc ? alloc.disk : undefined,
      used: seen.disk ? used.disk : undefined,
      waiting: seen.wait ? wait.disk : undefined,
    },
  ];
  // GPUs only when something asked for one. Nothing measures GPU use in
  // the job ad, so that column stays empty by design rather than by
  // accident.
  if (alloc.gpus > 0 || wait.gpus > 0) {
    rows.push({
      label: 'GPUs',
      unit: 'count',
      allocated: seen.alloc ? alloc.gpus : undefined,
      waiting: seen.wait ? wait.gpus : undefined,
    });
  }

  return { running, idle, reporting, rows };
}
