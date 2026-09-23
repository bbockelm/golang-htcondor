// The batch model behind /jobs and /users/<owner>.
//
// HTCondor is batch-oriented: a submission produces one cluster that may
// hold many jobs, and the listing pages render one row per batch with the
// jobs inside it. Both pages ask the same questions of the same job ads --
// group them, filter them, total their resources -- so the answers live
// here rather than in either page.

import { displayJobStatus, type ClassAd, type DisplayStatus, type DisplayStatusInfo } from '@/lib/api';

// Attributes every batch listing needs. QDate has to be asked for
// explicitly: the schedd does not backfill it, and the submit path sets it
// at submit time (see submit.go). The Request* attributes drive the
// resource totals in the summary panel.
export const BATCH_PROJECTION =
  'ClusterId,ProcId,JobStatus,HoldReason,HoldReasonCode,Owner,Cmd,Args,QDate,JobBatchName,Iwd,RequestCpus,RequestMemory,RequestGpus';

// Batch is what we render: one batch's worth of jobs aggregated.
export interface Batch {
  batchID: number; // HTCondor's ClusterId — internal name only
  // Display name: BatchName if set, else batch id, else "?".
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
  // Per-status counts — keyed by DisplayStatus so spool-held shows
  // up as "Uploading Inputs" instead of being lumped under "Held".
  statusCounts: Record<DisplayStatus, number>;
  jobCount: number;
  // The individual jobs, kept around so the row can expand inline.
  jobs: BatchJob[];
}

export interface BatchJob {
  // Display id used in URLs ("3.0").
  id: string;
  jobIdx: number; // ProcId
  display: DisplayStatusInfo;
  cmd?: string;
  args?: string;
  submittedUnix?: number;
}

export function groupIntoBatches(jobs: ClassAd[]): Batch[] {
  const map = new Map<number, Batch>();
  for (const j of jobs) {
    const cluster = num(j.ClusterId);
    const proc = num(j.ProcId);
    if (cluster === undefined) continue;

    let b = map.get(cluster);
    if (!b) {
      b = {
        batchID: cluster,
        name: str(j.JobBatchName) ?? String(cluster),
        owner: str(j.Owner),
        cmd: str(j.Cmd),
        args: str(j.Args),
        submittedUnix: num(j.QDate),
        statusCounts: {} as Record<DisplayStatus, number>,
        jobCount: 0,
        jobs: [],
      };
      map.set(cluster, b);
    }

    b.jobCount++;
    const display = displayJobStatus({
      status: j.JobStatus as number | string | null | undefined,
      holdReasonCode: j.HoldReasonCode as number | string | null | undefined,
    });
    b.statusCounts[display.key] = (b.statusCounts[display.key] ?? 0) + 1;
    const q = num(j.QDate);
    if (q !== undefined && (b.submittedUnix === undefined || q < b.submittedUnix)) {
      b.submittedUnix = q;
    }
    if (!b.owner) b.owner = str(j.Owner);
    if (!b.cmd) b.cmd = str(j.Cmd);
    if (!b.args) b.args = str(j.Args);
    const bn = str(j.JobBatchName);
    if (bn && b.name === String(b.batchID)) {
      b.name = bn;
    }

    b.jobs.push({
      id: `${cluster}.${proc ?? 0}`,
      jobIdx: proc ?? 0,
      display,
      cmd: str(j.Cmd),
      args: str(j.Args),
      submittedUnix: q,
    });
  }

  // Sort jobs within each batch by job index for stable display.
  for (const b of map.values()) {
    b.jobs.sort((a, b) => a.jobIdx - b.jobIdx);
  }

  // Newest batch first. The table's own sort takes over from here; this
  // only fixes the order the sort starts from.
  return Array.from(map.values()).sort((a, b) => b.batchID - a.batchID);
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
  'ClusterId,ProcId,JobStatus,HoldReasonCode,RequestCpus,RequestMemory,RequestDisk,RequestGpus,CPUsUsage,MemoryUsage,ResidentSetSize,DiskUsage';

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
      const cpus = num(j.CPUsUsage);
      // MemoryUsage is an expression in the job ad more often than not,
      // so ResidentSetSize -- which the starter writes as a literal in
      // KiB -- is the one that can be trusted to be a number.
      const rss = num(j.ResidentSetSize);
      const mem = num(j.MemoryUsage) ?? (rss !== undefined ? rss / 1024 : undefined);
      const disk = num(j.DiskUsage);
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
