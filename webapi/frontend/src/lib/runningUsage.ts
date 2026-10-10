// Memory and CPU of running jobs against what they asked for, for the
// /jobs running view.
//
// Two numbers, and they are not the same kind of number:
//
//   - Memory is a PEAK. HTCondor keeps no current memory figure in the job
//     ad: MemoryUsage and ResidentSetSize only ever ratchet up, so the
//     honest reading is "the most this job has used", which is also the
//     one that matters -- a job is held for going over its request, not
//     for averaging under it.
//
//   - CPU is a RATE, and where it comes from changes what it means.
//     CpusUsage in the job ad is an average since the job started on most
//     execute nodes, so a job that computed hard for an hour and has been
//     stuck in I/O since still reads as busy. When per-job samples are
//     being kept, the average of their CpuUtil (cores used over each
//     sample interval) over the last hour is what the job is doing now.
//     Each reading keeps its source so the tooltip can say which one it
//     is, and a job with no recent sample falls back to CpusUsage rather
//     than disappearing.

import { jobIdOf, scheddOf, type ClassAd } from '@/lib/api';
import { attr, num, type BatchJob } from '@/lib/batches';
import type { MetricsResponse } from '@/lib/metrics';

// Narrow on purpose: this is fetched only for the running view, and only
// the running jobs, every 30 seconds. ResidentSetSize is here because
// MemoryUsage is an expression over it and only evaluates to a number when
// both are asked for.
export const RUNNING_USAGE_PROJECTION =
  'ClusterId,ProcId,JobStatus,RequestMemory,RequestCpus,MemoryUsage,ResidentSetSize,CpusUsage';

// How far back "recent" CPU looks.
export const RECENT_CPU_WINDOW_SECONDS = 3600;
export const RECENT_CPU_GROUP_BY = 'ClusterId,ProcId';
export const RECENT_CPU_AGG = 'avg:CpuUtil';

export type CpuSource = 'recent' | 'since-start';

export interface JobUsage {
  memUsedMiB?: number;
  memReqMiB?: number;
  cpuUsed?: number;
  cpuReq?: number;
  cpuSource?: CpuSource;
}

// recentCpuConstraint narrows the samples query to the clusters on screen.
// A range rather than a list: it stays short whatever the number of
// clusters, and the samples are laid out by ClusterId, so a range is what
// the store can skip through cheaply. Rows for clusters in the range that
// are not on screen are simply never looked up.
export function recentCpuConstraint(ads: ClassAd[]): string | undefined {
  let lo = Infinity;
  let hi = -Infinity;
  for (const ad of ads) {
    const c = num(ad.ClusterId);
    if (c === undefined) continue;
    if (c < lo) lo = c;
    if (c > hi) hi = c;
  }
  if (!Number.isFinite(lo)) return undefined;
  return lo === hi ? `ClusterId == ${lo}` : `ClusterId >= ${lo} && ClusterId <= ${hi}`;
}

// recentCpuByJob reads the samples answer into "cluster.proc" -> cores.
// Undefined when samples are not being kept, which is different from an
// empty map (kept, but nothing recent for these jobs).
export function recentCpuByJob(resp: MetricsResponse | undefined): Map<string, number> | undefined {
  if (!resp || !resp.enabled || !resp.columns) return undefined;
  const idx = new Map(resp.columns.map((c, i) => [c.name, i]));
  const ci = idx.get('ClusterId');
  const pi = idx.get('ProcId');
  const vi = idx.get('avg_CpuUtil');
  const out = new Map<string, number>();
  if (ci === undefined || pi === undefined || vi === undefined) return out;
  for (const row of resp.rows ?? []) {
    const v = row[vi];
    // An empty cell is a job whose samples in the window all lacked a
    // rate (its first interval of a run has none). That is "no recent
    // reading", not zero.
    if (v === undefined || v === '') continue;
    const n = Number(v);
    if (!Number.isFinite(n)) continue;
    out.set(`${row[ci]}.${row[pi]}`, n);
  }
  return out;
}

// jobUsageByJob joins the usage ads and the recent CPU readings, keyed by
// the same id the batch table gives each job (BatchJob.id).
//
// Recent readings are joined only for single-access-point rows: the
// samples are keyed by cluster and proc, which two access points can
// share.
export function jobUsageByJob(
  ads: ClassAd[],
  recent: Map<string, number> | undefined,
): Map<string, JobUsage> {
  const out = new Map<string, JobUsage>();
  for (const ad of ads) {
    const cluster = num(ad.ClusterId);
    if (cluster === undefined) continue;
    const proc = num(ad.ProcId) ?? 0;
    const id = jobIdOf(ad) ?? `${cluster}.${proc}`;
    // MemoryUsage is MiB; ResidentSetSize is KiB.
    const rss = num(attr(ad, 'ResidentSetSize'));
    const mem = num(attr(ad, 'MemoryUsage')) ?? (rss !== undefined ? rss / 1024 : undefined);
    const u: JobUsage = {
      memUsedMiB: mem,
      memReqMiB: num(attr(ad, 'RequestMemory')),
      cpuReq: num(attr(ad, 'RequestCpus')),
    };
    const r = scheddOf(ad) ? undefined : recent?.get(`${cluster}.${proc}`);
    if (r !== undefined) {
      u.cpuUsed = r;
      u.cpuSource = 'recent';
    } else {
      const lifetime = num(attr(ad, 'CpusUsage'));
      if (lifetime !== undefined) {
        u.cpuUsed = lifetime;
        u.cpuSource = 'since-start';
      }
    }
    out.set(id, u);
  }
  return out;
}

// --- Readings: what a UsageBar draws ---

// The tone of a bar is its one judgement, and each is spelled out in the
// text as well, never left to the colour alone.
//   warn     memory at 90% of its request or more, where a job is close
//            to being held; CPU over 110% of its request.
//   critical memory over its request.
//   muted    CPU under a quarter of its request: idle cores, worth a look
//            but not a problem.
//   none     nothing measured yet.
export type UsageTone = 'normal' | 'warn' | 'critical' | 'muted' | 'none';

export interface UsageReading {
  // Fraction of the request used, for the fill. Undefined when the
  // request is not a number.
  fill?: number;
  // Fraction for a thin mark at the batch's largest job, and that job's
  // own tone: one job over its memory request is worth seeing on a batch
  // whose median job is fine, without painting the whole batch red.
  tick?: number;
  tickTone?: UsageTone;
  tone: UsageTone;
  text: string;
  title: string;
  // For sorting.
  sortValue?: number;
}

const NOT_REPORTED: UsageReading = {
  tone: 'none',
  text: 'not reported yet',
  title: 'This job has not reported its usage yet.',
};

const BATCH_NOT_REPORTED: UsageReading = {
  tone: 'none',
  text: 'not reported yet',
  title: 'None of these jobs has reported its usage yet.',
};

export function memoryTone(frac: number | undefined): UsageTone {
  if (frac === undefined) return 'normal';
  if (frac > 1) return 'critical';
  if (frac >= 0.9) return 'warn';
  return 'normal';
}

export function cpuTone(frac: number | undefined): UsageTone {
  if (frac === undefined) return 'normal';
  if (frac > 1.1) return 'warn';
  if (frac < 0.25) return 'muted';
  return 'normal';
}

const pct = (f: number) => `${Math.round(f * 100)}%`;

// fmtMiB renders one memory figure; fmtMiBPair renders "used / request" in
// one unit, chosen by the larger of the two so "0.5 / 2.0 GB" never turns
// into "512 MB / 2.0 GB".
export function fmtMiB(mib: number): string {
  return mib >= 1024 ? `${(mib / 1024).toFixed(1)} GB` : `${Math.round(mib)} MB`;
}

function fmtMiBPair(used: number, req: number): string {
  if (Math.max(used, req) >= 1024) {
    return `${(used / 1024).toFixed(1)} / ${(req / 1024).toFixed(1)} GB`;
  }
  return `${Math.round(used)} / ${Math.round(req)} MB`;
}

// fmtMedianMax renders "median 1.1 · max 1.9 of 2.0 GB": one unit for
// all three when they share one, which is what keeps the batch column
// narrow enough to sit beside the others.
function fmtMedianMax(med: number, max: number, req: number): string {
  const gb = (v: number) => v >= 1024;
  if (gb(med) && gb(max) && gb(req)) {
    return `median ${(med / 1024).toFixed(1)} · max ${(max / 1024).toFixed(1)} of ${(req / 1024).toFixed(1)} GB`;
  }
  if (!gb(med) && !gb(max) && !gb(req)) {
    return `median ${Math.round(med)} · max ${Math.round(max)} of ${Math.round(req)} MB`;
  }
  return `median ${fmtMiB(med)} · max ${fmtMiB(max)} of ${fmtMiB(req)}`;
}

function fmtCores(v: number): string {
  return Number.isInteger(v) ? String(v) : v.toFixed(1);
}

function coresWord(req: number): string {
  return req === 1 ? 'core' : 'cores';
}

const SOURCE_PHRASE: Record<CpuSource, string> = {
  recent: 'averaged over the last hour',
  'since-start': 'averaged since the job started',
};

export function jobMemoryReading(u: JobUsage | undefined): UsageReading {
  if (!u || u.memUsedMiB === undefined) return NOT_REPORTED;
  const used = u.memUsedMiB;
  const req = u.memReqMiB;
  if (req === undefined || req <= 0) {
    return {
      tone: 'normal',
      text: fmtMiB(used),
      title: `Peak memory ${fmtMiB(used)}`,
    };
  }
  const frac = used / req;
  const tone = memoryTone(frac);
  return {
    fill: frac,
    tone,
    text: fmtMiBPair(used, req) + (tone === 'normal' ? '' : ` · ${pct(frac)}`),
    title: `Peak memory ${fmtMiB(used)} of ${fmtMiB(req)} requested (${pct(frac)})`,
    sortValue: frac,
  };
}

export function jobCpuReading(u: JobUsage | undefined): UsageReading {
  if (!u || u.cpuUsed === undefined || u.cpuSource === undefined) return NOT_REPORTED;
  const used = u.cpuUsed;
  const req = u.cpuReq;
  const when = SOURCE_PHRASE[u.cpuSource];
  if (req === undefined || req <= 0) {
    return {
      tone: 'normal',
      text: `${used.toFixed(1)} cores`,
      title: `Using ${used.toFixed(1)} cores, ${when}`,
    };
  }
  const frac = used / req;
  const tone = cpuTone(frac);
  return {
    fill: frac,
    tone,
    text:
      `${used.toFixed(1)} / ${fmtCores(req)} ${coresWord(req)}` +
      (tone === 'warn' ? ` · ${pct(frac)}` : ''),
    title: `Using ${used.toFixed(1)} of ${fmtCores(req)} requested ${coresWord(req)} (${pct(frac)}), ${when}`,
    sortValue: frac,
  };
}

function median(sorted: number[]): number {
  const m = sorted.length >> 1;
  return sorted.length % 2 ? sorted[m] : (sorted[m - 1] + sorted[m]) / 2;
}

// The request every job in the set shares, or undefined when they differ
// -- in which case absolute numbers would be read against the wrong
// request and the text falls back to percentages.
function commonRequest(reqs: number[]): number | undefined {
  return reqs.every((r) => r === reqs[0]) ? reqs[0] : undefined;
}

function plural(n: number, one: string, many: string): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

// batchMemoryReading: the median job's peak as the fill, the largest
// job's as a tick. The median, because one job that blew up should not
// make the whole batch look oversized, and the tick, because that one job
// is the one about to be held.
export function batchMemoryReading(
  jobs: BatchJob[],
  usage: ReadonlyMap<string, JobUsage>,
): UsageReading {
  const pairs: { used: number; req: number }[] = [];
  let unreported = 0;
  for (const j of jobs) {
    const u = usage.get(j.id);
    if (u?.memUsedMiB === undefined) {
      unreported++;
      continue;
    }
    if (u.memReqMiB !== undefined && u.memReqMiB > 0) {
      pairs.push({ used: u.memUsedMiB, req: u.memReqMiB });
    }
  }
  if (pairs.length === 0) return BATCH_NOT_REPORTED;

  const fracs = pairs.map((p) => p.used / p.req).sort((a, b) => a - b);
  const medFrac = median(fracs);
  const maxFrac = fracs[fracs.length - 1];
  const over = fracs.filter((f) => f > 1).length;
  const near = fracs.filter((f) => f >= 0.9 && f <= 1).length;
  const req = commonRequest(pairs.map((p) => p.req));

  let text: string;
  if (req !== undefined) {
    const used = pairs.map((p) => p.used).sort((a, b) => a - b);
    text = fmtMedianMax(median(used), used[used.length - 1], req);
  } else {
    text = `median ${pct(medFrac)} · max ${pct(maxFrac)} of request`;
  }

  const lines = [
    `Peak memory of ${plural(pairs.length, 'running job', 'running jobs')}: median ${pct(medFrac)}, largest ${pct(maxFrac)} of the request`,
  ];
  if (over > 0) lines.push(`${plural(over, 'job is', 'jobs are')} over the request`);
  if (near > 0) lines.push(`${plural(near, 'job is', 'jobs are')} within 10% of the request`);
  if (unreported > 0) lines.push(`${plural(unreported, 'job has', 'jobs have')} not reported yet`);

  return {
    fill: medFrac,
    tick: maxFrac,
    tone: memoryTone(medFrac),
    tickTone: memoryTone(maxFrac),
    text,
    title: lines.join('\n'),
    sortValue: medFrac,
  };
}

// batchCpuReading: the batch's mean cores used against its mean request,
// with the busiest job as a tick.
export function batchCpuReading(
  jobs: BatchJob[],
  usage: ReadonlyMap<string, JobUsage>,
): UsageReading {
  const pairs: { used: number; req: number; source: CpuSource }[] = [];
  let unreported = 0;
  for (const j of jobs) {
    const u = usage.get(j.id);
    if (u?.cpuUsed === undefined || u.cpuSource === undefined) {
      unreported++;
      continue;
    }
    if (u.cpuReq !== undefined && u.cpuReq > 0) {
      pairs.push({ used: u.cpuUsed, req: u.cpuReq, source: u.cpuSource });
    }
  }
  if (pairs.length === 0) return BATCH_NOT_REPORTED;

  const meanUsed = pairs.reduce((s, p) => s + p.used, 0) / pairs.length;
  const meanReq = pairs.reduce((s, p) => s + p.req, 0) / pairs.length;
  const frac = meanUsed / meanReq;
  const maxFrac = Math.max(...pairs.map((p) => p.used / p.req));
  const req = commonRequest(pairs.map((p) => p.req));
  const recent = pairs.filter((p) => p.source === 'recent').length;
  const sinceStart = pairs.length - recent;

  const text =
    req !== undefined
      ? `mean ${meanUsed.toFixed(1)} of ${fmtCores(req)} ${coresWord(req)}`
      : `mean ${pct(frac)} of request`;

  let when: string;
  if (sinceStart === 0) when = SOURCE_PHRASE.recent;
  else if (recent === 0) when = 'averaged since each job started';
  else
    when = `averaged over the last hour for ${plural(recent, 'job', 'jobs')}, since it started for ${plural(sinceStart, 'job', 'jobs')}`;

  const lines = [
    `CPU of ${plural(pairs.length, 'running job', 'running jobs')}: mean ${meanUsed.toFixed(1)} of ${fmtCores(Number(meanReq.toFixed(1)))} requested cores (${pct(frac)}), busiest ${pct(maxFrac)}`,
    when.charAt(0).toUpperCase() + when.slice(1),
  ];
  if (unreported > 0) lines.push(`${plural(unreported, 'job has', 'jobs have')} not reported yet`);

  return {
    fill: frac,
    tick: maxFrac,
    tone: cpuTone(frac),
    tickTone: cpuTone(maxFrac) === 'warn' ? 'warn' : 'normal',
    text,
    title: lines.join('\n'),
    sortValue: frac,
  };
}
