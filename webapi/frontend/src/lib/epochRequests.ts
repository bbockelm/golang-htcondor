// What each run of a job asked for, from epoch_history.
//
// The job ad holds one request, the one in force now. A job that is
// restarted at a larger request -- a retry ladder climbing a rung on
// eviction, a formula regrowing after a hold -- has held several, and the
// queue remembers only the last.
//
// The samples cannot stand in for it. job_metrics rows are taken as the
// schedd commits usage updates, and a run's samples can carry a
// neighbouring run's request at either end: the on-evict transform
// rewrites RequestMemory as the shadow exits, alongside the update
// carrying that run's final usage, and the schedd bumps NumShadowStarts
// before the next shadow starts, so the first row of a run can still hold
// the previous run's figures.
//
// The shadow writes the epoch record from its OWN copy of the job ad --
// the copy the schedd handed it when the run began -- so that record is
// the request the run actually held, taken before either rewrite.
//
// The two agree on which run is which without translation: the sampler
// derives RunInstanceID as NumShadowStarts-1, the same way HTCondor's
// epoch writer does.

import type { ClassAd, HistoryListResponse } from './api';
import { attr } from './jobRequests';

// EPOCH_REQUEST_PROJECTION is what a run's record is read for. Narrow:
// the whole epoch ad is the whole job ad, and a job with many runs would
// send it many times over.
export const EPOCH_REQUEST_PROJECTION = [
  'ClusterId',
  'ProcId',
  'RunInstanceID',
  'EpochAdType',
  'RequestMemory',
  'RequestCpus',
  'RequestDisk',
  'RequestGPUs',
].join(',');

// EPOCH_REQUEST_LIMIT caps the read. A job leaves several records per run
// -- the run itself plus a file-transfer record per leg -- so this is far
// more runs than it looks.
export const EPOCH_REQUEST_LIMIT = 500;

// epochConstraint selects one job's records, or undefined for an id that
// is not "cluster.proc" (the placeholder a static export renders with).
export function epochConstraint(jobID: string | undefined): string | undefined {
  if (!jobID) return undefined;
  const [cluster, proc] = jobID.split('.');
  if (!/^\d+$/.test(cluster ?? '') || !/^\d+$/.test(proc ?? '')) return undefined;
  return `ClusterId == ${cluster} && ProcId == ${proc}`;
}

// A run leaves more than one record behind and only one of them is the
// run ending. job_ad_instance_recording.cpp names the kind in
// EpochAdType: "EPOCH" is the finished run -- the shadow writes the whole
// job ad at exit, at hold and on vacate -- while "SPAWN" is a filtered
// projection that usually carries none of this, and
// INPUT/OUTPUT/CHECKPOINT/COMMON are the file-transfer records, which
// carry only what <BANNER>_JOB_ATTRS names.
//
// A record with no EpochAdType is kept: a schedd old enough not to write
// one wrote only the single kind.
const runInstanceType = 'EPOCH';

function isRunRecord(ad: ClassAd): boolean {
  const t = attr(ad, 'EpochAdType');
  return t === undefined || t === null || t === runInstanceType;
}

function runOf(ad: ClassAd): number | undefined {
  const v = attr(ad, 'RunInstanceID');
  if (typeof v === 'number' && Number.isInteger(v) && v >= 0) return v;
  if (typeof v === 'string' && /^\d+$/.test(v)) return Number(v);
  return undefined;
}

// runAds keys a job's finished-run records by RunInstanceID. Later
// records win, which is how a run that was written more than once (a
// hold, then the exit) ends up represented by its last word.
export function runAds(resp: HistoryListResponse | undefined): Map<number, ClassAd> {
  const out = new Map<number, ClassAd>();
  for (const ad of resp?.ads ?? []) {
    if (!isRunRecord(ad)) continue;
    const run = runOf(ad);
    if (run !== undefined) out.set(run, ad);
  }
  return out;
}

// runRequest is the amount a run asked for, or undefined where the record
// cannot say.
//
// Only a literal counts. A request written as a rule over the job's own
// usage is stored as the rule, and the rule in a run's record evaluates
// against the usage that run FINISHED with -- which is the next run's
// request, not this one's. There is no number to recover there, so the
// run goes without one rather than being given a wrong one.
export function runRequest(ad: ClassAd | undefined, name: string): number | undefined {
  const v = attr(ad, name);
  if (typeof v === 'number') return Number.isFinite(v) && v > 0 ? v : undefined;
  if (typeof v === 'string' && /^\d+(\.\d+)?$/.test(v.trim())) {
    const n = Number(v);
    return Number.isFinite(n) && n > 0 ? n : undefined;
  }
  return undefined;
}
