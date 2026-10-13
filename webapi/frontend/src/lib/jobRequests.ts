// What a job asked for, read one way everywhere on the job and archive
// pages.
//
// A request can be written as a rule rather than a number:
//
//   RequestMemory = ifthenelse(MemoryUsage =!= undefined,
//                              max({ 2048, 3 * MemoryUsage / 2 }), 2048)
//
// which reaches the browser as the string "/Expr(...)/". The server
// evaluates each Request* attribute in the job's own ad and sends the
// numbers in the "evaluated" member (see annotateEvaluatedRequests in
// httpserver/job_request_attrs.go), so nothing here re-implements ClassAd
// evaluation. The resource table, the usage bars and the usage graphs'
// "requested" line all read jobRequest, and so agree.

import type { ClassAd } from './api';
import { unwrapExpr } from './requirements';

export type RequestAttr = 'RequestCpus' | 'RequestMemory' | 'RequestDisk' | 'RequestGPUs';

// The member the server adds beside the ad's own attributes. Not a job
// attribute, so the attribute table leaves it out.
export const EVALUATED_KEY = 'evaluated';

export interface JobRequest {
  // The number the job asks for; undefined when the ad does not say or the
  // rule has no value in the job's own ad (one that reads the machine).
  value?: number;
  // The rule's text when the request was written as an expression.
  expr?: string;
}

// attr reads an attribute by name, ignoring case as ClassAds do: an exact
// match first, then any spelling.
export function attr(job: ClassAd | undefined, name: string): unknown {
  if (!job) return undefined;
  if (name in job) return job[name];
  const lower = name.toLowerCase();
  for (const k of Object.keys(job)) {
    if (k.toLowerCase() === lower) return job[k];
  }
  return undefined;
}

function isExpr(v: unknown): v is string {
  return typeof v === 'string' && v.startsWith('/Expr(');
}

function toNum(v: unknown): number | undefined {
  if (typeof v === 'number') return Number.isFinite(v) ? v : undefined;
  if (typeof v === 'string' && v.trim() !== '' && !isExpr(v)) {
    const n = Number(v);
    return Number.isFinite(n) ? n : undefined;
  }
  return undefined;
}

export function jobRequest(job: ClassAd | undefined, name: RequestAttr): JobRequest {
  const raw = attr(job, name);
  const evaluated = attr(job, EVALUATED_KEY);
  const fromServer =
    evaluated && typeof evaluated === 'object' && !Array.isArray(evaluated)
      ? toNum(attr(evaluated as ClassAd, name))
      : undefined;
  const out: JobRequest = { value: fromServer ?? toNum(raw) };
  if (isExpr(raw)) out.expr = unwrapExpr(raw);
  return out;
}

// gpusUsed is how many GPUs the job kept busy: GPUsAverageUsage, the run's
// average, else GPUsUsage, the running job's recent figure. A finished
// job's history record carries only the average. Both are summed over the
// job's GPUs, so 2 is two GPUs fully busy. The server leaves out a figure
// larger than the GPUs the job held.
export function gpusUsed(job: ClassAd | undefined): number | undefined {
  return toNum(attr(job, 'GPUsAverageUsage')) ?? toNum(attr(job, 'GPUsUsage'));
}

// hasGpus decides whether a GPU row or series belongs on the page: the job
// asked for at least one GPU, or it has some assigned, provisioned or in
// use. RequestGPUs = 0 alone is a job without GPUs.
export function hasGpus(job: ClassAd | undefined): boolean {
  if ((jobRequest(job, 'RequestGPUs').value ?? 0) > 0) return true;
  if ((toNum(attr(job, 'GPUsProvisioned')) ?? 0) > 0) return true;
  if ((gpusUsed(job) ?? 0) > 0) return true;
  const assigned = attr(job, 'AssignedGPUs');
  return typeof assigned === 'string' && assigned.trim() !== '';
}
