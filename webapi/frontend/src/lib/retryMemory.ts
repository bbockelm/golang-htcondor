// What a memory retry ladder says about one job, read off the ad the job
// and archive pages already fetch whole.
//
// `retry_request_memory` installs a transform that runs when the job is
// evicted (HTCondor's SetBuiltInOnEvictCheck), leaving the job with:
//
//   RetryRequestMemory = { 2048, 4096, 8192 }
//   EVALSET RequestMemory RetryRequestMemory[RetryRequestMemoryIndex?:0]
//   EVALSET RetryRequestMemoryIndex MIN({size(RetryRequestMemory)-1,
//                                        (RetryRequestMemoryIndex?:0)+1})
//
// Two consequences shape everything below.
//
// The list holds the RETRIES, not the first request: rung 0 is what the
// job asks for after its first eviction, so the request it started at is
// not in the list at all. RequestMemory held it until the first eviction
// overwrote it, which is why a climber's record cannot name it.
//
// The index is bumped AFTER the request is set, so an index of k means
// the job was evicted k times and now asks for rungs[k-1] -- except at
// the top, where the index sticks at size-1 while the request keeps
// moving, and k is only a lower bound.
//
// The other two spellings leave no list. `retry_request_memory_increase`
// with a max leaves MaxRequestMemory and NextRequestMemory; a single
// retry value leaves neither, and only TransformOnEvict says the job has
// a ladder at all.

import { attr } from './jobRequests';
import { formatMiB } from './utilization';
import type { ClassAd } from './api';

export interface MemoryLadder {
  // The rungs, when the job was submitted with a list of them. Each is a
  // request the job retries at, in order, the first after one eviction.
  rungs?: number[];
  // How many times the job was evicted for outgrowing its request and
  // started again at a larger one. Undefined when the record cannot say:
  // the job has a ladder it has not climbed, or an index it never wrote.
  climbs?: number;
  // Whether climbs is a floor rather than the count: the index saturates
  // at the top rung, so every eviction past that one looks the same.
  atLeast: boolean;
  // The largest request the ladder will ever reach.
  ceiling?: number;
}

function toNum(v: unknown): number | undefined {
  if (typeof v === 'number') return Number.isFinite(v) ? v : undefined;
  if (typeof v === 'string' && v.trim() !== '' && !v.startsWith('/Expr(')) {
    const n = Number(v);
    return Number.isFinite(n) ? n : undefined;
  }
  return undefined;
}

// numList reads a ClassAd list of numbers. A list literal marshals to a
// JSON array (classad's marshalValue), so this is an array or nothing; a
// list written as an expression arrives as "/Expr(...)/" and is not one.
function numList(v: unknown): number[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: number[] = [];
  for (const e of v) {
    const n = toNum(e);
    if (n === undefined) return undefined;
    out.push(n);
  }
  return out.length > 0 ? out : undefined;
}

// namesRequestMemory reports whether a TransformOnEvict list names
// RequestMemory. It is a space-separated attribute list, built by
// submit's is_attr_in_attr_list.
function namesRequestMemory(list: unknown): boolean {
  if (typeof list !== 'string') return false;
  return list
    .split(/\s+/)
    .some((name) => name.replace(/,$/, '').toLowerCase() === 'requestmemory');
}

// memoryLadder reads the job's ladder, or returns undefined for a job
// submitted without one. It follows the server's readRetryLadder: the
// attribute that says a job HAS a ladder is TransformOnEvict, and the one
// that says it USED it is RetryRequestMemoryIndex, which the transform
// creates on the first eviction and not before.
export function memoryLadder(job: ClassAd | undefined): MemoryLadder | undefined {
  if (!job) return undefined;
  const rungs = numList(attr(job, 'RetryRequestMemory'));
  const max = toNum(attr(job, 'MaxRequestMemory'));
  const index = toNum(attr(job, 'RetryRequestMemoryIndex'));

  // An index without a transform is still a ladder: a record old enough
  // to predate TransformOnEvict, or one whose cluster half did not reach
  // the mirror.
  const has =
    namesRequestMemory(attr(job, 'TransformOnEvict')) ||
    max !== undefined ||
    rungs !== undefined ||
    (index !== undefined && index >= 1);
  if (!has) return undefined;

  const out: MemoryLadder = { atLeast: false };
  if (rungs) out.rungs = rungs;
  out.ceiling = max ?? (rungs ? rungs[rungs.length - 1] : undefined);
  if (index !== undefined && index >= 1) {
    out.climbs = index;
    out.atLeast = rungs !== undefined && index >= rungs.length - 1;
  }
  return out;
}

// climbedLadder reports whether the job is KNOWN to have been stopped for
// outgrowing its memory and started again at a larger request.
export function climbedLadder(ladder: MemoryLadder | undefined): boolean {
  return ladder?.climbs !== undefined && ladder.climbs >= 1;
}

// ladderNote is the line under the memory request in the resource table:
// short, because the table has one line to give it. The fuller reading --
// the rungs themselves -- is ladderTitle's, on hover.
export function ladderNote(ladder: MemoryLadder | undefined): string | undefined {
  if (!ladder) return undefined;
  if (ladder.climbs === undefined) {
    return ladder.ceiling !== undefined
      ? `retries up to ${formatMiB(ladder.ceiling)}`
      : 'retries at more memory';
  }
  const n = ladder.climbs;
  const count = ladder.atLeast ? `${n} or more restarts` : `${n} restart${n === 1 ? '' : 's'}`;
  return `after ${count} at more memory`;
}

// ladderTitle spells the ladder out for a tooltip: the sizes the job
// retries at, and where it has got to. Undefined when the record carries
// no rungs to name.
export function ladderTitle(ladder: MemoryLadder | undefined): string | undefined {
  if (!ladder?.rungs) return undefined;
  const sizes = ladder.rungs.map(formatMiB).join(', ');
  const head = `Runs out of memory and starts again at the next of ${sizes}.`;
  if (ladder.climbs === undefined) return `${head} It has not had to yet.`;
  const n = ladder.climbs;
  return ladder.atLeast
    ? `${head} It has done so at least ${n} times, and the record stops counting there.`
    : `${head} It has done so ${n === 1 ? 'once' : `${n} times`}.`;
}

// ladderLine is the memory card's sentence: why the request drawn beside
// the job's peak is not the request it started with. Nothing to say for a
// job that never had to climb -- the resource table carries that -- so
// this speaks only where the drawn request would otherwise mislead.
export function ladderLine(
  ladder: MemoryLadder | undefined,
  requestedMiB: number | undefined,
): string | undefined {
  if (!climbedLadder(ladder)) return undefined;
  const n = ladder!.climbs!;
  const times = ladder!.atLeast ? `at least ${n} times` : n === 1 ? 'once' : `${n} times`;
  const what =
    requestedMiB !== undefined ? `The ${formatMiB(requestedMiB)} requested is` : 'The request shown is';
  return `${what} where it ended up: it ran out of memory and started again at a larger request ${times}.`;
}
