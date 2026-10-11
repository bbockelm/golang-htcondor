// What the jobs listing says about how long its jobs have left: one line
// per batch, one cell per job, from POST /api/v1/jobs/runtime-estimates.
//
// The rule is to state facts. A waiting job's wait depends on the pool
// and cannot be known, so a waiting job gets how long it runs once
// started and never a finish time, and a batch with jobs still waiting
// gets no finish time for the batch as a whole: extrapolating one from
// throughput was right too rarely to show. Only running jobs get a clock
// time. A DAG gets no finish time at all: its nodes not yet submitted are
// in no estimate, so a DAG's row says how many nodes are left and when its
// running nodes are expected to finish. Pure functions, so the wording is
// tested without rendering.

import type { JobRuntimeEstimate } from '@/lib/api';
import type { BatchJob, DagNodeCounts } from '@/lib/batches';
import { approxDuration, humanDuration } from '@/lib/duration';
import type { EstimateRequestJob } from '@/lib/useRuntimeEstimates';

// A job as these functions see it: whether it waits or runs, and its
// estimate if the server gave one.
export interface TimedJob {
  status: 'idle' | 'running' | 'other';
  estimate?: JobRuntimeEstimate;
  // A DAG's DAGMan job: never estimated, and not one of its nodes.
  dagman?: boolean;
}

// timedStatus is what the time-left wording needs of a job's status.
export function timedStatus(j: BatchJob): TimedJob['status'] {
  if (j.display.key === 'idle') return 'idle';
  if (j.display.key === 'running') return 'running';
  return 'other';
}

// estimateRequestJobs is the jobs of a listing to ask for estimates:
// every one but the DAGMan jobs, which are never estimated.
export function estimateRequestJobs(jobs: readonly BatchJob[]): EstimateRequestJob[] {
  return jobs.filter((j) => !j.dagman).map((j) => ({ id: j.id, status: timedStatus(j) }));
}

// NO_HISTORY is why a waiting or running job shows no time.
export const NO_HISTORY = 'No finished runs to compare yet';

// median of numbers, interpolated; undefined when there are none.
export function median(xs: readonly number[]): number | undefined {
  if (xs.length === 0) return undefined;
  const s = [...xs].sort((a, b) => a - b);
  const mid = (s.length - 1) / 2;
  const lo = Math.floor(mid);
  return s[lo] + (s[Math.ceil(mid)] - s[lo]) * (mid - lo);
}

// clockTime is a finish time as people say it: "4:30 PM" today, "Tue
// 4:30 PM" this week, "Oct 20, 4:30 PM" after that. More than an hour out
// it is rounded to five minutes -- the figure is approximate, and
// "4:37 PM" would claim otherwise.
export function clockTime(unix: number, now: number): string {
  const step = unix - now > 3600 ? 300 : 60;
  const d = new Date(Math.round(unix / step) * step * 1000);
  const today = new Date(now * 1000);
  // Non-breaking, so a narrow cell never strands the "PM".
  const time = d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' }).replace(/ /g, '\u00a0');
  if (d.toDateString() === today.toDateString()) return time;
  if (unix - now < 6 * 86400) {
    return `${d.toLocaleDateString(undefined, { weekday: 'short' })} ${time}`;
  }
  return `${d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}, ${time}`;
}

// usable is an estimate with numbers in it.
function usable(e: JobRuntimeEstimate | undefined): e is JobRuntimeEstimate & { estimate_seconds: number } {
  return !!e && e.available && e.estimate_seconds !== undefined;
}

// expectedEnd is when a running job is expected to finish, in unix
// seconds, or undefined when there is no such time: not running, no
// estimate, or past what comparable jobs took (exceeded_history).
// fetchedAt is when the estimate was asked for; its remaining time was
// measured then.
export function expectedEnd(j: TimedJob, fetchedAt: number): number | undefined {
  if (j.status !== 'running' || !usable(j.estimate)) return undefined;
  const rem = j.estimate.remaining_seconds;
  if (j.estimate.exceeded_history || rem === undefined) return undefined;
  return fetchedAt + rem;
}

// isLongerThanUsual: a running job that has outrun nearly every
// comparable job.
export function isLongerThanUsual(j: TimedJob): boolean {
  return j.status === 'running' && !!j.estimate?.available && j.estimate.exceeded_history;
}

// longerThanUsualText is the batch's Status chip, or undefined when no
// job is past its usual time. A one-job batch's chip names the job,
// not a count.
export function longerThanUsualText(jobs: readonly TimedJob[]): string | undefined {
  const n = jobs.filter(isLongerThanUsual).length;
  if (n === 0) return undefined;
  if (jobs.length === 1) return 'Running longer than usual';
  return `${n.toLocaleString()} running longer than usual`;
}

// The Time left cell of a batch row.
export interface BatchTimeLeft {
  main: string;
  sub?: string;
  // Further small lines under sub.
  more?: string[];
  // Hover text: the usual range, or why there is nothing to show.
  title?: string;
  // From a broad, rarely-close basis: shown with a "rough guess" chip.
  rough?: boolean;
  // The batch's jobs are all past their usual time.
  overrun?: boolean;
}

// batchTimeLeft summarizes a batch's waiting and running jobs, or
// returns undefined when it has neither (all held, say), which the row
// shows as a bare dash.
export function batchTimeLeft(
  jobs: readonly TimedJob[],
  fetchedAt: number,
  now: number,
): BatchTimeLeft | undefined {
  const idle = jobs.filter((j) => j.status === 'idle');
  const running = jobs.filter((j) => j.status === 'running');
  if (idle.length === 0 && running.length === 0) return undefined;

  const { ends, latest, range } = runningEnds(running, fetchedAt);
  const mostBy = median(ends);
  const endsTitle = range
    ? `Running jobs usually done between ${clockTime(range[0], now)} and ${clockTime(range[1], now)}`
    : undefined;

  if (idle.length > 0) {
    const w = waitingSummary(idle);
    const runningPart = latest !== undefined ? `running ones done by ~${clockTime(latest, now)}` : undefined;
    if (w === undefined) {
      if (runningPart === undefined) return { main: '—', title: NO_HISTORY };
      return {
        main: `Running ones done by ~${clockTime(latest!, now)}`,
        sub: `${idle.length.toLocaleString()} waiting`,
        title: endsTitle,
      };
    }
    return { main: w.text, sub: runningPart, title: w.title, rough: w.rough };
  }

  if (latest !== undefined) {
    const most = mostBy !== undefined && ends.length > 1 ? clockTime(mostBy, now) : undefined;
    const all = clockTime(latest, now);
    const sub = most !== undefined && most !== all ? `most by ${most}` : undefined;
    if (ends.length === running.length) {
      return { main: `All done by ~${all}`, sub, title: endsTitle };
    }
    return {
      main: `${ends.length.toLocaleString()} of ${running.length.toLocaleString()} done by ~${all}`,
      sub,
      title: endsTitle,
    };
  }

  const over = running.filter(isLongerThanUsual);
  if (over.length > 0) {
    const usual = approxDuration(median(over.map((j) => j.estimate!.estimate_seconds!))!);
    if (running.length === 1) {
      const elapsed = (over[0].estimate!.elapsed_seconds ?? 0) + Math.max(0, now - fetchedAt);
      return { main: `Past its usual ${usual}`, sub: `running ${humanDuration(elapsed)}`, overrun: true };
    }
    return { main: `Past their usual ${usual}`, overrun: true };
  }
  return { main: '—', title: NO_HISTORY };
}

// runningEnds is when running jobs are expected to finish: each one's
// expected end, the latest of them -- each job's typical finish, not a
// bound on the batch: about one job in ten runs past its own -- and the
// span from the earliest usual end to the latest.
function runningEnds(
  running: readonly TimedJob[],
  fetchedAt: number,
): { ends: number[]; latest?: number; range?: [number, number] } {
  const ends: number[] = [];
  const endLo: number[] = [];
  const endHi: number[] = [];
  for (const j of running) {
    const end = expectedEnd(j, fetchedAt);
    if (end === undefined) continue;
    ends.push(end);
    const e = j.estimate!;
    const elapsed = e.elapsed_seconds ?? 0;
    if (e.p10_seconds !== undefined) endLo.push(fetchedAt + e.p10_seconds - elapsed);
    if (e.p90_seconds !== undefined) endHi.push(fetchedAt + e.p90_seconds - elapsed);
  }
  return {
    ends,
    latest: ends.length ? Math.max(...ends) : undefined,
    range: endLo.length && endHi.length ? [Math.min(...endLo), Math.max(...endHi)] : undefined,
  };
}

// waitingSummary is the line for waiting jobs with estimates -- "N waiting
// · each about 1h once started" -- and its hover text, or undefined when
// none has one.
function waitingSummary(idle: readonly TimedJob[]): { text: string; title?: string; rough: boolean } | undefined {
  const est = idle.map((j) => j.estimate).filter(usable);
  if (est.length === 0) return undefined;
  // Most of a batch's waiting jobs share one basis; call the figure
  // rough when most of them are.
  const rough = est.filter((e) => e.rough).length * 2 >= est.length;
  const typical = approxDuration(median(est.map((e) => e.estimate_seconds))!);
  const lo = median(est.flatMap((e) => (e.p10_seconds !== undefined ? [e.p10_seconds] : [])));
  const hi = median(est.flatMap((e) => (e.p90_seconds !== undefined ? [e.p90_seconds] : [])));
  let title: string | undefined;
  if (lo !== undefined && hi !== undefined && approxDuration(lo) !== approxDuration(hi)) {
    title = rough
      ? `Each could run anywhere from ${approxDuration(lo)} to ${approxDuration(hi)}`
      : `Each usually runs ${approxDuration(lo)} to ${approxDuration(hi)}`;
  }
  return {
    text: `${idle.length.toLocaleString()} waiting · each ${rough ? 'roughly' : 'about'} ${typical} once started`,
    title,
    rough,
  };
}

// nodesLeftText is a DAG's "7 of 20 nodes left": nodes neither done nor
// failed.
export function nodesLeftText(n: DagNodeCounts): string {
  const left = Math.max(0, n.total - n.done - n.failed);
  return `${left.toLocaleString()} of ${n.total.toLocaleString()} ${n.total === 1 ? 'node' : 'nodes'} left`;
}

// dagTimeLeft is the Time left cell of a DAG's row. It never gives a
// finish time for the DAG: nodes not yet submitted are in no estimate.
// The main line is how many nodes are left, from the DAG's own counts
// when it has reported them, else how many node jobs are in the queue;
// under it, when the running node jobs are expected to finish, and what
// the waiting ones are expected to run. The DAGMan jobs are left out.
// Undefined -- a bare dash -- when there is nothing to say.
export function dagTimeLeft(
  jobs: readonly TimedJob[],
  nodes: DagNodeCounts | undefined,
  fetchedAt: number,
  now: number,
): BatchTimeLeft | undefined {
  const nodeJobs = jobs.filter((j) => !j.dagman);
  const idle = nodeJobs.filter((j) => j.status === 'idle');
  const running = nodeJobs.filter((j) => j.status === 'running');
  let main: string;
  if (nodes !== undefined) {
    main = nodesLeftText(nodes);
  } else if (nodeJobs.length > 0) {
    main = `${nodeJobs.length.toLocaleString()} node ${nodeJobs.length === 1 ? 'job' : 'jobs'} in the queue`;
  } else {
    return undefined;
  }

  const lines: string[] = [];
  const titles: string[] = [];
  const { ends, latest, range } = runningEnds(running, fetchedAt);
  if (latest !== undefined) {
    const at = clockTime(latest, now);
    lines.push(
      ends.length === running.length
        ? `running nodes done by ~${at}`
        : `${ends.length.toLocaleString()} of ${running.length.toLocaleString()} running nodes done by ~${at}`,
    );
    if (range) {
      titles.push(`Running nodes usually done between ${clockTime(range[0], now)} and ${clockTime(range[1], now)}`);
    }
  }
  const w = idle.length > 0 ? waitingSummary(idle) : undefined;
  if (w) {
    lines.push(w.text);
    if (w.title) titles.push(w.title);
  } else if (idle.length > 0) {
    lines.push(`${idle.length.toLocaleString()} waiting`);
  }
  if (latest === undefined && !w && running.length + idle.length > 0 && !running.some(isLongerThanUsual)) {
    titles.push(NO_HISTORY);
  }
  return {
    main,
    sub: lines[0],
    more: lines.length > 1 ? lines.slice(1) : undefined,
    title: titles.length ? titles.join('\n') : undefined,
  };
}

// The Time left cell of one job.
export interface JobTimeLeft {
  main?: string;
  sub?: string;
  title?: string;
  rough?: boolean;
  // The amber "Longer than usual" chip.
  longer?: boolean;
}

// jobTimeLeft is one waiting or running job's cell, or undefined for a
// job that is neither.
export function jobTimeLeft(j: TimedJob, fetchedAt: number, now: number): JobTimeLeft | undefined {
  if (j.status === 'other') return undefined;
  const e = j.estimate;
  if (!usable(e)) return { main: '—', title: NO_HISTORY };
  const rough = !!e.rough;
  const range =
    e.p10_seconds !== undefined && e.p90_seconds !== undefined &&
    approxDuration(e.p10_seconds) !== approxDuration(e.p90_seconds)
      ? `${rough ? 'anywhere from' : 'usually'} ${approxDuration(e.p10_seconds)} to ${approxDuration(e.p90_seconds)}`
      : undefined;
  if (isLongerThanUsual(j)) {
    return { longer: true, sub: `similar jobs: ~${approxDuration(e.estimate_seconds)}`, title: range };
  }
  if (j.status === 'running') {
    const end = expectedEnd(j, fetchedAt);
    if (end === undefined) return { main: '—', title: NO_HISTORY };
    // A job due any moment says a minute, not "0s", until the next
    // refresh re-estimates it.
    const left = approxDuration(Math.max(60, end - now));
    return {
      main: rough ? `Roughly ${left}` : `~${left}`,
      sub: `done ~${clockTime(end, now)}`,
      title: range,
      rough,
    };
  }
  const total = approxDuration(e.estimate_seconds);
  return {
    main: rough ? `Runs roughly ${total} once started` : `Runs ~${total} once started`,
    title: range,
    rough,
  };
}

// RangeBarGeometry places one job on a shared axis from 0 to scale
// seconds, as percentages: the usual range, the typical run, and how far
// a running job has got.
export interface RangeBarGeometry {
  bandLeft: number;
  bandWidth: number;
  tick: number;
  elapsed?: number;
  overrun: boolean;
}

export function rangeBar(j: TimedJob, scale: number, fetchedAt: number, now: number): RangeBarGeometry | undefined {
  const e = j.estimate;
  if (!usable(e) || j.status === 'other' || !(scale > 0)) return undefined;
  const pct = (s: number) => Math.max(0, Math.min(100, (s / scale) * 100));
  const lo = e.p10_seconds ?? e.estimate_seconds;
  const hi = e.p90_seconds ?? e.estimate_seconds;
  const g: RangeBarGeometry = {
    bandLeft: pct(lo),
    bandWidth: Math.max(1, pct(hi) - pct(lo)),
    tick: pct(e.estimate_seconds),
    overrun: isLongerThanUsual(j),
  };
  if (j.status === 'running' && e.elapsed_seconds !== undefined) {
    g.elapsed = pct(e.elapsed_seconds + Math.max(0, now - fetchedAt));
  }
  return g;
}

// rangeBarScale is the axis a batch's bars share: a little past the
// longest range or run among them, so every bar fits and they compare.
export function rangeBarScale(jobs: readonly TimedJob[], fetchedAt: number, now: number): number {
  let m = 0;
  for (const j of jobs) {
    const e = j.estimate;
    if (!usable(e) || j.status === 'other') continue;
    m = Math.max(m, e.p90_seconds ?? 0, e.estimate_seconds);
    if (j.status === 'running' && e.elapsed_seconds !== undefined) {
      m = Math.max(m, e.elapsed_seconds + Math.max(0, now - fetchedAt));
    }
  }
  return m * 1.1;
}
