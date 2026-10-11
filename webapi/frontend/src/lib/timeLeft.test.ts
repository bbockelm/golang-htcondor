import { describe, expect, it } from 'vitest';

import type { JobRuntimeEstimate } from '@/lib/api';
import { groupIntoBatches } from '@/lib/batches';
import {
  batchTimeLeft,
  clockTime,
  dagTimeLeft,
  estimateRequestJobs,
  expectedEnd,
  jobTimeLeft,
  longerThanUsualText,
  median,
  NO_HISTORY,
  rangeBar,
  rangeBarScale,
  type TimedJob,
} from '@/lib/timeLeft';
import { requestIds } from '@/lib/useRuntimeEstimates';

// 2026-10-11 13:00 local: far enough from midnight that an hour or two
// either way is still today.
const now = Math.floor(new Date(2026, 9, 11, 13, 0, 0).getTime() / 1000);

function est(over: Partial<JobRuntimeEstimate> = {}): JobRuntimeEstimate {
  return {
    available: true,
    estimate_seconds: 3600,
    p10_seconds: 2400,
    p90_seconds: 9000,
    basis: { level: 'template', sample_count: 12 },
    rough: false,
    exceeded_history: false,
    ...over,
  };
}

function idle(over: Partial<JobRuntimeEstimate> = {}): TimedJob {
  return { status: 'idle', estimate: est(over) };
}

// running is a job elapsed seconds into a run with remaining left.
function running(elapsed: number, remaining: number, over: Partial<JobRuntimeEstimate> = {}): TimedJob {
  return {
    status: 'running',
    estimate: est({ elapsed_seconds: elapsed, remaining_seconds: remaining, estimate_seconds: elapsed + remaining, ...over }),
  };
}

function overrun(elapsed: number, usual = 3600): TimedJob {
  return {
    status: 'running',
    estimate: est({ elapsed_seconds: elapsed, estimate_seconds: usual, exceeded_history: true }),
  };
}

const noEstimate = (status: TimedJob['status']): TimedJob => ({ status });

describe('median', () => {
  it('interpolates between the middle two', () => {
    expect(median([])).toBeUndefined();
    expect(median([5])).toBe(5);
    expect(median([3, 1, 2])).toBe(2);
    expect(median([4, 1, 3, 2])).toBe(2.5);
  });
});

describe('clockTime', () => {
  it('rounds far times to five minutes and near ones to the minute', () => {
    const at = (h: number, m: number) => Math.floor(new Date(2026, 9, 11, h, m).getTime() / 1000);
    expect(clockTime(at(16, 32), now)).toBe(clockTime(at(16, 30), now));
    expect(clockTime(at(13, 32), now)).not.toBe(clockTime(at(13, 30), now));
  });

  it('names the day when it is not today', () => {
    const tomorrow = now + 86400;
    expect(clockTime(tomorrow, now)).toMatch(/^\S+ /);
    expect(clockTime(tomorrow, now)).not.toBe(clockTime(now + 3600, now));
  });
});

describe('batchTimeLeft', () => {
  it('gives an all-running batch its latest and median finish', () => {
    const jobs = [running(600, 1200), running(600, 1800), running(600, 6000)];
    const t = batchTimeLeft(jobs, now, now)!;
    expect(t.main).toBe(`All done by ~${clockTime(now + 6000, now)}`);
    expect(t.sub).toBe(`most by ${clockTime(now + 1800, now)}`);
    expect(t.rough).toBeFalsy();
    expect(t.title).toMatch(/^Running jobs usually done between /);
  });

  it('says nothing about "most" for a single job', () => {
    const t = batchTimeLeft([running(60, 600)], now, now)!;
    expect(t.main).toBe(`All done by ~${clockTime(now + 600, now)}`);
    expect(t.sub).toBeUndefined();
  });

  it('counts from when the estimates were fetched, not now', () => {
    const fetchedAt = now - 300;
    const t = batchTimeLeft([running(60, 1200)], fetchedAt, now)!;
    expect(t.main).toBe(`All done by ~${clockTime(fetchedAt + 1200, now)}`);
  });

  it('gives a queued batch no finish time, only how long each runs', () => {
    const jobs = [idle(), idle({ estimate_seconds: 3000 }), idle({ estimate_seconds: 4200 })];
    const t = batchTimeLeft(jobs, now, now)!;
    expect(t.main).toBe('3 waiting · each about 1h once started');
    expect(t.sub).toBeUndefined();
    expect(t.title).toBe('Each usually runs 40m to 2h30m');
    expect(`${t.main} ${t.sub ?? ''}`).not.toMatch(/done by|PM|AM/);
  });

  it('adds the running part of a mixed batch on its own line', () => {
    const jobs = [idle(), idle(), running(600, 1200), running(600, 2400)];
    const t = batchTimeLeft(jobs, now, now)!;
    expect(t.main).toBe('2 waiting · each about 1h once started');
    expect(t.sub).toBe(`running ones done by ~${clockTime(now + 2400, now)}`);
  });

  it('counts every waiting job, even those without a figure', () => {
    const jobs = [idle(), noEstimate('idle'), noEstimate('idle')];
    expect(batchTimeLeft(jobs, now, now)!.main).toBe('3 waiting · each about 1h once started');
  });

  it('calls a rough figure rough', () => {
    const jobs = [idle({ rough: true, estimate_seconds: 7200, p10_seconds: 900, p90_seconds: 21600 })];
    const t = batchTimeLeft(jobs, now, now)!;
    expect(t.main).toBe('1 waiting · each roughly 2h once started');
    expect(t.rough).toBe(true);
    expect(t.title).toBe('Each could run anywhere from 15m to 6h');
  });

  it('shows the running part alone when the waiting jobs have no figure', () => {
    const t = batchTimeLeft([noEstimate('idle'), running(60, 600)], now, now)!;
    expect(t.main).toBe(`Running ones done by ~${clockTime(now + 600, now)}`);
    expect(t.sub).toBe('1 waiting');
  });

  it('says which running jobs it can speak for', () => {
    const t = batchTimeLeft([running(60, 600), overrun(9000), noEstimate('running')], now, now)!;
    expect(t.main).toBe(`1 of 3 done by ~${clockTime(now + 600, now)}`);
  });

  it('says a lone job is past its usual time', () => {
    const t = batchTimeLeft([overrun(5 * 3600 + 40 * 60, 7200)], now, now)!;
    expect(t.main).toBe('Past its usual 2h');
    expect(t.sub).toBe('running 5h40m');
    expect(t.overrun).toBe(true);
  });

  it('says several jobs are past their usual time', () => {
    const t = batchTimeLeft([overrun(9000), overrun(12000)], now, now)!;
    expect(t.main).toBe('Past their usual 1h');
    expect(t.overrun).toBe(true);
  });

  it('shows a dash, and why, without any figure', () => {
    for (const jobs of [[noEstimate('idle')], [noEstimate('running')], [noEstimate('idle'), noEstimate('running')]]) {
      expect(batchTimeLeft(jobs, now, now)).toEqual({ main: '—', title: NO_HISTORY });
    }
    const unavailable: TimedJob = { status: 'idle', estimate: { available: false, reason: 'insufficient_history', exceeded_history: false } };
    expect(batchTimeLeft([unavailable], now, now)).toEqual({ main: '—', title: NO_HISTORY });
  });

  it('has nothing to say about a batch with no waiting or running jobs', () => {
    expect(batchTimeLeft([noEstimate('other')], now, now)).toBeUndefined();
    expect(batchTimeLeft([], now, now)).toBeUndefined();
  });

  it('never names the mechanism', () => {
    const all = [
      batchTimeLeft([running(600, 1200), running(60, 60)], now, now),
      batchTimeLeft([idle({ rough: true }), running(60, 60)], now, now),
      batchTimeLeft([overrun(9000)], now, now),
      jobTimeLeft(running(600, 1200, { rough: true }), now, now),
      jobTimeLeft(overrun(9000), now, now),
      jobTimeLeft(idle(), now, now),
    ];
    for (const t of all) {
      expect(`${t?.main} ${t?.sub} ${t?.title}`).not.toMatch(/model|estimat|window|residual|level|percentile|p90|p10/i);
    }
  });
});

describe('longerThanUsualText', () => {
  it('counts the jobs past their usual time', () => {
    expect(longerThanUsualText([running(60, 600), idle()])).toBeUndefined();
    expect(longerThanUsualText([overrun(9000), overrun(9000), running(60, 60)])).toBe('2 running longer than usual');
    expect(longerThanUsualText([overrun(9000), running(60, 60)])).toBe('1 running longer than usual');
  });

  it('names a one-job batch\'s job rather than counting it', () => {
    expect(longerThanUsualText([overrun(9000)])).toBe('Running longer than usual');
  });
});

describe('jobTimeLeft', () => {
  it('gives a running job its time left and finish', () => {
    const t = jobTimeLeft(running(25 * 60, 35 * 60), now, now)!;
    expect(t).toMatchObject({ main: '~35m', sub: `done ~${clockTime(now + 35 * 60, now)}`, rough: false });
    expect(t.title).toBe('usually 40m to 2h30m');
  });

  it('counts down between refreshes', () => {
    expect(jobTimeLeft(running(0, 3600), now - 600, now)!.main).toBe('~50m');
    // Due already: a minute, not zero.
    expect(jobTimeLeft(running(0, 60), now - 600, now)!.main).toBe('~1m');
  });

  it('calls a rough running figure rough', () => {
    const t = jobTimeLeft(running(600, 3000, { rough: true }), now, now)!;
    expect(t.main).toBe('Roughly 50m');
    expect(t.rough).toBe(true);
    expect(t.title).toBe('anywhere from 40m to 2h30m');
  });

  it('flags a job past its usual time, with what similar jobs took', () => {
    expect(jobTimeLeft(overrun(3 * 3600 + 720), now, now)).toMatchObject({
      longer: true,
      sub: 'similar jobs: ~1h',
    });
  });

  it('gives a waiting job how long it runs, never a finish time', () => {
    expect(jobTimeLeft(idle(), now, now)).toMatchObject({ main: 'Runs ~1h once started' });
    expect(jobTimeLeft(idle({ rough: true, estimate_seconds: 7200 }), now, now)).toMatchObject({
      main: 'Runs roughly 2h once started',
      rough: true,
    });
    expect(jobTimeLeft(idle(), now, now)!.sub).toBeUndefined();
  });

  it('shows a dash without a figure, and nothing for other states', () => {
    expect(jobTimeLeft(noEstimate('idle'), now, now)).toEqual({ main: '—', title: NO_HISTORY });
    expect(jobTimeLeft(noEstimate('other'), now, now)).toBeUndefined();
    expect(jobTimeLeft({ status: 'other', estimate: est() }, now, now)).toBeUndefined();
  });
});

describe('expectedEnd', () => {
  it('has none for a waiting or overrun job', () => {
    expect(expectedEnd(idle(), now)).toBeUndefined();
    expect(expectedEnd(overrun(9000), now)).toBeUndefined();
    expect(expectedEnd(running(10, 50), now)).toBe(now + 50);
  });
});

describe('rangeBar', () => {
  it('places every job of a batch on one axis', () => {
    const jobs = [running(1500, 2100), idle(), overrun(11520)];
    const scale = rangeBarScale(jobs, now, now);
    expect(scale).toBeCloseTo(11520 * 1.1);
    const r = rangeBar(jobs[0], scale, now, now)!;
    expect(r.elapsed).toBeCloseTo((1500 / scale) * 100);
    expect(r.tick).toBeCloseTo((3600 / scale) * 100);
    expect(r.overrun).toBe(false);
    expect(rangeBar(jobs[1], scale, now, now)!.elapsed).toBeUndefined();
    expect(rangeBar(jobs[2], scale, now, now)!.overrun).toBe(true);
    expect(rangeBar(noEstimate('idle'), scale, now, now)).toBeUndefined();
  });
});

describe('requestIds', () => {
  it('asks about running jobs first, then waiting ones, within the cap', () => {
    const jobs = [
      { id: '1.0', status: 'idle' as const },
      { id: '1.1', status: 'running' as const },
      { id: '1.2', status: 'other' as const },
      { id: '1.3', status: 'idle' as const },
      { id: '2.0', status: 'running' as const },
    ];
    expect(requestIds(jobs)).toEqual(['1.1', '2.0', '1.0', '1.3']);
    expect(requestIds(jobs, 3)).toEqual(['1.1', '2.0', '1.0']);
  });
});

// A DAG's DAGMan job as the listing sees it: running, never estimated.
const dagman: TimedJob = { status: 'running', dagman: true };
const nodes = { total: 20, done: 11, failed: 2, queued: 3 };

describe('dagTimeLeft', () => {
  it('says how many nodes are left and when the running ones finish, never when the DAG does', () => {
    const t = dagTimeLeft([dagman, running(600, 1200), running(600, 2400)], nodes, now, now)!;
    expect(t.main).toBe('7 of 20 nodes left');
    expect(t.sub).toBe(`running nodes done by ~${clockTime(now + 2400, now)}`);
    expect(t.more).toBeUndefined();
    expect(t.title).toMatch(/^Running nodes usually done between /);
  });

  it('gives waiting node jobs how long each runs, on its own line', () => {
    const t = dagTimeLeft([dagman, running(600, 1200), idle(), idle()], nodes, now, now)!;
    expect(t.main).toBe('7 of 20 nodes left');
    expect(t.sub).toBe(`running nodes done by ~${clockTime(now + 1200, now)}`);
    expect(t.more).toEqual(['2 waiting · each about 1h once started']);
    expect(t.title).toContain('Each usually runs 40m to 2h30m');
    const waiting = dagTimeLeft([dagman, idle({ rough: true })], nodes, now, now)!;
    expect(waiting.sub).toBe('1 waiting · each roughly 1h once started');
    expect(waiting.more).toBeUndefined();
  });

  it('says which running nodes it can speak for', () => {
    const t = dagTimeLeft([running(60, 600), overrun(9000), noEstimate('running')], nodes, now, now)!;
    expect(t.sub).toBe(`1 of 3 running nodes done by ~${clockTime(now + 600, now)}`);
  });

  it('counts the node jobs in the queue before the DAG reports its nodes', () => {
    const t = dagTimeLeft([dagman, running(60, 600), noEstimate('idle'), noEstimate('other')], undefined, now, now)!;
    expect(t.main).toBe('3 node jobs in the queue');
    expect(t.sub).toBe(`running nodes done by ~${clockTime(now + 600, now)}`);
    expect(t.more).toEqual(['1 waiting']);
    expect(dagTimeLeft([dagman, noEstimate('idle')], undefined, now, now)!.main).toBe('1 node job in the queue');
    expect(dagTimeLeft([dagman], undefined, now, now)).toBeUndefined();
  });

  it('still counts nodes with nothing waiting or running, and says why there is no time', () => {
    expect(dagTimeLeft([dagman], { total: 1, done: 0, failed: 0, queued: 0 }, now, now)).toEqual({
      main: '1 of 1 node left', sub: undefined, more: undefined, title: undefined,
    });
    const t = dagTimeLeft([dagman, noEstimate('idle')], nodes, now, now)!;
    expect(t).toEqual({ main: '7 of 20 nodes left', sub: '1 waiting', more: undefined, title: NO_HISTORY });
  });

  it('never claims a finish time for the DAG, nor names the mechanism', () => {
    const all = [
      dagTimeLeft([dagman, running(600, 1200), running(60, 60), idle()], nodes, now, now),
      dagTimeLeft([dagman, running(600, 1200)], undefined, now, now),
      dagTimeLeft([dagman, overrun(9000)], nodes, now, now),
      dagTimeLeft([dagman, idle({ rough: true })], nodes, now, now),
    ];
    for (const t of all) {
      const text = [t?.main, t?.sub, ...(t?.more ?? []), t?.title].join(' ');
      expect(text).not.toMatch(/all done|most by|running ones/i);
      expect(text).not.toMatch(/model|estimat|window|residual|level|percentile|p90|p10/i);
      // Every clock time is the running nodes'.
      for (const m of text.matchAll(/done (by|between)/g)) {
        expect(text.slice(0, m.index)).toMatch(/running nodes $|Running nodes usually $/);
      }
    }
  });

  it('leaves a non-DAG batch as it was', () => {
    const jobs = [running(600, 1200), running(600, 1800), running(600, 6000)];
    expect(batchTimeLeft(jobs, now, now)!.main).toBe(`All done by ~${clockTime(now + 6000, now)}`);
  });
});

describe('estimateRequestJobs', () => {
  it('asks about every node job of a DAG but not its DAGMan job', () => {
    const [dag] = groupIntoBatches([
      { ClusterId: 100, ProcId: 0, JobStatus: 2, Owner: 'carol', Cmd: '/usr/bin/condor_dagman', JobBatchName: 'foo.dag+100' },
      { ClusterId: 101, ProcId: 0, JobStatus: 2, Owner: 'carol', Cmd: 'condor_dagman', JobBatchName: 'foo.dag+100', DAGManJobId: 100 },
      { ClusterId: 201, ProcId: 0, JobStatus: 2, Owner: 'carol', Cmd: '/bin/node', JobBatchName: 'foo.dag+100', DAGManJobId: 100 },
      { ClusterId: 202, ProcId: 0, JobStatus: 1, Owner: 'carol', Cmd: '/bin/node', JobBatchName: 'foo.dag+100', DAGManJobId: 101 },
    ]);
    expect(estimateRequestJobs(dag.jobs)).toEqual([
      { id: '201.0', status: 'running' },
      { id: '202.0', status: 'idle' },
    ]);
  });

  it('asks about every job of a plain batch', () => {
    const [b] = groupIntoBatches([
      { ClusterId: 7, ProcId: 0, JobStatus: 2, Owner: 'a', Cmd: '/bin/x' },
      { ClusterId: 7, ProcId: 1, JobStatus: 5, Owner: 'a', Cmd: '/bin/x' },
    ]);
    expect(estimateRequestJobs(b.jobs)).toEqual([
      { id: '7.0', status: 'running' },
      { id: '7.1', status: 'other' },
    ]);
  });
});
