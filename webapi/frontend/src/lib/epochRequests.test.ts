import { describe, expect, it } from 'vitest';

import type { ClassAd, HistoryListResponse } from './api';
import { epochConstraint, runAds, runRequest } from './epochRequests';

// One finished-run record, at the width the projection asks for.
function epochAd(run: number, req: number | string, type: string | undefined = 'EPOCH'): ClassAd {
  const ad: Record<string, unknown> = {
    ClusterId: 12428255,
    ProcId: 40559,
    RunInstanceID: run,
    RequestMemory: req,
  };
  if (type !== undefined) ad.EpochAdType = type;
  return ad as ClassAd;
}

const resp = (ads: ClassAd[]): HistoryListResponse => ({ ads });

describe('epochConstraint', () => {
  it('names one job', () => {
    expect(epochConstraint('12428255.40559')).toBe('ClusterId == 12428255 && ProcId == 40559');
  });

  it('refuses anything that is not cluster.proc', () => {
    // "_" is the placeholder a static export renders the route with, and
    // a complete multi-AP job_id is not a constraint either.
    for (const id of ['_', '', '12428255', 'ap2001#12428255.40559#1762', undefined]) {
      expect(epochConstraint(id)).toBeUndefined();
    }
  });
});

describe('runAds', () => {
  it('keys the finished-run records by run', () => {
    const m = runAds(resp([epochAd(0, 2048), epochAd(1, 4096), epochAd(2, 8192)]));
    expect([...m.keys()]).toEqual([0, 1, 2]);
    expect(runRequest(m.get(1), 'RequestMemory')).toBe(4096);
  });

  it('leaves out the records that are not the run ending', () => {
    // A transfer record carries whatever <BANNER>_JOB_ATTRS names, and
    // SPAWN is a filtered projection: reading them as runs would give a
    // run two answers, or one with no request at all.
    const m = runAds(
      resp([
        epochAd(0, 2048),
        epochAd(0, 99, 'SPAWN'),
        epochAd(0, 99, 'INPUT'),
        epochAd(0, 99, 'OUTPUT'),
        epochAd(0, 99, 'COMMON'),
        epochAd(0, 99, 'CHECKPOINT'),
      ]),
    );
    expect(m.size).toBe(1);
    expect(runRequest(m.get(0), 'RequestMemory')).toBe(2048);
  });

  it('keeps a record from a schedd that writes no EpochAdType', () => {
    const m = runAds(resp([epochAd(0, 2048, undefined)]));
    expect(runRequest(m.get(0), 'RequestMemory')).toBe(2048);
  });

  it('is empty for an access point that keeps no epoch history', () => {
    expect(runAds(resp([])).size).toBe(0);
    expect(runAds(undefined).size).toBe(0);
  });

  it('lets a run written more than once have its last word', () => {
    // The shadow writes at hold and again at exit.
    const m = runAds(resp([epochAd(1, 4096), epochAd(1, 8192)]));
    expect(runRequest(m.get(1), 'RequestMemory')).toBe(8192);
  });
});

describe('runRequest', () => {
  it('reads a literal, whichever way it arrives', () => {
    expect(runRequest(epochAd(0, 2048), 'RequestMemory')).toBe(2048);
    expect(runRequest(epochAd(0, '2048'), 'RequestMemory')).toBe(2048);
  });

  it('refuses a rule, which names the NEXT run s request', () => {
    // A request written over the job's own usage evaluates, in a run's
    // own record, against the usage that run finished with.
    const ad = epochAd(0, '/Expr(ifthenelse(MemoryUsage =!= undefined, max({2048, 3 * MemoryUsage / 2}), 2048))/');
    expect(runRequest(ad, 'RequestMemory')).toBeUndefined();
  });

  it('refuses what is missing or not a positive number', () => {
    expect(runRequest(undefined, 'RequestMemory')).toBeUndefined();
    expect(runRequest({} as ClassAd, 'RequestMemory')).toBeUndefined();
    expect(runRequest(epochAd(0, 0), 'RequestMemory')).toBeUndefined();
    expect(runRequest(epochAd(0, -1), 'RequestMemory')).toBeUndefined();
  });
});
