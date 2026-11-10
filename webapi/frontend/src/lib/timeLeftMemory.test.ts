import { describe, expect, it } from 'vitest';

import type { JobRuntimeEstimate, RuntimeMemory } from '@/lib/api';
import {
  isMoreMemoryThanUsual,
  jobTimeLeft,
  moreMemoryText,
  moreMemoryTitle,
  type TimedJob,
} from '@/lib/timeLeft';

// The listing's "More memory than usual" chips: per running job, and per
// batch as a count.

const now = Math.floor(new Date(2026, 9, 11, 13, 0, 0).getTime() / 1000);

function mem(over: Partial<RuntimeMemory> = {}): RuntimeMemory {
  return {
    sample_count: 9,
    p10_mib: 900,
    p25_mib: 1000,
    p50_mib: 1229,
    p75_mib: 1500,
    p90_mib: 2048,
    rough: false,
    above_usual: false,
    ...over,
  };
}

function job(status: TimedJob['status'], memory: RuntimeMemory | undefined, over: Partial<JobRuntimeEstimate> = {}): TimedJob {
  return {
    status,
    estimate: {
      available: true,
      estimate_seconds: 3600,
      p10_seconds: 2400,
      p90_seconds: 9000,
      exceeded_history: false,
      ...(status === 'running' ? { elapsed_seconds: 600, remaining_seconds: 3000 } : {}),
      memory,
      ...over,
    },
  };
}

const above = mem({ above_usual: true, peak_mib: 6246 });

describe('isMoreMemoryThanUsual', () => {
  it('is the server\'s above_usual, for a running job with an estimate', () => {
    expect(isMoreMemoryThanUsual(job('running', above))).toBe(true);
    expect(isMoreMemoryThanUsual(job('running', mem({ peak_mib: 1000 })))).toBe(false);
    expect(isMoreMemoryThanUsual(job('running', undefined))).toBe(false);
    // A job no longer running is no longer judged, whatever the last answer said.
    expect(isMoreMemoryThanUsual(job('idle', above))).toBe(false);
    expect(isMoreMemoryThanUsual(job('running', above, { available: false }))).toBe(false);
    expect(isMoreMemoryThanUsual({ status: 'running' })).toBe(false);
  });
});

describe('moreMemoryTitle', () => {
  it('states the peak and what similar jobs peaked at', () => {
    expect(moreMemoryTitle(above)).toBe('Peak so far 6.1 GB; similar jobs peak at about 1.2 GB, 9 in 10 under 2 GB');
    expect(moreMemoryTitle(mem({ p50_mib: 700, p90_mib: 900 }))).toBe('Similar jobs peak at about 700 MB, 9 in 10 under 900 MB');
  });
});

describe('the job cell', () => {
  it('carries the chip\'s hover text only when the job is above usual', () => {
    expect(jobTimeLeft(job('running', above), now, now)?.memory).toBe(
      'Peak so far 6.1 GB; similar jobs peak at about 1.2 GB, 9 in 10 under 2 GB',
    );
    expect(jobTimeLeft(job('running', mem({ peak_mib: 1000 })), now, now)?.memory).toBeUndefined();
    expect(jobTimeLeft(job('running', undefined), now, now)?.memory).toBeUndefined();
  });

  it('shows the chip beside "Longer than usual" for a job that is both', () => {
    const t = jobTimeLeft(job('running', above, { exceeded_history: true, remaining_seconds: undefined }), now, now);
    expect(t?.longer).toBe(true);
    expect(t?.memory).toContain('Peak so far 6.1 GB');
  });

  it('leaves the run time wording alone', () => {
    const plain = jobTimeLeft(job('running', undefined), now, now);
    const flagged = jobTimeLeft(job('running', above), now, now);
    expect({ ...flagged, memory: undefined }).toEqual(plain);
  });
});

describe('moreMemoryText', () => {
  it('counts the batch\'s running jobs above usual', () => {
    expect(moreMemoryText([job('running', above), job('running', above), job('running', mem()), job('idle', mem())])).toBe(
      '2 using more memory than usual',
    );
  });

  it('names a one-job batch\'s job rather than counting it', () => {
    expect(moreMemoryText([job('running', above)])).toBe('Using more memory than usual');
  });

  it('says nothing when no job is above usual', () => {
    expect(moreMemoryText([job('running', mem()), job('idle', undefined)])).toBeUndefined();
    expect(moreMemoryText([])).toBeUndefined();
  });
});
