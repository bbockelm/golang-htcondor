import { describe, expect, it } from 'vitest';

import { climbedLadder, ladderNote, ladderTitle, memoryLadder } from './retryMemory';

// The shape CHTC submits: six retries, the transform that drives them,
// and the index the first eviction writes.
const RUNGS = [2048, 4096, 8192, 16384, 32768, 65536];
const laddered = (extra: Record<string, unknown> = {}) => ({
  RequestMemory: 2048,
  RetryRequestMemory: RUNGS,
  TransformOnEvict: 'RequestMemory RetryRequestMemoryIndex',
  ...extra,
});

describe('memoryLadder', () => {
  it('reads nothing from a job submitted without one', () => {
    expect(memoryLadder({ RequestMemory: 2048 })).toBeUndefined();
    expect(memoryLadder(undefined)).toBeUndefined();
  });

  it('ignores a transform that rewrites some other request', () => {
    expect(memoryLadder({ TransformOnEvict: 'RequestDisk' })).toBeUndefined();
  });

  it('reads the rungs and the ceiling of a ladder nothing has climbed', () => {
    const l = memoryLadder(laddered());
    expect(l).toEqual({ rungs: RUNGS, ceiling: 65536, atLeast: false });
    expect(climbedLadder(l)).toBe(false);
  });

  it('counts the evictions behind the index', () => {
    // The transform sets RequestMemory to rungs[k-1] and then bumps the
    // index to k, so index 2 is a job evicted twice, now asking 4096.
    const l = memoryLadder(laddered({ RequestMemory: 4096, RetryRequestMemoryIndex: 2 }));
    expect(l?.climbs).toBe(2);
    expect(l?.atLeast).toBe(false);
    expect(climbedLadder(l)).toBe(true);
  });

  it('calls the count a floor once the index has stuck at the top', () => {
    // MIN({size-1, k+1}) pins the index at 5 for a six-rung ladder, so a
    // job evicted five times and one evicted fifty look the same.
    const l = memoryLadder(laddered({ RequestMemory: 65536, RetryRequestMemoryIndex: 5 }));
    expect(l?.climbs).toBe(5);
    expect(l?.atLeast).toBe(true);
  });

  it('takes an index without a transform as a ladder', () => {
    const l = memoryLadder({ RequestMemory: 4096, RetryRequestMemoryIndex: 1 });
    expect(l?.climbs).toBe(1);
    expect(l?.rungs).toBeUndefined();
  });

  it('reads the increment spelling, which leaves a ceiling and no rungs', () => {
    const l = memoryLadder({
      RequestMemory: 2048,
      MaxRequestMemory: 32768,
      NextRequestMemory: '/Expr((RequestMemory + 2048))/',
      TransformOnEvict: 'RequestMemory',
    });
    expect(l).toEqual({ ceiling: 32768, atLeast: false });
  });

  it('reads the single-retry spelling, which leaves only the transform', () => {
    const l = memoryLadder({ RequestMemory: 2048, TransformOnEvict: 'RequestMemory' });
    expect(l).toEqual({ ceiling: undefined, atLeast: false });
  });

  it('does not invent rungs from a list written as an expression', () => {
    const l = memoryLadder(laddered({ RetryRequestMemory: '/Expr({ 2048, RequestMemory * 2 })/' }));
    expect(l?.rungs).toBeUndefined();
    expect(l?.ceiling).toBeUndefined();
  });

  it('reads the attributes however they are spelled', () => {
    const l = memoryLadder({ retryrequestmemory: RUNGS, retryrequestmemoryindex: 3 });
    expect(l?.rungs).toEqual(RUNGS);
    expect(l?.climbs).toBe(3);
  });
});

describe('ladderNote', () => {
  it('says nothing about a job without a ladder', () => {
    expect(ladderNote(undefined)).toBeUndefined();
  });

  it('counts one restart in the singular', () => {
    expect(ladderNote(memoryLadder(laddered({ RetryRequestMemoryIndex: 1 })))).toBe(
      'after 1 restart at more memory',
    );
  });

  it('keeps the count open where the index stops counting', () => {
    expect(ladderNote(memoryLadder(laddered({ RetryRequestMemoryIndex: 5 })))).toBe(
      'after 5 or more restarts at more memory',
    );
  });

  it('names the ceiling of a ladder nothing has climbed', () => {
    expect(ladderNote(memoryLadder(laddered()))).toBe('retries up to 64 GB');
  });

  it('falls back to the bare fact when the record names no sizes', () => {
    expect(ladderNote(memoryLadder({ TransformOnEvict: 'RequestMemory' }))).toBe('retries at more memory');
  });
});

describe('ladderTitle', () => {
  it('needs rungs to name', () => {
    expect(ladderTitle(memoryLadder({ TransformOnEvict: 'RequestMemory' }))).toBeUndefined();
  });

  it('spells out a ladder the job has not had to climb', () => {
    expect(ladderTitle(memoryLadder(laddered()))).toBe(
      'Runs out of memory and starts again at the next of 2 GB, 4 GB, 8 GB, 16 GB, 32 GB, 64 GB. It has not had to yet.',
    );
  });

  it('says once rather than 1 times', () => {
    expect(ladderTitle(memoryLadder(laddered({ RetryRequestMemoryIndex: 1 })))).toMatch(/It has done so once\.$/);
  });

  it('says where the count stops', () => {
    expect(ladderTitle(memoryLadder(laddered({ RetryRequestMemoryIndex: 5 })))).toMatch(
      /at least 5 times, and the record stops counting there\.$/,
    );
  });
});
