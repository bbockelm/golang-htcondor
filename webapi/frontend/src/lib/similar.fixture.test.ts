import { describe, expect, it } from 'vitest';

import { estimateFixture, estimateGroup, similarFixture, type JobGroup } from './similar.fixture';

// A job's estimate and its similar jobs, as the fixtures give them, must
// describe one group: the demo and the smoke suite show both on one page.

function agree(group?: JobGroup) {
  const est = estimateFixture('1.0', { requested_mib: 1300 }, group);
  const sim = similarFixture('1.0', {}, group);
  expect(sim.estimate_level).toBe(est.basis!.level);
  expect(sim.level).toBe(est.basis!.level);
  // The estimate is the group's typical run, and its range the group's.
  expect([est.estimate_seconds, est.p10_seconds, est.p90_seconds, est.basis!.sample_count]).toEqual([
    sim.runtimes!.p50,
    sim.runtimes!.p10,
    sim.runtimes!.p90,
    sim.runtimes!.count,
  ]);
  const m = est.memory!;
  expect([m.sample_count, m.p10_mib, m.p25_mib, m.p50_mib, m.p75_mib, m.p90_mib]).toEqual([
    sim.memory!.count,
    sim.memory!.p10,
    sim.memory!.p25,
    sim.memory!.p50,
    sim.memory!.p75,
    sim.memory!.p90,
  ]);
  // The count above the request is counted from the jobs listed.
  const all = similarFixture('1.0', { page_size: 200 }, group).jobs;
  expect(m.above_requested).toBe(all.filter((j) => j.peak_memory_mib !== null && j.peak_memory_mib > 1300).length);
}

describe('the estimate and similar-jobs fixtures', () => {
  it('describe the same group by default', () => agree());

  it('describe the same group when a test gives its own', () =>
    agree({
      runtimes: { count: 12, p10: 9000, p25: 9900, p50: 10800, p75: 14400, p90: 18000 },
      memory: { count: 12, p10: 700, p25: 800, p50: 950, p75: 1100, p90: 1300 },
    }));

  it('leave the default group as the similar view has always drawn it', () => {
    expect(estimateGroup().runtimes.p50).toBe(2700);
    expect(estimateGroup().memory!.p50).toBe(1200);
  });
});
