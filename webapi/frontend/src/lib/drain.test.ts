import { describe, expect, it } from 'vitest';
import {
  byMachine,
  clockTime,
  drainCell,
  drainDuration,
  drainTotals,
  slotEnd,
  submittedFrom,
  timelineMarks,
  type DrainSlot,
  type MachineDrain,
} from './drain';

const now = new Date(2026, 9, 12, 15, 10); // Mon Oct 12 2026, 3:10 PM local
const at = (seconds: number) => new Date(now.getTime() + seconds * 1000).toISOString();
const clock = (seconds: number) => clockTime(new Date(now.getTime() + seconds * 1000), now);

function node(over: Partial<MachineDrain>): MachineDrain {
  return {
    machine: 'e1.chtc.wisc.edu',
    draining: false,
    jobs_total: 0,
    jobs_estimated: 0,
    jobs_from_this_ap: 0,
    jobs_unknown_end: 0,
    jobs_unknown_from_other_aps: 0,
    evicted_on_drain: 0,
    exceeded: 0,
    ...over,
  };
}

describe('drainDuration', () => {
  it.each([
    [0, 'under a minute'],
    [59, 'under a minute'],
    [60, '1m'],
    [40 * 60, '40m'],
    [7800, '2h10m'],
    [7200, '2h'],
    [5 * 3600 + 5 * 60, '5h05m'],
    [86400 + 5 * 3600, '1 day 5h'],
    [86400, '1 day'],
    [259200, '3 days'],
    [233000, '3 days'],
  ])('%d seconds is %s', (s, want) => {
    expect(drainDuration(s)).toBe(want);
  });
});

describe('clockTime', () => {
  it('omits the day today, names it this week, dates it beyond', () => {
    expect(clock(3600)).not.toMatch(/Mon|Tue|Oct/);
    expect(clock(2 * 86400)).toMatch(/^Wed /);
    expect(clock(10 * 86400)).toMatch(/^Oct 22 /);
  });
});

describe('drainCell', () => {
  it('all estimated', () => {
    const c = drainCell(
      node({ jobs_total: 8, jobs_estimated: 8, jobs_from_this_ap: 8, likely_empty_seconds: 7800, likely_empty_at: at(7800) }),
      0,
      now,
    );
    expect(c.primary).toBe('About 2h10m');
    expect(c.detail).toBe(`likely by ${clock(7800)} · all 8 jobs estimated`);
    expect(c.warning).toBeUndefined();
  });

  it('counts the answer’s age off every figure', () => {
    const c = drainCell(
      node({ jobs_total: 1, jobs_estimated: 1, likely_empty_seconds: 7800, likely_empty_at: at(7740) }),
      600,
      now,
    );
    expect(c.primary).toBe('About 2h');
    expect(c.detail).toContain('its 1 job estimated');
  });

  it('mixed', () => {
    const c = drainCell(
      node({
        jobs_total: 6,
        jobs_estimated: 2,
        jobs_from_this_ap: 2,
        jobs_unknown_end: 4,
        jobs_unknown_from_other_aps: 4,
        likely_empty_seconds: 5400,
        at_least_seconds: 5400,
        unknown_up_to_seconds: 259200,
        at_most_seconds: 259300,
      }),
      0,
      now,
    );
    expect(c.primary).toBe('At least 1h30m');
    expect(c.detail).toBe('2 of 6 jobs estimated · 4 from other access points could run up to 3 days');
  });

  it('mixed, with this access point’s own unestimated jobs among the rest', () => {
    const c = drainCell(
      node({
        jobs_total: 3,
        jobs_estimated: 1,
        jobs_unknown_end: 2,
        jobs_unknown_from_other_aps: 1,
        likely_empty_seconds: 600,
        at_least_seconds: 600,
        unknown_up_to_seconds: 3600,
      }),
      0,
      now,
    );
    expect(c.detail).toBe('1 of 3 jobs estimated · 2 without an estimate could run up to 1h');
  });

  it('none estimated', () => {
    const c = drainCell(
      node({ jobs_total: 3, jobs_unknown_end: 3, jobs_unknown_from_other_aps: 3, unknown_up_to_seconds: 259200 }),
      0,
      now,
    );
    expect(c).toEqual({ primary: 'Up to 3 days', detail: 'jobs from other access points' });
  });

  it('none estimated and no limit', () => {
    const c = drainCell(node({ jobs_total: 1, jobs_unknown_end: 1, jobs_unknown_from_other_aps: 1 }), 0, now);
    expect(c).toEqual({ primary: 'No time limit', detail: 'a job from another access point' });
  });

  it('evicted on drain', () => {
    const c = drainCell(
      node({ jobs_total: 3, evicted_on_drain: 3, likely_empty_seconds: 30, likely_empty_at: at(30) }),
      0,
      now,
    );
    expect(c).toEqual({ primary: 'Empty in seconds', detail: '3 jobs would be evicted', warning: undefined });

    const later = drainCell(
      node({
        jobs_total: 2,
        jobs_estimated: 1,
        evicted_on_drain: 1,
        likely_empty_seconds: 3600,
        likely_empty_at: at(3600),
      }),
      0,
      now,
    );
    expect(later.primary).toBe('About 1h');
    expect(later.detail).toBe(`likely by ${clock(3600)} · 1 job would be evicted`);
  });

  it('exceeded with nothing else known', () => {
    const c = drainCell(
      node({ jobs_total: 2, jobs_unknown_end: 2, exceeded: 1, jobs_from_this_ap: 1, jobs_unknown_from_other_aps: 1, unknown_up_to_seconds: 7200 }),
      0,
      now,
    );
    expect(c).toEqual({ primary: 'Unclear', detail: 'could run up to 2h', warning: '1 job is running longer than usual' });
  });

  it('exceeded beside an estimate', () => {
    const c = drainCell(
      node({
        jobs_total: 2,
        jobs_estimated: 1,
        jobs_unknown_end: 1,
        exceeded: 1,
        likely_empty_seconds: 1800,
        at_least_seconds: 1800,
        unknown_up_to_seconds: 259200,
      }),
      0,
      now,
    );
    expect(c.primary).toBe('At least 30m');
    expect(c.warning).toBe('1 job is running longer than usual');
  });

  it('idle and drained nodes', () => {
    expect(drainCell(undefined, 0, now)).toEqual({ primary: 'Empty now', detail: '' });
    expect(drainCell(node({ likely_empty_seconds: 0 }), 0, now).primary).toBe('Empty now');
    expect(drainCell(node({ draining: true }), 0, now).primary).toBe('Drained');
  });

  it('draining', () => {
    const c = drainCell(
      node({ draining: true, jobs_total: 3, jobs_estimated: 3, likely_empty_seconds: 2400, likely_empty_at: at(2400) }),
      0,
      now,
    );
    expect(c.primary).toBe('Draining · about 40m');
  });
});

describe('slotEnd', () => {
  const base: DrainSlot = { name: 'slot1_1@e1', cpus: 1, from_this_ap: true, exceeded: false, evicted_on_drain: false };

  it('estimated', () => {
    const e = slotEnd({ ...base, expected_end: at(2700), usually_by: at(5400), retirement_deadline: at(259200) }, now);
    expect(e).toEqual({ primary: `~${clock(2700)}`, detail: `usually by ${clock(5400)}` });
  });

  it('another access point', () => {
    const e = slotEnd({ ...base, from_this_ap: false, retirement_deadline: at(2 * 86400) }, now);
    expect(e).toEqual({ primary: 'No estimate', detail: `retirement limit ${clock(2 * 86400)}` });
  });

  it('evicted', () => {
    expect(slotEnd({ ...base, from_this_ap: false, evicted_on_drain: true, retirement_deadline: at(30) }, now)).toEqual({
      primary: 'No estimate',
      detail: 'evicted if drained now',
    });
  });

  it('exceeded', () => {
    const e = slotEnd({ ...base, exceeded: true, retirement_deadline: at(3600) }, now);
    expect(e.warning).toBe('Running longer than usual');
    expect(e.detail).toBe(`retirement limit ${clock(3600)}`);
  });

  it('submitted from', () => {
    expect(submittedFrom(base)).toBe('this access point');
    expect(submittedFrom({ ...base, from_this_ap: false, submitted_from: 'ap2002.chtc.wisc.edu' })).toBe('ap2002.chtc.wisc.edu');
  });
});

describe('drainTotals', () => {
  it('adds up the nodes in view', () => {
    const t = drainTotals(
      [
        node({
          jobs_total: 3,
          jobs_estimated: 2,
          expected_ends: [
            { seconds: 1800, usually_by_seconds: 3000, cpus: 4 },
            { seconds: 7200, usually_by_seconds: 9000, cpus: 8 },
          ],
        }),
        node({ machine: 'd1', draining: true, jobs_total: 1, jobs_estimated: 1, likely_empty_seconds: 3000, expected_ends: [{ seconds: 3000, usually_by_seconds: 4000, cpus: 2 }] }),
        node({ machine: 'd2', draining: true, jobs_total: 1, jobs_unknown_end: 1, unknown_up_to_seconds: 100 }),
      ],
      0,
    );
    expect(t).toEqual({
      jobsRunning: 5,
      jobsEstimated: 3,
      coresFreeingNextHour: 6,
      drainingNodes: 2,
      drainingLikelyEmptyWithin2h: 1,
    });
  });
});

describe('timelineMarks', () => {
  it('places ends, ranges and the unknown band in six hours', () => {
    const t = timelineMarks(
      node({
        jobs_total: 3,
        jobs_estimated: 2,
        jobs_unknown_end: 1,
        exceeded: 0,
        unknown_up_to_seconds: 259200,
        expected_ends: [
          { seconds: 5400, usually_by_seconds: 10800, cpus: 1 },
          { seconds: 30000, usually_by_seconds: 40000, cpus: 1 },
        ],
      }),
      0,
    );
    expect(t.ticks).toEqual([0.25]);
    expect(t.bands).toEqual([{ from: 0.25, to: 0.5 }]);
    expect(t.unknown).toBe(1);
    expect(t.beyond).toBe('3 days');
  });
});

describe('byMachine', () => {
  it('is case-insensitive', () => {
    expect(byMachine([node({ machine: 'E1.Example' })]).get('e1.example')?.machine).toBe('E1.Example');
  });
});
