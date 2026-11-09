import { describe, expect, it } from 'vitest';

import {
  carryHoursMinutes,
  formatHoursMinutes,
  hoursMinutesToSeconds,
  splitHoursMinutes,
} from '@/lib/reservation';

describe('splitHoursMinutes', () => {
  it('splits seconds into whole hours and minutes', () => {
    expect(splitHoursMinutes(6 * 3600)).toEqual({ hours: 6, minutes: 0 });
    expect(splitHoursMinutes(50 * 60)).toEqual({ hours: 0, minutes: 50 });
    expect(splitHoursMinutes(5400)).toEqual({ hours: 1, minutes: 30 });
  });

  it('drops sub-minute remainders rather than showing a value the form cannot hold', () => {
    expect(splitHoursMinutes(59)).toEqual({ hours: 0, minutes: 0 });
    expect(splitHoursMinutes(3659)).toEqual({ hours: 1, minutes: 0 });
  });

  it('clamps nonsense to zero', () => {
    expect(splitHoursMinutes(-10)).toEqual({ hours: 0, minutes: 0 });
    expect(splitHoursMinutes(NaN)).toEqual({ hours: 0, minutes: 0 });
  });
});

describe('hoursMinutesToSeconds', () => {
  it('round-trips a split', () => {
    for (const s of [0, 60, 900, 3600, 5400, 6 * 3600, 36 * 3600]) {
      const { hours, minutes } = splitHoursMinutes(s);
      expect(hoursMinutesToSeconds(hours, minutes)).toBe(s);
    }
  });

  it('reads a cleared box as zero', () => {
    expect(hoursMinutesToSeconds(NaN, 15)).toBe(900);
    expect(hoursMinutesToSeconds(2, NaN)).toBe(7200);
    expect(hoursMinutesToSeconds(-1, -1)).toBe(0);
  });
});

describe('carryHoursMinutes', () => {
  it('rolls the minute spinner over the hour, in both directions', () => {
    // The complaint this exists for: at 45 the up arrow did nothing.
    expect(carryHoursMinutes(1, 60)).toEqual({ hours: 2, minutes: 0 });
    expect(carryHoursMinutes(0, 60)).toEqual({ hours: 1, minutes: 0 });
    expect(carryHoursMinutes(2, -15)).toEqual({ hours: 1, minutes: 45 });
  });

  it('leaves a value that needs no carry exactly as it was typed', () => {
    // 50 minutes is a real reservation length and the boxes step in
    // quarter hours without restricting them, so it has to survive.
    expect(carryHoursMinutes(1, 50)).toEqual({ hours: 1, minutes: 50 });
    expect(carryHoursMinutes(0, 45)).toEqual({ hours: 0, minutes: 45 });
    expect(carryHoursMinutes(6, 0)).toEqual({ hours: 6, minutes: 0 });
  });

  it('reads a spinner step from a value that is not a quarter hour', () => {
    // A step up from 50 lands on 60, which is the next quarter hour
    // above it and so the next hour at zero; a step down lands on 45.
    expect(carryHoursMinutes(1, 60)).toEqual({ hours: 2, minutes: 0 });
    expect(carryHoursMinutes(1, 45)).toEqual({ hours: 1, minutes: 45 });
  });

  it('stops at zero rather than going negative, since a duration cannot', () => {
    expect(carryHoursMinutes(0, -15)).toEqual({ hours: 0, minutes: 0 });
    expect(carryHoursMinutes(-1, 0)).toEqual({ hours: 0, minutes: 0 });
  });

  it('reads a cleared or pasted box without losing the other one', () => {
    expect(carryHoursMinutes(NaN, 30)).toEqual({ hours: 0, minutes: 30 });
    expect(carryHoursMinutes(2, NaN)).toEqual({ hours: 2, minutes: 0 });
    expect(carryHoursMinutes(0, 95)).toEqual({ hours: 1, minutes: 35 });
  });

  it('agrees with the pair the wire is split into', () => {
    for (const s of [900, 3600, 5400, 50 * 60, 6 * 3600]) {
      const pair = splitHoursMinutes(s);
      expect(carryHoursMinutes(pair.hours, pair.minutes)).toEqual(pair);
    }
  });
});

describe('formatHoursMinutes', () => {
  it('names only the units it has', () => {
    expect(formatHoursMinutes(6 * 3600)).toBe('6 h');
    expect(formatHoursMinutes(45 * 60)).toBe('45 min');
    expect(formatHoursMinutes(5400)).toBe('1 h 30 min');
    expect(formatHoursMinutes(0)).toBe('0 min');
  });

  it('keeps long durations in hours, for comparison with short ones', () => {
    expect(formatHoursMinutes(36 * 3600)).toBe('36 h');
  });
});
