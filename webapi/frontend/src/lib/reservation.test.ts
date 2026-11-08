import { describe, expect, it } from 'vitest';

import {
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
