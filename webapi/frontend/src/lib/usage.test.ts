import { describe, expect, it } from 'vitest';
import { formatP95, formatSeconds, p95SortValue, timeAgo } from './usage';
import type { UsageRow } from './api';

describe('formatSeconds', () => {
  it('picks a unit a reader can use', () => {
    expect(formatSeconds(0.005)).toBe('5 ms');
    expect(formatSeconds(0.25)).toBe('250 ms');
    expect(formatSeconds(1)).toBe('1 s');
    expect(formatSeconds(2.5)).toBe('2.5 s');
    expect(formatSeconds(30)).toBe('30 s');
    expect(formatSeconds(300)).toBe('5 min');
    expect(formatSeconds(90)).toBe('1 min 30 s');
    expect(formatSeconds(7200)).toBe('2 h');
  });
});

describe('formatP95', () => {
  it('shows a bucket bound as an upper bound', () => {
    expect(formatP95({ p95_seconds: 2.5 })).toBe('≤ 2.5 s');
  });
  it('shows past the last bound as longer than it', () => {
    expect(formatP95({ p95_seconds: null, p95_over_seconds: 300 })).toBe('> 5 min');
  });
  it('shows nothing when there is no distribution', () => {
    expect(formatP95({ p95_seconds: null })).toBe('—');
  });
  it('sorts longer-than-the-last-bound after every bound', () => {
    const over = { p95_seconds: null, p95_over_seconds: 300 } as UsageRow;
    const at = { p95_seconds: 300 } as UsageRow;
    expect(p95SortValue(over)!).toBeGreaterThan(p95SortValue(at)!);
  });
});

describe('timeAgo', () => {
  const now = Date.parse('2026-10-01T12:00:00Z');
  it('is relative to now', () => {
    expect(timeAgo('2026-10-01T11:59:58Z', now)).toBe('just now');
    expect(timeAgo('2026-10-01T11:55:00Z', now)).toBe('5m ago');
    expect(timeAgo('2026-09-28T12:00:00Z', now)).toBe('3d ago');
    expect(timeAgo(null, now)).toBe('—');
  });
});
