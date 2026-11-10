import { describe, expect, it } from 'vitest';
import { describeDegraded } from './multiap';
import { jobIdOf, scheddOf } from './api';

describe('describeDegraded', () => {
  it('names the staleness when the hub measured it', () => {
    expect(describeDegraded({ schedd: 'ap17', state: 'stale', staleness_seconds: 412 })).toBe(
      'ap17 (stale, 412 s behind)',
    );
  });
  it('falls back to the last sighting', () => {
    expect(describeDegraded({ schedd: 'ap31', state: 'absent' })).toBe('ap31 (absent)');
  });
});

describe('job identity', () => {
  it('reads the server-rendered id and access point', () => {
    expect(jobIdOf({ job_id: '1.0@ap1', schedd: 'ap1' })).toBe('1.0@ap1');
    expect(scheddOf({ job_id: '1.0@ap1', schedd: 'ap1' })).toBe('ap1');
  });
  it('is absent on a single-AP row', () => {
    expect(jobIdOf({ ClusterId: 1, ProcId: 0 })).toBeUndefined();
    expect(scheddOf({ ClusterId: 1 })).toBeUndefined();
  });
});
