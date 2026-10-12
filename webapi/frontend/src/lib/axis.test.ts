import { describe, expect, it } from 'vitest';

import { formatAxisTicks, niceTicks } from './axis';

describe('formatAxisTicks', () => {
  // The job page's memory graph topped out at "19.5 GB" with "9.8 GB" and
  // "0 MB" below it: rounded in MB, then converted, in two units.
  it('ticks a memory axis in round GB, all in one unit', () => {
    const ticks = niceTicks(10987, 'mib', 4);
    expect(formatAxisTicks(ticks, 'mib')).toEqual(['0', '5 GB', '10 GB', '15 GB']);
  });

  it('labels a sub-GB step in GB rather than mixing in MB', () => {
    const ticks = niceTicks(1500, 'mib', 4);
    expect(formatAxisTicks(ticks, 'mib')).toEqual(['0', '0.5 GB', '1 GB', '1.5 GB']);
  });

  it('stays in MB for an axis that never reaches a GB', () => {
    const ticks = niceTicks(900, 'mib', 4);
    expect(formatAxisTicks(ticks, 'mib')).toEqual(['0', '250 MB', '500 MB', '750 MB', '1,000 MB']);
  });

  it('converts a KiB axis (disk) through the same scale', () => {
    const ticks = niceTicks(6291456, 'kib', 4);
    expect(formatAxisTicks(ticks, 'kib')).toEqual(['0', '2 GB', '4 GB', '6 GB']);
  });
});
