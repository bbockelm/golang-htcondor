import { describe, expect, it } from 'vitest';
import { slotProjection, SLOT_PROJECTION } from '@/lib/pool';

describe('slotProjection', () => {
  // The server REFUSES a projection naming an attribute the caller may
  // not read rather than trimming it, so asking anyway would empty the
  // whole page instead of blanking one column. That is why this is a
  // different request and not just different rendering.
  it('omits the owner when the site withholds it', () => {
    const attrs = slotProjection(true).split(',');
    expect(attrs).not.toContain('RemoteOwner');
    // Everything the page needs to describe the machine is still asked for.
    for (const needed of ['Name', 'Machine', 'State', 'Activity', 'Cpus', 'Memory', 'GPUs']) {
      expect(attrs).toContain(needed);
    }
  });

  it('asks for the owner when it is not withheld', () => {
    expect(slotProjection(false).split(',')).toContain('RemoteOwner');
  });

  it('defaults to the unrestricted projection', () => {
    expect(SLOT_PROJECTION).toBe(slotProjection(false));
  });
});
